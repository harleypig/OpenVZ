package OpenVZ::vzctl;

# ABSTRACT: Call OpenVZ vzctl command from your program

#XXX: Do we need to load and parse the VZ system config file?
#XXX: Need to abstract out the common code into a top level OpenVZ module.
#XXX: Need to handle version specially, create a sub for it and remove it from
#     the validate hash for 'flag'.
#XXX: Need to use 'on_fail' option for validate_with for smoother error
#     handling.

=head1 SYNOPSIS

  use OpenVZ::vzctl;

  #XXX: need to add more examples

=head1 DESCRIPTION

This program is a simple (or not so simple in some cases) wrapper around the
'vzctl' program.  It will do some basic verification on options and parameters
but it will not (currently) do sanity checks on the values.

=cut

use strict;
use warnings;
use namespace::autoclean;

use Carp;
use Config::NameValue;
use File::Which;
use IPC::Run3::Simple;
use Params::Validate qw( :all );
use Regexp::Common qw( URI net );
use Sub::Exporter;

our %global;

# VERSION

############################################################################
# Base structure describing the subcommands and their arguments.

# Every subcommand requires ctid and has the optional flag.
# [parm] will make the parm optional in C<subcommand_specs>.

# subcommands like exec, exec2 and runscript run a command in the container.
# It's not really feasible to check within the container for the validity of
# a command or any arguments passed, so we'll assume the caller knows what
# they're doing with those by using C<allow_extra>.

my %vzctl = (

    destroy   => [],
    mount     => [],
    quotainit => [],
    quotaoff  => [],
    quotaon   => [],
    restart   => [],
    status    => [],
    stop      => [],
    umount    => [],

    start     => [qw( [force] [wait] )],
    enter     => [qw( [exec] allow_extra )],

    exec2     => [qw( allow_extra )],
    exec      => [qw( allow_extra )],
    runscript => [qw( allow_extra )],

    chkpnt    => [qw( [create_dumpfile] ) ],
    restore   => [qw( [restore_dumpfile] ) ],

    create    => [qw( [config] [hostname] [ipadd] [ostemplate] [private] [root] )],

    set       => [qw(

      [applyconfig] [applyconfig_map] [bootorder] [cpulimit] [cpumask] [cpus]
      [cpuunits] [disabled] [force] [hostname] [ioprio] [ipadd] [ipdel]
      [nameserver] [noatime] [onboot] [quotatime] [quotaugidlimit] [save]
      [searchdomain] [setmode] [userpasswd] [capability] [name] [iptables]
      [features] [devices] [devnodes] [netif_add] [netif_del] [pci_add]
      [pci_del] [diskinodes] [numfile] [numflock] [numiptent] [numothersock]
      [numproc] [numpty] [numsiginfo] [numtcpsock] [avnumproc] [diskspace]
      [dcachesize] [numfile] [numflock] [numiptent] [numothersock] [numproc]
      [numpty] [numsiginfo] [numtcpsock] [dgramrcvbuf] [kmemsize]
      [othersockbuf] [tcprcvbuf] [tcpsndbuf] [lockedpages] [oomguarpages]
      [physpages] [privvmpages] [shmpages] [swappages] [vmguarpages]

   )],

);

my %validate = do {

  my $cap_names = join '|', qw(

    chown dac_override dac_read_search fowner fsetid ipc_lock ipc_owner kill
    lease linux_immutable mknod net_admin net_bind_service net_broadcast
    net_raw setgid setpcap setuid setveid sys_admin sys_boot sys_chroot
    sys_module sys_nice sys_pacct sys_ptrace sys_rawio sys_resource sys_time
    sys_tty_config ve_admin

  );

  my $iptables_names = join '|', qw(

    ip_conntrack ip_conntrack_ftp ip_conntrack_irc ip_nat_ftp ip_nat_irc
    iptable_filter iptable_mangle iptable_nat ipt_conntrack ipt_helper
    ipt_length ipt_limit ipt_LOG ipt_multiport ipt_owner ipt_recent
    ipt_REDIRECT ipt_REJECT ipt_state ipt_tcpmss ipt_TCPMSS ipt_tos ipt_TOS
    ipt_ttl xt_mac

  );

  my $features_names = join '|', qw( sysfs nfs sit ipip ppp ipgre bridge nfsd);

  my %hash = (

    allow_extra => 1, # special case to handle parms we aren't going to check
                      # (e.g., exec and friends). Leave it as an invalid entry
                      # for validate_with so programmers will catch it before it
                      # goes live.

    bootorder  => { regex     => qr/^\d+$/ },
    capability => { regex     => qr/^(?:$cap_names):(?:on|off)$/ },
    cpumask    => { regex     => qr/^\d+(?:[,-]\d+)*|all$/ },
    ctid       => { callbacks => { 'validate ctid' => \&_validate_ctid } },
    exec       => { type      => SCALAR },
    flag       => { regex     => qr/^quiet|verbose$/ },
    force      => { type      => UNDEF },
    ioprio     => { regex     => qr/^[0-7]$/ },
    onboot     => { regex     => qr/^yes|no$/ },
    setmode    => { regex     => qr/^restart|ignore/ },
    userpasswd => { regex     => qr/^(?:\w+):(?:\w+)$/ },
    features   => { regex     => qr/^(?:$features_names):(?:on|off)$/ },
    devices    => { regex     => qr/^(?:(?:(?:b|c):\d+:\d+)|all:(?:r?w?))|none$/ },
    diskinodes => { regex     => qr/^\d+(?::\d+)?$/ },
    avnumproc  => { regex     => qr/^\d+(?:gmkp)?(?::\d+(?:gmkp))?$/i },

    ipadd => {
      type => SCALAR | ARRAYREF, # This handles the type check for us.
      callbacks => { 'do these look like valid ip(s)?' => sub {

        my @ips = ref $_[0] eq 'ARRAY' ? @$_[0] : $_[0];
        my @bad_ips = grep { ! /^$RE{net}{IPv4}$/ } @ips;
        return ! @bad_ips; # return 1 if there are no bad ips, undef otherwise.

        #NOTE: I can't find a way to modify the incoming data, and it may not
        #      be a good idea to do that in any case. Unless, and until, I can
        #      figure out how to do this the right way this will be an atomic
        #      operation. It's either all good, or it's not.

    }}},

    ipdel => {
      type => SCALAR | ARRAYREF, # This handles the type check for us.
      callbacks => { 'do these look like valid ip(s)?' => sub {

        my @ips = ref $_[0] eq 'ARRAY' ? @$_[0] : $_[0];
        my @bad_ips = grep { ! /^$RE{net}{IPv4}$/ } @ips;
        return 1 if grep { /^all$/i } @bad_ips;
        return ! @bad_ips;

        #NOTE: See ipadd note.

    }}},

    iptables => {
      type => SCALAR | ARRAYREF, # This handles the type check for us.
      callbacks => { 'see manpage for list of valid iptables names' => sub {

        my @names;

        if ( ref $_[0] eq 'ARRAY' ) {

          @names = @$_[0];

        } else {

          my $names = shift;
          return unless $names =~ s/^['"](.*?)['"]$/$1/;
          @names = split /\s+/, $names;

        }

        my @bad_names = grep { ! /^$iptables_names$/ } @names;
        return ! @bad_names;

        #NOTE: See ipadd note.

    }}},

    create_dumpfile => { callbacks => { 'does it look like a valid filename?' => sub {
      my $file = sprintf 'file://localhost/%s', +shift;
      $file =~ /^$RE{URI}{file}$/;
    }}},

    restore_dumpfile => { callbacks => { 'does file exist?' => sub { -e( +shift ) } } },

    devnodes => { callbacks => { 'setting access to devnode' => sub {

      return 1 if $_[0] eq 'none';
      ( my $device = $_[0] ) =~ s/^(.*?):r?w?q?$/$1/;
      $device = "/dev/$device";
      return -e $device;

    }}},

  );

  my %same = (

    # SCALAR checks
    exec => [qw(

      applyconfig applyconfig_map config hostname name netif_add netif_del
      ostemplate pci_add pci_del private root searchdomain

    )],

    #XXX: Need to make 'config', 'ostemplate', 'private' and 'root' more
    #     robust.  We can pull the data from the global config file to help
    #     validate this info.

    # UNDEF checks
    force => [qw( save wait )],

    # INT checks
    bootorder => [qw( cpulimit cpus cpuunits quotatime quotaugidlimit )],

    # yes or no checks
    onboot => [qw( disabled noatime )],

    # ip checks
    ipadd  => [qw( nameserver )],

    # hard|soft limits (no suffixes)
    diskinodes => [qw(

      numfile numflock numiptent numothersock numproc numpty numsiginfo
      numtcpsock

    )],

    # hard|soft limits (with suffixes)
    avnumproc => [qw(

      dcachesize dgramrcvbuf diskspace kmemsize lockedpages numfile numflock
      numiptent numothersock numproc numpty numsiginfo numtcpsock oomguarpages
      othersockbuf physpages privvmpages shmpages swappages tcprcvbuf tcpsndbuf
      vmguarpages

    )],
  );

  $hash{ $same{ $_ } } = $hash{ $_ }
    for keys %same;

  %hash;

};

############################################################################
# Public functions

#XXX: Should be extracted out into common module (OpenVZ.pm?)

=function execute

This function should not be called directly unless you know what you're doing.

C<execute> uses L<IPC::Run3::Simple>'s C<run3> function to make system calls.
C<run3> returns whatever is sent to STDOUT, STDERR and the exit value as well
as the execution time of the system call.

This function is the workhorse of this package.  It expects the following
parameters as a hashref

  command => program name to be called (e.g., vzctl) (STRING)
  params  => parameters to be passed to the command to be called (ARRAYREF)

C<params> is optional.

The params value will not be checked for validity.  It is assumed that if you
are calling this subroutine you have already validated whatever is going to be
passed on the command line.

=cut

sub execute {

  my %arg = validate( @_, {
    'command' => { callbacks => { 'find command path' => \&_find_command } },
    'params'  => { type => ARRAYREF, optional => 1 },
  });

  # XXX: Need to handle also the case of a hashref
  return run3([ $global{ path }{ $arg{ command } }, @{ $arg{ params } } ]);

}

=function vzctl

C<vzctl> is used to call C<execute> with vzctl as the specific command.

C<vzctl> expects a hashref with the required keys C<subcommand> and C<ctid>
and does B<NOT> check the validity of any remaining keys.

A C<flag> key is optional and accepts C<quiet>, C<verbose> and C<version>.

If the C<flag> key is set to C<version> then C<vzctl> will ignore all other
parameters and make the equivalent call of C<vzctl --version>, which returns
the version number of the installed vzctl command.

An example of a valid call would be

  my $result = vzctl({ subcommand => 'set', 'ctid' => 101, ipadd => '1.2.3.4', save => undef });

In this case, C<set> and C<101> would be validated, but C<1.2.3.4> and the
value for C<save> would just be passed along to C<execute> as is.

The C<undef> value in C<save> is a hint to C<vzctl> that the C<save> parameter
should be passed as a switch (i.e., --save instead of --save undef).

When a value is an arrayref, e.g., ipadd => [qw( 1.2.3.4 2.3.4.5 )]. C<vzctl>
will send the same parameter multiple times.  The previous example would
become '--ipadd 1.2.3.4 --ipadd 2.3.4.5'.

You're probably better off if you use the functions designed for
a specific command unless you know what you're doing.

=cut

sub vzctl {

  my $spec = subcommand_specs(qw( flag ctid ));

  my $subcommands = join '|', keys %vzctl;
  $spec->{ subcommand } = { regex => qr/^$subcommands$/ },

  my %arg = validate_with(
    params => @_,
    spec   => $spec,
    allow_extra => 1,
  );

  my %hash = ( command => 'vzctl' );

  if ( exists $arg{ flag } && $arg{ flag } eq 'version' ) {

    $hash{ params } = [ '--version' ];
    return execute( \%hash );

  }

  my @params;

  push @params, ( sprintf '--%s', delete $arg{ flag } )
    if exists $arg{ flag };

  push @params, delete $arg{ subcommand };

  delete $arg{ ctid };
  push @params, $global{ ctid };

  for my $p ( keys %arg ) {

    my $arg_name = "--$p";
    my $ref      = ref $arg{ $p };

    if ( $ref eq 'ARRAY' ) {

      push @params, ( $arg_name, $_ )
        for @{ $arg{ $p } };

    } elsif ( $ref eq '' ) {

      push @params, $arg_name;
      push @params, $arg{ $p }
        unless $arg{ $p } eq undef;

    } else {

      croak "Don't know how to handle ref type $ref for $p";

    }
  }

  $hash{ params } = \@params;

  return execute( \%hash );

}

=function subcommand_specs

C<subcommand_specs> expects a list.  The first element will be checked against
a list of known subcommands for vzctl.

If the first element is a known subcommand a predefined hashref will be
instantiated.  Any following elements will be treated as additional
specification names to be included.  Duplicates will be silently ignored.  If
an element is preceded by a dash (-), that element will be removed from the
hashref.

If the first element is not a known subcommand a hashref will be created with
the specification names provided, including the first element.  Using a dash
makes no sense in this context, but will not cause any problems.

C<subcommand_specs> will return the hashref described previously that
can be used in the C<spec> option of C<Params::Validate>'s C<validate_with>
function.  E.g., the call

  my $spec = subcommand_specs( 'stop' );

will return a hashref into C<$spec> that looks like

  $spec = {
    flag  => { regex => qr/^quiet|verbose|version$/, optional => 1 },
    ctid  => { callback => { 'validate ctid' => \&_validate_ctid } },
  }

while the call

  my $spec = subcommand_specs( 'ctid' );

would yield

  $spec = { ctid => { callback => { 'validate ctid' => \&_validate_ctid } } };

If a parameter is surrounded with square brackets ( [] ) the parameter is made
optional.

In order to automate as much of this as possible, there is a special case for
the 'allow_extra' option to C<validate_with>.  If the returned hash has a key
named 'allow_extra', you should set C<allow_extra =&gt; 1> in your call to
validate_with.  Or just delete it if you want to override it for whatever
reason.

=cut

sub subcommand_specs {

  my @args = validate_with(
    params => \@_,
    spec => [ { type => SCALAR } ],
    allow_extra => 1,
  );

  my %spec_hash;

  my $subcommands = join '|', keys %vzctl;

  if ( $args[0] =~ /^$subcommands$/ ) {

    # then build predefined specification hash

    my @specs = @{ $vzctl{ +shift @args } };

    # Every subcommand has these two at a minimum.
    unshift @specs, '[flag]', 'ctid';

    for my $spec ( @specs ) {

      my $optional = $spec =~ s/^\[(.*)\]$/$1/;

      croak "Unknown spec $spec"
        unless exists $validate{ $spec };

      next if grep { /^-$spec$/ } @args;

      $spec_hash{ $spec } = $validate{ $spec };

      $spec_hash{ $spec }{ optional } = 1
        if $optional;

    }
  }

  # build custom specification hash if any args are left

  for my $spec ( @args ) {

    next if $spec =~ /^-/;
    next if exists $spec_hash{ $spec };

    croak "Unknown spec $spec"
      unless exists $validate{ $spec };

    $spec_hash{ $spec } = $validate{ $spec };

  }

  return \%spec_hash;

}

############################################################################
# Internal Functions

# Determines if the specified command is installed, what its path is and
# caches it.

#XXX: Should be extracted out into common module (OpenVZ.pm?)

sub _find_command {

  #my ( $pgm, $params ) = @_;
  my $pgm = shift;

  return 1
    if exists $global{ path }{ $pgm };

  $global{ path }{ $pgm } = which( $pgm )
    or croak "Could not find $pgm in path ($ENV{PATH})";

  return 1;

}

# Is the provided ctid a valid container identifier?

sub _validate_ctid {

  #my ( $ctid, $params ) = @_;
  my $check_ctid = shift;

  { no warnings qw( numeric uninitialized );

    return 1
      if ( exists $global{ ctid } && $global{ ctid } == $check_ctid )
      || ( exists $global{ name } && $global{ name } eq $check_ctid );
  };

  # XXX: Need to modify this when vzlist is handled so we keep things
  # uncluttered.

  $DB::single = 1;

  my ( $stdout, $stderr, $syserr ) = execute({
    command => 'vzlist',
    params  => [ '-Ho', 'ctid,name', $check_ctid ],
  });

  croak 'vzlist did not execute'
    if $syserr == -1;

  $syserr >>= 8;

  croak "Invalid or unknown container ($check_ctid): $stderr"
    if $syserr == 1;

  $stdout =~ s/^\s*(.*?)\s*$/$1/;
  my ( $ctid, $name ) = split /\s+/, $stdout;

  $global{ ctid } = $ctid;
  $global{ name } = $name;

  return 1;

}

# Generate the code for each of the subcommands
# https://metacpan.org/module/Sub::Exporter#Export-Configuration

sub _generate_subcommand {

  my ( $class, $name, $arg, $collection ) = @_;
  my $spec = subcommand_specs( $name );

  # the !! forces either undef or 1
  my $allow_extra = !! delete $spec->{ allow_extra };

  #XXX: Need to handle case of calling class using something like
  #
  # use OpenVZ::vzctl set => { -as => 'setip', arg => 'ipadd' };
  #
  # and creating a sub that only accepts the ipadd parameter.

  sub {

    my %arg = validate_with(
      params      => \@_,
      spec        => $spec,
      allow_extra => $allow_extra,
    );

    $arg{ subcommand } = $name;

    vzctl( \%arg );

  }
}

############################################################################
# Setup exporter

my @exports = qw( execute vzctl subcommand_specs );

push @exports, ( $_ => \&_generate_subcommand )
  for keys %vzctl;

my $config = {

  exports => \@exports,
  groups  => {},
  collectors => [],

};

Sub::Exporter::setup_exporter( $config );

1;
