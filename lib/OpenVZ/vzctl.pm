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

=head2 NOTE

All of the commands for vzctl are implemented and all of the options for each
command is provided for, but some commands and options I don't use so I'm not
sure how to test them.  Tests are welcome.

If you want to know what commands and options are available read C<vzctl>s man
page.  I followed that in creating this module.

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

=vzctl_cmd chkpnt

C<chkpnt> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

Can be either a CTID or name. The command C<vzlist -Ho name,ctid value> is
used to determine if C<value> is a valid identifier.

=item create_dumpfile (optional)

Expects a scalar that looks like a file but does not check if it's possible to
write to the specified file.  L<Regexp::Common>'s C<URI> regex is used to
determine what looks like a file.

=back

See the C<vzctl> manpage for information on the C<chkpnt> command.

=vzctl_cmd create

C<create> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=item config (optional)

Expects a scalar, but doesn't check validity of value.

=item hostname (optional)

Expects a scalar, but doesn't check validity of value.

=item ipadd (optional)

Expects a scalar or a reference to an array. L<Regexp::Common>'s C<net IPv4> regex
is used to determine if the values are valid looking ips.

=item ostemplate (optional)

Expects a scalar, but doesn't check validity of value.

=item private (optional)

Expects a scalar, but doesn't check validity of value.

=item root (optional)

Expects a scalar, but doesn't check validity of value.

=back

See the C<vzctl> manpage for information on the C<create> command.

=vzctl_cmd destroy

C<destroy> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=back

See the C<vzctl> manpage for information on the C<destroy> command.

=vzctl_cmd enter

C<enter> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=item exec (optional)

Expects a scalar or reference to an array but doesn't check for the validity
of the command.

=back

See the C<vzctl> manpage for information on the C<enter> command.

=vzctl_cmd exec

C<exec> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=item command (required)

Expects a scalar or a reference to an array but doesn't check for the validity
of the command.

=back

See the C<vzctl> manpage for information on the C<exec> command.

=vzctl_cmd exec2

C<exec2> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=item command (required)

Expects a scalar or a reference to an array but doesn't check for the validity
of the command.

=back

See the C<vzctl> manpage for information on the C<exec2> command.

=vzctl_cmd mount

C<mount> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=back

See the C<vzctl> manpage for information on the C<mount> command.

=vzctl_cmd quotainit

C<quotainit> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=back

See the C<vzctl> manpage for information on the C<quotainit> command.

=vzctl_cmd quotaoff

C<quotaoff> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=back

See the C<vzctl> manpage for information on the C<quotaoff> command.

=vzctl_cmd quotaon

C<quotaon> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=back

See the C<vzctl> manpage for information on the C<quotaon> command.

=vzctl_cmd restart

C<restart> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=back

See the C<vzctl> manpage for information on the C<restart> command.

=vzctl_cmd restore

C<restore> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=item restore_dumpfile

Checks if the file exists, but does not check for validity of file format.

=back

See the C<vzctl> manpage for information on the C<restore> command.

=vzctl_cmd runscript

C<runscript> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=item script (required)

Expects a scalar or a reference to an array but doesn't check for the validity
of the script.

=back

See the C<vzctl> manpage for information on the C<runscript> command.

=vzctl_cmd set

C<set> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=item applyconfig

=item applyconfig_map

=item hostname

=item name

=item netif_add

=item netif_del

=item pci_add

=item pci_del

=item searchdomain

Expects a scalar. No other validation is performed.

=item avnumproc

=item dcachesize

=item dgramrcvbuf

=item diskinodes

=item diskspace

=item kmemsize

=item lockedpages

=item numfile

=item numflock

=item numiptent

=item numothersock

=item numproc

=item numpty

=item numsiginfo

=item numtcpsock

=item oomguarpages

=item othersockbuf

=item physpages

=item privvmpages

=item shmpages

=item swappages

=item tcprcvbuf

=item tcpsndbuf

=item vmguarpages

Expects an integer followed by an optional 'g', 'm', 'k' or 'p', followed
optionally by a colon and an integer and an optional 'g', 'm', 'k' or 'p'.
E.g., 5M or 5M:15M.

=item bootorder

=item cpulimit

=item cpus

=item cpuunits

=item quotatime

=item quotaugidlimit

Expects an integer.

=item capability

Expects one of the following capabilities

    chown dac_override dac_read_search fowner fsetid ipc_lock ipc_owner kill
    lease linux_immutable mknod net_admin net_bind_service net_broadcast
    net_raw setgid setpcap setuid setveid sys_admin sys_boot sys_chroot
    sys_module sys_nice sys_pacct sys_ptrace sys_rawio sys_resource sys_time
    sys_tty_config ve_admin

joined with either 'on' or 'off' with a colon. E.g., 'chown:on'.

=item cpumask

Expects either a comma separated list of integers or the word 'all'.

=item devices

Expects a device that matches the regex

  /^(?:(?:(?:b|c):\d+:\d+)|all:(?:r?w?))|none$/

No other validation is performed.

XXX Better explanation needed here.

=item devnodes

=item features

Expects one of the following features

  sysfs nfs sit ipip ppp ipgre bridge nfsd

followed by a colon and either 'on' or 'off'.

=item force

=item save

Expects either undef or the empty string.

=item ioprio

Expects a single integer from 0 to 7.

=item ipadd

=item ipdel

Expects either an array reference or a space separated list of ips to be added
or deleted. L<Regexp::Common>'s C<net IPv4> regex is used to determine if the
ips look valid.  No other validation is performed.

C<ipdel> also accepts 'all' to delete all ips.

=item iptables

Expects either an array reference or space separated list of one or more of
the following

    ip_conntrack ip_conntrack_ftp ip_conntrack_irc ip_nat_ftp ip_nat_irc
    iptable_filter iptable_mangle iptable_nat ipt_conntrack ipt_helper
    ipt_length ipt_limit ipt_LOG ipt_multiport ipt_owner ipt_recent
    ipt_REDIRECT ipt_REJECT ipt_state ipt_tcpmss ipt_TCPMSS ipt_tos ipt_TOS
    ipt_ttl xt_mac

=item nameserver

=item disabled

=item noatime

=item onboot

Expects either 'yes' or 'no'.

=item setmode

Expects either 'restart' or 'ignore'.

=item userpasswd

Expects two strings separated by a colon.  No other validation is performed on
the value.

=back

See the C<vzctl> manpage for information on the C<set> command.

=vzctl_cmd start

C<start> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=item force

=item wait

Expects either undef or the empty string.

=back

See the C<vzctl> manpage for information on the C<start> command.

=vzctl_cmd status

C<status> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=back

See the C<vzctl> manpage for information on the C<status> command.

=vzctl_cmd stop

C<stop> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=back

See the C<vzctl> manpage for information on the C<stop> command.

=vzctl_cmd umount

C<umount> expects a hash reference with the following keys and values.

=over 4

=item ctid (required)

See C<chkpnt> for details.

=back

See the C<vzctl> manpage for information on the C<umount> command.

=cut

# Every subcommand requires ctid and has the optional flag of C<quiet> or
# C<verbose>.  Though these flags are mutually exclusive, C<vzctl> will accept
# both at the same time.  Results are undefined when using both flag at the
# same time.

# Surrounding a paremeter with square brackets ( [parm] ) will make the parm
# optional in C<subcommand_specs>.

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

    exec      => [qw( command )],
    exec2     => [qw( command )],
    runscript => [qw( script )],

    start     => [qw( [force] [wait] )],
    enter     => [qw( [exec] )],

    chkpnt    => [qw( [create_dumpfile] )],
    restore   => [qw( [restore_dumpfile] )],

    create    => [qw( [config] [hostname] [ipadd] [ostemplate] [private] [root] )],

    set       => [qw(

      [applyconfig] [applyconfig_map] [avnumproc] [bootorder] [capability]
      [cpulimit] [cpumask] [cpus] [cpuunits] [dcachesize] [devices] [devnodes]
      [dgramrcvbuf] [disabled] [diskinodes] [diskspace] [features] [force]
      [hostname] [ioprio] [ipadd] [ipdel] [iptables] [kmemsize] [lockedpages]
      [name] [nameserver] [netif_add] [netif_del] [noatime] [numfile]
      [numflock] [numiptent] [numothersock] [numproc] [numpty] [numsiginfo]
      [numtcpsock] [onboot] [oomguarpages] [othersockbuf] [pci_add] [pci_del]
      [physpages] [privvmpages] [quotatime] [quotaugidlimit] [save]
      [searchdomain] [setmode] [shmpages] [swappages] [tcprcvbuf] [tcpsndbuf]
      [userpasswd] [vmguarpages]

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

  my $features_names = join '|', qw( sysfs nfs sit ipip ppp ipgre bridge nfsd );

  my %hash = (

    avnumproc   => { type => SCALAR, regex => qr/^\d+[gmkp]?(?::\d+[gmkp]?)?$/i },
    bootorder   => { type => SCALAR, regex => qr/^\d+$/ },
    capability  => { type => SCALAR, regex => qr/^(?:$cap_names):(?:on|off)$/i },
    cpumask     => { type => SCALAR, regex => qr/^\d+(?:[,-]\d+)*|all$/i },
    devices     => { type => SCALAR, regex => qr/^(?:(?:[bc]:\d+:\d+)|all:(?:r?w?))|none$/i },
    features    => { type => SCALAR, regex => qr/^(?:$features_names):(?:on|off)$/i },
    flag        => { type => SCALAR, regex => qr/^quiet|verbose/i },
    ioprio      => { type => SCALAR, regex => qr/^[0-7]$/ },
    onboot      => { type => SCALAR, regex => qr/^yes|no$/i },
    setmode     => { type => SCALAR, regex => qr/^restart|ignore/i },
    userpasswd  => { type => SCALAR, regex => qr/^(?:\w+):(?:\w+)$/ },

    applyconfig => { type => SCALAR, callbacks => { 'do not want empty strings' => sub { return $_[0] ne '' }}},
    ctid        => { type => SCALAR, callbacks => { 'validate ctid' => \&_validate_ctid } },

    force       => { type => UNDEF },

    command => {
      type      => SCALAR | ARRAYREF,
      callbacks => { 'do not want empty values' => sub {

        return ref $_[0] eq '' ? do { $_[0] ne '' }
                               : do { defined $_[0]->[0] && $_[0]->[0] ne '' };

      }},
    },

    ipadd => {
      type => SCALAR | ARRAYREF,
      callbacks => { 'do these look like valid ip(s)?' => sub {

        my @ips = ref $_[0] eq 'ARRAY' ? @{ $_[0] } : $_[0];
        return unless @ips;
        # I'd rather not do
        no warnings 'uninitialized';
        # but
        # my @bad_ips = grep { defined    && ! /^$RE{net}{IPv4}$/ } @ips;
        # my @bad_ips = grep { defined $_ && ! /^$RE{net}{IPv4}$/ } @ips;
        # don't work and I'm not sure what else to try.
        my @bad_ips = grep { ! /^$RE{net}{IPv4}$/ } @ips;
        return ! @bad_ips; # return 1 if there are no bad ips, undef otherwise.

        #NOTE: I can't find a way to modify the incoming data, and it may not
        #      be a good idea to do that in any case. Unless, and until, I can
        #      figure out how to do this the right way this will be an atomic
        #      operation. It's either all good, or it's not.

    }}},

    ipdel => {
      type => SCALAR | ARRAYREF,
      callbacks => { 'do these look like valid ip(s)?' => sub {

        my @ips = ref $_[0] eq 'ARRAY' ? @{ $_[0] } : $_[0];
        return unless @ips;
        no warnings 'uninitialized'; # see notes for ipadd
        my @bad_ips = grep { ! /^$RE{net}{IPv4}$/ } @ips;
        return 1 if grep { /^all$/i } @bad_ips;
        return ! @bad_ips;

        #NOTE: See ipadd note.

    }}},

    iptables => {
      type => SCALAR | ARRAYREF,
      callbacks => { 'see manpage for list of valid iptables names' => sub {

        my @names;

        if ( ref $_[0] eq 'ARRAY' ) {

          @names = @$_[0];

        } else {

          my $names = shift;
          return unless $names =~ s/^['"](.*?)['"]$/$1/;
          @names = split /\s+/, $names;

        }

        no warnings 'uninitialized'; # see notes for ipadd
        my @bad_names = grep { ! /^$iptables_names$/ } @names;
        return ! @bad_names;

        #NOTE: See ipadd note.

    }}},

    create_dumpfile => {
      type      => SCALAR,
      callbacks => { 'does it look like a valid filename?' => sub {
        return if $_[0] eq '';
        my $file = sprintf 'file://localhost/%s', +shift;
        $file =~ /^$RE{URI}{file}$/;
    }}},

    restore_dumpfile => {
      type      => SCALAR,
      callbacks => { 'does file exist?' => sub { -e( +shift ) } },
    },

    devnodes => {
      type      => SCALAR,
      callbacks => { 'setting access to devnode' => sub {

      return if ! defined $_[0] || $_[0] eq '';
      return 1 if $_[0] eq 'none';
      ( my $device = $_[0] ) =~ s/^(.*?):r?w?q?$/$1/;
      $device = "/dev/$device";
      return -e $device;

    }}},

  );

  my %same = (

    # SCALAR checks
    applyconfig => [qw(

      applyconfig_map config hostname name netif_add netif_del ostemplate
      pci_add pci_del private root searchdomain

    )],

    #XXX: Need to make 'config', 'ostemplate', 'private' and 'root' more
    #     robust.  We can pull the data from the global config file to help
    #     validate this info.

    # SCALAR | ARRAYREF checks
    command => [qw( exec script )],

    # UNDEF checks
    force => [qw( save wait )],

    # INT checks
    bootorder => [qw( cpulimit cpus cpuunits quotatime quotaugidlimit )],

    # yes or no checks
    onboot => [qw( disabled noatime )],

    # ip checks
    ipadd  => [qw( nameserver )],

    # hard|soft limits
    avnumproc => [qw(

      dcachesize dgramrcvbuf diskinodes diskspace kmemsize lockedpages numfile
      numflock numiptent numothersock numproc numpty numsiginfo numtcpsock
      oomguarpages othersockbuf physpages privvmpages shmpages swappages
      tcprcvbuf tcpsndbuf vmguarpages

    )],
  );

  for my $key ( keys %same ) {

    $hash{ $_ } = $hash{ $key }
      for @{ $same{ $key } };

  }

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

{ # Hide subcommands regex

my $subcommands = join '|', keys %vzctl;

sub vzctl {

  my $spec = subcommand_specs(qw( flag ctid ));
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
        if $arg{ $p } ne '';

    } else {

      croak "Don't know how to handle ref type $ref for $p";

    }
  }

  $hash{ params } = \@params;

  return execute( \%hash );

}
} # End hiding

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

  #XXX: Need to handle case of calling class using something like
  #
  # use OpenVZ::vzctl set => { -as => 'setip', arg => 'ipadd' };
  #
  # and creating a sub that only accepts the ipadd parameter.

  my ( $class, $name, $arg, $collection ) = @_;
  my $spec = subcommand_specs( $name );

  my %sub_spec;

  $sub_spec{ spec } = $spec;

  sub {

    $sub_spec{ params } = \@_;
    my %arg = validate_with( %sub_spec );
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
