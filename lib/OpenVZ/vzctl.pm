package OpenVZ::vzctl;

# ABSTRACT: Call OpenVZ vzctl command from your program

#XXX: Do we need to load and parse the VZ system config file?
#XXX: Need to abstract out the common code into a top level OpenVZ module.
#XXX: Need to handle version specially, create a sub for it and remove it from
#     the validate hash for 'flag'.

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

    chkpnt    => [ '[create_dumpfile]' ],
    restore   => [ '[restore_dumpfile]' ],

    create    => [qw( [ostemplate] [config] [private] [root] [ipadd] [hostname] )],
#    create => <ctid> [--ostemplate <name>] [--config <name>] [--private <path>] [--root <path>] [--ipadd <addr>] | [--hostname <name>]

#    set => <ctid> [--save] [--force] [--setmode restart|ignore]
#   [--ipadd <addr>] [--ipdel <addr>|all] [--hostname <name>]
#   [--nameserver <addr>] [--searchdomain <name>]
#   [--onboot yes|no] [--bootorder <N>]
#   [--userpasswd <user>:<passwd>]
#   [--cpuunits <N>] [--cpulimit <N>] [--cpus <N>] [--cpumask <cpus>]
#   [--diskspace <soft>[:<hard>]] [--diskinodes <soft>[:<hard>]]
#   [--quotatime <N>] [--quotaugidlimit <N>]
#   [--noatime yes|no] [--capability <name>:on|off ...]
#   [--devices b|c:major:minor|all:r|w|rw]
#   [--devnodes device:r|w|rw|none]
#   [--netif_add <ifname[,mac,host_ifname,host_mac,bridge]]>]
#   [--netif_del <ifname>]
#   [--applyconfig <name>] [--applyconfig_map <name>]
#   [--features <name:on|off>] [--name <vename>] [--ioprio <N>]
#   [--pci_add [<domain>:]<bus>:<slot>.<func>] [--pci_del <d:b:s.f>]
#   [--iptables <name>] [--disabled <yes|no>]
#   [UBC parameters]

);

my %validate = (

  allow_extra => 1, # special case to handle parms we aren't going to check
                    # (e.g., exec and friends). Leave it as an invalid entry
                    # for validate_with so programmers will catch it before it
                    # goes live.

  ctid       => { callbacks => { 'validate ctid' => \&_validate_ctid } },
  exec       => { type      => SCALAR },
  flag       => { regex     => qr/^quiet|verbose|version$/ },
  force      => { type      => UNDEF },
  wait       => { type      => UNDEF },
  hostname   => { type      => SCALAR },

  ostemplate => { type      => SCALAR }, #XXX: Need to make these more robust.
  config     => { type      => SCALAR }, #XXX: We can pull the data from the
  private    => { type      => SCALAR }, #XXX: global config file to help
  root       => { type      => SCALAR }, #XXX: validate this info.

  ipadd      => {
    type => SCALAR | ARRAYREF, # This handles the type check for us.
    callbacks => { 'do these look like valid ip(s)?' => sub {

      my $value = shift;
      my @ips = ref $value eq 'ARRAY' ? @$value : $value;
      my @bad_ips = grep { ! /^$RE{net}{IPv4}$/ } @ips;

      die "Need to handle bad ips somehow while still allowing good ips to be set.";

  }}},

  create_dumpfile => { callbacks => { 'does it look like a valid filename?' => sub {
    my $file = sprintf 'file://localhost/%s', +shift;
    $file =~ /^$RE{URI}{file}$/;
  }}},

  restore_dumpfile => { callbacks => { 'does file exist?' => sub { -e( +shift ) } } },

);

#  my %regexen = (
#
#    'bytes'      => sub { +shift =~ /^\d+(?:gmk)?(:\d+(?:gmk)?)?$/ },
#    'capability' => sub { +shift =~ /^(?:$capability_params):(?:on|off)(?:\s+(?:$capability_params):(?:on|off))*$/ },
#    'createveid' => sub { +shift > 100 },
#    'diskspace'  => sub { +shift =~ /^\d+(?:gmk)?(?::\d+(?:gmk)?)?$/i },
#    'features'   => sub { +shift =~ /^(?:$features_params):(?:on|off)$/ },
#    'filename' => sub { my $file = sprintf 'file://localhost/%s', +shift; $file =~ /^$RE{URI}{file}$/ },
#    'fqdn'       => sub { +shift =~ /^(?:$RE{net}{domain}{-nospace})$/ },
#    'iopriority' => sub { +shift =~ /^[0-7]$/ },
#    'ipaddr'     => sub { +shift =~ /^(?:$RE{net}{IPv4})(?:[,\s]$RE{net}{IPv4})*$/ },
#    'ipdel'      => sub { +shift =~ /^(?:$RE{net}{IPv4}|all)$/ },
#    'iptables'   => sub { +shift =~ /^$iptables_params$/ },
#    'items'      => sub { +shift =~ /^\d+(?::\d+)?$/ },
#    'login'      => sub { +shift =~ /^[a-z][a-z0-9_-]{1,15}$/ },
#    'meminfo' => sub { +shift => /^(?:(?:(?:privvm)?pages:\d+)|none)$/ },
#    'num2'     => sub { +shift =~ /^\d+(?::\d+)?$/ },
#    'nump'     => sub { +shift =~ /^\d+%?$/ },
#    'num'      => sub { +shift =~ /^\d+$/ },
#    'onoff'    => sub { +shift =~ /^\w+:(?:on|off)$/ },
#    'pages'    => sub { +shift =~ /^\d+[gmkp]?(?::(?:\d+[gmkp]?|unlimited))?$/ },
#    'setmode'  => sub { +shift =~ /^restart|ignore$/ },
#    'userpass' => sub { +shift =~ /^(?:\w+):(?:\w+)$/ },
#    'veid' => sub { my $ctid = shift; ( $ctid > 100 ) || ( $ctid =~ /^[a-z][a-z0-9_-]{1,15}$/ ) },
#    'yesno' => sub { +shift =~ /^yes|no$/i },
#
#    'true' => sub { 1 },  # we just assume the caller has done their legwork
#    'cmds' => sub { 1 },
#
#    'die'    => sub { croak sprintf '%s not supported at this time',   +shift },
#    'seeman' => sub { croak sprintf '%s not recommended--see manpage', +shift },
#
#  );

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
