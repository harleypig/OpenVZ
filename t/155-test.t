#!/usr/bin/perl

use strict;
use warnings;

use Test::Most tests => 1070;
use Test::NoWarnings;

use Try::Tiny;
use Algorithm::Combinatorics 'combinations';

#use Regexp::Common qw( URI net );
#use Params::Validate qw( :all );

$ENV{ PATH } = "t/bin:$ENV{PATH}"; # run our test versions of commands

BEGIN { use_ok( 'OpenVZ::vzctl', ':all' ) }

# Copy this hash from OpenVZ::vzctl

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

#    set       => [qw(
#
#      [applyconfig] [applyconfig_map] [avnumproc] [bootorder] [capability]
#      [cpulimit] [cpumask] [cpus] [cpuunits] [dcachesize] [devices] [devnodes]
#      [dgramrcvbuf] [disabled] [diskinodes] [diskspace] [features] [force]
#      [hostname] [ioprio] [ipadd] [ipdel] [iptables] [kmemsize] [lockedpages]
#      [name] [nameserver] [netif_add] [netif_del] [noatime] [numfile]
#      [numflock] [numiptent] [numothersock] [numproc] [numpty] [numsiginfo]
#      [numtcpsock] [onboot] [oomguarpages] [othersockbuf] [pci_add] [pci_del]
#      [physpages] [privvmpages] [quotatime] [quotaugidlimit] [save]
#      [searchdomain] [setmode] [shmpages] [swappages] [tcprcvbuf] [tcpsndbuf]
#      [userpasswd] [vmguarpages]
#
#   )],

);

my %check = do {

#  my $cap_names = join '|', qw(
#
#    chown dac_override dac_read_search fowner fsetid ipc_lock ipc_owner kill
#    lease linux_immutable mknod net_admin net_bind_service net_broadcast
#    net_raw setgid setpcap setuid setveid sys_admin sys_boot sys_chroot
#    sys_module sys_nice sys_pacct sys_ptrace sys_rawio sys_resource sys_time
#    sys_tty_config ve_admin
#
#  );
#
#  my $iptables_names = join '|', qw(
#
#    ip_conntrack ip_conntrack_ftp ip_conntrack_irc ip_nat_ftp ip_nat_irc
#    iptable_filter iptable_mangle iptable_nat ipt_conntrack ipt_helper
#    ipt_length ipt_limit ipt_LOG ipt_multiport ipt_owner ipt_recent
#    ipt_REDIRECT ipt_REJECT ipt_state ipt_tcpmss ipt_TCPMSS ipt_tos ipt_TOS
#    ipt_ttl xt_mac
#
#  );
#
#  my $features_names = join '|', qw( sysfs nfs sit ipip ppp ipgre bridge nfsd);

  # Basic types to check for:

  # UNDEF         undef
  my $scalar    = 'scalar';
  my $arrayref  = [qw( one two )];
  my $hashref   = { one => 1, two => 2 };
  my $coderef   = sub {};
  my $glob      = do { local *GLOB };
  my $globref   = \*GLOB;

  # default bad arrayref
  #   bad  => [ '', $scalar, \$scalar, [], $arrayref, {}, $hashref, $coderef, $glob, $globref ],

  my %hash = (

#    applyconfig => { type      => SCALAR },

    applyconfig => {
      good => [ $scalar ],
      bad  => [ '', \$scalar, $arrayref, $hashref, $coderef, $glob, *GLOB, $globref ],
    },

#    avnumproc   => { regex     => qr/^\d+[gmkp]?(?::\d+[gmkp]?)?$/i },
#    bootorder   => { regex     => qr/^\d+$/ },
#    capability  => { regex     => qr/^(?:$cap_names):(?:on|off)$/i },

#    command     => { type      => SCALAR | ARRAYREF },

    command => {
      good => [ 'good', [qw( one two )] ],
      bad  => {
        '' => qr/\QThe 'command' parameter ("") to \E.*\Q did not pass the 'do not want empty values' callback/i,
        \$scalar => qr/\QThe 'command' parameter ("SCALAR(\E.*\Q)") to \E.*\Q was a 'scalarref', which is not one of the allowed types: scalar arrayref/,
        [] => qr//,
        {} => qr/\QThe 'command' parameter ("HASH(\E.*\Q)") to \E.*\Q was a 'hashref', which is not one of the allowed types: scalar arrayref/,
        $hashref => qr/\QThe 'command' parameter ("HASH(\E.*\Q)") to \E.*\Q was a 'hashref', which is not one of the allowed types: scalar arrayref/,
        $coderef => qr/\QThe 'command' parameter ("CODE(\E.*\Q)") to \E.*\Q was a 'coderef', which is not one of the allowed types: scalar arrayref/,
        $glob => qr/\QThe 'command' parameter ("*main::GLOB(\E.*\Q)") to \E.*\Q was a 'globref', which is not one of the allowed types: scalar arrayref/,
        $globref => qr/\QThe 'command' parameter ("GLOB(\E.*\Q)") to \E.*\Q was a 'globref', which is not one of the allowed types: scalar arrayref/,
      },
      bare => 1, # --command should not appear in the actual command
    },

#    cpumask     => { regex     => qr/^\d+(?:[,-]\d+)*|all$/i },
#    ctid        => { callbacks => { 'validate ctid' => \&_validate_ctid } },
#    devices     => { regex     => qr/^(?:(?:(?:b|c):\d+:\d+)|all:(?:r?w?))|none$/i },
#    features    => { regex     => qr/^(?:$features_names):(?:on|off)$/i },
#    flag        => { regex     => qr/^quiet|verbose$/i },

#    force       => { type      => UNDEF },

    force => {
      good => [ undef, '' ],
      bad  => [ \'scalar', $scalar, \$scalar, $arrayref, $hashref, $coderef, $glob, *GLOB, $globref ],
    },

#    ioprio      => { regex     => qr/^[0-7]$/ },
#    onboot      => { regex     => qr/^yes|no$/i },
#    setmode     => { regex     => qr/^restart|ignore/i },
#    userpasswd  => { regex     => qr/^(?:\w+):(?:\w+)$/ },

#    ipadd => {
#      type => SCALAR | ARRAYREF, # This handles the type check for us.
#      callbacks => { 'do these look like valid ip(s)?' => sub {
#
#        my @ips = ref $_[0] eq 'ARRAY' ? @$_[0] : $_[0];
#        my @bad_ips = grep { ! /^$RE{net}{IPv4}$/ } @ips;
#        return ! @bad_ips; # return 1 if there are no bad ips, undef otherwise.
#
#        #NOTE: I can't find a way to modify the incoming data, and it may not
#        #      be a good idea to do that in any case. Unless, and until, I can
#        #      figure out how to do this the right way this will be an atomic
#        #      operation. It's either all good, or it's not.
#
#    }}},

    ipadd => {
      good => [ '1.2.3.4', [qw( 1.2.3.4 2.3.4.5 )] ],
      bad  => [ '', \$scalar, $hashref, $coderef, $glob, *GLOB, $globref, '300.1.2.3', [qw( 1.2.3.4 300.1.2.3 )] ],
    },

#    ipdel => {
#      type => SCALAR | ARRAYREF, # This handles the type check for us.
#      callbacks => { 'do these look like valid ip(s)?' => sub {
#
#        my @ips = ref $_[0] eq 'ARRAY' ? @$_[0] : $_[0];
#        my @bad_ips = grep { ! /^$RE{net}{IPv4}$/ } @ips;
#        return 1 if grep { /^all$/i } @bad_ips;
#        return ! @bad_ips;
#
#        #NOTE: See ipadd note.
#
#    }}},
#
#    iptables => {
#      type => SCALAR | ARRAYREF, # This handles the type check for us.
#      callbacks => { 'see manpage for list of valid iptables names' => sub {
#
#        my @names;
#
#        if ( ref $_[0] eq 'ARRAY' ) {
#
#          @names = @$_[0];
#
#        } else {
#
#          my $names = shift;
#          return unless $names =~ s/^['"](.*?)['"]$/$1/;
#          @names = split /\s+/, $names;
#
#        }
#
#        my @bad_names = grep { ! /^$iptables_names$/ } @names;
#        return ! @bad_names;
#
#        #NOTE: See ipadd note.
#
#    }}},

#    create_dumpfile => {
#      type      => SCALAR, # This handles the type check for us.
#      callbacks => { 'does it look like a valid filename?' => sub {
#        my $file = sprintf 'file://localhost/%s', +shift;
#        $file =~ /^$RE{URI}{file}$/;
#    }}},

    create_dumpfile => {
      good => [ '/tmp/testfile' ],
      bad  => [ '', \$scalar, $arrayref, $hashref, $coderef, $glob, *GLOB, $globref ],
    },

#    restore_dumpfile => {
#      type      => SCALAR, # This handles the type check for us.
#      callbacks => { 'does file exist?' => sub { -e( +shift ) } } },

    restore_dumpfile => {
      good => [ '/dev/urandom' ],
      bad  => [ '', '/why/do/you/have/a/path/that/looks/like/this', \$scalar, $arrayref, $hashref, $coderef, $glob, *GLOB, $globref ],
    },

#    devnodes => { callbacks => { 'setting access to devnode' => sub {
#
#      return 1 if $_[0] eq 'none';
#      ( my $device = $_[0] ) =~ s/^(.*?):r?w?q?$/$1/;
#      $device = "/dev/$device";
#      return -e $device;
#
#    }}},

  );

  my %same = (

    # SCALAR checks
    applyconfig => [qw(

      applyconfig_map config hostname name netif_add netif_del ostemplate
      pci_add pci_del private root searchdomain

    )],

    # SCALAR | ARRAYREF checks
    command => [qw( exec script )],

    # UNDEF checks
    force => [qw( save wait )],

#    # INT checks
#    bootorder => [qw( cpulimit cpus cpuunits quotatime quotaugidlimit )],
#
#    # yes or no checks
#    onboot => [qw( disabled noatime )],

    # ip checks
    ipadd  => [qw( nameserver )],

#    # hard|soft limits
#    avnumproc => [qw(
#
#      dcachesize dgramrcvbuf diskspace kmemsize lockedpages numfile numflock
#      numiptent numothersock numproc numpty numsiginfo numtcpsock oomguarpages
#      othersockbuf physpages privvmpages shmpages swappages tcprcvbuf
#      tcpsndbuf vmguarpages
#
#    )],
  );

  for my $key ( keys %same ) {

    $hash{ $_ } = $hash{ $key }
      for @{ $same{ $key } };

  }

  %hash;

};

my %regex = (

  invalid_ctid => qr/\QInvalid or unknown container (invalid_ctid): Container(s) not found/,
  invalid_name => qr/\QInvalid or unknown container (invalid_name): CT ID invalid_name is invalid./,
  badparm      => qr/The following parameter was passed .* but was not listed in the validation options: badparm/,
  badflag      => qr/The 'flag' parameter \("badflag"\) to .* did not pass regex check/,

);

my @bad_ctids    = qw( invalid_ctid invalid_name );
my @global_flags = ( 'version', '', 'quiet', 'verbose' );

#my $invalid_ctid_rx = qr/\QInvalid or unknown container (invalid_ctid): Container(s) not found/;
#my $invalid_name_rx = qr/\QInvalid or unknown container (invalid_name): CT ID invalid_name is invalid./;
#my $badparm_rx      = qr/The following parameter was passed .* but was not listed in the validation options: badparm/;
#my $badflag_rx      = qr/The 'flag' parameter \("badflag"\) to .* did not pass regex check/;

for my $cmd ( sort keys %vzctl ) {
  for my $flag ( sort @global_flags ) {
    for my $parm ( sort @{ $vzctl{ $cmd } } ) {

      my $ctid = int 100 + rand( 100 );
      my $name = join '', map { chr( 97 + rand( 26 ) ) } 0 .. ( int rand 20 ) + 1;
      my $test = "$ctid,$name";

      for my $ctid ( @bad_ctids, $test ) {

        my %hash = ( ctid => $ctid );

        $hash{ flag } = $flag
          if $flag ne '';

        for my $bad_value ( @{ $check{ $parm }{ bad } } ) {

          my %bad_hash = %hash;
          $bad_hash{ $parm } = $bad_value;
          my $bad_regex = exists $regex{ $ctid } ? $regex{ $ctid } : qr/huh?/;

          my $info = sprintf '%s %s%s --%s %s -- caught bad value', $cmd, ($flag?"$flag ":''), $ctid, $parm, $bad_value;

          no strict 'refs';
          throws_ok { $cmd->( \%bad_hash ) } $bad_regex, $info;

        }
      }
    }
  }
}
