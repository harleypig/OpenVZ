
use Test::Most skip_all => 'being phased out';
use Test::NoWarnings;

use Regexp::Common qw( URI net );
use Params::Validate qw( :all );
use Data::Dump 'dump';

$ENV{ PATH } = "t/bin:$ENV{PATH}"; # run our test versions of commands

BEGIN { use_ok( 'OpenVZ::vzctl', ':all' ) }

# Copy the %vzctl and %validate hashes from the source file and paste it here
# This way any changes to the source will be caught here and the programmer
# will have to at least put in a little effort to test. :]

my %expected_vzctl = (

    start     => [qw( [force] [wait] )],
    enter     => [qw( [exec] allow_extra )],

    exec2     => [qw( allow_extra )],
    exec      => [qw( allow_extra )],
    runscript => [qw( allow_extra )],

    chkpnt    => [qw( [create_dumpfile] )],
    restore   => [qw( [restore_dumpfile] )],

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

my %expected_validate = do {

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

  for my $key ( keys %same ) {

    $hash{ $_ } = $hash{ $key }
      for @{ $same{ $key } };

  }

  %hash;

};

cmp_deeply( %OpenVZ::vzctl::vzctl, %expected_vzctl, 'vzctl hash' );
cmp_deeply( %OpenVZ::vzctl::validate, %expected_validate, 'validate hash' );

# see t/bin/vzlist for info on how to handle ctid testing

throws_ok { status( ctid => 'invalid_ctid' ) } qr/\QInvalid or unknown container (invalid_ctid): Container(s) not found/, 'caught invalid ctid';
throws_ok { status( ctid => 'invalid_name' ) } qr/\QInvalid or unknown container (invalid_name): CT ID invalid_name is invalid./, 'caught invalid name';

my $test_ctid = 101;
my $test_name = 'name';

my @valid_ctid_name = status( ctid => "$test_ctid,$test_name" );

is( $OpenVZ::vzctl::global{ 'ctid' }, $test_ctid, 'global ctid set correctly');
is( $OpenVZ::vzctl::global{ 'name' }, $test_name, 'global name set correctly');
is( $valid_ctid_name[0], "vzctl status $test_ctid", "command called correctly ($valid_ctid_name[0])" );
is( $valid_ctid_name[1], '', 'nothing in stderr' );
is( $valid_ctid_name[2], 0, 'syserr is 0' );
like( $valid_ctid_name[3], qr/^\d+(\.\d+)?$/, "time was reported ($valid_ctid_name[3] s)" );

my $test2_ctid = 102;

my @valid_ctid = start( ctid => $test2_ctid );

is( $OpenVZ::vzctl::global{ 'ctid' }, $test2_ctid, 'global ctid set correctly');
is( $OpenVZ::vzctl::global{ 'name' }, undef, 'global name set correctly');
is( $valid_ctid[0], "vzctl start $test2_ctid", "command called correctly ($valid_ctid[0])" );
is( $valid_ctid[1], '', 'nothing in stderr' );
is( $valid_ctid[2], 0, 'syserr is 0' );
like( $valid_ctid[3], qr/^\d+(\.\d+)?$/, "time was reported ($valid_ctid[3] s)" );
