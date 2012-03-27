#!/usr/bin/perl

use strict;
use warnings;

use Test::Most tests => 7011;
use Test::NoWarnings;

use Try::Tiny;

use Carp;
use Data::Dump 'dump';

$ENV{ PATH } = "t/bin:$ENV{PATH}";  # run our test versions of commands

BEGIN { use_ok( 'OpenVZ::vzctl', ':all' ) }

my %check = do {

    # Basic types to check for:

    my $scalar   = 'scalar';
    my $arrayref = [qw( bad1 bad2 )];
    my $hashref  = { bad3 => 4, bad5 => 6 };
    my $coderef  = sub { };
    my $glob     = do { local *GLOB };
    my $globref  = \*GLOB;

    my $not_allowed_type = qr/not one of the allowed types/;
    my $did_not_pass     = qr/did not pass/;

    my @cap_names      = capabilities();

    cmp_bag( \@cap_names, [qw(

      chown dac_override dac_read_search fowner fsetid ipc_lock ipc_owner kill
      lease linux_immutable mknod net_admin net_bind_service net_broadcast
      net_raw setgid setpcap setuid setveid sys_admin sys_boot sys_chroot
      sys_module sys_nice sys_pacct sys_ptrace sys_rawio sys_resource sys_time
      sys_tty_config ve_admin

    )], 'got expected capablity names' );

    my @good_cap_names = map { ( "$_:on", "$_:off" ) } @cap_names;
    my @bad_cap_names  = map { ( "$_:bad", $did_not_pass ) } @cap_names;
    push @bad_cap_names, 'justallaroundbad', $did_not_pass;

    my @features_names = features();

    cmp_bag( \@features_names, [qw( sysfs nfs sit ipip ppp ipgre bridge nfsd)], 'got expected features names' );

    my @good_features_names = map { ( "$_:on", "$_:off" ) } @features_names;
    my @bad_features_names = map { ( "$_:bad", $did_not_pass ) } @features_names;
    push @bad_features_names, 'justallaroundbad', $did_not_pass;

    my @iptables_modules = iptables_modules();

    cmp_bag( \@iptables_modules, [qw(

      ip_conntrack ip_conntrack_ftp ip_conntrack_irc ip_nat_ftp ip_nat_irc
      iptable_filter iptable_mangle iptable_nat ipt_conntrack ipt_helper
      ipt_length ipt_limit ipt_LOG ipt_multiport ipt_owner ipt_recent
      ipt_REDIRECT ipt_REJECT ipt_state ipt_tcpmss ipt_TCPMSS ipt_tos ipt_TOS
      ipt_ttl xt_mac

    )], 'got expected iptables modules' );

    my @iptables_names = map { ( "$_:on", "$_:off" ) } @iptables_modules;

    my %hash = (

        applyconfig => {
            good => [$scalar],
            bad  => [
                undef,    $not_allowed_type, '',        $did_not_pass,
                \$scalar, $not_allowed_type, $arrayref, $not_allowed_type,
                $hashref, $not_allowed_type, $coderef,  $not_allowed_type,
                $glob,    $not_allowed_type, $globref,  $not_allowed_type,
            ],
        },

        avnumproc => {
            good => [
                100,    '101g',    '102m',      '103k',
                '104p', '105:106', '107g:108m', '109k:110p'
            ],
            bad => [
                undef,    $not_allowed_type, '',        $did_not_pass,
                \$scalar, $not_allowed_type, $arrayref, $not_allowed_type,
                $hashref, $not_allowed_type, $coderef,  $not_allowed_type,
                $glob,    $not_allowed_type, $globref,  $not_allowed_type,
            ],
        },

        bootorder => {
            good => [1],
            bad  => [
                undef,    $not_allowed_type, '',        $did_not_pass,
                \$scalar, $not_allowed_type, $arrayref, $not_allowed_type,
                $hashref, $not_allowed_type, $coderef,  $not_allowed_type,
                $glob,    $not_allowed_type, $globref,  $not_allowed_type,
            ],
        },

        capability => {
            good => \@good_cap_names,
            bad  => [
                undef,     $not_allowed_type,
                '',        $did_not_pass,
                \$scalar,  $not_allowed_type,
                $arrayref, $not_allowed_type,
                $hashref,  $not_allowed_type,
                $coderef,  $not_allowed_type,
                $glob,     $not_allowed_type,
                $globref,  $not_allowed_type,
                @bad_cap_names,
            ],
        },

        command => {
            good => [ 'good', [qw( one two )] ],
            bad => [
                undef, $not_allowed_type, '', $did_not_pass,
                \$scalar, $not_allowed_type, [], $did_not_pass,
                $hashref, $not_allowed_type, $coderef, $not_allowed_type,
                $glob,    $not_allowed_type, $globref, $not_allowed_type,
            ],
            bare => 1,  # --command should not appear in the actual command
        },

        cpumask => {
            good => [ 1, '2:3', 'all' ],
            bad  => [
                undef,    $not_allowed_type, '',       $did_not_pass,
                \$scalar, $not_allowed_type, $hashref, $not_allowed_type,
                $coderef, $not_allowed_type, $glob,    $not_allowed_type,
                $globref, $not_allowed_type,
            ],
        },

        devices => {
            good => [ 'none', 'all:r', 'all:w', 'all:rw', 'b:1:2', 'c:3:4' ],
            bad  => [
                undef,    $not_allowed_type, '',       $did_not_pass,
                \$scalar, $not_allowed_type, $hashref, $not_allowed_type,
                $coderef, $not_allowed_type, $glob,    $not_allowed_type,
                $globref, $not_allowed_type, 'all',    $did_not_pass,
            ],
        },

        features => {
            good => \@good_features_names,
            bad  => [
                undef,    $not_allowed_type,
                '',       $did_not_pass,
                \$scalar, $not_allowed_type,
                $hashref, $not_allowed_type,
                $coderef, $not_allowed_type,
                $glob,    $not_allowed_type,
                $globref, $not_allowed_type,
                @bad_features_names
            ],
        },

        force => {
            good => [undef],
            bad  => [
                $scalar,  $not_allowed_type, \$scalar, $not_allowed_type,
                $hashref, $not_allowed_type, $coderef, $not_allowed_type,
                $glob,    $not_allowed_type, $globref, $not_allowed_type,
            ],
        },

        ioprio => {
            good => [ 0 .. 7 ],
            bad  => [
                undef,    $not_allowed_type, '',       $did_not_pass,
                \$scalar, $not_allowed_type, $hashref, $not_allowed_type,
                $coderef, $not_allowed_type, $glob,    $not_allowed_type,
                $globref, $not_allowed_type, 8,        $did_not_pass,
            ],
        },

        onboot => {
            good => [qw( yes no )],
            bad  => [
                undef,    $not_allowed_type, '',       $did_not_pass,
                $scalar,  $did_not_pass,     \$scalar, $not_allowed_type,
                $hashref, $not_allowed_type, $coderef, $not_allowed_type,
                $glob,    $not_allowed_type, $globref, $not_allowed_type,
            ],
        },

        setmode => {
            good => [qw( restart ignore )],
            bad  => [
                undef,    $not_allowed_type, '',       $did_not_pass,
                $scalar,  $did_not_pass,     \$scalar, $not_allowed_type,
                $hashref, $not_allowed_type, $coderef, $not_allowed_type,
                $glob,    $not_allowed_type, $globref, $not_allowed_type,
            ],
        },

        #    userpasswd  => { regex     => qr/^(?:\w+):(?:\w+)$/ },
        userpasswd => {
            good => ['joeuser:seekrit'],
            bad  => [
                undef,    $not_allowed_type, '',       $did_not_pass,
                $scalar,  $did_not_pass,     \$scalar, $not_allowed_type,
                $hashref, $not_allowed_type, $coderef, $not_allowed_type,
                $glob,    $not_allowed_type, $globref, $not_allowed_type,
            ],
        },

        ipadd => {
            good => [ '1.2.3.4', [qw( 1.2.3.4 2.3.4.5 )] ],
            bad => [
                undef,                     $not_allowed_type,
                '',                        $did_not_pass,
                $scalar,                   $did_not_pass,
                \$scalar,                  $not_allowed_type,
                [],                        $did_not_pass,
                $hashref,                  $not_allowed_type,
                $coderef,                  $not_allowed_type,
                $glob,                     $not_allowed_type,
                $globref,                  $not_allowed_type,
                '300.1.2.3',               $did_not_pass,
                [qw( 1.2.3.4 300.1.2.3 )], $did_not_pass,
                [ qw( 1.2.3.4 2.3.4.5 ), '' ], $did_not_pass,
            ],
        },

        ipdel => {
            good => [ 'all', '1.2.3.4', [qw( 1.2.3.4 2.3.4.5 )] ],
            bad => [
                undef,                     $not_allowed_type,
                '',                        $did_not_pass,
                $scalar,                   $did_not_pass,
                \$scalar,                  $not_allowed_type,
                [],                        $did_not_pass,
                $hashref,                  $not_allowed_type,
                $coderef,                  $not_allowed_type,
                $glob,                     $not_allowed_type,
                $globref,                  $not_allowed_type,
                '300.1.2.3',               $did_not_pass,
                [qw( 1.2.3.4 300.1.2.3 )], $did_not_pass,
                [ qw( 1.2.3.4 2.3.4.5 ), '' ], $did_not_pass,
            ],
        },

        iptables => {
            good => \@iptables_names,
            bad  => [
                undef,    $not_allowed_type, '',        $did_not_pass,
                $scalar,  $did_not_pass,     \$scalar,  $not_allowed_type,
                [],       $did_not_pass,     $arrayref, $did_not_pass,
                $hashref, $not_allowed_type, $coderef,  $not_allowed_type,
                $glob,    $not_allowed_type, $globref,  $not_allowed_type,
            ],
        },

        create_dumpfile => {
            good => ['/tmp/testfile'],
            bad  => [
                undef,    $not_allowed_type, '',        $did_not_pass,
                \$scalar, $not_allowed_type, $arrayref, $not_allowed_type,
                $hashref, $not_allowed_type, $coderef,  $not_allowed_type,
                $glob,    $not_allowed_type, $globref,  $not_allowed_type,
            ],
        },

        restore_dumpfile => {
            good => ['/dev/urandom'],
            bad  => [
                undef,
                $not_allowed_type,
                '',
                $did_not_pass,
                \$scalar,
                $not_allowed_type,
                $arrayref,
                $not_allowed_type,
                $hashref,
                $not_allowed_type,
                $coderef,
                $not_allowed_type,
                $glob,
                $not_allowed_type,
                $globref,
                $not_allowed_type,
                '/why/do/you/have/a/path/that/looks/like/this',
                $did_not_pass,
            ],
        },

        #    devnodes => { callbacks => { 'setting access to devnode' => sub {
        devnodes => {
            good => [
                qw( none urandom:r urandom:w urandom:q urandom:rw urandom:rq urandom:wq )
            ],
            bad => [
                undef,     $not_allowed_type, '',       $did_not_pass,
                $scalar,   $did_not_pass,     \$scalar, $not_allowed_type,
                $arrayref, $not_allowed_type, $hashref, $not_allowed_type,
                $coderef,  $not_allowed_type, $glob,    $not_allowed_type,
                $globref,  $not_allowed_type,
            ],
        },
    );

    my %same = (

        # SCALAR checks
        applyconfig => [ qw(

                applyconfig_map config hostname name netif_add netif_del ostemplate
                pci_add pci_del private root searchdomain

                )
        ],

        # SCALAR | ARRAYREF checks
        command => [qw( exec script )],

        # UNDEF checks
        force => [qw( save wait )],

        # INT checks
        bootorder => [qw( cpulimit cpus cpuunits quotatime quotaugidlimit )],

        # yes or no checks
        onboot => [qw( disabled noatime )],

        # ip checks
        ipadd => [qw( nameserver )],

        # hard|soft limits
        avnumproc => [ qw(

                dcachesize dgramrcvbuf diskinodes diskspace kmemsize lockedpages numfile
                numflock numiptent numothersock numproc numpty numsiginfo numtcpsock
                oomguarpages othersockbuf physpages privvmpages shmpages swappages
                tcprcvbuf tcpsndbuf vmguarpages

                )
        ],
    );

    for my $key ( keys %same ) {

        $hash{ $_ } = $hash{ $key } for @{ $same{ $key } };

    }

    %hash;

};

my @bad_ctids = qw( invalid_ctid invalid_name );
my @global_flags = ( '', 'quiet', 'verbose' );

my %invalid_regex = (

    invalid_ctid =>
        qr/\QInvalid or unknown container (invalid_ctid): Container(s) not found/,
    invalid_name =>
        qr/\QInvalid or unknown container (invalid_name): CT ID invalid_name is invalid./,

);

# XXX: my $badparm_rx      = qr/The following parameter was passed .* but was not listed in the validation options: badparm/;

for my $cmd ( sort( known_commands() ) ) {
    for my $parm ( sort keys %{ subcommand_specs( $cmd ) } ) {

        next if $parm =~ /^ctid|flag$/;  # these are tested for every time

        note( "Testing $cmd $parm bad ctids" );

        for my $ctid ( @bad_ctids ) {

            my %invalid_hash = ( ctid => $ctid );

            my $bad_regex = $invalid_regex{ $ctid };

            for my $flag ( @global_flags ) {

                $invalid_hash{ flag } = $flag
                    if $flag ne '';

                my $info = sprintf '%s %s%s --%s ... -- caught %s',
                    $cmd, ( $flag ? "--$flag " : '' ), $ctid, $parm, $ctid;

                no strict 'refs';
                throws_ok { $cmd->( \%invalid_hash ) } $invalid_regex{ $ctid },
                    $info;

            }  # end my $flag ( @global_flags )
        }  # end for my $ctid ( @bad_ctids )

        my $ctid = int 100 + rand( 100 );
        my $name = join '',
            map { chr( 97 + rand( 26 ) ) } 0 .. ( int rand 20 ) + 1;
        my $test = "$ctid,$name";

        for my $flag ( @global_flags ) {

            note( "Testing $cmd $parm bad values" );

            my $bad_values = $check{ $parm }{ bad };

            for ( my $ix = 0 ; $ix < @$bad_values ; $ix += 2 ) {

                my %bad_hash = ( ctid => $ctid, $parm => $bad_values->[$ix] );

                $bad_hash{ flag } = $flag
                    if $flag ne '';

                no warnings 'uninitialized';
                my $info = sprintf '%s %s%s --%s %s -- caught bad value',
                    $cmd, ( $flag ? "$flag " : '' ), $ctid, $parm,
                    $bad_values->[$ix];

                no strict 'refs';
                throws_ok { $cmd->( \%bad_hash ) } $bad_values->[ $ix + 1 ],
                    $info;

            }  # end for ( my $ix = 0; $ix < @$bad_values ; $ix += 2 )

            note( "Testing $cmd $parm good values" );

            my $good_values = $check{ $parm }{ good };

            for ( my $ix = 0 ; $ix < @$good_values ; $ix++ ) {

                my $expected_parm;

                my $value_ref = ref $good_values->[$ix];

                if ( $value_ref eq 'ARRAY' ) {

                    if ( $parm =~ /^command|script$/ ) {

                        $expected_parm = join ' ', @{ $good_values->[$ix] };

                    } else {

                        $expected_parm = join ' ',
                            map { "--$parm $_" } @{ $good_values->[$ix] };

                    }

                } elsif ( $value_ref eq '' ) {

                    if ( defined $good_values->[$ix] ) {

                        if ( $parm =~ /^command|script$/ ) {

                            $expected_parm = $good_values->[$ix];

                        } else {

                            $expected_parm = sprintf '--%s %s', $parm,
                                $good_values->[$ix];

                        }

                    } else {

                        $expected_parm = "--$parm";

                    }

                } else {

                    carp "Expecting scalar or arrayref for good test values";

                }

                my $expected = sprintf 'vzctl %s%s %s %s',
                    ( $flag ? "--$flag " : '' ), $cmd, $ctid, $expected_parm;

                my %good_hash = ( ctid => $test, $parm => $good_values->[$ix] );

                $good_hash{ flag } = $flag
                    if $flag ne '';

                my @result;
                { no strict 'refs'; @result = $cmd->( \%good_hash ) };

                is( $result[0], $expected, "got $expected" );
                is( $result[1], '',        'got empty stderr' );
                is( $result[2], 0,         'syserr was 0' );
                like( $result[3], qr/^\d+(?:.\d+)?$/, 'time was reported' );

            }  # end for ( my $ix = 0, $ix < @$good_values ; $ix++ )
        }  # end for my $flag ...

        note( "Deleting $parm" );
        delete $check{ $parm }
            unless $parm =~ /^command|force|hostname|ipadd$/
        ;  # these appear in multiple commands

    }  # end for my $parm ...
}  # end for my $cmd ...

delete $check{ $_ } for qw( command force hostname ipadd );

cmp_deeply( \%check, {}, 'checked all options' );
