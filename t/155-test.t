#!/usr/bin/perl

use strict;
use warnings;

use Test::Most tests => 353;
use Test::NoWarnings;

use Try::Tiny;

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
    runscript => [qw( command )],

    enter     => [qw( [exec] )],
    start     => [qw( [force] [wait] )],

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

my $invalid_ctid_rx = qr/\QInvalid or unknown container (invalid_ctid): Container(s) not found/;
my $invalid_name_rx = qr/\QInvalid or unknown container (invalid_name): CT ID invalid_name is invalid./;
my $badparm_rx      = qr/The following parameter was passed .* but was not listed in the validation options: badparm/;
my $badflag_rx      = qr/The 'flag' parameter \("badflag"\) to .* did not pass regex check/;

for my $cmd ( keys %vzctl ) {

  my @possible_parms = grep { ! /allow_extra/ } @{ $vzctl{ $cmd } };
  my $allow_extra    = @possible_parms != @{ $vzctl{ $cmd } };
  my $ctid           = int 100 + rand( 100 );
  my $name           = join '', map { chr( 97 + rand( 26 ) ) } 0 .. ( int rand 20 ) + 1;
  my $test           = "$ctid,$name";

  # Test invalid ctid and name
  no strict 'refs';
  throws_ok { $cmd->( ctid => 'invalid_ctid' ) } $invalid_ctid_rx, "($cmd) caught invalid ctid";
  throws_ok { $cmd->( ctid => 'invalid_name' ) } $invalid_name_rx, "($cmd) caught invalid name";

  # Test bad global flag
  throws_ok { $cmd->( ctid => $test, flag => 'badflag' ) } $badflag_rx, "($cmd) caught bad global flag";

  my %global_flag = (

    ''        => { ctid => $test },
    'quiet'   => { ctid => $test, flag => 'quiet' },
    'verbose' => { ctid => $test, flag => 'verbose' },

  );

  for my $flag ( keys %global_flag ) {

    my @response = $cmd->( $global_flag{ $flag } );

    my $expected_cmd = sprintf 'vzctl %s%s %s', ($flag?"--$flag ":''), $cmd, $ctid;

    is( $OpenVZ::vzctl::global{ 'ctid' }, $ctid, "($cmd) global ctid ($ctid) set correctly");
    is( $OpenVZ::vzctl::global{ 'name' }, $name, "($cmd) global name ($name) set correctly");
    is( $response[0], $expected_cmd, "($cmd) command called correctly ($response[0])" );
    is( $response[1], '', "($cmd) nothing in stderr" );
    is( $response[2], 0, "($cmd) syserr is 0" );
    like( $response[3], qr/^\d+(\.\d+)?$/, "($cmd) time was reported ($response[3] s)" );

    delete $OpenVZ::vzctl::global{ 'ctid' };
    delete $OpenVZ::vzctl::global{ 'name' };

    ok( ! exists $OpenVZ::vzctl::global{ 'ctid' }, "($cmd) global ctid reset");
    ok( ! exists $OpenVZ::vzctl::global{ 'name' }, "($cmd) global name reset");

  }

  if ( $allow_extra ) {

     warn "should extra parms have --'s forced?\n";

     my @response = $cmd->( ctid => $test, extra => 'parm' );
     my $expected_cmd = "vzctl $cmd $ctid --extra parm";

     is( $OpenVZ::vzctl::global{ 'ctid' }, $ctid, "($cmd) global ctid ($ctid) set correctly");
     is( $OpenVZ::vzctl::global{ 'name' }, $name, "($cmd) global name ($name) set correctly");
     is( $response[0], $expected_cmd, "($cmd) command called correctly ($response[0])" );
     is( $response[1], '', "($cmd) nothing in stderr" );
     is( $response[2], 0, "($cmd) syserr is 0" );
     like( $response[3], qr/^\d+(\.\d+)?$/, "($cmd) time was reported ($response[3] s)" );

  } else {

    throws_ok { $cmd->( ctid => $test, badparm => 'blech' ) } $badparm_rx, "($cmd) caught bad parm";

  }
}
