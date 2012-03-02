
use Test::Most tests => 16;
use Test::NoWarnings;

use Data::Dump 'dump';

$ENV{ PATH } = "t/bin:$ENV{PATH}"; # run our test versions of commands

BEGIN { use_ok( 'OpenVZ::vzctl', 'start', 'status' ) }

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
