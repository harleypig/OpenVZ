
use Test::Most tests => 34;
use Test::NoWarnings;

#use Regexp::Common qw( URI net );
#use Params::Validate qw( :all );

$ENV{ PATH } = "t/bin:$ENV{PATH}"; # run our test versions of commands

BEGIN { use_ok( 'OpenVZ::vzctl', 'exec' ) }

my $ctid = int 100 + rand( 100 );
my $name = join '', map { chr( 97 + rand( 26 ) ) } 0 .. ( int rand 20 ) + 1;
my $test = "$ctid,$name";

my $invalid_ctid_rx = qr/\QInvalid or unknown container (invalid_ctid): Container(s) not found/;
my $invalid_name_rx = qr/\QInvalid or unknown container (invalid_name): CT ID invalid_name is invalid./;
my $badparm_rx      = qr/The following parameter was passed .* but was not listed in the validation options: badparm/;
my $badflag_rx      = qr/The 'flag' parameter \("badflag"\) to .* did not pass regex check/;

throws_ok { exec( ctid => 'invalid_ctid' ) } $invalid_ctid_rx, 'caught invalid ctid';
throws_ok { exec( ctid => $test, flag => 'badflag' ) } $badflag_rx, 'caught bad flag';

my %hash = (

  ''        => { ctid => $test },
  'quiet'   => { ctid => $test, flag => 'quiet' },
  'verbose' => { ctid => $test, flag => 'verbose' },

);

for my $flag ( keys %hash ) {

  my @response = exec( $hash{ $flag } );

  my $expected_cmd = sprintf 'vzctl %sexec %s', ($flag?"--$flag ":''), $ctid;

  is( $OpenVZ::vzctl::global{ 'ctid' }, $ctid, "global ctid ($ctid) set correctly");
  is( $OpenVZ::vzctl::global{ 'name' }, $name, "global name ($name) set correctly");
  is( $response[0], $expected_cmd, "command called correctly ($response[0])" );
  is( $response[1], '', 'nothing in stderr' );
  is( $response[2], 0, 'syserr is 0' );
  like( $response[3], qr/^\d+(\.\d+)?$/, "time was reported ($response[3] s)" );

  $OpenVZ::vzctl::global{ 'ctid' } = 0;
  $OpenVZ::vzctl::global{ 'name' } = '';

  is( $OpenVZ::vzctl::global{ 'ctid' }, 0, "global ctid reset");
  is( $OpenVZ::vzctl::global{ 'name' }, '', "global name reset");

}

my @response = exec( ctid => $test, extra => 'parm' );
my $expected_cmd = "vzctl exec $ctid --extra parm";

is( $OpenVZ::vzctl::global{ 'ctid' }, $ctid, "global ctid ($ctid) set correctly");
is( $OpenVZ::vzctl::global{ 'name' }, $name, "global name ($name) set correctly");
is( $response[0], $expected_cmd, "command called correctly ($response[0])" );
is( $response[1], '', 'nothing in stderr' );
is( $response[2], 0, 'syserr is 0' );
like( $response[3], qr/^\d+(\.\d+)?$/, "time was reported ($response[3] s)" );
