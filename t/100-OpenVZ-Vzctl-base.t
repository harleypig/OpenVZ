#!/usr/bin/perl

use 5.006;

use strict;
use warnings;

use Test::Most tests => 30;
use Test::NoWarnings;

BEGIN { use_ok( 'OpenVZ::Vzctl', qw( execute vzctl known_commands ) ) }

my @expect_execute_ls = (
    q{OpenVZ
OpenVZ.pm},
    q{},
    0,
    ignore(),
);

my @expect_execute_false = ( q{}, q{}, 256, ignore(), );

my $object = OpenVZ::Vzctl->new;
isa_ok( $object, 'OpenVZ::Vzctl', 'object created' );

note( 'Exceptions' ); #############################################################################################################
throws_ok { execute() } qr/Mandatory parameter 'command' missing in call/, 'empty call to execute dies correctly (functional)';
throws_ok { execute( '' ) } qr/Odd number of parameters/, 'null call to execute dies correctly (functional)';
throws_ok { execute( [] ) } qr/Odd number of parameters/, 'empty arrayref call to execute dies correctly (functional)';
throws_ok { execute( {} ) } qr/Mandatory parameter 'command' missing in call/,
    'empty hashref call to execute dies correctly (functional)';

throws_ok { $object->execute() } qr/Mandatory parameter 'command' missing in call/, 'empty call to execute dies correctly (oop)';
throws_ok { $object->execute( '' ) } qr/Odd number of parameters/, 'null call to execute dies correctly (oop)';
throws_ok { $object->execute( [] ) } qr/Odd number of parameters/, 'empty arrayref call to execute dies correctly (oop)';
throws_ok { $object->execute( {} ) } qr/Mandatory parameter 'command' missing in call/,
    'empty hashref call to execute dies correctly (oop)';

throws_ok { vzctl() } qr/Expecting array or hash reference in 'spec'/, 'empty call to vzctl dies correctly (functional)';
throws_ok { vzctl( '' ) } qr/Expecting array or hash reference in 'params'/, 'null call to vzctl dies correctly (functional)';
throws_ok { vzctl( [] ) } qr/Mandatory parameters 'ctid', 'subcommand', 'flag' missing/,
    'empty arrayref call to vzctl dies correctly (functional)';
throws_ok { vzctl( {} ) } qr/Mandatory parameters 'ctid', 'subcommand', 'flag' missing/,
    'empty hashref call to vzctl dies correctly (functional)';

throws_ok { $object->vzctl() } qr/Expecting array or hash reference in 'spec'/, 'empty call to vzctl dies correctly (functional)';
throws_ok { $object->vzctl( '' ) } qr/Expecting array or hash reference in 'params'/,
    'null call to vzctl dies correctly (functional)';
throws_ok { $object->vzctl( [] ) } qr/Mandatory parameters 'ctid', 'subcommand', 'flag' missing/,
    'empty arrayref call to vzctl dies correctly (functional)';
throws_ok { $object->vzctl( {} ) } qr/Mandatory parameters 'ctid', 'subcommand', 'flag' missing/,
    'empty hashref call to vzctl dies correctly (functional)';

throws_ok { vzctl( { subcommand => 'badsubcommand' } ) } qr/did not pass regex check/, 'badsubcommand dies correctly (functional)';
throws_ok { $object->vzctl( { subcommand => 'badsubcommand' } ) } qr/did not pass regex check/,
    'badsubcommand dies correctly (oop)';

{
    no warnings 'once';
    throws_ok { execute( \*GLOB ) } qr/Odd number of parameters/, 'glob call to execute dies correctly (functional)';
    throws_ok { $object->execute( \*GLOB ) } qr/Odd number of parameters/, 'glob call to execute dies correctly (oop)';

    throws_ok { vzctl( \*GLOB ) } qr/Expecting array or hash reference in 'params'/,
        'glob call to vzctl dies correctly (functional)';
    throws_ok { $object->vzctl( \*GLOB ) } qr/Expecting array or hash reference in 'params'/,
        'glob call to vzctl dies correctly (functional)';
}

note( 'Valid' ); ##################################################################################################################
cmp_deeply( [ execute( { command => 'false' } ) ], \@expect_execute_false, 'execute false works (functional)' );
cmp_deeply( [ execute( { command => 'ls', params => ['lib'] } ) ], \@expect_execute_ls, 'execute ls worked (functional)' );

cmp_deeply( [ $object->execute( { command => 'false' } ) ], \@expect_execute_false, 'execute false works (oop)' );
cmp_deeply( [ $object->execute( { command => 'ls', params => ['lib'] } ) ], \@expect_execute_ls, 'execute ls worked (oop)' );

# Valid calls to vzctl are tested in the respective subcommand test files.

###################################################################################################################################
# Test known_commands

my @known_commands = sort( known_commands() );

cmp_bag(
    \@known_commands, [ qw(

            chkpnt create destroy enter exec exec2 mount quotainit quotaoff quotaon
            restart restore runscript set start status stop umount

            ),
    ],
    'got expected known commands',
);

