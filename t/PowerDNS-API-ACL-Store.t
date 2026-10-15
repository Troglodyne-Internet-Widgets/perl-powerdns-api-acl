#!/usr/bin/env perl
use 5.014;
use strict;
use warnings FATAL => 'all';
use re '/aasx';

# Both import by being loaded, which ProhibitUnusedImports cannot see.
use Test2::V1 -i;                 ## no critic (ProhibitUnusedImports)
use Test2::Plugin::NoWarnings;    ## no critic (ProhibitUnusedImports)
use FindBin::libs;
use File::Temp  qw{tempdir};
use Digest::SHA qw{sha256_hex};

use PowerDNS::API::ACL::Store;

my $ZONE = 'lab.test.test.';

sub fresh {
    my $dir = tempdir( CLEANUP => 1 );
    return ( PowerDNS::API::ACL::Store->new( path => "$dir/acl.db" ), "$dir/acl.db" );
}

subtest 'a token is a secret that the store keeps only the digest of' => sub {
    my ( $store, $path ) = fresh();
    my $secret = $store->add_token('web');

    like( $secret, qr/\A[\w-]{40,}\z/, 'the secret is long and URL-safe' );
    isnt( $store->add_token('db'), $secret, 'and each token gets its own' );

    my $raw = do { local ( @ARGV, $/ ) = $path; <> };
    ok( index( $raw, $secret ) < 0,              'the database does not hold the secret' );
    ok( index( $raw, sha256_hex($secret) ) >= 0, 'only its digest' );

    like( dies { $store->add_token('web') }, qr/already[ ]a[ ]token/, 'a label is taken once' );
    like( dies { $store->add_token(q{}) },   qr/needs[ ]a[ ]label/,   'and a token needs one' );

    is( [ map { $_->{label} } $store->tokens ], [qw{db web}], 'tokens lists them by label' );
};

subtest 'a grant belongs to a token and to a name in its zone' => sub {
    my ($store) = fresh();
    my $secret = $store->add_token('web');

    ok( $store->add_grant( 'web', zone => 'Lab.Test.Test', name => 'web.lab.test.test', types => [qw{a aaaa}], access => 'write' ), 'a grant is added' );
    ok( $store->add_grant( 'web', zone => $ZONE, name => "*.svc.$ZONE", access => 'read' ), 'and one with a pattern and no types' );
    ok( $store->add_grant( 'web', zone => $ZONE, name => $ZONE,         access => 'read' ), 'and one for the zone apex' );

    my @grants = $store->grants('web');
    is(
        [ map { [ @{$_}{qw{zone name access}}, join( q{,}, @{ $_->{types} } ) ] } @grants ],
        [ [ $ZONE, "*.svc.$ZONE", 'read', q{*} ], [ $ZONE, $ZONE, 'read', q{*} ], [ $ZONE, "web.$ZONE", 'write', 'A,AAAA' ] ],
        'stored canonical: lower case, the trailing dot, upper case types, and * for every type'
    );
    is( scalar $store->grants_for_token($secret),     3,  'the secret finds the grants of its token' );
    is( [ $store->grants_for_token('not-a-secret') ], [], 'and another secret finds none' );
    is( [ $store->grants_for_token(undef) ],          [], 'nor does no secret at all' );

    like( dies { $store->add_grant( 'web',    zone => $ZONE, name => 'web.other.test.', access => 'read' ) },  qr/not[ ]in[ ]the[ ]zone/, 'a name outside the zone is refused' );
    like( dies { $store->add_grant( 'web',    zone => $ZONE, name => "xlab.test.test.", access => 'read' ) },  qr/not[ ]in[ ]the[ ]zone/, 'including one that only ends with the same letters' );
    like( dies { $store->add_grant( 'web',    zone => $ZONE, name => "a.$ZONE",         access => 'admin' ) }, qr/read[ ]or[ ]write/,     'access is read or write' );
    like( dies { $store->add_grant( 'nobody', zone => $ZONE, name => "a.$ZONE",         access => 'read' ) },  qr/no[ ]token[ ]labelled/, 'and the token must exist' );
};

subtest 'removing a token takes its grants with it' => sub {
    my ( $store, $path ) = fresh();
    my $secret = $store->add_token('web');
    $store->add_grant( 'web', zone => $ZONE, name => "web.$ZONE", access => 'write' );

    my ($grant) = $store->grants('web');
    ok( $store->remove_grant( $grant->{id} ),  'a grant is removed by its id' );
    ok( !$store->remove_grant( $grant->{id} ), 'once' );

    $store->add_grant( 'web', zone => $ZONE, name => "web.$ZONE", access => 'write' );
    ok( $store->remove_token('web'),  'a token is removed' );
    ok( !$store->remove_token('web'), 'once' );
    is( [ $store->grants_for_token($secret) ], [], 'and its secret opens nothing' );

    # A second connection, as the proxy and pdns-acl each have, sees the same.
    my $again = PowerDNS::API::ACL::Store->new( path => $path );
    my $count = $again->{dbh}->selectrow_array('SELECT COUNT(*) FROM grants');
    is( $count, 0, 'no grant of it is left in the database' );
};

like( dies { PowerDNS::API::ACL::Store->new }, qr/needs[ ]a[ ]path/, 'new refuses to run without a path' );

done_testing;
