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

# A grant that every token here can start with.
my %OWN = ( zone => $ZONE, name => "web.$ZONE", access => 'write' );

sub fresh {
    my $dir = tempdir( CLEANUP => 1 );
    return ( PowerDNS::API::ACL::Store->new( path => "$dir/acl.db" ), "$dir/acl.db" );
}

subtest 'a token is a secret that the store keeps only a salted digest of' => sub {
    my ( $store, $path ) = fresh();
    my $secret = $store->add_token( 'web', {%OWN} );

    like( $secret, qr/\A[\w-]{40,}\z/, 'the secret is long and URL-safe' );
    isnt( $store->add_token( 'db', {%OWN} ), $secret, 'and each token gets its own' );

    my $raw = do { local ( @ARGV, $/ ) = $path; <> };
    ok( index( $raw, $secret ) < 0,                  'the database does not hold the secret' );
    ok( index( $raw, sha256_hex($secret) ) < 0,      'nor its unsalted digest' );
    ok( index( $raw, $store->digest($secret) ) >= 0, 'only the salted one' );

    my ($other) = fresh();
    isnt( $other->digest($secret), $store->digest($secret), 'and another database salts the same secret differently' );

    my $reopened = PowerDNS::API::ACL::Store->new( path => $path );
    is( scalar $reopened->grants_for_token($secret), 1, 'the salt is kept, so the secret still works after the database is opened again' );

    like( dies { $store->add_token( 'web', {%OWN} ) }, qr/already[ ]a[ ]token/, 'a label is taken once' );
    like( dies { $store->add_token( q{},   {%OWN} ) }, qr/needs[ ]a[ ]label/,   'and a token needs one' );

    is( [ map { $_->{label} } $store->tokens ], [qw{db web}], 'tokens lists them by label' );
};

subtest 'a token that could do nothing is not made' => sub {
    my ($store) = fresh();

    like( dies { $store->add_token('web') },                                        qr/needs[ ]at[ ]least[ ]one/,    'a token with no grant is refused' );
    like( dies { $store->add_token( 'web', {%OWN}, { %OWN, access => 'admin' } ) }, qr/read,[ ]write[ ]or[ ]manage/, 'as is one with a grant that is not valid' );
    is( [ $store->tokens ], [], 'and neither left a token behind' );
};

subtest 'a grant belongs to a token and to a name in its zone' => sub {
    my ($store) = fresh();
    my $secret = $store->add_token( 'web', { zone => 'Lab.Test.Test', name => 'web.lab.test.test', types => [qw{a aaaa}], access => 'write' } );

    ok( $store->add_grant( 'web', zone => $ZONE, name => "*.svc.$ZONE", access => 'read' ), 'a grant with a pattern and no types is added' );
    ok( $store->add_grant( 'web', zone => $ZONE, name => $ZONE,         access => 'read' ), 'and one for the zone apex' );
    ok( $store->add_grant( 'web', zone => $ZONE, access => 'manage' ), 'and a manage grant, which needs no name' );

    my @grants = $store->grants('web');
    is(
        [ map { [ @{$_}{qw{zone name access}}, join( q{,}, @{ $_->{types} } ) ] } @grants ],
        [ [ $ZONE, "*.svc.$ZONE", 'read', q{*} ], [ $ZONE, $ZONE, 'read', q{*} ], [ $ZONE, $ZONE, 'manage', q{*} ], [ $ZONE, "web.$ZONE", 'write', 'A,AAAA' ] ],
        'stored canonical: lower case, the trailing dot, upper case types, * for every type, and the zone as the name of a manage grant'
    );
    is( scalar $store->grants_for_token($secret),     4,  'the secret finds the grants of its token' );
    is( [ $store->grants_for_token('not-a-secret') ], [], 'and another secret finds none' );
    is( [ $store->grants_for_token(undef) ],          [], 'nor does no secret at all' );

    like( dies { $store->add_grant( 'web',    zone => $ZONE, name => 'web.other.test.', access => 'read' ) },   qr/not[ ]in[ ]the[ ]zone/,                  'a name outside the zone is refused' );
    like( dies { $store->add_grant( 'web',    zone => $ZONE, name => 'xlab.test.test.', access => 'read' ) },   qr/not[ ]in[ ]the[ ]zone/,                  'including one that only ends with the same letters' );
    like( dies { $store->add_grant( 'web',    zone => $ZONE, name => "a.$ZONE",         access => 'manage' ) }, qr/manage[ ]grant[ ]is[ ]for[ ]the[ ]zone/, 'a manage grant for a name in the zone is refused' );
    like( dies { $store->add_grant( 'web',    zone => $ZONE, name => "a.$ZONE",         access => 'admin' ) },  qr/read,[ ]write[ ]or[ ]manage/,            'access is read, write or manage' );
    like( dies { $store->add_grant( 'nobody', zone => $ZONE, name => "a.$ZONE",         access => 'read' ) },   qr/no[ ]token[ ]labelled/,                  'and the token must exist' );
};

subtest 'removing a token takes its grants with it, and its last grant cannot go alone' => sub {
    my ( $store, $path ) = fresh();
    my $secret = $store->add_token( 'web', {%OWN} );
    $store->add_grant( 'web', zone => $ZONE, name => "*.web.$ZONE", access => 'write' );

    my ( $first, $last ) = $store->grants('web');
    ok( $store->remove_grant( $first->{id} ),  'a grant is removed by its id' );
    ok( !$store->remove_grant( $first->{id} ), 'once' );
    like( dies { $store->remove_grant( $last->{id} ) }, qr/last[ ]grant[ ]of[ ]the[ ]token[ ]web/, 'the last grant of a token is not removed' );
    is( scalar $store->grants('web'), 1, 'and is still there' );

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
