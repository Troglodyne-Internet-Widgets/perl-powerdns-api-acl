#!/usr/bin/env perl
use 5.014;
use strict;
use warnings FATAL => 'all';
use re '/aasx';

# Both import by being loaded, which ProhibitUnusedImports cannot see.
use Test2::V1 -i;                 ## no critic (ProhibitUnusedImports)
use Test2::Plugin::NoWarnings;    ## no critic (ProhibitUnusedImports)
use FindBin::libs;
use Digest::SHA qw{hmac_sha256_hex};

use PowerDNS::API::ACL::Derived;

{

    package Fake::Store;
    sub new              { my ( $class, %grants_of ) = @_; return bless {%grants_of}, $class }
    sub grants_for_token { my ( $self,  $token )     = @_; return @{ $self->{$token} // [] } }
}

my $KEY  = 'a-key-for-tests';
my $ZONE = 'lab.test.test.';

subtest 'token_for' => sub {
    my $token = PowerDNS::API::ACL::Derived->token_for( $KEY, 'Web1.Lab.Test.Test.' );
    is( $token,                                                               'web1.lab.test.test:' . hmac_sha256_hex( 'web1.lab.test.test.', $KEY ), 'is the name, in lower case and without its dot, and the HMAC of the name with its dot' );
    is( PowerDNS::API::ACL::Derived->token_for( $KEY, 'web1.lab.test.test' ), $token,                                                                 'and does not depend on the trailing dot of the name' );
    isnt( PowerDNS::API::ACL::Derived->token_for( 'another-key', 'web1.lab.test.test' ), $token, 'but does depend on the key' );
};

subtest 'new' => sub {
    like( dies { PowerDNS::API::ACL::Derived->new( zones => [$ZONE] ) },               qr/needs[ ]a[ ]key/, 'refuses no key, which would make every token one that anybody can mint' );
    like( dies { PowerDNS::API::ACL::Derived->new( key   => q{}, zones => [$ZONE] ) }, qr/needs[ ]a[ ]key/, 'and an empty key' );
};

subtest 'grants_for_token' => sub {
    my $fallback = Fake::Store->new( 'from-the-db' => [ { zone => $ZONE, name => "db.$ZONE", types => ['A'], access => 'read' } ] );
    my $derived  = PowerDNS::API::ACL::Derived->new( key => $KEY, zones => [ 'lab.test.test', 'other.test.test.' ], fallback => $fallback );
    my $token    = PowerDNS::API::ACL::Derived->token_for( $KEY, "web1.$ZONE" );

    is(
        [ $derived->grants_for_token($token) ],
        [ { zone => $ZONE, name => "web1.$ZONE", types => ['*'], access => 'write' }, { zone => $ZONE, name => "*.web1.$ZONE", types => ['*'], access => 'write' }, ],
        'a token that the key made writes its name and the names below it, in the zone that holds the name'
    );

    my $whole = PowerDNS::API::ACL::Derived->token_for( $KEY, $ZONE );
    is( [ map { $_->{name} } $derived->grants_for_token($whole) ], [ $ZONE, "*.$ZONE" ], 'the name of a zone is in the zone, and its token writes the whole zone' );

    is( [ $derived->grants_for_token( PowerDNS::API::ACL::Derived->token_for( $KEY, 'web1.elsewhere.test' ) ) ], [], 'a name in none of the zones has no grant' );
    is( [ $derived->grants_for_token( PowerDNS::API::ACL::Derived->token_for( $KEY, 'xlab.test.test' ) ) ],      [], 'and a name that only ends in the text of a zone is not in it' );

    is( [ $derived->grants_for_token( PowerDNS::API::ACL::Derived->token_for( 'another-key', "web1.$ZONE" ) ) ], [], 'a token that another key made has none' );

    my $forged = 'lab.test.test:' . substr( $token, index( $token, q{:} ) + 1 );
    is( [ $derived->grants_for_token($forged) ], [], 'nor does the HMAC of one name under another name' );

    is( [ map { $_->{name} } $derived->grants_for_token('from-the-db') ],                                       ["db.$ZONE"], 'a token of another kind gets what the fallback gives it' );
    is( [ PowerDNS::API::ACL::Derived->new( key => $KEY, zones => [$ZONE] )->grants_for_token('from-the-db') ], [],           'and nothing without a fallback' );
    is( [ $derived->grants_for_token(q{}) ],                                                                    [],           'an empty token has none' );
};

subtest 'same' => sub {
    ok( PowerDNS::API::ACL::Derived::same( 'abc',  'abc' ),  'equal strings are the same' );
    ok( !PowerDNS::API::ACL::Derived::same( 'abc', 'abd' ),  'one byte apart are not' );
    ok( !PowerDNS::API::ACL::Derived::same( 'abc', 'abcd' ), 'nor is a prefix' );
};

done_testing();
