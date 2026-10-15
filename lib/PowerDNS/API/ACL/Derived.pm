package PowerDNS::API::ACL::Derived;

#ABSTRACT: Tokens that a key derives from a name, so the proxy holds no record of them

use 5.014;
use strict;
use warnings FATAL => 'all';
use re '/aasx';

use Digest::SHA qw{hmac_sha256_hex};

use PowerDNS::API::ACL;

=head1 SYNOPSIS

    use PowerDNS::API::ACL::Derived;

    # Where the key is kept: whoever mints the tokens.
    my $token = PowerDNS::API::ACL::Derived->token_for( $key, 'web1.lab.example.net' );

    # Where the proxy runs.
    my $acl = PowerDNS::API::ACL->new(
        store => PowerDNS::API::ACL::Derived->new(
            key      => $key,
            zones    => ['lab.example.net.'],
            fallback => PowerDNS::API::ACL::Store->new( path => '/var/lib/pdns-acl/acl.db' ),
        ),
    );

=head1 DESCRIPTION

A token of L<PowerDNS::API::ACL::Store> is made on the server, and the server
must be asked for each new client.  A token of this class is made anywhere
that the key is kept, and the server needs only the key to check it.  So a
program that keeps the key can give each host that it builds a token, and
the server accepts the token of a host that was built after the server was.

A derived token names the name that it was made for, as
C<NAME:HMAC>.  NAME is the name without its trailing dot, in lower case.  HMAC
is the HMAC-SHA-256 of the name, with its trailing dot, under the key, in hex.

A derived token gets two write grants in each zone of C<zones> that holds its
name: the name itself, and C<*.> and the name.  So the host of
C<web1.lab.example.net> can write its own records and the
C<_acme-challenge> records of its certificates, and nothing else.  The name
can be a zone of C<zones>.  The token then writes the whole zone.

=head2 Limitations

=over 4

=item * A derived token cannot be revoked by itself.  A new key revokes every
token that the old key made.

=item * A derived token has no label, so C<pdns-acl token list> does not show
it.

=back

=cut

=method new(key => $key, zones => \@zones, fallback => $store)

C<key> is the secret that the tokens are made with.  C<zones> are the zones in
which a derived token gets its grants, as PowerDNS names them.  C<fallback> is
optional.  It answers C<grants_for_token> for every token that is not a
derived token, as L<PowerDNS::API::ACL::Store> does.

Dies when C<key> is empty.

=cut

sub new {
    my ( $class, %opts ) = @_;
    die "PowerDNS::API::ACL::Derived needs a key\n" unless $opts{key};

    return bless {
        key      => $opts{key},
        zones    => [ map { PowerDNS::API::ACL->canonical_name($_) } @{ $opts{zones} // [] } ],
        fallback => $opts{fallback},
    }, $class;
}

=method token_for($key, $name)

Returns the token for C<$name> under C<$key>.  A class method.

=cut

sub token_for {
    my ( undef, $key, $name ) = @_;
    $name = PowerDNS::API::ACL->canonical_name($name);
    return substr( $name, 0, -1 ) . q{:} . hmac_sha256_hex( $name, $key );
}

=method grants_for_token($token)

Returns the grants of C<$token>, as L<PowerDNS::API::ACL::Store> does.  A
derived token that this key did not make, or whose name is in none of the
zones, has none.  Another token gets the grants that C<fallback> gives it.

=cut

sub grants_for_token {
    my ( $self, $token ) = @_;
    return () unless $token;

    my ($name) = $token =~ m/\A([^:]+):[[:xdigit:]]{64}\z/;
    unless ( defined $name ) {
        return $self->{fallback} ? $self->{fallback}->grants_for_token($token) : ();
    }

    return () unless same( $token, $self->token_for( $self->{key}, $name ) );

    $name = PowerDNS::API::ACL->canonical_name($name);
    my @grants;
    foreach my $zone ( @{ $self->{zones} } ) {
        next unless $name eq $zone || substr( $name, -length(".$zone") ) eq ".$zone";
        push( @grants, map { { zone => $zone, name => $_, types => [q{*}], access => 'write' } } $name, "*.$name" );
    }

    return @grants;
}

=method same($given, $expected)

True when the two strings are equal.  It reads every byte of both, so the time
that it takes does not tell how much of C<$given> was right.  A function.

=cut

sub same {
    my ( $given, $expected ) = @_;
    return 0 unless length $given == length $expected;

    my $diff = 0;
    $diff |= ord( substr( $given, $_, 1 ) ) ^ ord( substr( $expected, $_, 1 ) ) foreach 0 .. length($given) - 1;

    return $diff == 0 ? 1 : 0;
}

1;
