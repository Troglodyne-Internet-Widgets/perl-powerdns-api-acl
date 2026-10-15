package PowerDNS::API::ACL::Proxy;

#ABSTRACT: A PSGI application that passes allowed requests on to the PowerDNS API

use 5.014;
use strict;
use warnings FATAL => 'all';
use re '/aasx';

use Cpanel::JSON::XS ();
use HTTP::Tiny::UNIX ();
use Plack::Request   ();

use PowerDNS::API::ACL;
use PowerDNS::API::ACL::Store;

=head1 SYNOPSIS

    # app.psgi
    use PowerDNS::API::ACL::Proxy;

    PowerDNS::API::ACL::Proxy->new(
        db       => '/var/lib/pdns-acl/acl.db',
        upstream => '/var/spool/powerdns/api.sock',
        api_key  => $ENV{PDNS_API_KEY},
    )->to_app;

=head1 DESCRIPTION

Checks each request against L<PowerDNS::API::ACL>, and passes an allowed
request on to PowerDNS with the real API key in place of the token of the
client.  A client presents its token as PowerDNS expects a key, in the
C<X-API-Key> header, so a client of PowerDNS needs no change but the URL and
the key.

A refused request gets the status that C<authorize> in L<PowerDNS::API::ACL> chose,
and a body in the form that PowerDNS gives an error, C<{"error": "..."}>.

Serve it with any PSGI server, behind a web server that terminates TLS.  The
token travels in a header, so it must not travel in the clear.

=cut

my $JSON = Cpanel::JSON::XS->new->utf8->canonical;

=method new(%opts)

=over 4

=item C<db>

The path of the database of L<PowerDNS::API::ACL::Store>.  Or pass C<store>,
an object that answers as the store does.

=item C<upstream>

Where the PowerDNS API listens: a path to its unix socket, as
C<webserver-address> names it from PowerDNS 5.0, or a URL such as
C<http://127.0.0.1:8081>.

=item C<api_key>

The key of the PowerDNS API.  It never leaves this process except toward
C<upstream>.

=item C<timeout>

Seconds to wait for PowerDNS.  The default is 10.

=back

=cut

sub new {
    my ( $class, %opts ) = @_;

    foreach my $required (qw{upstream api_key}) {
        die "PowerDNS::API::ACL::Proxy needs $required\n" unless $opts{$required};
    }
    my $store = $opts{store} // PowerDNS::API::ACL::Store->new( path => $opts{db} // die "PowerDNS::API::ACL::Proxy needs db or store\n" );

    # HTTP::Tiny::UNIX reads http: followed by a socket path, then the path of
    # the request after a second slash.
    my $base = index( $opts{upstream}, q{/} ) == 0 ? "http:$opts{upstream}/" : $opts{upstream} =~ s{/+\z}{}r;

    # No keep_alive: HTTP::Tiny checks a kept connection with peerhost, which a
    # unix socket does not have, and a connection to one costs next to nothing.
    return bless {
        acl     => PowerDNS::API::ACL->new( store => $store ),
        base    => $base,
        api_key => $opts{api_key},
        http    => HTTP::Tiny::UNIX->new( keep_alive => 0, timeout => $opts{timeout} // 10 ),
    }, $class;
}

=method to_app()

Returns the PSGI application.

=cut

sub to_app {
    my ($self) = @_;
    return sub { return $self->handle( Plack::Request->new(shift) ) };
}

=method handle($request)

Answers one L<Plack::Request>, and returns the PSGI response.

=cut

sub handle {
    my ( $self, $req ) = @_;

    my $content = $req->content;
    my $body;
    if ($content) {
        $body = eval { $JSON->decode($content) };
        return error( 400, 'The body is not JSON' ) unless defined $body;
    }

    my $verdict = $self->{acl}->authorize(
        token  => scalar $req->header('X-API-Key'),
        method => $req->method,
        path   => $req->path_info,
        body   => $body,
    );
    return error( $verdict->{status}, $verdict->{reason} ) unless $verdict->{allow};

    my $query = $req->env->{QUERY_STRING};
    my $res   = $self->{http}->request(
        $req->method,
        $self->{base} . $req->path_info . ( $query ? "?$query" : q{} ),
        {
            headers => { 'X-API-Key' => $self->{api_key}, 'Content-Type' => 'application/json', Accept => 'application/json' },
            ( $content ? ( content => $content ) : () ),
        },
    );

    # 599 is HTTP::Tiny saying that no answer came, which is not PowerDNS
    # refusing the request.
    return error( 502, "PowerDNS did not answer: $res->{content}" ) if $res->{status} == 599;

    my $out = $res->{content} // q{};
    if ( $verdict->{filter} && $res->{success} ) {
        my $zone = eval { $JSON->decode($out) };
        return error( 502, 'PowerDNS answered with a zone that is not JSON' ) unless ref $zone eq 'HASH';
        $out = $JSON->encode( PowerDNS::API::ACL->filter_zone( $zone, $verdict->{filter} ) );
    }

    return [ $res->{status}, [ 'Content-Type' => $res->{headers}{'content-type'} // 'application/json' ], [$out] ];
}

=method error($status, $message)

Returns a PSGI response with C<$status> and a body as PowerDNS writes an
error.  A class method, and a function.

=cut

sub error {
    my ( $status, $message ) = @_;
    return [ $status, [ 'Content-Type' => 'application/json' ], [ $JSON->encode( { error => $message } ) ] ];
}

1;
