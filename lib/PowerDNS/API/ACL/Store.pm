package PowerDNS::API::ACL::Store;

#ABSTRACT: The tokens and grants of PowerDNS::API::ACL, kept in SQLite

use 5.014;
use strict;
use warnings FATAL => 'all';
use re '/aasx';

use Crypt::PRNG qw{random_bytes_b64u};
use DBI;
use Digest::SHA     qw{hmac_sha256_hex};
use List::Util 1.33 qw{any};
use Time::HiRes     qw{time};

use PowerDNS::API::ACL;

=head1 SYNOPSIS

    my $store  = PowerDNS::API::ACL::Store->new( path => '/var/lib/pdns-acl/acl.db' );
    my $secret = $store->add_token(
        'web1',
        { zone => 'lab.example.net.', name => 'web1.lab.example.net.',   types => [qw{A AAAA}], access => 'write' },
        { zone => 'lab.example.net.', name => '*.web1.lab.example.net.', access => 'write' },
    );

=head1 DESCRIPTION

A token is a random secret that a client presents as its API key.  The store
keeps only an HMAC-SHA-256 of each secret, keyed with a random salt that the
database makes when it is created.  So a copy of the database does not give
anybody a working key, and a digest from one database means nothing in
another.  C<add_token> returns the secret once, and nothing can show it again.

Each token has a label, which is how an operator names it, and at least one
grant.  A token with no grant could do nothing, so the store does not make
one, and does not remove the last grant of a token.  Remove the token instead.
L<PowerDNS::API::ACL> says what a grant means.

=cut

my @ACCESS = qw{read write manage};

my @SCHEMA = (
    q{CREATE TABLE IF NOT EXISTS settings (
        name  TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )},
    q{CREATE TABLE IF NOT EXISTS tokens (
        id      INTEGER PRIMARY KEY,
        label   TEXT NOT NULL UNIQUE,
        digest  TEXT NOT NULL UNIQUE,
        created REAL NOT NULL
    )},
    q{CREATE TABLE IF NOT EXISTS grants (
        id       INTEGER PRIMARY KEY,
        token_id INTEGER NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
        zone     TEXT NOT NULL,
        name     TEXT NOT NULL,
        types    TEXT NOT NULL,
        access   TEXT NOT NULL CHECK (access IN ('read', 'write', 'manage')),
        UNIQUE (token_id, zone, name, types, access)
    )},
);

=method new(path => $path)

Opens the database at C<$path>.  If it is new, creates its tables and its
salt.

=cut

sub new {
    my ( $class, %opts ) = @_;
    die "PowerDNS::API::ACL::Store needs a path\n" unless defined $opts{path};

    my $dbh = DBI->connect( "dbi:SQLite:dbname=$opts{path}", q{}, q{}, { RaiseError => 1, PrintError => 0, AutoCommit => 1, sqlite_unicode => 1 } );

    # SQLite enforces a foreign key only when each connection asks it to, and
    # the cascade is what removes the grants of a removed token.
    $dbh->do('PRAGMA foreign_keys = ON');
    $dbh->do($_) foreach @SCHEMA;

    # OR IGNORE, so that the first connection makes the salt and every later
    # one keeps it.
    $dbh->do( q{INSERT OR IGNORE INTO settings (name, value) VALUES ('salt', ?)}, undef, random_bytes_b64u(32) );
    my ($salt) = $dbh->selectrow_array(q{SELECT value FROM settings WHERE name = 'salt'});

    return bless { dbh => $dbh, salt => $salt }, $class;
}

=method digest($secret)

Returns the digest that the database keeps for C<$secret>.

=cut

sub digest {
    my ( $self, $secret ) = @_;
    return hmac_sha256_hex( $secret, $self->{salt} );
}

=method add_token($label, @grants)

Makes a token with this label and these grants, and returns its secret.  Each
grant is a hash reference, as C<add_grant> takes it.

Dies when the label is taken, when there is no grant, or when a grant is
invalid.  Then it makes nothing.

=cut

sub add_token {
    my ( $self, $label, @grants ) = @_;
    die "A token needs a label\n" unless $label;
    die "There is already a token labelled $label\n" if $self->token_id($label);
    die "A token with no grant could do nothing, so $label needs at least one\n" unless @grants;

    my $secret = random_bytes_b64u(32);
    $self->transaction(
        sub {
            $self->{dbh}->do( 'INSERT INTO tokens (label, digest, created) VALUES (?, ?, ?)', undef, $label, $self->digest($secret), time );
            $self->add_grant( $label, %$_ ) foreach @grants;
        }
    );

    return $secret;
}

=method remove_token($label)

Removes the token and its grants.  Returns true when there was one.

=cut

sub remove_token {
    my ( $self, $label ) = @_;
    return $self->{dbh}->do( 'DELETE FROM tokens WHERE label = ?', undef, $label ) > 0 ? 1 : 0;
}

=method tokens()

Returns each token as a hash reference of C<label>, C<created> (epoch seconds)
and C<grants> (how many), sorted by label.

=cut

sub tokens {
    my ($self) = @_;
    return @{
        $self->{dbh}->selectall_arrayref(
            'SELECT t.label, t.created, COUNT(g.id) AS grants FROM tokens t LEFT JOIN grants g ON g.token_id = t.id GROUP BY t.id ORDER BY t.label',
            { Slice => {} },
        )
    };
}

=method token_id($label)

Returns the row id of the token with this label, or undef.

=cut

sub token_id {
    my ( $self, $label ) = @_;
    my ($id) = $self->{dbh}->selectrow_array( 'SELECT id FROM tokens WHERE label = ?', undef, $label );
    return $id;
}

=method add_grant($label, zone => $zone, name => $name, types => \@types, access => $access)

Adds a grant to the token with this label.  C<types> defaults to C<['*']>.

C<access> is C<read>, C<write> or C<manage>.  A C<manage> grant is for the
zone itself, so its C<name> is the zone, and is the zone when left out, and
its C<types> are C<*>.

Dies when there is no such token, when C<access> is none of those, or when
C<name> is not in C<zone>.  A name pattern is checked without its C<*.>, so
C<*.lab.example.net.> is in C<lab.example.net.>.

=cut

sub add_grant {
    my ( $self, $label, %grant ) = @_;

    my $token  = $self->token_id($label) // die "There is no token labelled $label\n";
    my $access = $grant{access}          // q{};
    die "Access is read, write or manage, not '$access'\n" unless any { $_ eq $access } @ACCESS;

    my $zone = PowerDNS::API::ACL->canonical_name( $grant{zone} );
    die "A grant needs a zone\n" if $zone eq q{.};

    my $name = PowerDNS::API::ACL->canonical_name( $grant{name} // ( $access eq 'manage' ? $zone : undef ) );
    die "A manage grant is for the zone $zone itself, not for $name\n" if $access eq 'manage' && $name ne $zone;

    my $bare = index( $name, q{*.} ) == 0 ? substr( $name, 2 ) : $name;
    die "$name is not in the zone $zone\n" unless $bare eq $zone || substr( $bare, -length ".$zone" ) eq ".$zone";

    my $types = $access eq 'manage' ? q{*} : join( q{,}, map { uc } @{ $grant{types} // [q{*}] } );
    $self->{dbh}->do( 'INSERT OR IGNORE INTO grants (token_id, zone, name, types, access) VALUES (?, ?, ?, ?, ?)', undef, $token, $zone, $name, $types, $access );

    return 1;
}

=method remove_grant($id)

Removes the grant with this row id, as C<grants> reports it.  Returns true
when there was one.  Dies when it is the last grant of its token.

=cut

sub remove_grant {
    my ( $self, $id ) = @_;

    my ( $label, $count ) = $self->{dbh}->selectrow_array( 'SELECT t.label, (SELECT COUNT(*) FROM grants o WHERE o.token_id = g.token_id) FROM grants g JOIN tokens t ON t.id = g.token_id WHERE g.id = ?', undef, $id );
    return 0 unless defined $label;
    die "Grant $id is the last grant of the token $label, which could then do nothing.  Remove the token instead.\n" if $count < 2;

    return $self->{dbh}->do( 'DELETE FROM grants WHERE id = ?', undef, $id ) > 0 ? 1 : 0;
}

=method grants($label)

Returns the grants of the token with this label, each as a hash reference of
C<id>, C<zone>, C<name>, C<types> (an array reference) and C<access>.

=cut

sub grants {
    my ( $self, $label ) = @_;
    return $self->select_grants( 'SELECT g.id, g.zone, g.name, g.types, g.access FROM grants g JOIN tokens t ON t.id = g.token_id WHERE t.label = ? ORDER BY g.zone, g.name, g.id', $label );
}

=method grants_for_token($secret)

Returns the grants of the token whose secret this is, as C<grants> does, or
nothing when no token has this secret.  L<PowerDNS::API::ACL> asks this for
each request.

=cut

sub grants_for_token {
    my ( $self, $secret ) = @_;
    return () unless $secret;
    return $self->select_grants( 'SELECT g.id, g.zone, g.name, g.types, g.access FROM grants g JOIN tokens t ON t.id = g.token_id WHERE t.digest = ? ORDER BY g.id', $self->digest($secret) );
}

=method select_grants($sql, @bind)

Runs a query that selects the columns of a grant, and returns each row as
C<grants> describes it.

=cut

sub select_grants {
    my ( $self, $sql, @bind ) = @_;
    my $rows = $self->{dbh}->selectall_arrayref( $sql, { Slice => {} }, @bind );
    $_->{types} = [ split m/,/, $_->{types} ] foreach @$rows;
    return @$rows;
}

=method transaction($code)

Runs C<$code> in one transaction, and rolls it back if C<$code> dies.  Dies
with what C<$code> died with.

=cut

sub transaction {
    my ( $self, $code ) = @_;

    my $dbh = $self->{dbh};
    $dbh->begin_work;
    my $ok    = eval { $code->(); 1 };
    my $error = $@;
    if ($ok) {
        $dbh->commit;
        return 1;
    }
    $dbh->rollback;
    die $error;
}

1;
