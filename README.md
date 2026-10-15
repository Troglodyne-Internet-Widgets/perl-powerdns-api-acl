# NAME

PowerDNS::API::ACL - Per-token access control in front of the PowerDNS HTTP API

# VERSION

version 0.001

# SYNOPSIS

```perl
use PowerDNS::API::ACL;
use PowerDNS::API::ACL::Store;

my $store = PowerDNS::API::ACL::Store->new( path => '/var/lib/pdns-acl/acl.db' );
my $acl   = PowerDNS::API::ACL->new( store => $store );

my $verdict = $acl->authorize(
    token  => 'the-key-the-client-sent',
    method => 'PATCH',
    path   => '/api/v1/servers/localhost/zones/lab.example.net.',
    body   => { rrsets => [ { name => 'web1.lab.example.net.', type => 'A', changetype => 'REPLACE' } ] },
);
return [ $verdict->{status}, [], [ $verdict->{reason} ] ] unless $verdict->{allow};
```

# DESCRIPTION

The PowerDNS API has one key, and the key can do everything: read and rewrite
every zone, create and delete zones, and change the configuration of the
server.  A client that needs to write one record must therefore be trusted with
all of them.

This distribution puts a list of grants between a client and that key.  Each
client gets a token of its own.  A grant lets one token read or write the
records of a set of names in one zone.  [PowerDNS::API::ACL::Proxy](https://metacpan.org/pod/PowerDNS%3A%3AAPI%3A%3AACL%3A%3AProxy) is a PSGI
application that checks each request against the grants, and passes only
allowed requests to PowerDNS with the real key.  [PowerDNS::API::ACL::Store](https://metacpan.org/pod/PowerDNS%3A%3AAPI%3A%3AACL%3A%3AStore)
keeps the tokens and the grants in SQLite, and `pdns-acl` manages them.

This module is the decision.  It knows the requests that a record client makes,
which are the calls that dns-lexicon makes:

- `GET /api/v1/servers/:server/zones/:zone`

    Allowed when the token has any grant in the zone.  The response holds every
    record of the zone, so the proxy passes on only the records that the token can
    read.  See `filter_zone`.

- `PATCH /api/v1/servers/:server/zones/:zone`

    Allowed when every rrset in the body is one that the token can write.  One
    rrset that it cannot write refuses the whole request, because PowerDNS applies
    a PATCH as one change.

- `PUT /api/v1/servers/:server/zones/:zone/notify`

    Allowed when the token can write anything in the zone.

Every other request is refused.  That includes the list of zones, the creation
and deletion of a zone, search, and the configuration of the server.

## Grants

A grant has four parts:

- `zone`

    The zone, as PowerDNS names it, with the trailing dot.

- `name`

    The names that the grant covers.  Either one name, such as
    `webmail.lab.example.net.`, or `*.` and a name, such as
    `*.lab.example.net.`, which covers every name below that name at any depth
    and not the name itself.  The name must be in the zone.

- `types`

    The record types that the grant covers, such as `A` and `CNAME`, or `*` for
    every type.

- `access`

    `read` or `write`.  A write grant also lets the token read.

Names compare without regard to case, and always with the trailing dot.

# METHODS

## new(store => $store)

`store` is a [PowerDNS::API::ACL::Store](https://metacpan.org/pod/PowerDNS%3A%3AAPI%3A%3AACL%3A%3AStore), or anything that answers
`grants_for_token`.

## canonical\_name($name)

Returns `$name` in lower case with one trailing dot.  A class method.

## covers($grant, $name, $type)

True when `$grant` covers the record `$name` of type `$type`.  A class
method, and it ignores `access`.

## authorize(token => $token, method => $method, path => $path, body => $body)

Decides one request.  `body` is the decoded JSON of the request, or undef.

Returns a hash reference.  `allow` is true or false, `status` is the HTTP
status of a refusal (401 for an unknown token, 403 for a refused request), and
`reason` says why.  An allowed GET of a zone also carries `filter`, the
grants that `filter_zone` needs for the response.

## filter\_zone($zone, $grants)

Takes the decoded response to a GET of a zone and the `filter` that
`authorize` returned, and removes each rrset that none of the grants covers.
Changes `$zone` in place and returns it.  A class method.

# AUTHORS

Current Maintainers:

- George S. Baugh <george@troglodyne.net>

# COPYRIGHT AND LICENSE

Copyright (c) 2026 Troglodyne LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
