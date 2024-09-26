---
title: Usage of PAKE with TLS 1.3
abbrev: TLS 1.3 PAKE
docname: draft-bmw-tls-pake13-latest
category: info

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: L. Bauman
    name: Laura Bauman
    organization: Apple, Inc.
    email: l_bauman@apple.com
 - ins: S. Menon
   name: Samir Menon
   organization: Apple, Inc.
   email: samir_menon@apple.com
 - ins: C. Wood
    name: Chris Wood
    organization: Apple, Inc.
    email: cawood@apple.com

informative:
  speke:
    title: "Extended Password Key Exchange Protocols Immune to Dictionary Attacks"
    date: 1997
    author:
      ins: D. Jablon
      name: David Jablon
  opaque:
    title: "OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks"
    date: 2018
    author:
      ins: S. Jarecki
      name: Stanislaw Jarecki
    author:
      ins: H. Krawczyk
      name: Hugo Krawczyk
    author:
      ins: J. Xu
      name: Jiayu Xu


--- abstract

TODO: Most of this text is copied from draft-barnes-tls-pake-04
and is in the process of being updated.

The pre-shared key mechanism available in TLS 1.3 is not suitable
for usage with low-entropy keys, such as passwords entered by users.
This document describes an extension that enables the use of
password-authenticated key exchange protocols with TLS 1.3.


--- middle


# Introduction

DISCLAIMER: This is a work-in-progress draft and has not yet
seen significant security analysis. It should not be used as a basis
for building production systems.

In some applications, it is desireable to enable a client and server
to authenticate to one another using a low-entropy pre-shared value,
such as a user-entered password.

In prior versions of TLS, this functionality has been provided by
the integration of the Secure Remote Password PAKE protocol (SRP)
{{?RFC5054}}.  The specific SRP integration described in RFC 5054
does not immediately extend to TLS 1.3 because it relies on the
Client Key Exchange and Server Key Exchange messages, which no
longer exist in 1.3.

TLS 1.3 itself provides a mechanism for authentication with
pre-shared keys (PSKs).  However, PSKs used with this protocol need
to be "full-entropy", because the binder values used for
authentication can be used to mount a dictionary attack on the PSK.
So while the TLS 1.3 PSK mechanism is suitable for the session
resumption cases for which it is specified, it cannot be used when
the client and server share only a low-entropy secret.

Enabling TLS to address this use case effectively requires the TLS
handshake to execute a password-authenticated key establishment
(PAKE) protocol.  This document describes a TLS extension `pake`
that can carry data necessary to execute a PAKE.

This extension is generic, in that it can be used to carry key
exchange information for multiple different PAKEs. We assume that
prior to the TLS handshake the client and server will both have
knowledge of the password or PAKE-specific values derived from the 
password (e.g. augmented PAKEs only require one party to know the
actual password). The choice of PAKE and any required parameters will 
be explicitly specified using IANA assigned values. As a first
case, this document defines a concrete protocol for executing the
SPAKE2+ PAKE protocol {{!RFC9383}}.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{!RFC2119}}.

The mechanisms described in this document also apply to DTLS 1.3
{{!RFC9147}}, but for brevity, we will refer only to TLS
throughout.

# Setup

In order to use this protocol, a TLS client and server need to have
pre-provisioned a password (or derived values as described by the 
desired PAKE protocol(s)).

Servers will of course have multiple instances of this configuration
information for different clients.  Clients may also have multiple
identities, even within a given server.  We assume that in either
case, a single opaque "identity" value is sufficient to identify the
required parameters.

# TLS Extensions

A client offers to authenticate with PAKE by including a `pake`
extension in its ClientHello.  The content of this exension is a
`PAKEClientHello` value, providing a list of PAKE/identity pairs 
under which the client can authenticate, and for each pair, 
the client's first message for the underlying PAKE protocol.

The inclusion of the `NamedPAKE` field in the `PAKEShare` allows
implementations to support multiple PAKEs and negotiate which
to use in the context of the handshake. For instance, if a 
client knows a password but not which PAKE the server supports
it could send corresponding PAKEShares for each PAKE.

If a client sends the `pake` extension, then it MAY also send the
`key_share` and `pre_shared_key` extensions, to allow the server to
choose an authentication mode.  Unlike PSK-based authentication,
however, authentication with PAKE cannot be combined with the
normal TLS ECDH mechanism.  Forward secrecy is provided by the PAKE
itself.

~~~~~
enum {
    // TODO: names should fully specify parameters. 
    
    SPAKE2PLUS_V1 (0xXXXX),
    OPAQUE_V1 (0xXXXX),
    ...
    etc.
    
} NamedPAKE;

struct {
    NamedPAKE   pake;
    opaque      identity<0..2^16-1>;
    opaque      pake_message<1..2^16-1>;
} PAKEShare;

struct {
    PAKEShare client_shares<0..2^16-1>;
} PAKEClientHello;
~~~~~

A server that receives a `pake` extension examines the list of
client shares to see if there is one with a PAKE selection and identity 
the server recognizes.  If so, the server may indicate its choice of PAKE
authentication by including a `pake` extension in its
ServerHello.  The content of this exension is a `PAKEServerHello`
value, specifying the PAKE and identity value for the password 
the server has selected, and the server's first message in the PAKE protocol.

Use of PAKE authenication is compatible with standard
certificate-based authentication of both clients and servers.  If a
server includes an `pake` extension in its ServerHello, it may still
send the Certificate and CertificateVerify messages, and/or send a
CertificateRequest message to the client.

If a server uses PAKE authentication, then it MUST NOT send an
extension of type `key_share`, `pre_shared_key`, or `early_data`.

~~~~~
struct {
    PAKEShare server_share;
} PAKEServerHello;
~~~~~

Based on the messages exchanged in the ClientHello and ServerHello,
the client and server execute the specified PAKE protocol to derive
a shared key.  This key is used as the `ECDH(E)` input to the TLS
1.3 key schedule.

As with client authentication via certificates, the server has not
authenticated the client until after it has received the client's
Finished message.  When a server negotiates the use of this
mechanism for authentication, it MUST NOT send application data
before it has received the client's Finished message.


# Compatible PAKE Protocols

In order to be usable with the `pake` extension, a PAKE protocol
must specify some syntax for its messages, and the protocol itself
must be compatible with the message flow described above.  A
specification describing the use of a particular PAKE protocol with
TLS must provide the following details:

* A `NamedPAKE` registered value indicating pre-provisioned parameters
* Content of the `pake_message` field in a ClientHello
* Content of the `pake_message` field in a ServerHello
* How the PAKE protocol is executed based on those messages
* How the outputs of the PAKE protocol are used to populate the
  `PSK` and `ECDH(E)` inputs to the TLS key schedule.

The underlying cryptographic protocol must be compatible with the
message flow described above:

* It must be possible to execute in one round-trip, with the client
  speaking first
* The Finished MAC must provide sufficient key confirmation for the
  protocol, taking into account the contents of the handshake
  messages

In addition, to be compatible with the security requirements of TLS
1.3, PAKE protocols defined for use with TLS 1.3 MUST provide
forward secrecy.

Several current PAKE protocols satisfy these requirements, for
example:

* SPAKE2+ (described below) {{!RFC9383}}
* SPEKE and derivatives such as Dragonfly {{speke}} {{?RFC7664}}
* OPAQUE {{opaque}}
* SRP {{?RFC2945}}


# SPAKE2+ Implementation

# Pre-provisioned Parameters

In order to use SPAKE2+, a TLS client and server need to have
pre-provisioned the values required to execute the SPAKE2+ protocol
(see Section 3.1 and Section 4 of {{!RFC9383}}):

* A DH group `G` of order `p*h`, with `p` a large prime, and generator
  `P`
* A cryptographic hash algorithm `H`
* Fixed elements `M` and `N` for the group
* A password `pw`

Note that the hash function `H` might be different from the hash
function associated with the ciphersuite negotiated by the two
parties.  The hash function `H` MUST be a hash function suitable for
hashing passwords, e.g., Argon2 or scrypt {{?RFC9106}}
{{?RFC7914}}.

The TLS client and server roles map to the `Prover` and `Verifier` roles in the
SPAKE2+ specification, respectively.  The identity of the server is
the domain name sent in the `server_name` extension of the
ClientHello message.  The identity of the client is an opaque octet
string, specified in the `spake2` ClientHello extension, defined
below. 

[[TODO: clarify/generalize identity requirements. I don't think it is necessary to require that `server_name` extension matches the server identity.]]

From the shared password, each party computes two shared integers
`w0` and `w1` by running the following algorithm twice (changing the
`context` value each time):

[[TODO: generalize for server not knowing password for SPAKE2+?]]

~~~~~
struct {
  uint16 context;
  opaque client\_identity<0..255>;
  opaque server\_name<0..255>;
  opaque password<0..255>;
} PasswordInput;
~~~~~

* Encode the following values into a `PasswordInput` structure:
  * `client_identity`: The client's identity, as described above.
  * `server_name`: The server's identity, as described above.
  * `password`: The password `pw`
  * `context`: One of the following values:
    * 0x7730, when generating `w0`
    * 0x7731, when generating `w1`

* Use the hash function `H` with the encoded `PasswordInput`
  structure as input to derive an `n`-byte string, where `n` is the
  byte-length of `p`.

* Interpret the `n`-bit string as an integer `w` in network byte
  order.  Return the result `(w % p) * h` of reducing `w` mod p and
  multiplying it by `h`.

Servers MUST store only the value `w0` and the product `L = w1*G`,
where `G` is the fixed generator of the group.  Clients will need to
have access to the values `w0` and `w1` directly, but SHOULD
generate these values dynamically, rather than caching them.


# Content of the TLS Extensions

The content of a `pake_message` in a ClientHello is the client's key
share `X`.  The value `X` is computed as specified in
{{!RFC9383}}, as `X = x*P + w0*M`, where `M` is a fixed
value for the DH group and `x` is selected uniformly at random 
from the integers in `[0, p-1]`.  The format of the key share 
`X` is the same as for a `KeyShareEntry.key_exchange` value from 
the same group.

The content of a `pake_message` in a ServerHello is the server's key
share `Y`.  The value `Y` is computed as specified in
{{!RFC9383}}, as `Y = y*P + w0*N`, where `N` is a fixed
value for the DH group and `y` is selected uniformly at random 
from the integers in `[0, p-1]`.  The format of the key share 
`Y` is the same as for a `KeyShareEntry.key_exchange` value from 
the same group.

Based on these messages, both the client and server can compute the
two shared values as specified in {{!RFC9383}}.

| Name | Value    | Client          | Server         |
|:-----|:---------|:----------------|:---------------|
| Z    | h\*x\*y\*P  | h\*x\*(Y - w0\*N)  | h\*y\*(X - w0\*M) |
| V    | h\*w1\*y\*P | h\*w1\*(Y - w0\*N) | h\*y\*L           |

The following value is used as the `(EC)DHE` input to the TLS 1.3
key schedule:

~~~~~
K = H(Z || V)
~~~~~

[[TODO: should this be `K_main = H(TT)`? where TT is the transcript including Z and V?]]

Here `H` is the hash function corresponding to the TLS cipher suite
in use and `||` represents concatenation of octet strings.


# Security Considerations

Many of the security properties of this protocol will derive from
the PAKE protocol being used.  Security considerations for PAKE
protocols are noted in {{compatible-pake-protocols}}.

If a server doesn't recognize any of the identities supplied by the 
client in the ClientHello `pake` extension, the server MAY abort the handshake with an 
"unknown_psk_identity" alert. In this case, the server acts as an oracle
for identities, in which each handshake allows an attacker 
to learn whether the server recognizes any of the identities in a set.

Alternatively, if the server wishes to hide the fact that these client
identities are unrecognized, the server MAY simulate the protocol as 
if an identity was recognized, but then reject the client's 
Finished message with a "decrypt_error" alert, as if the password was incorrect.
This is similar to the procedure outlined in {{?RFC5054}}

To simulate the protocol, the server should:

* Select a random identity supplied by the client.
* Include the `pake` extension in its ServerHello, containing a `server_share` with
the randomly selected `identity` and corresponding `pake`. To generate the `pake_message`,
the server should select a `w0` uniformly at random from the integers in `[0, p-1]`,
and then calculate `pake_message` as normal using `w0`.
* Perform the rest of the protocol as normal. Because `w0` was selected uniformly at random,
the server will reject the client's Finished message with overwhelming probability.

A server that performs the simulation of the protocol acts only 
as an all-or-nothing oracle for whether a given (identity, password) pair
is correct. If an attacker does not supply a correct pair, 
they do not learn anything beyond this fact.

## Security when using SPAKE2+

For the most part, the security properties of the password-based
authentication described in this document are the same as those
described in the Security Considerations of
{{!RFC9383}}.  The TLS Finished MAC provides the key
confirmation required for the security of the protocol.  Note that
all of the elements covered by the example confirmation hash listed
in that document are also covered by the Finished MAC:

* `idProver`, `idVerifier`, and `X` are included via the ClientHello
* `Y` via the ServerHello
* `K`, and `w` via the TLS key schedule 

[[TODO: align with SPAKE2+ terminology]]

The `x` and `y` values used in the SPAKE2+ protocol MUST have the
same ephemerality properties as the key shares sent in the
`key_shares` extension.  In particular, `x` and `y` MUST NOT be
equal to zero.   This ensures that TLS sessions using SPAKE2+ have
the same forward secrecy properties as sessions using the normal TLS
(EC)DH mechanism.

# Open Items

# IANA Considerations

This document requests that IANA add a value to the TLS
ExtensionType Registry with the following contents:

| Value | Extension Name | TLS 1.3 | Reference |
|:------|:---------------|:-------:|:---------:|
| TBD   | pake           | CH, SH  | RFC XXXX  |

[[ RFC EDITOR: Please replace "TBD" in the above table with the
value assigned by IANA, and replace "XXXX" with the RFC number
assigned to this document. ]]

[[TODO: add IANA request for the `NamedPake` for SPAKE2+?]]
