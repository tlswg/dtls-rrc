---
v: 3

title: Return Routability Check for DTLS 1.2 and DTLS 1.3
abbrev: DTLS Return Routability Check
docname: draft-ietf-tls-dtls-rrc-latest
category: std
consensus: true
submissiontype: IETF
updates: 9146

ipr: trust200902
area: Security
workgroup: TLS
keyword: DTLS, RRC, CID

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  docmapping: yes

author:
  - ins: H. Tschofenig
    name: Hannes Tschofenig
    org: University of Applied Sciences Bonn-Rhein-Sieg
    abbrev: H-BRS
    role: editor
    email: Hannes.Tschofenig@gmx.net
  - ins: A. Kraus
    name: Achim Kraus
    email: achimkraus@gmx.net
  - ins: T. Fossati
    name: Thomas Fossati
    organization: Linaro
    email: thomas.fossati@linaro.org

entity:
  SELF: "RFCthis"

--- abstract

This document specifies a return routability check for use in context of the
Connection ID (CID) construct for the Datagram Transport Layer Security (DTLS)
protocol versions 1.2 and 1.3.

--- middle

# Introduction

A Connection ID (CID) is an identifier carried in the record layer header of a DTLS datagram
that gives the receiver additional information for selecting the appropriate
security context.  The CID mechanism has been specified in {{!RFC9146}} for
DTLS 1.2 and in {{!RFC9147}} for DTLS 1.3.

Section 6 of {{!RFC9146}} describes how the use of CID increases the attack
surface of DTLS 1.2 and 1.3 by providing both on-path and off-path attackers an opportunity for
(D)DoS.  It also describes the steps a DTLS principal must take when a
record with a CID is received that has a source address different
from the one currently associated with the DTLS connection.  However, the
actual mechanism for ensuring that the new peer address is willing to receive
and process DTLS records is left open.  To address the gap, this document defines a Return
Routability Check (RRC) sub-protocol for DTLS 1.2 and 1.3 inspired by the path validation procedure defined in {{Section 8.2 of RFC9000}}.

The return routability check is performed by the receiving endpoint before the
CID-address binding is updated in that endpoint's session state.
This is done in order to give the receiving endpoint confidence
that the sending peer is in fact reachable at the source address indicated in the received datagram.

{{regular}} of this document explains the fundamental mechanism that aims to reduce the DDoS attack surface.
Additionally, in {{enhanced}}, a more advanced address validation mechanism is discussed.
This mechanism is designed to counteract off-path attackers trying to place themselves on-path by racing packets that trigger address rebinding at the receiver.
To gain a detailed understanding of the attacker model, please refer to {{attacker}}.

Apart from of its use in the context of CID-address binding updates,
the path validation capability offered by RRC can be used at any time by either endpoint. For
instance, an endpoint might use RRC to check that a peer is still reachable at
its last known address after a period of quiescence.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

This document assumes familiarity with the CID format and protocol defined for
DTLS 1.2 {{!RFC9146}} and for DTLS 1.3 {{!RFC9147}}.  The presentation language
used in this document is described in Section 4 of {{!RFC8446}}.

In this document, the term "anti-amplification limit" means three times the amount of data received from an unvalidated address.
This includes all DTLS records originating from that source address, excluding those that have been discarded.
This follows the pattern of {{?RFC9000}}, applying a similar concept to DTLS.

The term "address" is defined in {{Section 1.2 of ?RFC9000}}.

The terms "client", "server", "peer" and "endpoint" are defined in {{Section 1.1 of RFC8446}}.

# RRC Extension

The use of RRC is negotiated via the `rrc` extension.
The `rrc` extension is only defined for DTLS 1.2 and DTLS 1.3.
On connecting, a client wishing to use RRC includes the `rrc` extension in its ClientHello.
If the server is capable of meeting this requirement, it responds with a
`rrc` extension in its ServerHello.  The `extension_type` value for this
extension is TBD1 and the `extension_data` field of this extension is empty.
A client offering the `rrc` extension MUST also offer the `connection_id` extension {{!RFC9146}}.
A client offering the `connection_id` extension SHOULD also offer the `rrc` extension, unless the application using DTLS has its own address validation mechanism.
The client and server MUST NOT use RRC unless both sides have successfully exchanged `rrc` extensions.

## RRC and CID Interplay

RRC offers an in-protocol mechanism to perform peer address validation that
complements the "peer address update" procedure described in {{Section 6 of
RFC9146}}.  Specifically, when both CID {{RFC9146}} and RRC have been
successfully negotiated for the session, if a record with CID is received that
has the source address of the enclosing UDP datagram different from what is
currently associated with that CID value, the receiver SHOULD perform a return
routability check as described in {{path-validation}}, unless an application-specific
address validation mechanism can be triggered instead (e.g., CoAP Echo {{?RFC9175}}).

# Return Routability Check Message Types

This document defines the `return_routability_check` content type
({{fig-rrc-msg}}) to carry Return Routability Check messages.

The RRC sub-protocol consists of three message types: `path_challenge`, `path_response`
and `path_drop` that are used for path validation and selection as described in
{{path-validation}}.

Each message carries a Cookie, an 8-byte field containing 64 bits of entropy (e.g., obtained from the CSPRNG used by the TLS implementation, see {{Appendix C.1 of !RFC8446}}).

The `return_routability_check` message MUST be authenticated and encrypted
using the currently active security context.

~~~ tls-msg
enum {
    invalid(0),
    change_cipher_spec(20),
    alert(21),
    handshake(22),
    application_data(23),
    heartbeat(24),  /* RFC 6520 */
    tls12_cid(25),  /* RFC 9146, DTLS 1.2 only */
    return_routability_check(TBD2), /* NEW */
    (255)
} ContentType;

uint64 Cookie;

enum {
    path_challenge(0),
    path_response(1),
    path_drop(2),
    (255)
} rrc_msg_type;

struct {
    rrc_msg_type msg_type;
    select (return_routability_check.msg_type) {
        case path_challenge: Cookie;
        case path_response:  Cookie;
        case path_drop:      Cookie;
    };
} return_routability_check;
~~~
{: #fig-rrc-msg align="left"
   title="Return Routability Check Message"}

Future extensions to the RRC sub-protocol may
define new message types.
Implementations MUST be able to parse and understand the three RRC message types defined in this document.
In addition, implementations MUST be able to parse and gracefully ignore messages with an unknown `msg_type`.

# Path Validation Procedure {#path-validation}

A receiver that observes the peer's address change MUST stop sending
any buffered application data, or limit the data sent to the unvalidated
address to the anti-amplification limit.
It then initiates the return routability check.

This document describes two kinds of checks: basic ({{regular}}) and enhanced ({{enhanced}}).
The choice of one or the other depends on whether the off-path attacker scenario described in {{off-path}} is to be considered.
(The decision on what strategy to choose depends mainly on the threat model, but
may also be influenced by other considerations.  Examples of impacting factors
include: the need to minimise implementation complexity, privacy concerns, and the
need to reduce the time it takes to switch path.  The choice may be offered as
a configuration option to the user of the TLS implementation.)

After the path validation procedure is completed, any pending send operation is
resumed to the bound peer address.

{{path-challenge-reqs}} and {{path-response-reqs}} list the requirements for
the initiator and responder roles, broken down per protocol phase.

Please note that the presented algorithms are not designed to handle nested rebindings, i.e. rebindings that may occur while a path is being validated following a previous rebinding.
If this happens (which should rarely occur), the `path_response` message is dropped, the address validation times out, and the address will not be updated.
A new path validation will start when new data is received.

## Basic {#regular}

The basic return routability check comprises the following steps:

1. The receiver (i.e., the initiator) creates a `return_routability_check` message of
   type `path_challenge` and places the unpredictable cookie into the message.
1. The message is sent to the observed new address and a timer T (see
   {{timer-choice}}) is started.
1. The peer (i.e., the responder) cryptographically verifies the received
   `return_routability_check` message of
   type `path_challenge` and responds by echoing the cookie value in a
   `return_routability_check` message of type `path_response`.
1. When the initiator receives the `return_routability_check`
   message  of type `path_response` and verifies that it contains the sent cookie, it updates the peer
   address binding.
1. If T expires the peer address binding is not updated.

## Enhanced {#enhanced}

The enhanced return routability check comprises the following steps:

1. The receiver (i.e., the initiator) creates a `return_routability_check` message of
   type `path_challenge` and places the unpredictable cookie into the message.
1. The message is sent to the previously valid address, which corresponds to the
   old path. Additionally, a timer T is started, see {{timer-choice}}.
1. If the path is still functional, the peer (i.e., the responder) cryptographically verifies the received
   `return_routability_check` message of
   type `path_challenge`.
   The action to be taken depends on whether the path through which the message was received remains the preferred one.
   - If the path through which the message was received is preferred,
   a `return_routability_check` message of type `path_response` MUST be returned.
   - If the path through which the message was received is no longer preferred,
   a `return_routability_check` message of type `path_drop` MUST be returned.  (Note that the responder must have initiated a voluntary path migration in order to know that this path is no longer the preferred one.)

   In either case, the peer echoes the cookie value in the response.
1. The initiator receives and verifies that the `return_routability_check`
   message contains the previously sent cookie. The actions taken by the
   initiator differ based on the received message:
   - When a `return_routability_check` message of type `path_response` was received,
   the initiator MUST continue using the previously valid address, i.e., no switch
   to the new path takes place and the peer address binding is not updated.
   - When a `return_routability_check` message of type `path_drop` was received,
   the initiator MUST perform a return routability check on the observed new
   address, as described in {{regular}}.
1. If T expires the peer address binding is not updated. In this case, the
   initiator MUST perform a return routability check on the observed new
   address, as described in {{regular}}.

## Path Challenge Requirements {#path-challenge-reqs}

* The initiator MAY send multiple `return_routability_check` messages of type
  `path_challenge` to cater for packet loss on the probed path.
  * Each `path_challenge` SHOULD go into different transport packets.  (Note that
    the DTLS implementation may not have control over the packetization done by
    the transport layer.)
  * The transmission of subsequent `path_challenge` messages SHOULD be paced to
    decrease the chance of loss.
  * Each `path_challenge` message MUST contain random data.
  * In general, the number of "backup" `path_challenge` messages depends on the application, since some are more sensitive to latency caused by changes in the path than others.
In the absence of application-specific requirements, the initiator can send a `path_challenge` message once per round-trip time (RTT), up to the anti-amplification limit.
* The initiator MAY use padding using the record padding mechanism available in
  DTLS 1.3 (and in DTLS 1.2, when CID is enabled on the sending direction) up
  to the anti-amplification limit to probe if the path MTU (PMTU) for the new
  path is still acceptable.

## Path Response/Drop Requirements {#path-response-reqs}

* The responder MUST NOT delay sending an elicited `path_response` or
  `path_drop` messages.
* The responder MUST send exactly one `path_response` or `path_drop` message
  for each valid `path_challenge` it received.
* The responder MUST send the `path_response` or the `path_drop` to the address from
  which the corresponding `path_challenge` was received.  This ensures that the
  path is functional in both directions.
* The initiator MUST silently discard any invalid `path_response` or
  `path_drop` it receives.

Note that RRC does not cater for PMTU discovery on the reverse path.  If the
responder wants to do PMTU discovery using RRC, it should initiate a new path
validation procedure.

## Timer Choice {#timer-choice}

When setting T, implementations are cautioned that the new path could have a
longer RTT than the original.

In settings where there is external information about the RTT of the active
path (i.e., the old path), implementations SHOULD use T = 3xRTT.

If an implementation has no way to obtain information regarding the RTT of the
active path, T SHOULD be set to 1s.

Profiles for specific deployment environments -- for example, constrained
networks {{?I-D.ietf-uta-tls13-iot-profile}} -- MAY specify a different, more
suitable value for T.

# Example

{{fig-handshake}} shows an example of a DTLS 1.3 handshake in which a client and a server successfully negotiate support for both the CID and RRC extensions.

~~~
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share
     | + signature_algorithms
     | + rrc
     v + connection_id=empty
                               -------->
                                                  ServerHello  ^ Key
                                                 +  key_share  | Exch
                                          + connection_id=100  |
                                                        + rrc  v
                                        {EncryptedExtensions}  ^  Server
                                         {CertificateRequest}  v  Params
                                                {Certificate}  ^
                                          {CertificateVerify}  | Auth
                               <--------           {Finished}  v

     ^ {Certificate}
Auth | {CertificateVerify}
     v {Finished}              -------->
       [Application Data]      <------->  [Application Data]

              +  Indicates noteworthy extensions sent in the
                 previously noted message.

              {} Indicates messages protected using keys
                 derived from a [sender]_handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from [sender]_application_traffic_secret_N.
~~~
{: #fig-handshake title="Message Flow for Full DTLS Handshake"}

Once a connection has been established, the client and the server
exchange application payloads protected by DTLS with a unilaterally used
CID. In this case, the client is requested to use CID 100 for records
sent to the server.

At some point in the communication interaction, the address used by
the client changes and, thanks to the CID usage, the security context to
interpret the record is successfully located by the server.  However, the
server wants to test the reachability of the client at its new address.

{{fig-rrc-example}} shows the server initiating a "basic" RRC exchange
(see {{regular}}) that establishes reachability of the client at the new
address.

~~~
      Client                                             Server
      ------                                             ------

      Application Data            ========>
      <CID=100>
      Src-IP=A
      Dst-IP=Z
                                  <========        Application Data
                                                       Src-IP=Z
                                                       Dst-IP=A

                              <<------------->>
                              <<   Some      >>
                              <<   Time      >>
                              <<   Later     >>
                              <<------------->>


      Application Data            ========>
      <CID=100>
      Src-IP=B
      Dst-IP=Z

                                             <<< Unverified IP
                                                 Address B >>

                                  <--------  Return Routability Check
                                             path_challenge(cookie)
                                                    Src-IP=Z
                                                    Dst-IP=B

      Return Routability Check    -------->
      path_response(cookie)
      Src-IP=B
      Dst-IP=Z

                                             <<< IP Address B
                                                 Verified >>


                                  <========        Application Data
                                                       Src-IP=Z
                                                       Dst-IP=B
~~~
{: #fig-rrc-example title='"Basic" Return Routability Example'}

# Operational Considerations

## Logging Anomalous Events

Logging of RRC operations at both ends of the protocol can be generally useful for the users of an implementation.
In particular, for security information and event management (SIEM) and troubleshooting purposes, it is strongly advised that implementations collect statistics about any unsuccessful RRC operations, as they could represent security-relevant events when they coincide with attempts by an attacker to interfere with the end-to-end path.
It is also advisable to log instances where multiple responses to a single `path_challenge` are received, as this could suggest an off-path attack attempt.

In some cases, the presence of frequent path probes could indicate a problem with the stability of the path.
This information can be used to identify any issues with the underlying connectivity service.

## Middlebox Interference

Since the DTLS 1.3 encrypted packet's record type is opaque to on-path observers, RRC messages are immune to middlebox interference when using DTLS 1.3.
In contrast, DTLS 1.2 RRC messages that are not wrapped in the `tls12_cid` record (e.g., in the server-to-client direction if the server negotiated a zero-length CID) have the `return_routability_check` content type in plain text, making them susceptible to interference (e.g., dropping of `path_challenge` messages), which would hinder the RRC functionality altogether.
Therefore, when using RRC in DTLS 1.2, it is recommended to enable CID in both directions.

# Security Considerations

Note that the return routability checks do not protect against flooding of
third-parties if the attacker is on-path, as the attacker can redirect the
return routability checks to the real peer (even if those datagrams are
cryptographically authenticated).  On-path adversaries can, in general, pose a
harm to connectivity.

If the RRC challenger reuses a cookie that was previously used in the same connection and does not implement anti-replay protection (see {{Section 4.5.1 of RFC9147}} and {{Section 4.1.2.6 of !RFC6347}}), an attacker could replay a previously sent `path_response` message containing the reused cookie to mislead the challenger into switching to a path of the attacker's choosing.
To prevent this, RRC cookies must be _freshly_ generated using a reliable source of entropy {{?RFC4086}}.
See {{Appendix C.1 of RFC8446}} for guidance.

## Attacker Model {#attacker}

Two classes of attackers are considered, off-path and on-path, with increasing
capabilities (see {{fig-attacker-capabilities}}) partly following terminology
introduced in QUIC ({{Section 21.1 of RFC9000}}):

* An off-path attacker is not on the original path between the DTLS peers, but
  is able to observe packets on the original path and has a faster forwarding path
  compared to the DTLS peers, which allows it to make copies of the observed
  packets, race its copies to either peer and consistently win the race.

* An on-path attacker is on the original path between the DTLS peers and is
  therefore capable, compared to the off-path attacker, to also drop and delay
  records at will.

Note that, in general, attackers cannot craft DTLS records in a way that would
successfully pass verification, due to the cryptographic protections applied by
the DTLS record layer.

~~~ aasvg
    .--> .------------------------------------. <--.
    |    | Inspect un-encrypted portions      |    |
    |    +------------------------------------+    |
    |    | Inject                             |    |
off-path +------------------------------------+    |
    |    | Reorder                            |    |
    |    +------------------------------------+    |
    |    | Modify un-authenticated portions   | on-path
    '--> +------------------------------------+    |
         | Delay                              |    |
         +------------------------------------+    |
         | Drop                               |    |
         +------------------------------------+    |
         | Manipulate the packetization layer |    |
         '------------------------------------' <--'
~~~
{: #fig-attacker-capabilities artwork-align="center"
   title="Attacker capabilities"}

RRC is designed to defend against the following attacks:

* On-path and off-path attackers that try to create an amplification attack by
  spoofing the source address of the victim ({{sec-amplification}}).

* Off-path attackers that try to put themselves on-path ({{off-path}}),
  provided that the enhanced path validation algorithm is used ({{enhanced}}).

### Amplification {#sec-amplification}

Both on-path and off-path attackers can send a packet (either by modifying it
on the fly, or by copying, injecting, and racing it, respectively) with the
source address modified to that of a victim host.  If the traffic generated by
the server in response is larger compared to the received packet (e.g., a CoAP
server returning an MTU's worth of data from a 20-bytes GET request {{?I-D.irtf-t2trg-amplification-attacks}}) the
attacker can use the server as a traffic amplifier toward the victim.

#### Mitigation Strategy

When receiving a packet with a known CID that has a source address different from the one currently associated with the DTLS connection, an
RRC-capable endpoint will not send a (potentially large) response but instead a
small `path_challenge` message to the victim host.  Since the host is not able
to decrypt it and generate a valid `path_response`, the address validation
fails, which in turn keeps the original address binding unaltered.

Note that in case of an off-path attacker, the original packet still reaches
the intended destination; therefore, an implementation could use a different
strategy to mitigate the attack.

### Off-Path Packet Forwarding {#off-path}

An off-path attacker that can observe packets might forward copies of
genuine packets to endpoints over a different path. If the copied packet arrives before
the genuine packet, this will appear as a path change, like in a genuine NAT rebinding occurrence. Any genuine
packet will be discarded as a duplicate. If the attacker is able to
continue forwarding packets, it might be able to cause migration to a
path via the attacker. This places the attacker on-path, giving it
the ability to observe or drop all subsequent packets.

This style of attack relies on the attacker using a path that has
the same or better characteristics (e.g., due to a more favourable service level agreements) as the direct path between
endpoints. The attack is more effective if relatively few packets are
sent or if packet loss coincides with the attempted attack.

A data packet received on the original path that increases the
maximum received packet number will cause the endpoint to move back
to that path. Therefore, eliciting packets on this path increases the
likelihood that the attack is unsuccessful. Note however that, unlike QUIC,
DTLS has no "non-probing" packets so this would require application specific
mechanisms.

#### Mitigation Strategy

{{fig-off-path}} illustrates the case where a receiver receives a
packet with a new source address. In order
to determine that this path change was not triggered
by an off-path attacker, the receiver will send an RRC message of type
`path_challenge` (1) on the old path.

~~~ aasvg
        new                  old
        path  .----------.  path
              |          |
        .-----+ Receiver +-----.
        |     |          |     |
        |     '----------'     |
        |                      |
        |                      |
        |                      |
   .----+------.               |
  / Attacker? /                |
 '------+----'                 |
        |                      |
        |                      |
        |                      |
        |     .----------.     |
        |     |          |     |
        '-----+  Sender  +-----'
              |          |
              '----------'
~~~~
{: #fig-off-path artwork-align="center"
   title="Off-Path Packet Forwarding Scenario"}

Three cases need to be considered:

Case 1: The old path is dead (e.g., due to a NAT rebinding), which leads to a
timeout of (1).

As shown in {{fig-old-path-dead}}, a `path_challenge` (2) needs to be sent on
the new path.  If the sender replies with a `path_response` on the new path
(3), the switch to the new path is considered legitimate.

~~~ aasvg

          new                      old
          path    .----------.    path
          .------>|          +-------.
          | .-----+ Receiver +...... |
          | | .---+          |     . |
          | | |   '----------'     . |
 path-    3 | |                    . 1 path-
 response | | |                    . | challenge
          | | |                    . |
       .--|-+-|----------------------v--.
      /   |   |       NAT            X / timeout
     '----|-+-|-----------------------'
          | | |                    .
          | | 2 path-              .
          | | | challenge          .
          | | |   .----------.     .
          | | '-->|          |     .
          | '-----+  Sender  +.....'
          '-------+          |
                  '----------'
~~~~
{: #fig-old-path-dead artwork-align="center"
   title="Old path is dead"}

Case 2: The old path is alive but not preferred.

This case is shown in {{fig-old-path-not-preferred}} whereby the sender
replies with a `path_drop` message (2) on the old path.  This triggers
the receiver to send a `path_challenge` (3) on the new path. The sender
will reply with a `path_response` (4) on the new path, thus providing
confirmation for the path migration.

~~~ aasvg
            new                      old
            path    .----------.    path
            .------>|          |<------.
            | .-----+ Receiver +-----. |
            | | .---+          +---. | |
            | | |   '----------'   | | |
   path-    4 | |        path-     1 | |
   response | | |        challenge | | |
            | | |                  | | |
  .---------|-+-|----.          .--|-+-|-----------.
 / AP/NAT A |   |   /          /   |   | AP/NAT B /
'-----------|---|--'          '----|-+-|---------'
            | | |                  | | |
            | | 3 path-            | | 2 path-
            | | | challenge        | | | drop
            | | |   .----------.   | | |
            | | '-->|          |<--' | |
            | '-----+  Sender  +-----' |
            '-------+          +-------'
                    '----------'
~~~
{: #fig-old-path-not-preferred artwork-align="center"
   title="Old path is not preferred"}

Case 3: The old path is alive and preferred.

This is most likely the result of an off-path attacker trying to place itself
on path.  The receiver sends a `path_challenge` on the old path and the sender
replies with a `path_response` (2) on the old path. The interaction is shown in
{{fig-old-path-preferred}}. This results in the connection not being migrated
to the new path, thus thwarting the attack.

~~~ aasvg
        new                    old
        path  .----------.    path
              |          +-------.
        .-----+ Receiver +-----. |
        |     |          |<--. | |
        |     '----------'   | | |
        |                    | | 1 path-
        |                    | | | challenge
        |                    | | |
    .---+------.          .--|-+-|-----.
   / off-path /          / AP| / |NAT /
  / attacker /          '----|-+-|---'
 '------+---'                | | |
        |                    | | |
        |           path-    2 | |
        |           response | | |
        |     .----------.   | | |
        |     |          +---' | |
        '-----+  Sender  +-----' |
              |          |<------'
              '----------'
~~~
{: #fig-old-path-preferred artwork-align="center"
   title="Old path is preferred"}

Note that this defense is imperfect, but this is not considered a serious
problem. If the path via the attacker is reliably faster than the
old path despite multiple attempts to use that old path, it
is not possible to distinguish between an attack and an improvement
in routing.

An endpoint could also use heuristics to improve detection of this
style of attack. For instance, NAT rebinding is improbable if
packets were recently received on the old path.
Endpoints can also look for duplicated
packets. Conversely, a change in connection ID is more likely to
indicate an intentional migration rather than an attack. Note that
changes in connection IDs are supported in DTLS 1.3 but not in
DTLS 1.2.

# Privacy Considerations

When using DTLS 1.3, peers SHOULD avoid using the same CID on multiple network
paths, in particular when initiating connection migration or when probing a new
network path, as described in {{path-validation}}, as an adversary can otherwise
correlate the communication interaction across those different paths.  DTLS 1.3
provides mechanisms to ensure that a new CID can always be used.  In
general, an endpoint should proactively send a RequestConnectionId message to ask for new
CIDs as soon as the pool of spare CIDs is depleted (or goes below a threshold).
Also, in case a peer might have exhausted available CIDs, a migrating endpoint
could include NewConnectionId in packets sent on the new path to make sure that
the subsequent path validation can use fresh CIDs.

Note that DTLS 1.2 does not offer the ability to request new CIDs during the session lifetime since CIDs have the same life-span
of the connection.  Therefore, deployments that use DTLS in multihoming
environments SHOULD refuse to use CIDs with DTLS 1.2
and switch to DTLS 1.3 if the correlation privacy threat is a concern.

# IANA Considerations

[^to-be-removed]

## New TLS ContentType

IANA is requested to allocate an entry in the TLS `ContentType` registry within the "Transport Layer Security (TLS) Parameters" registry group {{!IANA.tls-parameters}} for the `return_routability_check(TBD2)` message defined in this document.
IANA is requested to set the `DTLS_OK` column to `Y` and to add the following note prior to the table:

> NOTE: The return_routability_check content type is only
> applicable to DTLS 1.2 and 1.3.

## New TLS ExtensionType

IANA is requested to allocate the extension code point (TBD1) for the `rrc`
extension to the `TLS ExtensionType Values` registry as described in
{{tbl-ext}}.

| Value | Extension Name | TLS 1.3 | DTLS-Only  | Recommended  | Reference | Comment |
| ----- | -------------- | ------- | ---------- | ------------ | --------- | ------- |
| TBD1  | rrc            | CH, SH  | Y          | N            | {{&SELF}} |         |
{: #tbl-ext align="left"
   title="rrc entry in the TLS ExtensionType Values registry" }

## New "RRC Message Type" Registry

IANA is requested to create a new registry "RRC Message Types" within the Transport Layer Security (TLS) Parameters registry group {{!IANA.tls-parameters}}.
This registry will be administered under the "Expert Review" policy ({{Section 4.5 of !RFC8126}}).

Follow the procedures in {{Section 16 of !I-D.ietf-tls-rfc8447bis}} to submit registration requests.

Each entry in the registry must include the following fields:

{:vspace}
Value:
: A (decimal) number in the range 0 to 253

Description:
: A brief description of the RRC message

DTLS-Only:
: Whether the message applies only to DTLS.
Since RRC is only available in DTLS, this column will be set to `Y` for all the current entries in this registry.
Future work may define new RRC Message Types that also apply to TLS.

Recommended:
: Whether the message is recommended for implementations to support.
The semantics for this field is defined in {{Section 5 of !RFC8447}} and updated in {{Section 3 of !I-D.ietf-tls-rfc8447bis}}

Reference:
: A reference to a publicly available specification for the value

Comment:
: Any relevant notes or comments that relate to this entry

The initial state of this sub-registry is as follows:

| Value | Description    | DTLS-Only | Recommended |  Reference | Comment |
|-------|----------------|-----------|-------------|------------|---------|
| 0     | path_challenge | Y         | Y           | {{&SELF}}  |         |
| 1     | path_response  | Y         | Y           | {{&SELF}}  |         |
| 2     | path_drop      | Y         | Y           | {{&SELF}}  |         |
| 3-253 | Unassigned     |           |             |            |         |
| 254-255 | Reserved for Private Use | Y | | {{&SELF}} | |
{: #tbl-rrc-mt align="left"
   title="Initial Entries in RRC Message Type registry" }

IANA is requested to add the following note for additional information regarding the use of RRC message codepoints in experiments:

Note:
: As specified in {{!RFC8126}}, assignments made in the Private Use space are not generally useful for broad interoperability.
Those making use of the Private Use range are responsible for ensuring that no conflicts occur within the intended scope of use.
For widespread experiments, provisional registrations ({{Section 4.13 of !RFC8126}}) are available.

### Designated Expert Instructions

To enable a broadly informed review of registration decisions, it is recommended that multiple Designated Experts be appointed who are able to represent the perspectives of both the transport and security areas.

In cases where a registration decision could be perceived as creating a conflict of interest for a particular Expert, that Expert SHOULD defer to the judgment of the other Experts.

# Acknowledgments

We would like to thank
Colin Perkins,
Eric Rescorla,
Hanno Becker,
{{{Hanno Böck}}},
Joe Clarke,
{{{Manuel Pégourié-Gonnard}}},
Marco Tiloca,
Martin Thomson,
Mike Bishop,
Mike Ounsworth,
Mohit Sahni,
Rich Salz,
Russ Housley,
Sean Turner, and
Yaron Sheffer
for their input to this document.

--- back

[^rfced-remove]: RFC Editor: please remove this section before publishing as an RFC.
[^to-be-removed]: RFC Editor: please replace {{&SELF}} with this RFC number and remove this note.
