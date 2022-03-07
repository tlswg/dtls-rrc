---
title: Return Routability Check for DTLS 1.2 and DTLS 1.3
abbrev: DTLS Return Routability Check
docname: draft-ietf-tls-dtls-rrc-latest
category: std
updates: 6347

ipr: pre5378Trust200902
area: Security
workgroup: TLS
keyword: Internet-Draft

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
  text-list-symbols: -o*+
  docmapping: yes
author:
 -
       ins: H. Tschofenig
       name: Hannes Tschofenig
       organization: Arm Limited
       role: editor
       email: hannes.tschofenig@arm.com
 -
       ins: T. Fossati
       name: Thomas Fossati
       organization: Arm Limited
       email: thomas.fossati@arm.com

--- abstract

This document specifies a return routability check for use in context of the
Connection ID (CID) construct for the Datagram Transport Layer Security (DTLS)
protocol versions 1.2 and 1.3.

--- middle

# Introduction

In "classical" DTLS, selecting a security context of an incoming DTLS record is
accomplished with the help of the 5-tuple, i.e. source IP address, source port,
transport protocol, destination IP address, and destination port.  Changes to
this 5 tuple can happen for a variety reasons over the lifetime of the DTLS
session.  In the IoT context, NAT rebinding is common with sleepy devices.
Other examples include end host mobility and multi-homing.  Without CID, if the
source IP address and/or source port changes during the lifetime of an ongoing
DTLS session then the receiver will be unable to locate the correct security
context.  As a result, the DTLS handshake has to be re-run.  Of course, it is
not necessary to re-run the full handshake if session resumption is supported
and negotiated.

A CID is an identifier carried in the record layer header of a DTLS datagram
that gives the receiver additional information for selecting the appropriate
security context.  The CID mechanism has been specified in
{{!I-D.ietf-tls-dtls-connection-id}} for DTLS 1.2 and in
{{!I-D.ietf-tls-dtls13}} for DTLS 1.3.

Section 6 of {{!I-D.ietf-tls-dtls-connection-id}} describes how the use of CID
increases the attack surface by providing both on-path and off-path attackers
an opportunity for (D)DoS.  It then goes on describing the steps a DTLS
principal must take when a record with a CID is received that has a source
address (and/or port) different from the one currently associated with the DTLS
connection.  However, the actual mechanism for ensuring that the new peer
address is willing to receive and process DTLS records is left open.  This
document standardizes a return routability check (RRC) as part of the DTLS
protocol itself.

The return routability check is performed by the receiving peer before the
CID-to-IP address/port binding is updated in that peer's session state
database.  This is done in order to provide more confidence to the receiving
peer that the sending peer is reachable at the indicated address and port.

Note however that, irrespective of CID, if RRC has been successfully negotiated
by the peers, path validation can be used at any time by either endpoint. For
instance, an endpoint might use RRC to check that a peer is still in possession
of its address after a period of quiescence.

# Conventions and Terminology

{::boilerplate bcp14}

This document assumes familiarity with the CID format and protocol defined for
DTLS 1.2 {{!I-D.ietf-tls-dtls-connection-id}} and for DTLS 1.3
{{!I-D.ietf-tls-dtls13}}.  The presentation language used in this document is
described in Section 4 of {{!RFC8446}}.

This document reuses the definition of "anti-amplification limit" from
{{?RFC9000}} to mean three times the amount of data received from an
unvalidated address.  This includes all DTLS records originating from that
source address, excluding discarded ones.

# RRC Extension

The use of RRC is negotiated via the `rrc` DTLS-only extension.  On connecting,
the client includes the `rrc` extension in its ClientHello if it wishes to use
RRC.  If the server is capable of meeting this requirement, it responds with a
`rrc` extension in its ServerHello.  The `extension_type` value for this
extension is TBD1 and the `extension_data` field of this extension is empty.
The client and server MUST NOT use RRC unless both sides have successfully
exchanged `rrc` extensions.

Note that the RRC extension applies to both DTLS 1.2 and DTLS 1.3.

# The Return Routability Check Message

When a record with CID is received that has the source address of the enclosing
UDP datagram different from the one previously associated with that CID, the
receiver MUST NOT update its view of the peer's IP address and port number with
the source specified in the UDP datagram before cryptographically validating
the enclosed record(s) but instead perform a return routability check.

~~~~
enum {
    invalid(0),
    change_cipher_spec(20),
    alert(21),
    handshake(22),
    application_data(23),
    heartbeat(24),  /* RFC 6520 */
    return_routability_check(TBD2), /* NEW */
    (255)
} ContentType;

uint64 Cookie;

enum {
    path_challenge(0),
    path_response(1),
    path_delete(2),
    reserved(2..255)
} rrc_msg_type;

struct {
    rrc_msg_type msg_type;
    select (return_routability_check.msg_type) {
        case path_challenge: Cookie;
        case path_response:  Cookie;
        case path_delete:  Cookie;
    };
} return_routability_check;
~~~~

The cookie is a 8-byte field containing arbitrary data.

The `return_routability_check` message MUST be authenticated and encrypted using
the currently active security context.

# Off-Path Packet Forwarding {#off-path}

An off-path attacker that can observe packets might forward copies of
genuine packets to endpoints. If the copied packet arrives before
the genuine packet, this will appear as a NAT rebinding. Any genuine
packet will be discarded as a duplicate. If the attacker is able to
continue forwarding packets, it might be able to cause migration to a
path via the attacker. This places the attacker on-path, giving it
the ability to observe or drop all subsequent packets.

This style of attack relies on the attacker using a path that has
approximately the same characteristics as the direct path between
endpoints. The attack is more reliable if relatively few packets are
sent or if packet loss coincides with the attempted attack.

A data packet received on the original path that increases the
maximum received packet number will cause the endpoint to move back
to that path. Eliciting packets on this path increases the
likelihood that the attack is unsuccessful.

{{fig-off-path}} demonstrates the case where a receiver receives a
packet with a new source IP address and/or new port number. The
receiver needs to determine whether this path change is caused
by an attacker and will send a RRC message of type path_challenge (RRC-1)
on the old path. 

~~~~
        new   +--------+  old
        path  |        |  path
       +----->|Receiver|<-----+
       |      |        |      |
       |      +--------+      |
       |                      |
       |                      |
       |                      |
       |                      |
       |                      |
 +----------+                 |
 | Attacker?|                 |
 +----------+                 |
       |                      |
       |                      |
       |                      |
       |      +--------+      |
       |      |        |      |
       +------| Sender |------+
              |        |
              +--------+
~~~~
{: #fig-off-path title="Off-Path Packet Forwarding Scenario"}

Three cases need to be considered:

Case 1: The old path is dead, which leads to a timeout of RRC-1. 

As shown in {{fig-old-path-dead}}, a RRC message of type 
path_challenge (RRC-2) needs to be sent on the new path. In this
situation the switch to the new path is considered legitimate.
The sender will reply with RRC-3 containing a path_response on
the new path.

~~~~
   ...................>+--------+
   .           ********|        |********
   .           *+----->|Receiver|<-----+*
   .           *| new  |        | old  |*
   .     RRC-2 *| path +--------+ path |* RRC-1
   .      with *|                      |* with
   .     path- *|                      |* path-
   . challenge *|                      |* challenge
   .           *|                      |*
   .           *|                      |*
   .      +----------+                 |*
   .      | Attacker |                 |*
   .      +----------+                 |*
   .           *|                      |v
   .           *|                      |timeout
   .           *|                      |
   .RRC-3      *|      +--------+      |
   .with       *|      |        |      |
   .path-      *+------| Sender |------+
   .response   *******>|        |
   ....................+--------+
~~~~
{: #fig-old-path-dead title="Old path is dead"}

Case 2: The old path is alive but not preferred. 

This case is shown in {{fig-old-path-not-preferred}} whereby the
sender replies with a RRC-2 path_delete message on the old path.
This triggers the receiver to send RRC-3 with a path-challenge
along the new path. The sender will reply with RRC-4 containing
a path_response along the new path.

~~~~
  ...................>+--------+<....................
  .           ********|        |********            .
  .           *+----->|Receiver|<-----+*            .
  .           *| new  |        | old  |*            .
  .     RRC-3 *| path +--------+ path |* RRC-1      .
  .      with *|                      |* with       .
  .     path- *|                      |* path-      .
  . challenge *|                      |* challenge  .
  .           *|                      |*            .
  .           *|                      |*            .
  .      +----------+                 |*            .
  .      | Attacker |                 |*            .
  .      +----------+                 |*            .
  .           *|                      |*            .
  .           *|                      |*            .
  .           *|                      |*            .
  .RRC-4      *|      +--------+      |*       RRC-2.
  .with       *|      |        |      |*        with.
  .path-      *+------| Sender |------+*       path-.
  .response   *******>|        |<*******      delete.
  ....................+--------+.....................
~~~~
{: #fig-old-path-not-preferred title="Old path is not preferred"}

Case 3: The old path is alive and preferred. 

This is most likely the result of an attacker. The sender replies 
with RRC-2 containing a path_response along the old path. The
interaction is shown in {{fig-old-path-preferred}}. This results
in the connection being migrated back to the old path.

~~~~
               +--------+<....................
               |        |********            .
        +----->|Receiver|<-----+*            .
        | new  |        | old  |*            .
        | path +--------+ path |* RRC-1      .
        |                      |* with       .
        |                      |* path-      .
        |                      |* challenge  .
        |                      |*            .
        |                      |*            .
  +----------+                 |*            .
  | Attacker |                 |*            .
  +----------+                 |*            .
        |                      |*            .
        |                      |*            .
        |                      |*            .
        |      +--------+      |*       RRC-2.
        |      |        |      |*        with.
        +------| Sender |------+*       path-.
               |        |<*******    response.
               +--------+.....................
~~~~
{: #fig-old-path-preferred title="Old path is preferred"}

Note that this defense is imperfect, but this is not considered a serious
problem. If the path via the attack is reliably faster than the
old path despite multiple attempts to use that old path, it
is not possible to distinguish between an attack and an improvement
in routing.

An endpoint could also use heuristics to improve detection of this
style of attack. For instance, NAT rebinding is improbable if
packets were recently received on the old path; similarly, rebinding
is rare on IPv6 paths. Endpoints can also look for duplicated
packets. Conversely, a change in connection ID is more likely to
indicate an intentional migration rather than an attack. Note, however,
changes in connection IDs are only supported in DTLS 1.3 but not in
DTLS 1.2.

# Path Validation Procedure

Note: This algorithm does not take the {{off-path}} scenario into account.

The receiver that observes the peer's address or port update MUST stop sending
any buffered application data (or limit the data sent to the unvalidated
address to the anti-amplification limit) and initiate the return routability
check that proceeds as follows:

1. An unpredictable cookie is placed in a `return_routability_check` message of
   type path_challenge;
1. The message is sent to the observed new address and a timer T (see
   {{timer-choice}}) is started;
1. The peer endpoint, after successfully verifying the received
   `return_routability_check` message responds by echoing the cookie value in a
   `return_routability_check` message of type path_response;
1. When the initiator receives and verifies the `return_routability_check`
   message contains the sent cookie, it updates the peer address binding;
1. If T expires, or the address confirmation fails, the peer address binding is
   not updated.

After this point, any pending send operation is resumed to the bound peer
address.

{{path-challenge-reqs}} and {{path-response-reqs}} contain the requirements for
the initiator and responder roles, broken down per protocol phase.

# Enhanced Path Validation Procedure

Note: This algorithm also takes the {{off-path}} scenario into account.

The receiver that observes the peer's address or port update MUST stop sending
any buffered application data (or limit the data sent to the unvalidated
address to the anti-amplification limit) and initiate the return routability
check that proceeds as follows:

1. An unpredictable cookie is placed in a `return_routability_check` message of
   type path_challenge;
1. The message is sent to the previously valid address and a timer T (see
   {{timer-choice}}) is started;
1. The peer endpoint, after successfully verifying the received
   `return_routability_check` message responds by echoing the cookie value in a
   `return_routability_check` message of type path_response if the path through
   which the message was received is preferred. If the path is not preferred,
   a `return_routability_check` message of type path_delete MUST be returned;
1. When the initiator receives and verifies that the `return_routability_check`
   message contains the sent cookie, it updates the peer address binding;
1. If T expires, or the address confirmation fails, the peer address binding is
   not updated. In this case, a new `return_routability_check` message of type
   path_challenge MUST be sent to the observed new address containing a new
   cookie value. A timer is started and step (3) from above is applied.

After this point, any pending send operation is resumed to the bound peer
address.

{{path-challenge-reqs}} and {{path-response-reqs}} contain the requirements for
the initiator and responder roles, broken down per protocol phase.


## Path Challenge Requirements {#path-challenge-reqs}

* The initiator MAY send multiple `return_routability_check` messages of type
  path_challenge to cater for packet loss on the probed path.
  * Each path_challenge SHOULD go into different transport packets.  (Note that
    the DTLS implementation may not have control over the packetization done by
    the transport layer.)
  * The transmission of subsequent path_challenge messages SHOULD be paced to
    decrease the chance of loss.
  * Each path_challenge message MUST contain random data.
* The initiator MAY use padding using the record padding mechanism available in
  DTLS 1.3 (and in DTLS 1.2, when CID is enabled on the sending direction) up
  to the anti-amplification limit to probe if the path MTU (PMTU) for the new
  path is still acceptable.

## Path Response Requirements {#path-response-reqs}

* The responder MUST NOT delay sending an elicited path_response or
  path_delete messages.
* The responder MUST send exactly one path_response or path_delete message 
  for each received path_challenge.
* The responder MUST send the path_response or the  path_delete on the path 
  where the corresponding path_challenge has been received, so that validation
  succeeds only if the path is functional in both directions. The initiator
  MUST NOT enforce this behaviour.
* The initiator MUST silently discard any invalid path_response it receives.

Note that RRC does not cater for PMTU discovery on the reverse path.  If the
responder wants to do PMTU discovery using RRC, it should initiate a new path
validation procedure.

## Timer Choice {#timer-choice}

When setting T, implementations are cautioned that the new path could have a
longer round-trip time (RTT) than the original.

In settings where there is external information about the RTT of the active
path, implementations SHOULD use T = 3xRTT.

If an implementation has no way to obtain information regarding the RTT of the
active path, a value of 1s SHOULD be used.

Profiles for specific deployment environments -- for example, constrained
networks {{?I-D.ietf-uta-tls13-iot-profile}} -- MAY specify a different, more
suitable value.

# Example

The example TLS 1.3 handshake shown in {{fig-handshake}} shows a client
and a server negotiating the support for CID and for the RRC extension.

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

              *  Indicates optional or situation-dependent
                 messages/extensions that are not always sent.

              {} Indicates messages protected using keys
                 derived from a [sender]_handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from [sender]_application_traffic_secret_N.
~~~
{: #fig-handshake title="Message Flow for Full TLS Handshake"}

Once a connection has been established the client and the server
exchange application payloads protected by DTLS with an unilaterally used
CIDs. In our case, the client is requested to use CID 100 for records
sent to the server.

At some point in the communication interaction the IP address used by
the client changes and, thanks to the CID usage, the security context to
interpret the record is successfully located by the server.  However, the
server wants to test the reachability of the client at his new IP address.

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
{: #fig-rrc-example title="Return Routability Example"}

# Security and Privacy Considerations

Note that the return routability checks do not protect against flooding of
third-parties if the attacker is on-path, as the attacker can redirect the
return routability checks to the real peer (even if those datagrams are
cryptographically authenticated).  On-path adversaries can, in general, pose a
harm to connectivity.

# IANA Considerations

IANA is requested to allocate an entry to the TLS `ContentType`
registry, for the `return_routability_check(TBD2)` message defined in
this document. The `return_routability_check` content type is only
applicable to DTLS 1.2 and 1.3.

IANA is requested to allocate the extension code point (TBD1) for the `rrc`
extension to the `TLS ExtensionType Values` registry as described in
{{tbl-ext}}.

| Value | Extension Name | TLS 1.3 | DTLS-Only | Recommended | Reference |
|--------------------------------------------------------------------------|
| TBD1  | rrc            | CH, SH  | Y          | N            | RFC-THIS  |
{: #tbl-ext title="rrc entry in the TLS ExtensionType Values registry" }

# Open Issues

Issues against this document are tracked at https://github.com/tlswg/dtls-rrc/issues

# Acknowledgments

We would like to thank
Achim Kraus,
Hanno Becker,
Hanno Böck,
Manuel Pegourie-Gonnard,
Mohit Sahni and
Rich Salz
for their input to this document.

--- back

# History

<cref>RFC EDITOR: PLEASE REMOVE THIS SECTION</cref>

draft-ietf-tls-dtls-rrc-05

   - Added text about off-path packet forwarding

draft-ietf-tls-dtls-rrc-04

   -  Re-submitted draft to fix references

draft-ietf-tls-dtls-rrc-03

   -  Added details for challenge-response exchange

draft-ietf-tls-dtls-rrc-02

   - Undo the TLS flags extension for negotiating RRC, use a new extension type

draft-ietf-tls-dtls-rrc-01

   - Use the TLS flags extension for negotiating RRC
   - Enhanced IANA consideration section
   - Expanded example section
   - Revamp message layout:
     - Use 8-byte fixed size cookies
     - Explicitly separate path challenge from response

draft-ietf-tls-dtls-rrc-00

   - Draft name changed after WG adoption

draft-tschofenig-tls-dtls-rrc-01

   - Removed text that overlapped with draft-ietf-tls-dtls-connection-id

draft-tschofenig-tls-dtls-rrc-00

   - Initial version
