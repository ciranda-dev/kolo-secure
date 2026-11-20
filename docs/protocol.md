# Protocol and design

## Design

- Channel binding over the TLS 1.3 session kolo-transport already has, in
  the style of RFC 9266 `tls-exporter`, RFC 8471 Token Binding and RFC
  9261 Exported Authenticators: each side signs a value exported from the
  TLS session (RFC 9846 section 7.5, with RFC 5705 labels). TLS 1.3 gives
  the encryption and forward secrecy; kolo-secure adds only who the peer
  is.
- The exporter derives from `exporter_secret`, which covers the
  TLS transcript up to the server Finished: both key shares, both randoms,
  the ephemeral certificate and the ALPN. Two TLS sessions spliced by a
  relay give two unrelated values, so a proof made on one is worthless on
  the other.
- Each signature covers the protocol version, the signer's role (dialer
  or listener), the exporter value and both public keys, under the
  Ed25519ctx (RFC 8032) context `kolo-secure/proof/v0`. The listener
  proof and the dialer finish share that context; the signed role
  separates them, and tests fail if the role stops changing the signed
  bytes. A proof does not
  verify on another connection (replay), for the other role (reflection),
  or for another pair of peers (unknown key share). A peer that presents
  our own key is rejected.
- Keys are compared by exact bytes. Go's Ed25519 verification is
  cofactorless, so the holder of a key can also prove up to 7 other
  public keys, its own plus a small-order point; that is not
  impersonation of anyone else, but a key must be matched byte for byte
  against keys learned out of band, never by a looser equality.
- Version 0 accepts only version 0; there is no negotiation to downgrade,
  and the version is signed.
- Go's `crypto/ed25519` accepts a signature made without any private
  key for a small-order public key: for the identity point
  `01 00 .. 00`, `R = 01 00 .. 00` and `S = 0` verify for every message.
  kolo-id `Verify` rejects these keys, and kolo-secure also rejects
  the 14 encodings that Go decodes to one of the 8 small-order points, by
  comparing bytes, before it verifies anything. The list was derived with
  an independent Edwards25519 implementation (not a dependency), and a
  test forges a signature for each entry with `crypto/ed25519` and
  checks that kolo-id `Verify` refuses every entry too, so the two rules
  cannot drift unnoticed.
- Why not a second key exchange inside QUIC: it would need either double
  encryption and a record layer of its own on top of QUIC streams, or
  keys that are thrown away. The cases where it would help (hiding the
  dialer from an active prober, running without QUIC) are not needed
  here. Why not a signed certificate extension or raw public
  keys: both need control of the TLS certificates,
  which kolo-transport keeps ephemeral, and Go's `crypto/tls` has no RFC
  7250 support.
- `NewListener` and `(*Listener).Dial` let one UDP socket carry
  incoming and outgoing secure connections and other datagrams, which
  hole punching needs (the peer sees the same address it was told), and
  let kolo-transport run over any `net.PacketConn`, such as a relayed
  one.
- Only the handshake is bounded here; everything after it is a plain
  kolo-transport connection with its limits. Handshake messages are read
  with a length of at most two bytes and a body of at most 256 bytes, so
  a peer cannot make the reader allocate more.
- Bytes the peer sent before its proof was checked, on other streams,
  reach the application only after `Dial` or `Accept` returns, and then
  belong to the authenticated peer: only the TLS endpoint can send on the
  connection.
- What it does not do: it adds no forward secrecy or rekeying beyond TLS
  1.3; a stolen kolo-id key lets the thief impersonate that node on new
  connections. The dialer sends its key first, to whoever answered the
  TLS handshake, so an active prober learns it, and learns the listener's
  key by connecting; passive observers see neither. Addresses, timing and
  sizes are visible. Any valid key authenticates: deciding whether to
  trust it is up to the application. Each handshake costs one Ed25519
  signature and one verification.

## Formats

Exporter: label `EXPERIMENTAL-kolo-secure/channel-binding/v0` (the RFC
5705 private-use prefix), no context, 32 bytes.

Signed message, in [kolo-codec](https://github.com/ciranda-dev/kolo-codec)
encoding, signed with Ed25519ctx under the context `kolo-secure/proof/v0`:

    uvarint(version 0) ‖ uvarint(role: 1 dialer, 2 listener) ‖ exporter (32) ‖ dialer key (32) ‖ listener key (32)

Messages travel on the first bidirectional stream the dialer opens, each
as `uvarint(length) ‖ body` with a length from 1 to 256:

| # | Direction | Body |
|---|---|---|
| 1 | dialer to listener | `uvarint(1) ‖ uvarint(version 0) ‖ dialer key (32)` |
| 2 | listener to dialer | `uvarint(2) ‖ uvarint(version 0) ‖ listener key (32) ‖ signature (64)`, then the end of the stream |
| 3 | dialer to listener | `uvarint(3) ‖ signature (64)`, then the end of the stream |

There is no JSON form.

## References

- [RFC 9846, The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/info/rfc9846), section 7.5, Exporters (Proposed Standard, July 2026; obsoletes RFC 8446).
  Takes: the TLS exporter value that each side signs.
- [RFC 5705, Keying Material Exporters for TLS](https://www.rfc-editor.org/info/rfc5705) (Proposed Standard, March 2010).
  Takes: exporter labels.
- [RFC 9266, Channel Bindings for TLS 1.3](https://www.rfc-editor.org/info/rfc9266) (Proposed Standard, July 2022).
  Takes: the idea of the tls-exporter channel binding.
  Not implemented: the channel binding type as other protocols use it.
- [RFC 8471, The Token Binding Protocol Version 1.0](https://www.rfc-editor.org/info/rfc8471) (Proposed Standard, October 2018).
  Takes: the idea of signing exported keying material.
  Not implemented: its messages.
- [RFC 9261, Exported Authenticators in TLS](https://www.rfc-editor.org/info/rfc9261) (Proposed Standard, July 2022).
  Takes: the idea of signing exported keying material.
  Not implemented: its messages.
- [RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/info/rfc8032) (Informational, January 2017).
  Takes: Ed25519ctx with the context `kolo-secure/proof/v0`.
- [RFC 8827, WebRTC Security Architecture](https://www.rfc-editor.org/info/rfc8827) (Proposed Standard, January 2021).
  Takes: listed for the threat model.
