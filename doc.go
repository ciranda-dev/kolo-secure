// Package kolosecure authenticates a kolo-transport connection with the
// kolo-id identities of both peers.
//
// After the QUIC handshake, each side signs the connection's TLS exporter
// value (RFC 9846 section 7.5), its role and both public keys with its
// kolo-id key, and checks the peer's signature. A connection is returned
// only once the peer has proved it holds its key on this very connection,
// so a proof cannot be replayed on another connection, reflected, or
// relayed by a man in the middle.
//
// Experimental: the API may change before v1.0.0.
package kolosecure
