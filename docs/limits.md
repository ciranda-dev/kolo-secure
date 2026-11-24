# Limits

Every option, default and bound of kolo-secure, with the reason for it. A value out of range returns `ErrInvalidConfig`.

## Config

`Config` (nil or a zero field means the default; out of range is
`ErrInvalidConfig`):

| Option | Default | Range | Why |
|---|---|---|---|
| `Transport` (passed to kolo-transport) | nil (its defaults) | see kolo-transport | Passed through unchanged, so `WindowGrowth` and its options work as kolo-transport documents them; `Conn.AllowWindowGrowth` marks a connection you trust. |
| `HandshakeTimeout` (kolo-secure handshake, after the QUIC handshake) | 10s | 1s to 60s | Security: it bounds how long a peer that finished QUIC can hold a `MaxPending` slot without authenticating. |
| `MaxPending` (per listener: handshaking or waiting for `Accept`) | 64, or the transport `MaxConns` if lower | 1 to the transport `MaxConns` (100 by default) | Memory and security: it limits what peers that finish QUIC and then stall, or an application that stops calling `Accept`, can hold. kolo-transport `MaxConns` also counts these connections, so a larger value would never be reached; `Listen` and `NewListener` return `ErrInvalidConfig` for it. There is no other maximum: raise the transport `MaxConns` (and `MaxMemory`) with it. |
| handshake message size | 256 bytes | fixed | Memory: every kolo-secure message has a fixed size of at most 98 bytes (`TestWireFormat`), so a larger cap would only let a peer make the reader allocate more before the message is rejected. |

When `MaxPending` connections are pending, the listener closes each new
one at once with code 1, so its dialer fails fast with
`kolotransport.ErrPeerClosed` instead of waiting for a timeout. A slot is
held until the handshake fails or `Accept` takes the connection, so an
application that stops calling `Accept` makes the listener refuse
everyone. A peer that completes the QUIC handshake and then sends nothing
holds a slot for `HandshakeTimeout`; kolo-transport limits one source
address to `MaxConnsPerIP` connections (4 by default), so it takes about
`MaxPending / MaxConnsPerIP` addresses (16 at the defaults) to fill the
listener, and redialing keeps it full. Raise `MaxPending` or lower
`MaxConnsPerIP` and `HandshakeTimeout` if that matters.

