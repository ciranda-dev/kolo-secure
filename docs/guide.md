# Guide

How to use kolo-secure beyond the README quick start. Every default and bound is in [limits.md](limits.md); the design and the wire format are in [protocol.md](protocol.md).

A real node loads its identity with `koloid.Load` and learns the key of
the peer it dials from wherever it learned the address.

## API

From v0.1.1, kolo-secure is IPv4 only and IPv6 input, the v4-mapped
form included, is refused.

- `Listen(ctx, addr, id, cfg) (*Listener, error)` opens a kolo-transport
  listener on `addr` and authenticates every connection as `id`. An
  address kolo-transport refuses, such as an IPv6 host, is
  `ErrInvalidArgument` of both packages.
  `(*Listener).Accept(ctx)` returns the next connection whose dialer has
  proved its key; connections whose handshake fails are closed and never
  returned, so `Accept` itself fails only with `ErrClosed` or a context
  error. A connection whose peer leaves while it waits for `Accept` is
  dropped and frees its slot; streams the peer opens in that time wait
  in kolo-transport until the application accepts them. If the
  kolo-transport listener fails, the listener stops as if closed.
- `NewListener(tl, id, cfg) (*Listener, error)` does the same on an
  existing kolo-transport listener, such as one from
  `kolotransport.ListenConn`, so DHT packets (`ReadPacket`,
  `WritePacket`) and secure connections share one socket. The kolo-secure
  listener owns `tl`: it closes it on `Close`, and also when
  `NewListener` fails. `cfg.Transport` must be nil (`ErrInvalidConfig`),
  since `tl` is already configured; a nil `tl` is `ErrInvalidArgument`.
  After `NewListener`, use only `ReadPacket`, `WritePacket` and `Addr` on
  `tl`; `Close` also closes connections from `(*Listener).Dial`. `tl` is
  IPv4 only, as every kolo-transport listener.
- `(*Listener).Dial(ctx, addr, remote) (*Conn, error)` dials the
  `netip.AddrPort` from the listener's own socket (kolo-transport
  `Listener.Dial`, bounded by its `MaxDialed`) and runs the dialer side
  of the handshake, with the same checks on `remote` as `Dial`. Hole
  punching and relays always know the key they dial, so there is no
  `DialAny` form. An address kolo-transport refuses, such as an
  invalid one, IPv6, v4-mapped, port 0, unspecified, multicast,
  `0.0.0.0/8` or `240.0.0.0/4`, is `ErrInvalidArgument` of both
  packages. On a closed listener, or when `Close` runs during the call,
  it returns `ErrClosed`, unless its own context is done first.
  `Addr()` is the local address. `Close()` stops
  accepting, ends the handshakes in progress and closes every connection
  of the listener, including those already returned by `Accept`.
- `Dial(ctx, addr, id, remote, cfg) (*Conn, error)` connects as `id` and
  returns once the listener has proved it holds `remote`, which must be a
  32-byte key other than our own and not a small-order point
  (`ErrInvalidArgument` otherwise, nil included). An IPv6 or v4-mapped
  `addr` fails at once with `ErrInvalidArgument` of both packages. So
  does a destination kolo-transport refuses, such as port 0,
  unspecified, multicast, `0.0.0.0/8` or `240.0.0.0/4`, also when a
  host name resolves to it. Host names resolve to IPv4 only, so a name
  with no IPv4 address fails with a resolve error.
  The dialer sends its public key to whoever answers at `addr` before it
  has checked the listener's proof, so a wrong address sees the key.
  `DialAny(ctx, addr, id, cfg)` is the same but accepts any listener key;
  `RemotePublicKey` tells which one, and the caller decides whether to
  trust it. Both return after the dialer's own proof is sent; the listener checks it
  before its `Accept` returns the connection, and a listener that rejects
  it closes the connection, which the dialer then sees as
  `kolotransport.ErrPeerClosed` with code 1.
- `(*Conn).RemotePublicKey()` returns a copy of the peer's kolo-id public
  key. `OpenStream`, `AcceptStream`, `OpenUniStream`, `AcceptUniStream`,
  `LocalAddr`, `RemoteAddr`, `Close` and `CloseWithError` behave as in
  kolo-transport and return its stream types. `Context()` is canceled
  when the connection ends; its `context.Cause` is a kolo-transport error
  carrying at most a numeric code.
- `(*Conn).Stats()` returns kolo-transport's `ConnStats` for the connection (round-trip times, bytes, losses, congestion window,
  congestion controller, path changes; see "Connection statistics" in the kolo-transport guide). It is the transport's view of the
  connection: the handshake and your streams count together, and kolo-secure adds nothing. It never blocks, is safe from any
  goroutine and is the zero value once the connection has ended.
- `(*Conn).AllowWindowGrowth()` calls kolo-transport's
  `AllowWindowGrowth` on the connection, whether it came from `Accept`,
  `Dial`, `DialAny` or `(*Listener).Dial`, and decides nothing itself. Call
  it once your own policy admits `RemotePublicKey`, for example the paired
  peer. It reports whether growth is on: false when
  `Config.Transport.WindowGrowth` is off (the default) or the connection has
  ended; calling it again is safe. Set `Config.Transport` (or the listener
  given to `NewListener`) with `WindowGrowth` true and
  `MaxConnReceiveWindow` equal to `MaxStreamReceiveWindow`, so a connection
  nobody marked keeps exactly the initial windows; see the kolo-transport
  guide, "Faster transfers for trusted peers".
- A nil or zero identity is `ErrInvalidArgument`.
- Every blocking call returns `ctx.Err()` as soon as its context is done,
  also in the middle of the handshake.

## Errors

Errors of `Dial`, `DialAny` and `(*Listener).Dial` (the listener drops its handshake
errors), for `errors.Is`; none of them includes anything the peer sent
except the numeric QUIC close or reset code that kolo-transport keeps:

- `ErrProtocol`: a handshake message was empty, over 256 bytes,
  truncated, of the wrong type, or followed by unexpected bytes.
- `ErrUnsupportedVersion`: the peer speaks another handshake version.
- `ErrUnexpectedPeer`: the peer's key is not `remote`, or is our own key.
- `ErrAuthentication`: the peer's signature does not verify, or its key
  is a small-order Ed25519 point (see [protocol.md](protocol.md)).
- `ErrTimeout`: the handshake took longer than `HandshakeTimeout`.
- `ErrInvalidConfig`.
- `ErrInvalidArgument`, which also wraps kolo-transport's
  `ErrInvalidArgument` for an address it refuses.
- `ErrClosed` comes only from `Accept` and `(*Listener).Dial`, once the
  listener is closed.
- Other kolo-transport errors (`kolotransport.ErrPeerClosed`,
  `ErrHandshake`, ...) pass through unchanged.

A failed handshake closes the connection with application error code 1.
