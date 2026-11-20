# kolo-secure

An encrypted, authenticated channel between two Kolo peers, bound to their kolo-id identities.

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

[kolo-transport](https://github.com/ciranda-dev/kolo-transport) encrypts a QUIC connection with TLS 1.3 but does not say who is on the other side. kolo-secure adds that: after the QUIC handshake, each peer signs a value from the session's exporter ([RFC 9846, section 7.5](https://www.rfc-editor.org/info/rfc9846)), the channel binding of [RFC 9266](https://www.rfc-editor.org/info/rfc9266), with its [kolo-id](https://github.com/ciranda-dev/kolo-id) key under [Ed25519ctx (RFC 8032)](https://www.rfc-editor.org/info/rfc8032), and a connection is returned only after the peer's signature checks out.

The signature is valid for that one connection, so it cannot be replayed on another, and a relay in the middle makes the handshake fail on both sides. A dialer names the key it expects (`Dial`) or accepts any key and reads it afterwards (`DialAny`). Whether to trust a key is up to the application.

The dialer sends its public key to whoever answers at the address it dials, before it has checked the listener's proof, so a client that dials the wrong address shows its key to that host. Passive observers see neither key.

It is Go only and builds without cgo. It is IPv4 only: IPv6 input, the v4-mapped form included, is refused.

## Install

```sh
go get github.com/ciranda-dev/kolo-secure
```

## Quick start

A listener and a dialer, each with its own identity, over loopback. The dialer echoes a message through the listener.

```go
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	client, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}

	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", server, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept(ctx)
		if err != nil {
			return
		}
		fmt.Printf("dialer is %x\n", c.RemotePublicKey())
		s, err := c.AcceptStream(ctx)
		if err != nil {
			return
		}
		io.Copy(s, s)
		s.Close()
	}()

	c, err := kolosecure.Dial(ctx, l.Addr().String(), client, server.PublicKey(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	s, err := c.OpenStream(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := s.Write([]byte("hello kolo")); err != nil {
		log.Fatal(err)
	}
	s.Close()
	reply, err := io.ReadAll(s)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", reply)
}
```

```text
$ go run .
dialer is <64 hex characters>
hello kolo
```

A real node loads its identity with `koloid.Load` and learns the key of the peer it dials from wherever it learned the address.

## API

| Symbol | What it does |
|---|---|
| `Listen` | Open a listener as an identity; `Accept` returns a connection once the dialer has proved its key |
| `NewListener` | The same on an existing kolo-transport listener, so datagrams and secure connections share one socket |
| `Dial` | Connect as an identity to a listener whose key you know |
| `DialAny` | Connect and accept any listener key; `RemotePublicKey` tells which |
| `Listener.Dial` | Dial from the listener's own socket, as hole punching needs |
| `Conn.RemotePublicKey` | The peer's kolo-id public key |
| `Conn.Stats` | The connection's kolo-transport statistics: round-trip times, bytes, losses, congestion window, controller (zero after it ends) |
| `Conn.AllowWindowGrowth` | Mark the connection as trusted so its receive windows can grow (kolo-transport `WindowGrowth`); you decide who |
| `Conn.OpenStream`, `AcceptStream`, `OpenUniStream`, `AcceptUniStream` | Streams, as in kolo-transport |
| `Config` | `Transport`, `HandshakeTimeout` and `MaxPending` |

Errors are sentinels for `errors.Is`: `ErrProtocol`, `ErrUnsupportedVersion`, `ErrUnexpectedPeer`, `ErrAuthentication`, `ErrTimeout`, `ErrClosed`, `ErrInvalidConfig` and `ErrInvalidArgument`. A failed handshake closes the connection with application error code 1.

## Documentation

- [Guide](docs/guide.md): every call and every error.
- [Limits](docs/limits.md): options, defaults, ranges and what a stalled peer can hold.
- [Protocol and design](docs/protocol.md): channel binding, the signed message, the wire format, what it does not do and references.

## Status

Experimental. The API may change before v1.0.0.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.
