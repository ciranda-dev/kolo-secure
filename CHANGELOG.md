# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** `Config.MaxPending` no longer has a range maximum of 1000. It is at most the `MaxConns` of the transport listener, which counts the same connections; a larger value is `ErrInvalidConfig` from `Listen` and `NewListener`. The default is 64, or the transport `MaxConns` if lower, so a listener with a small `MaxConns` no longer needs `MaxPending` set. Needs the unreleased kolo-transport that adds `Listener.MaxConns`.

### Added

- `Listener.PublicKey` returns the public key the listener authenticates with, so a caller that is handed a listener can check whose it is.
- `Conn.SupportsDatagrams`, `Conn.SendDatagram` and `Conn.ReceiveDatagram` pass QUIC datagrams through to kolo-transport when both ends set `Config.Transport.Datagrams`. Needs the unreleased kolo-transport that adds them.

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-secure.
