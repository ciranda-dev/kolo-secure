package kolosecure

import "errors"

var (
	// ErrInvalidConfig means a Config field is out of range.
	ErrInvalidConfig = errors.New("kolosecure: invalid config")
	// ErrInvalidArgument means a nil or zero identity, a nil transport listener, a bad remote key, or an address kolo-transport refuses.
	ErrInvalidArgument = errors.New("kolosecure: invalid argument")
	// ErrClosed means the listener is closed.
	ErrClosed = errors.New("kolosecure: closed")
	// ErrProtocol means a handshake message was malformed, truncated, too large or unexpected.
	ErrProtocol = errors.New("kolosecure: invalid handshake message")
	// ErrUnsupportedVersion means the peer speaks another handshake version.
	ErrUnsupportedVersion = errors.New("kolosecure: unsupported handshake version")
	// ErrUnexpectedPeer means the peer key is not the expected one, or is the local key.
	ErrUnexpectedPeer = errors.New("kolosecure: unexpected peer key")
	// ErrAuthentication means the peer's proof did not verify, or its key cannot be authenticated.
	ErrAuthentication = errors.New("kolosecure: peer authentication failed")
	// ErrTimeout means the handshake took longer than HandshakeTimeout.
	ErrTimeout = errors.New("kolosecure: handshake timeout")
)
