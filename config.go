package kolosecure

import (
	"fmt"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// Config sets the limits of a Listener or a Dial. A zero field takes its default.
type Config struct {
	// Transport is passed to kolotransport.Listen or kolotransport.Dial; nil means its defaults. It must be nil for NewListener.
	Transport *kolotransport.Config
	// HandshakeTimeout bounds the kolo-secure handshake after the QUIC handshake. Default 10s, from 1s to 60s.
	HandshakeTimeout time.Duration
	// MaxPending caps the connections of a Listener that are handshaking or waiting for Accept. Listener only. Default 64 (or the transport MaxConns if lower), at most the transport MaxConns.
	MaxPending int
}

const (
	defaultHandshakeTimeout = 10 * time.Second
	minHandshakeTimeout     = time.Second
	maxHandshakeTimeout     = time.Minute
	defaultMaxPending       = 64
)

func (c *Config) withDefaults() (Config, error) {
	var out Config
	if c != nil {
		out = *c
	}
	switch t := out.HandshakeTimeout; {
	case t == 0:
		out.HandshakeTimeout = defaultHandshakeTimeout
	case t < minHandshakeTimeout || t > maxHandshakeTimeout:
		return Config{}, fmt.Errorf("%w: HandshakeTimeout must be between %v and %v", ErrInvalidConfig, minHandshakeTimeout, maxHandshakeTimeout)
	}
	if out.MaxPending < 0 {
		return Config{}, fmt.Errorf("%w: MaxPending must be at least 1", ErrInvalidConfig)
	}
	return out, nil
}

// limitPending applies the MaxPending default and checks it against the MaxConns of the transport listener, which counts the same connections.
func (c *Config) limitPending(maxConns int) error {
	switch n := c.MaxPending; {
	case n == 0:
		c.MaxPending = min(defaultMaxPending, maxConns)
	case n > maxConns:
		return fmt.Errorf("%w: MaxPending %d is above the transport MaxConns %d", ErrInvalidConfig, n, maxConns)
	}
	return nil
}
