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
	// MaxPending caps the connections of a Listener that are handshaking or waiting for Accept. Listener only. Default 64, from 1 to 1000.
	MaxPending int
}

const (
	defaultHandshakeTimeout = 10 * time.Second
	minHandshakeTimeout     = time.Second
	maxHandshakeTimeout     = time.Minute
	defaultMaxPending       = 64
	maxMaxPending           = 1000
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
	switch n := out.MaxPending; {
	case n == 0:
		out.MaxPending = defaultMaxPending
	case n < 1 || n > maxMaxPending:
		return Config{}, fmt.Errorf("%w: MaxPending must be between 1 and %d", ErrInvalidConfig, maxMaxPending)
	}
	return out, nil
}
