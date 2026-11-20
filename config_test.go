package kolosecure

import (
	"errors"
	"testing"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func TestConfigDefaults(t *testing.T) {
	for _, cfg := range []*Config{nil, {}} {
		c, err := cfg.withDefaults()
		if err != nil {
			t.Fatal(err)
		}
		if c.HandshakeTimeout != 10*time.Second || c.MaxPending != 64 || c.Transport != nil {
			t.Fatalf("defaults: %+v", c)
		}
	}
	tc := &kolotransport.Config{MaxConns: 3}
	c, err := (&Config{Transport: tc, HandshakeTimeout: time.Minute, MaxPending: 1000}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if c.HandshakeTimeout != time.Minute || c.MaxPending != 1000 || c.Transport != tc {
		t.Fatalf("kept values: %+v", c)
	}
}

func TestConfigRejectsOutOfRange(t *testing.T) {
	for _, cfg := range []Config{
		{HandshakeTimeout: time.Second - 1},
		{HandshakeTimeout: time.Minute + 1},
		{HandshakeTimeout: -1},
		{MaxPending: -1},
		{MaxPending: 1001},
	} {
		if _, err := cfg.withDefaults(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%+v: got %v", cfg, err)
		}
	}
}

func TestListenDialRejectInvalidConfig(t *testing.T) {
	checkGoroutines(t)
	id := newIdentity(t)
	bad := &Config{MaxPending: -1}
	if _, err := Listen(testCtx(t), "127.0.0.1:0", id, bad); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Listen: %v", err)
	}
	if _, err := DialAny(testCtx(t), "127.0.0.1:1", id, &Config{HandshakeTimeout: -1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("DialAny: %v", err)
	}
	badTransport := &Config{Transport: &kolotransport.Config{MaxIncomingStreams: -1}}
	if _, err := Listen(testCtx(t), "127.0.0.1:0", id, badTransport); !errors.Is(err, kolotransport.ErrInvalidConfig) || errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Listen with a bad transport config: %v", err)
	}
	if _, err := Dial(testCtx(t), "127.0.0.1:1", id, newIdentity(t).PublicKey(), badTransport); !errors.Is(err, kolotransport.ErrInvalidConfig) || errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Dial with a bad transport config: %v", err)
	}
}
