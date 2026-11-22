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
		if c.HandshakeTimeout != 10*time.Second || c.MaxPending != 0 || c.Transport != nil {
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
	} {
		if _, err := cfg.withDefaults(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%+v: got %v", cfg, err)
		}
	}
}

func TestMaxPendingFollowsMaxConns(t *testing.T) {
	checkGoroutines(t)
	id := newIdentity(t)
	if n := cap(listen(t, id, nil).slots); n != 64 {
		t.Fatalf("default: %d", n)
	}
	tc := func(conns int) *kolotransport.Config {
		return &kolotransport.Config{MaxConns: conns, MaxConnReceiveWindow: 64 << 10, MaxMemory: 1 << 30}
	}
	if n := cap(listen(t, id, &Config{Transport: tc(5)}).slots); n != 5 {
		t.Fatalf("default with MaxConns 5: %d", n)
	}
	if n := cap(listen(t, id, &Config{Transport: tc(5000), MaxPending: 2000}).slots); n != 2000 {
		t.Fatalf("2000 of 5000: %d", n)
	}
	if n := cap(listen(t, id, &Config{Transport: tc(5), MaxPending: 5}).slots); n != 5 {
		t.Fatalf("5 of 5: %d", n)
	}
	if _, err := Listen(testCtx(t), "127.0.0.1:0", id, &Config{Transport: tc(5), MaxPending: 6}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Listen with MaxPending above MaxConns: %v", err)
	}
	tl, err := kolotransport.Listen(testCtx(t), "127.0.0.1:0", tc(5))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewListener(tl, id, &Config{MaxPending: 6}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewListener with MaxPending above MaxConns: %v", err)
	}
	if _, err := tl.Accept(testCtx(t)); !errors.Is(err, kolotransport.ErrClosed) {
		t.Fatalf("transport listener not closed: %v", err)
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
