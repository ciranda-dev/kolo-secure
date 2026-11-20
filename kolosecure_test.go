package kolosecure

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func TestMutualAuthentication(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)
	l := listen(t, lid, nil)

	for _, remote := range []ed25519.PublicKey{lid.PublicKey(), nil} {
		client := dial(t, l.Addr().String(), did, remote, nil)
		server := accept(t, l)
		if !bytes.Equal(client.RemotePublicKey(), lid.PublicKey()) {
			t.Fatal("dialer sees the wrong listener key")
		}
		if !bytes.Equal(server.RemotePublicKey(), did.PublicKey()) {
			t.Fatal("listener sees the wrong dialer key")
		}

		ctx := testCtx(t)
		cs, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cs.Write([]byte("hello"))
		cs.Close()
		ss, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := io.ReadAll(ss); err != nil || string(got) != "hello" {
			t.Fatalf("listener read %q, %v", got, err)
		}
		ss.Write([]byte("hi"))
		ss.Close()
		if got, err := io.ReadAll(cs); err != nil || string(got) != "hi" {
			t.Fatalf("dialer read %q, %v", got, err)
		}

		us, err := server.OpenUniStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		us.Write([]byte("uni"))
		us.Close()
		ur, err := client.AcceptUniStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := io.ReadAll(ur); err != nil || string(got) != "uni" {
			t.Fatalf("dialer read %q, %v", got, err)
		}
		if client.LocalAddr().String() != server.RemoteAddr().String() {
			t.Fatal("addresses do not match")
		}
	}
}

func TestRemotePublicKeyIsACopy(t *testing.T) {
	checkGoroutines(t)
	lid := newIdentity(t)
	l := listen(t, lid, nil)
	c := dial(t, l.Addr().String(), newIdentity(t), nil, nil)
	accept(t, l)
	c.RemotePublicKey()[0] ^= 0xff
	if !bytes.Equal(c.RemotePublicKey(), lid.PublicKey()) {
		t.Fatal("RemotePublicKey shares memory")
	}
}

func TestCloseWithError(t *testing.T) {
	checkGoroutines(t)
	lid := newIdentity(t)
	l := listen(t, lid, nil)
	c := dial(t, l.Addr().String(), newIdentity(t), lid.PublicKey(), nil)
	s := accept(t, l)
	if err := s.CloseWithError(42, "bye"); err != nil {
		t.Fatal(err)
	}
	_, err := c.AcceptStream(testCtx(t))
	var e *kolotransport.Error
	if !errors.As(err, &e) || !errors.Is(err, kolotransport.ErrPeerClosed) || e.Code != 42 {
		t.Fatalf("got %v, want ErrPeerClosed with code 42", err)
	}
}

func TestDialWrongKey(t *testing.T) {
	checkGoroutines(t)
	l := listen(t, newIdentity(t), nil)
	_, err := Dial(testCtx(t), l.Addr().String(), newIdentity(t), newIdentity(t).PublicKey(), nil)
	if !errors.Is(err, ErrUnexpectedPeer) {
		t.Fatalf("got %v, want ErrUnexpectedPeer", err)
	}
	if _, err := l.Accept(shortCtx(t)); err != context.DeadlineExceeded {
		t.Fatalf("listener accepted after a failed dial: %v", err)
	}
}

func TestRejectsInvalidArguments(t *testing.T) {
	checkGoroutines(t)
	const addr = "127.0.0.1:1"
	id, other := newIdentity(t), newIdentity(t).PublicKey()
	ctx := testCtx(t)
	cases := map[string]func() error{
		"nil identity":    func() error { _, err := Dial(ctx, addr, nil, other, nil); return err },
		"zero identity":   func() error { _, err := Dial(ctx, addr, &koloid.Identity{}, other, nil); return err },
		"nil key":         func() error { _, err := Dial(ctx, addr, id, nil, nil); return err },
		"empty key":       func() error { _, err := Dial(ctx, addr, id, []byte{}, nil); return err },
		"short key":       func() error { _, err := Dial(ctx, addr, id, make([]byte, 31), nil); return err },
		"own key":         func() error { _, err := Dial(ctx, addr, id, id.PublicKey(), nil); return err },
		"small-order key": func() error { _, err := Dial(ctx, addr, id, smallOrderKeys[2], nil); return err },
		"DialAny nil":     func() error { _, err := DialAny(ctx, addr, nil, nil); return err },
		"DialAny zero":    func() error { _, err := DialAny(ctx, addr, &koloid.Identity{}, nil); return err },
		"Listen nil":      func() error { _, err := Listen(ctx, "127.0.0.1:0", nil, nil); return err },
		"Listen zero":     func() error { _, err := Listen(ctx, "127.0.0.1:0", &koloid.Identity{}, nil); return err },
	}
	for name, call := range cases {
		if err := call(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: got %v, want ErrInvalidArgument", name, err)
		}
	}
}

func TestDialBadAddress(t *testing.T) {
	checkGoroutines(t)
	id, remote := newIdentity(t), newIdentity(t).PublicKey()
	both := func(err error) bool {
		return errors.Is(err, ErrInvalidArgument) && errors.Is(err, kolotransport.ErrInvalidArgument)
	}
	if _, err := Listen(testCtx(t), "[::1]:0", id, nil); !both(err) {
		t.Fatalf("Listen [::1]:0: got %v, want ErrInvalidArgument from both packages", err)
	}
	// Stop at the first failure; 224.0.0.1 is last, so no other regression sends there.
	for _, addr := range []string{"127.0.0.1:0", "localhost:0", "[::1]:1", "[::ffff:127.0.0.1]:1", "0.0.0.0:1", "224.0.0.1:1"} {
		if _, err := Dial(shortCtx(t), addr, id, remote, nil); !both(err) {
			t.Fatalf("Dial %s: got %v, want ErrInvalidArgument from both packages", addr, err)
		}
		if _, err := DialAny(shortCtx(t), addr, id, nil); !both(err) {
			t.Fatalf("DialAny %s: got %v, want ErrInvalidArgument from both packages", addr, err)
		}
	}
}

func TestReplayedListenerProof(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)
	l := listen(t, lid, nil)

	// Record a genuine listener proof made for one connection.
	first := rawDial(t, l.Addr().String())
	s := sendHelloOpen(t, first, did.PublicKey())
	recorded := readBody(t, s)

	// Replay it on another connection.
	fake := rawListen(t)
	ctx := testCtx(t)
	served := make(chan struct{})
	go func() {
		defer close(served)
		c, err := fake.Accept(ctx)
		if err != nil {
			return
		}
		s, err := c.AcceptStream(ctx)
		if err != nil {
			return
		}
		readFrame(s)
		s.Write(frame(recorded))
		s.Close()
	}()
	_, err := Dial(testCtx(t), fake.Addr().String(), did, lid.PublicKey(), nil)
	<-served
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("got %v, want ErrAuthentication", err)
	}
}

func TestReplayedDialerProof(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)

	// Record a genuine dialer proof by letting the real dialer talk to the real listener key on connection 1.
	tap := rawListen(t)
	ctx := testCtx(t)
	recorded := make(chan []byte, 1)
	go func() {
		c, err := tap.Accept(ctx)
		if err != nil {
			recorded <- nil
			return
		}
		s, err := c.AcceptStream(ctx)
		if err != nil {
			recorded <- nil
			return
		}
		readFrame(s)
		k, err := c.ExportKey(exporterLabel)
		if err != nil {
			recorded <- nil
			return
		}
		sig, err := lid.Sign(proofContext, transcript(roleListener, k, did.PublicKey(), lid.PublicKey()))
		if err != nil {
			recorded <- nil
			return
		}
		s.Write(frame(encodeProof(lid.PublicKey(), sig)))
		s.Close()
		body, _ := readFrame(s)
		recorded <- body
	}()
	dial(t, tap.Addr().String(), did, lid.PublicKey(), nil)
	finish := <-recorded
	if finish == nil {
		t.Fatal("no proof recorded")
	}

	// Replay it as the dialer on connection 2.
	client, server := rawPair(t)
	result := runSecure(t, server, lid, false, nil)
	s := sendHelloOpen(t, client, did.PublicKey())
	readBody(t, s)
	s.Write(frame(finish))
	s.Close()
	if err := wait(t, result); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("got %v, want ErrAuthentication", err)
	}
}

func TestRoleSwappedProof(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)

	t.Run("listener signs as dialer", func(t *testing.T) {
		client, server := rawPair(t)
		result := runSecure(t, client, did, true, lid.PublicKey())
		s, err := server.AcceptStream(testCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		readBody(t, s)
		sig := sign(t, lid, transcript(roleDialer, ekm(t, server), did.PublicKey(), lid.PublicKey()))
		s.Write(frame(encodeProof(lid.PublicKey(), sig)))
		s.Close()
		if err := wait(t, result); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("got %v, want ErrAuthentication", err)
		}
	})

	t.Run("dialer signs as listener", func(t *testing.T) {
		client, server := rawPair(t)
		result := runSecure(t, server, lid, false, nil)
		s := sendHelloOpen(t, client, did.PublicKey())
		readBody(t, s)
		sig := sign(t, did, transcript(roleListener, ekm(t, client), did.PublicKey(), lid.PublicKey()))
		s.Write(frame(encodeFinish(sig)))
		s.Close()
		if err := wait(t, result); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("got %v, want ErrAuthentication", err)
		}
	})

	t.Run("dialer reflects the listener proof", func(t *testing.T) {
		client, server := rawPair(t)
		result := runSecure(t, server, lid, false, nil)
		s := sendHelloOpen(t, client, did.PublicKey())
		_, sig, err := decodeProof(readBody(t, s))
		if err != nil {
			t.Fatal(err)
		}
		s.Write(frame(encodeFinish(sig)))
		s.Close()
		if err := wait(t, result); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("got %v, want ErrAuthentication", err)
		}
	})
}

func TestReflectedKey(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)

	t.Run("listener presents the dialer key", func(t *testing.T) {
		client, server := rawPair(t)
		result := runSecure(t, client, did, true, nil)
		s, err := server.AcceptStream(testCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		key, err := decodeHello(readBody(t, s))
		if err != nil {
			t.Fatal(err)
		}
		s.Write(frame(encodeProof(key, make([]byte, 64))))
		s.Close()
		if err := wait(t, result); !errors.Is(err, ErrUnexpectedPeer) {
			t.Fatalf("got %v, want ErrUnexpectedPeer", err)
		}
	})

	t.Run("dialer presents the listener key", func(t *testing.T) {
		client, server := rawPair(t)
		result := runSecure(t, server, lid, false, nil)
		sendHello(t, client, lid.PublicKey())
		if err := wait(t, result); !errors.Is(err, ErrUnexpectedPeer) {
			t.Fatalf("got %v, want ErrUnexpectedPeer", err)
		}
	})
}

func TestSmallOrderKeyRejected(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)
	identityPoint := smallOrderKeys[2]
	forged := append(bytes.Clone(identityPoint), make([]byte, 32)...)

	t.Run("dialer", func(t *testing.T) {
		client, server := rawPair(t)
		msg := transcript(roleDialer, ekm(t, client), identityPoint, lid.PublicKey())
		if !stdVerify(identityPoint, msg, forged) {
			t.Fatal("expected the forged signature to verify under crypto/ed25519")
		}
		result := runSecure(t, server, lid, false, nil)
		s := sendHelloOpen(t, client, identityPoint)
		s.Write(frame(encodeFinish(forged)))
		s.Close()
		if err := wait(t, result); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("got %v, want ErrAuthentication", err)
		}
	})

	t.Run("listener", func(t *testing.T) {
		client, server := rawPair(t)
		result := runSecure(t, client, did, true, nil)
		s, err := server.AcceptStream(testCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		readBody(t, s)
		msg := transcript(roleListener, ekm(t, server), did.PublicKey(), identityPoint)
		if !stdVerify(identityPoint, msg, forged) {
			t.Fatal("expected the forged signature to verify under crypto/ed25519")
		}
		s.Write(frame(encodeProof(identityPoint, forged)))
		s.Close()
		if err := wait(t, result); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("got %v, want ErrAuthentication", err)
		}
	})
}

func TestRelayInTheMiddle(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)
	target := listen(t, lid, nil)
	relay := rawListen(t)
	ctx := testCtx(t)

	for _, remote := range []ed25519.PublicKey{lid.PublicKey(), nil} {
		relayed := make(chan struct{})
		go func() {
			defer close(relayed)
			down, err := relay.Accept(ctx)
			if err != nil {
				return
			}
			defer down.Close()
			up, err := kolotransport.Dial(ctx, target.Addr().String(), nil)
			if err != nil {
				return
			}
			defer up.Close()
			ds, err := down.AcceptStream(ctx)
			if err != nil {
				return
			}
			us, err := up.OpenStream(ctx)
			if err != nil {
				return
			}
			copied := make(chan struct{})
			go func() {
				defer close(copied)
				io.Copy(us, ds)
				us.Close()
			}()
			defer func() { <-copied }()
			io.Copy(ds, us)
			ds.Close()
			// Wait for the dialer to give up before tearing the relay down.
			down.AcceptStream(ctx)
		}()

		var err error
		if remote == nil {
			_, err = DialAny(ctx, relay.Addr().String(), did, nil)
		} else {
			_, err = Dial(ctx, relay.Addr().String(), did, remote, nil)
		}
		if !errors.Is(err, ErrAuthentication) {
			t.Fatalf("dialer through a relay: got %v, want ErrAuthentication", err)
		}
		<-relayed
		if _, err := target.Accept(shortCtx(t)); err != context.DeadlineExceeded {
			t.Fatalf("listener accepted a relayed connection: %v", err)
		}
	}
}

func TestHandshakeTimeout(t *testing.T) {
	checkGoroutines(t)
	cfg := &Config{HandshakeTimeout: time.Second}

	t.Run("dial", func(t *testing.T) {
		silent := rawListen(t)
		ctx := testCtx(t)
		done := make(chan struct{})
		go func() {
			defer close(done)
			c, err := silent.Accept(ctx)
			if err == nil {
				c.AcceptStream(ctx)
			}
		}()
		t.Cleanup(func() {
			silent.Close()
			<-done
		})
		start := time.Now()
		_, err := DialAny(ctx, silent.Addr().String(), newIdentity(t), cfg)
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("got %v, want ErrTimeout", err)
		}
		if d := time.Since(start); d < 900*time.Millisecond || d > 5*time.Second {
			t.Fatalf("took %v", d)
		}
	})

	t.Run("listener", func(t *testing.T) {
		client, server := rawPair(t)
		start := time.Now()
		_, err := secure(testCtx(t), server, time.Second, newIdentity(t), false, nil)
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("got %v, want ErrTimeout", err)
		}
		if d := time.Since(start); d < 900*time.Millisecond || d > 5*time.Second {
			t.Fatalf("took %v", d)
		}
		if _, err := client.AcceptStream(testCtx(t)); !errors.Is(err, kolotransport.ErrPeerClosed) {
			t.Fatalf("connection not closed after the timeout: %v", err)
		}
	})

	t.Run("listener with a stream", func(t *testing.T) {
		l := listen(t, newIdentity(t), cfg)
		c := rawDial(t, l.Addr().String())
		s, err := c.OpenStream(testCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		s.Write([]byte{40})
		var b [1]byte
		_, err = s.Read(b[:])
		var e *kolotransport.Error
		if !errors.As(err, &e) || !errors.Is(err, kolotransport.ErrPeerClosed) || e.Code != failCode {
			t.Fatalf("got %v, want ErrPeerClosed with code %d", err, failCode)
		}
	})
}

func TestMaxPending(t *testing.T) {
	checkGoroutines(t)
	lid := newIdentity(t)
	l := listen(t, lid, &Config{MaxPending: 1})

	// An authenticated connection waiting for Accept holds the only slot.
	first := newIdentity(t)
	dial(t, l.Addr().String(), first, lid.PublicKey(), nil)
	start := time.Now()
	_, err := Dial(testCtx(t), l.Addr().String(), newIdentity(t), lid.PublicKey(), nil)
	var e *kolotransport.Error
	if !errors.As(err, &e) || !errors.Is(err, kolotransport.ErrPeerClosed) || e.Code != failCode {
		t.Fatalf("dial while the listener is full: got %v, want ErrPeerClosed with code %d", err, failCode)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("refusal took %v", d)
	}

	// Accept frees it.
	if s := accept(t, l); !bytes.Equal(s.RemotePublicKey(), first.PublicKey()) {
		t.Fatal("accepted the wrong connection")
	}
	next := newIdentity(t)
	dial(t, l.Addr().String(), next, lid.PublicKey(), nil)
	if s := accept(t, l); !bytes.Equal(s.RemotePublicKey(), next.PublicKey()) {
		t.Fatal("accepted the wrong connection")
	}
}

func TestListenerClose(t *testing.T) {
	checkGoroutines(t)
	lid := newIdentity(t)
	l, err := Listen(testCtx(t), "127.0.0.1:0", lid, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := dial(t, l.Addr().String(), newIdentity(t), lid.PublicKey(), nil)
	s, err := l.Accept(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	// One more authenticated connection that nobody accepts.
	waiting := dial(t, l.Addr().String(), newIdentity(t), lid.PublicKey(), nil)
	// And one stalled in the handshake.
	rawDial(t, l.Addr().String())

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := l.Accept(testCtx(t)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
	if _, err := s.AcceptStream(testCtx(t)); !errors.Is(err, kolotransport.ErrClosed) {
		t.Fatalf("accepted connection still open: %v", err)
	}
	for _, d := range []*Conn{c, waiting} {
		if _, err := d.AcceptStream(testCtx(t)); !errors.Is(err, kolotransport.ErrPeerClosed) {
			t.Fatalf("dialer not told: %v", err)
		}
	}
}

func TestContextCanceled(t *testing.T) {
	checkGoroutines(t)
	lid := newIdentity(t)
	l := listen(t, lid, &Config{Transport: &kolotransport.Config{MaxIncomingStreams: 1}})
	client := dial(t, l.Addr().String(), newIdentity(t), nil, nil)
	accept(t, l)
	if _, err := client.OpenStream(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.OpenUniStream(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	silent := rawListen(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := silent.Accept(context.Background())
			if err != nil {
				return
			}
			go c.AcceptStream(context.Background())
		}
	}()
	t.Cleanup(func() {
		silent.Close()
		<-done
	})

	calls := map[string]func(context.Context) error{
		"Dial": func(ctx context.Context) error {
			_, err := Dial(ctx, silent.Addr().String(), lid, newIdentity(t).PublicKey(), nil)
			return err
		},
		"DialAny": func(ctx context.Context) error { _, err := DialAny(ctx, silent.Addr().String(), lid, nil); return err },
		"Listener.Dial": func(ctx context.Context) error {
			_, err := l.Dial(ctx, netip.MustParseAddrPort(silent.Addr().String()), newIdentity(t).PublicKey())
			return err
		},
		"Accept":          func(ctx context.Context) error { _, err := l.Accept(ctx); return err },
		"OpenStream":      func(ctx context.Context) error { _, err := client.OpenStream(ctx); return err },
		"AcceptStream":    func(ctx context.Context) error { _, err := client.AcceptStream(ctx); return err },
		"OpenUniStream":   func(ctx context.Context) error { _, err := client.OpenUniStream(ctx); return err },
		"AcceptUniStream": func(ctx context.Context) error { _, err := client.AcceptUniStream(ctx); return err },
	}
	for name, call := range calls {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(200*time.Millisecond, cancel)
		start := time.Now()
		if err := call(ctx); err != context.Canceled {
			t.Errorf("%s: got %v", name, err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: took %v", name, d)
		}

		ctx, cancel = context.WithCancel(context.Background())
		cancel()
		if err := call(ctx); err != context.Canceled {
			t.Errorf("%s with a canceled context: got %v", name, err)
		}
	}
}

func TestDialHandshakeCanceled(t *testing.T) {
	checkGoroutines(t)
	client, server := rawPair(t)
	sctx := testCtx(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.AcceptStream(sctx)
	}()
	t.Cleanup(func() {
		server.Close()
		<-done
	})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	if _, err := secure(ctx, client, defaultHandshakeTimeout, newIdentity(t), true, nil); err != context.Canceled {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func sendHelloOpen(t *testing.T, c *kolotransport.Conn, key []byte) *kolotransport.Stream {
	t.Helper()
	s, err := c.OpenStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(frame(encodeHello(key))); err != nil {
		t.Fatal(err)
	}
	return s
}

func sendHello(t *testing.T, c *kolotransport.Conn, key []byte) *kolotransport.Stream {
	t.Helper()
	s := sendHelloOpen(t, c, key)
	s.Close()
	return s
}

func TestPendingConnReleasedWhenPeerLeaves(t *testing.T) {
	checkGoroutines(t)
	lid := newIdentity(t)
	l := listen(t, lid, &Config{MaxPending: 1})
	gone, err := Dial(testCtx(t), l.Addr().String(), newIdentity(t), lid.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Let the listener verify the proof, so the connection waits for Accept, before the peer leaves.
	time.Sleep(200 * time.Millisecond)
	gone.Close()
	time.Sleep(200 * time.Millisecond)

	live := newIdentity(t)
	dial(t, l.Addr().String(), live, lid.PublicKey(), nil)
	if s := accept(t, l); !bytes.Equal(s.RemotePublicKey(), live.PublicKey()) {
		t.Fatal("Accept returned the connection whose peer left")
	}
}

func TestEarlyUniStreamDelivered(t *testing.T) {
	checkGoroutines(t)
	lid := newIdentity(t)
	l := listen(t, lid, nil)
	c := dial(t, l.Addr().String(), newIdentity(t), lid.PublicKey(), nil)
	for _, msg := range []string{"first", "second"} {
		us, err := c.OpenUniStream(testCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		us.Write([]byte(msg))
		us.Close()
	}
	time.Sleep(200 * time.Millisecond)
	s := accept(t, l)
	for _, want := range []string{"first", "second"} {
		r, err := s.AcceptUniStream(testCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := io.ReadAll(r); err != nil || string(got) != want {
			t.Fatalf("read %q, %v, want %q", got, err, want)
		}
	}
}

func TestDialClosedListenerIsNotErrClosed(t *testing.T) {
	checkGoroutines(t)
	lid := newIdentity(t)
	l, err := Listen(testCtx(t), "127.0.0.1:0", lid, nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	cfg := &Config{Transport: &kolotransport.Config{HandshakeTimeout: time.Second}}
	_, err = Dial(testCtx(t), addr, newIdentity(t), lid.PublicKey(), cfg)
	if err == nil || errors.Is(err, ErrClosed) {
		t.Fatalf("got %v, want an error other than ErrClosed", err)
	}
}

func TestFailedHandshakeReleasesSlot(t *testing.T) {
	checkGoroutines(t)
	lid := newIdentity(t)
	l := listen(t, lid, &Config{MaxPending: 1})
	for range 3 {
		raw := rawDial(t, l.Addr().String())
		s := sendRaw(t, raw, []byte{0x00})
		wantFailCode(t, readOne(s))
		did := newIdentity(t)
		dial(t, l.Addr().String(), did, lid.PublicKey(), nil)
		if c := accept(t, l); !bytes.Equal(c.RemotePublicKey(), did.PublicKey()) {
			t.Fatal("accepted the wrong connection")
		}
	}
}

func TestListenerRejectsBadFinish(t *testing.T) {
	checkGoroutines(t)
	lid := newIdentity(t)
	l := listen(t, lid, nil)
	raw := rawDial(t, l.Addr().String())
	s := sendHelloOpen(t, raw, newIdentity(t).PublicKey())
	readBody(t, s)
	s.Write(frame(encodeFinish(make([]byte, 64))))
	s.Close()
	if _, err := l.Accept(shortCtx(t)); err != context.DeadlineExceeded {
		t.Fatalf("Accept: got %v, want context.DeadlineExceeded", err)
	}
	_, err := raw.AcceptStream(testCtx(t))
	wantFailCode(t, err)
}

func TestTransportFailureStopsListener(t *testing.T) {
	checkGoroutines(t)
	l := listen(t, newIdentity(t), nil)
	l.tl.Close()
	deadline := time.Now().Add(5 * time.Second)
	for l.ctx.Err() == nil {
		if time.Now().After(deadline) {
			t.Fatal("listener context still live after its transport failed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := l.Accept(testCtx(t)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Accept: %v", err)
	}
}

func readOne(s *kolotransport.Stream) error {
	var b [1]byte
	_, err := s.Read(b[:])
	return err
}

func wantFailCode(t *testing.T, err error) {
	t.Helper()
	var e *kolotransport.Error
	if !errors.As(err, &e) || !errors.Is(err, kolotransport.ErrPeerClosed) || e.Code != failCode {
		t.Fatalf("got %v, want ErrPeerClosed with code %d", err, failCode)
	}
}
