package kolosecure

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func addrPort(t *testing.T, l *Listener) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

func wrap(t *testing.T, tl *kolotransport.Listener, id *koloid.Identity) *Listener {
	t.Helper()
	l, err := NewListener(tl, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestNewListener(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)
	tl := rawListen(t)
	l := wrap(t, tl, lid)
	dial(t, l.Addr().String(), did, lid.PublicKey(), nil)
	if s := accept(t, l); !bytes.Equal(s.RemotePublicKey(), did.PublicKey()) {
		t.Fatal("wrong dialer key")
	}
	l.Close()
	if _, err := tl.Accept(testCtx(t)); !errors.Is(err, kolotransport.ErrClosed) {
		t.Fatalf("transport listener still open after Close: %v", err)
	}

	bad := map[string]struct {
		id   *koloid.Identity
		cfg  *Config
		want error
	}{
		"Transport set": {lid, &Config{Transport: &kolotransport.Config{}}, ErrInvalidConfig},
		"bad config":    {lid, &Config{MaxPending: -1}, ErrInvalidConfig},
		"nil identity":  {nil, nil, ErrInvalidArgument},
		"zero identity": {&koloid.Identity{}, nil, ErrInvalidArgument},
	}
	for name, c := range bad {
		tl := rawListen(t)
		if _, err := NewListener(tl, c.id, c.cfg); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
		if _, err := tl.Accept(testCtx(t)); !errors.Is(err, kolotransport.ErrClosed) {
			t.Errorf("%s: transport listener not closed: %v", name, err)
		}
	}
	if _, err := NewListener(nil, lid, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("nil listener: %v", err)
	}
}

func TestListenerDial(t *testing.T) {
	checkGoroutines(t)
	aid, bid := newIdentity(t), newIdentity(t)
	a, b := listen(t, aid, nil), listen(t, bid, nil)

	for _, p := range []struct {
		from, to     *Listener
		fromID, toID *koloid.Identity
	}{{a, b, aid, bid}, {b, a, bid, aid}} {
		c, err := p.from.Dial(testCtx(t), addrPort(t, p.to), p.toID.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		if c.LocalAddr().String() != p.from.Addr().String() {
			t.Fatalf("LocalAddr %v, want the listener address %v", c.LocalAddr(), p.from.Addr())
		}
		if !bytes.Equal(c.RemotePublicKey(), p.toID.PublicKey()) {
			t.Fatal("dialer sees the wrong key")
		}
		if s := accept(t, p.to); !bytes.Equal(s.RemotePublicKey(), p.fromID.PublicKey()) {
			t.Fatal("listener sees the wrong key")
		}
	}

	if _, err := a.Dial(testCtx(t), addrPort(t, b), newIdentity(t).PublicKey()); !errors.Is(err, ErrUnexpectedPeer) {
		t.Fatalf("wrong key: got %v, want ErrUnexpectedPeer", err)
	}
	for name, remote := range map[string][]byte{
		"nil":         nil,
		"short":       make([]byte, 31),
		"own":         aid.PublicKey(),
		"small-order": smallOrderKeys[2],
	} {
		if _, err := a.Dial(testCtx(t), addrPort(t, b), remote); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s key: got %v, want ErrInvalidArgument", name, err)
		}
	}
	a.Close()
	if _, err := a.Dial(testCtx(t), addrPort(t, b), bid.PublicKey()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Dial on a closed listener: got %v, want ErrClosed", err)
	}
}

func TestListenerDialCanceled(t *testing.T) {
	checkGoroutines(t)
	a := listen(t, newIdentity(t), nil)
	silent := rawListen(t)
	ap, err := netip.ParseAddrPort(silent.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	if _, err := a.Dial(ctx, ap, newIdentity(t).PublicKey()); err != context.Canceled {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestListenerDialOverListenConn(t *testing.T) {
	checkGoroutines(t)
	aid, bid := newIdentity(t), newIdentity(t)
	pa, pb := memPair()
	ta, err := kolotransport.ListenConn(testCtx(t), pa, nil)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := kolotransport.ListenConn(testCtx(t), pb, nil)
	if err != nil {
		ta.Close()
		t.Fatal(err)
	}
	a, b := wrap(t, ta, aid), wrap(t, tb, bid)

	c, err := b.Dial(testCtx(t), pa.addrPort(), aid.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if !bytes.Equal(c.RemotePublicKey(), aid.PublicKey()) {
		t.Fatal("dialer sees the wrong key")
	}
	if s := accept(t, a); !bytes.Equal(s.RemotePublicKey(), bid.PublicKey()) {
		t.Fatal("listener sees the wrong key")
	}
}

func TestConnContext(t *testing.T) {
	checkGoroutines(t)
	lid := newIdentity(t)
	l := listen(t, lid, nil)
	c := dial(t, l.Addr().String(), newIdentity(t), lid.PublicKey(), nil)
	s := accept(t, l)
	if err := s.Context().Err(); err != nil {
		t.Fatalf("context done on a live connection: %v", err)
	}
	c.CloseWithError(9, "bye")
	select {
	case <-s.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("context not canceled after the peer closed")
	}
	var e *kolotransport.Error
	if err := context.Cause(s.Context()); !errors.As(err, &e) || !errors.Is(err, kolotransport.ErrPeerClosed) || e.Code != 9 {
		t.Fatalf("cause %v, want ErrPeerClosed with code 9", err)
	}
}

func TestListenerDialAfterCloseHonorsContext(t *testing.T) {
	checkGoroutines(t)
	a := listen(t, newIdentity(t), nil)
	b := listen(t, newIdentity(t), nil)
	a.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Dial(ctx, addrPort(t, b), newIdentity(t).PublicKey()); err != context.Canceled {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestListenerDialBadAddress(t *testing.T) {
	checkGoroutines(t)
	tl, err := kolotransport.Listen(testCtx(t), "127.0.0.1:0", &kolotransport.Config{MaxDialed: 1})
	if err != nil {
		t.Fatal(err)
	}
	a := wrap(t, tl, newIdentity(t))
	bid := newIdentity(t)
	b := listen(t, bid, nil)
	peer := addrPort(t, b)
	mapped := netip.AddrPortFrom(netip.AddrFrom16(peer.Addr().As16()), peer.Port())
	for _, addr := range []netip.AddrPort{{}, netip.MustParseAddrPort("127.0.0.1:0"), netip.MustParseAddrPort("[::1]:1000"), mapped, netip.MustParseAddrPort("224.0.0.1:1000")} {
		_, err := a.Dial(testCtx(t), addr, bid.PublicKey())
		if !errors.Is(err, ErrInvalidArgument) || !errors.Is(err, kolotransport.ErrInvalidArgument) {
			t.Fatalf("%v: got %v, want ErrInvalidArgument from both packages", addr, err)
		}
	}
	// With MaxDialed 1, this fails if a bad address left a dialed connection behind.
	c, err := a.Dial(testCtx(t), addrPort(t, b), bid.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestAcceptSkipsDeadConn(t *testing.T) {
	checkGoroutines(t)
	l := listen(t, newIdentity(t), nil)
	deadClient, deadServer := rawPair(t)
	_, liveServer := rawPair(t)
	deadClient.Close()
	select {
	case <-deadServer.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("connection did not end")
	}
	live := &Conn{tc: liveServer}
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for _, c := range []*Conn{{tc: deadServer}, live} {
			select {
			case l.ready <- c:
			case <-l.ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-sent
	})
	c, err := l.Accept(testCtx(t))
	if err != nil || c != live {
		t.Fatalf("got %v, %v, want the live connection", c, err)
	}
}

func TestListenerCloseDuringDialHandshake(t *testing.T) {
	checkGoroutines(t)
	a := listen(t, newIdentity(t), nil)
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
	ap, err := netip.ParseAddrPort(silent.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	time.AfterFunc(200*time.Millisecond, func() { closed <- a.Close() })
	start := time.Now()
	_, err = a.Dial(ctx, ap, newIdentity(t).PublicKey())
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v, want ErrClosed", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Dial took %v", d)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
}

func TestListenerCloseDuringTransportDial(t *testing.T) {
	checkGoroutines(t)
	pa, pb := memPair()
	defer pb.Close()
	ta, err := kolotransport.ListenConn(testCtx(t), pa, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := wrap(t, ta, newIdentity(t))
	closed := make(chan error, 1)
	time.AfterFunc(200*time.Millisecond, func() { closed <- a.Close() })
	start := time.Now()
	// Nothing reads pb, so the QUIC handshake never completes.
	_, err = a.Dial(testCtx(t), pb.addrPort(), newIdentity(t).PublicKey())
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v, want ErrClosed", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Dial took %v", d)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
}

func TestTransportReadErrorStopsListener(t *testing.T) {
	checkGoroutines(t)
	pa, pb := memPair()
	defer pb.Close()
	ta, err := kolotransport.ListenConn(testCtx(t), pa, nil)
	if err != nil {
		t.Fatal(err)
	}
	l := wrap(t, ta, newIdentity(t))
	pa.readErr <- errors.New("socket broken")
	deadline := time.Now().Add(5 * time.Second)
	for l.ctx.Err() == nil {
		if time.Now().After(deadline) {
			t.Fatal("listener context still live after a read error")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := l.Accept(testCtx(t)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Accept: %v", err)
	}
	if _, err := l.Dial(testCtx(t), pb.addrPort(), newIdentity(t).PublicKey()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Dial: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
}
