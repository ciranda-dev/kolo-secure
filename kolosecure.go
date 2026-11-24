package kolosecure

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

const failCode = 1

var errInvalidIdentity = fmt.Errorf("%w: nil or zero identity", ErrInvalidArgument)

// Listener accepts authenticated connections on one UDP socket.
type Listener struct {
	tl      *kolotransport.Listener
	id      *koloid.Identity
	timeout time.Duration
	slots   chan struct{}
	ready   chan *Conn
	done    chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	once    sync.Once
	err     error
}

// Listen opens a kolo-transport listener on addr, such as "127.0.0.1:0", and authenticates each connection as id.
func Listen(ctx context.Context, addr string, id *koloid.Identity, cfg *Config) (*Listener, error) {
	if id.PublicKey() == nil {
		return nil, errInvalidIdentity
	}
	c, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	tl, err := kolotransport.Listen(ctx, addr, c.Transport)
	if err != nil {
		return nil, wrapInvalid(err)
	}
	return newListener(tl, id, c), nil
}

// NewListener authenticates the connections of tl as id; it owns tl and closes it, also when it fails.
// cfg.Transport must be nil, since tl is already configured.
func NewListener(tl *kolotransport.Listener, id *koloid.Identity, cfg *Config) (*Listener, error) {
	if tl == nil {
		return nil, fmt.Errorf("%w: nil transport listener", ErrInvalidArgument)
	}
	fail := func(err error) (*Listener, error) {
		tl.Close()
		return nil, err
	}
	if id.PublicKey() == nil {
		return fail(errInvalidIdentity)
	}
	c, err := cfg.withDefaults()
	if err != nil {
		return fail(err)
	}
	if c.Transport != nil {
		return fail(fmt.Errorf("%w: Transport must be nil for NewListener", ErrInvalidConfig))
	}
	return newListener(tl, id, c), nil
}

func newListener(tl *kolotransport.Listener, id *koloid.Identity, c Config) *Listener {
	lctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		tl:      tl,
		id:      id,
		timeout: c.HandshakeTimeout,
		slots:   make(chan struct{}, c.MaxPending),
		ready:   make(chan *Conn),
		done:    make(chan struct{}),
		ctx:     lctx,
		cancel:  cancel,
	}
	l.wg.Add(1)
	go l.loop()
	return l
}

func (l *Listener) loop() {
	defer l.wg.Done()
	defer close(l.done)
	for {
		tc, err := l.tl.Accept(l.ctx)
		if err != nil {
			l.cancel()
			return
		}
		select {
		case l.slots <- struct{}{}:
			l.wg.Add(1)
			go l.serve(tc)
		default:
			tc.CloseWithError(failCode, "")
		}
	}
}

func (l *Listener) serve(tc *kolotransport.Conn) {
	defer l.wg.Done()
	defer func() { <-l.slots }()
	c, err := secure(l.ctx, tc, l.timeout, l.id, false, nil)
	if err != nil {
		return
	}
	select {
	case l.ready <- c:
	case <-tc.Context().Done():
	case <-l.ctx.Done():
		tc.Close()
	}
}

// Accept waits for the next connection whose peer has proved its identity; failed handshakes are skipped.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for {
		select {
		case c := <-l.ready:
			if l.ctx.Err() != nil {
				c.Close()
				return nil, ErrClosed
			}
			if c.tc.Context().Err() != nil {
				continue
			}
			return c, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-l.done:
			return nil, ErrClosed
		}
	}
}

// Dial connects to addr from the listener's socket (kolo-transport MaxDialed bounds these) and returns once the peer has proved it holds remote.
// remote is checked as in Dial, and the dialer's proof is checked by the peer after Dial returns.
func (l *Listener) Dial(ctx context.Context, addr netip.AddrPort, remote ed25519.PublicKey) (*Conn, error) {
	if err := checkRemote(l.id.PublicKey(), remote); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if l.ctx.Err() != nil {
		return nil, ErrClosed
	}
	tc, err := l.tl.Dial(ctx, addr)
	switch {
	case err == nil:
	case errors.Is(err, kolotransport.ErrInvalidArgument):
		return nil, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	case l.ctx.Err() != nil && ctx.Err() == nil:
		return nil, ErrClosed
	default:
		return nil, err
	}
	c, err := secure(ctx, tc, l.timeout, l.id, true, bytes.Clone(remote))
	if err != nil && l.ctx.Err() != nil && ctx.Err() == nil {
		return nil, ErrClosed
	}
	return c, err
}

// Addr returns the local address of the listener.
func (l *Listener) Addr() net.Addr { return l.tl.Addr() }

// Close stops accepting, ends pending handshakes and closes every connection of the listener, accepted or not.
// It is safe to call more than once.
func (l *Listener) Close() error {
	l.once.Do(func() {
		l.cancel()
		l.err = l.tl.Close()
		l.wg.Wait()
	})
	return l.err
}

// Dial connects to addr as id and returns once the listener has proved it holds remote.
// The listener checks the dialer's proof after Dial returns; if it rejects it, the connection closes with code 1.
func Dial(ctx context.Context, addr string, id *koloid.Identity, remote ed25519.PublicKey, cfg *Config) (*Conn, error) {
	local := id.PublicKey()
	if local == nil {
		return nil, errInvalidIdentity
	}
	if err := checkRemote(local, remote); err != nil {
		return nil, err
	}
	return connect(ctx, addr, id, bytes.Clone(remote), cfg)
}

// DialAny is like Dial but accepts any listener key; check RemotePublicKey before trusting the connection.
func DialAny(ctx context.Context, addr string, id *koloid.Identity, cfg *Config) (*Conn, error) {
	if id.PublicKey() == nil {
		return nil, errInvalidIdentity
	}
	return connect(ctx, addr, id, nil, cfg)
}

func wrapInvalid(err error) error {
	if errors.Is(err, kolotransport.ErrInvalidArgument) {
		return fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	return err
}

func checkRemote(local, remote ed25519.PublicKey) error {
	switch {
	case len(remote) != ed25519.PublicKeySize:
		return fmt.Errorf("%w: remote key must be %d bytes", ErrInvalidArgument, ed25519.PublicKeySize)
	case bytes.Equal(remote, local) || smallOrder(remote):
		return fmt.Errorf("%w: remote key is the local key or a small-order point", ErrInvalidArgument)
	}
	return nil
}

func connect(ctx context.Context, addr string, id *koloid.Identity, remote ed25519.PublicKey, cfg *Config) (*Conn, error) {
	c, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	tc, err := kolotransport.Dial(ctx, addr, c.Transport)
	if err != nil {
		return nil, wrapInvalid(err)
	}
	return secure(ctx, tc, c.HandshakeTimeout, id, true, remote)
}

func secure(ctx context.Context, tc *kolotransport.Conn, timeout time.Duration, id *koloid.Identity, dialer bool, want ed25519.PublicKey) (*Conn, error) {
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	peer, err := handshake(hctx, tc, id, dialer, want)
	if err != nil {
		tc.CloseWithError(failCode, "")
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if hctx.Err() != nil && (errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)) {
			return nil, ErrTimeout
		}
		return nil, err
	}
	return &Conn{tc: tc, remote: peer}, nil
}

func handshake(ctx context.Context, tc *kolotransport.Conn, id *koloid.Identity, dialer bool, want ed25519.PublicKey) (ed25519.PublicKey, error) {
	ekm, err := tc.ExportKey(exporterLabel)
	if err != nil {
		return nil, err
	}
	var s *kolotransport.Stream
	if dialer {
		s, err = tc.OpenStream(ctx)
	} else {
		s, err = tc.AcceptStream(ctx)
	}
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { s.SetDeadline(time.Now()) })
	defer stop()
	if dialer {
		return dialerHandshake(s, id, ekm, want)
	}
	return listenerHandshake(s, id, ekm)
}

// Conn is a connection whose peer has proved it holds RemotePublicKey.
type Conn struct {
	tc     *kolotransport.Conn
	remote ed25519.PublicKey
}

// RemotePublicKey returns a copy of the peer's kolo-id public key.
func (c *Conn) RemotePublicKey() ed25519.PublicKey { return bytes.Clone(c.remote) }

// OpenStream opens a bidirectional stream, as kolotransport.Conn.OpenStream.
func (c *Conn) OpenStream(ctx context.Context) (*kolotransport.Stream, error) {
	return c.tc.OpenStream(ctx)
}

// AcceptStream waits for the next bidirectional stream opened by the peer.
func (c *Conn) AcceptStream(ctx context.Context) (*kolotransport.Stream, error) {
	return c.tc.AcceptStream(ctx)
}

// OpenUniStream opens a unidirectional stream, as kolotransport.Conn.OpenUniStream.
func (c *Conn) OpenUniStream(ctx context.Context) (*kolotransport.SendStream, error) {
	return c.tc.OpenUniStream(ctx)
}

// AcceptUniStream waits for the next unidirectional stream opened by the peer.
func (c *Conn) AcceptUniStream(ctx context.Context) (*kolotransport.ReceiveStream, error) {
	return c.tc.AcceptUniStream(ctx)
}

// AllowWindowGrowth marks the connection as trusted for kolo-transport window growth, as kolotransport.Conn.AllowWindowGrowth.
// Call it once your own policy admits RemotePublicKey. It reports false when Config.Transport.WindowGrowth is off or the connection has ended.
func (c *Conn) AllowWindowGrowth() bool { return c.tc.AllowWindowGrowth() }

// Stats returns the connection's statistics as kolo-transport measures them, handshake and streams together.
// It is cheap, never blocks, is safe from any goroutine and is the zero value once the connection has ended.
func (c *Conn) Stats() kolotransport.ConnStats { return c.tc.Stats() }

// SupportsDatagrams reports whether both ends set Config.Transport.Datagrams, as kolotransport.Conn.SupportsDatagrams.
func (c *Conn) SupportsDatagrams() bool { return c.tc.SupportsDatagrams() }

// SendDatagram queues p as one QUIC datagram and never blocks, as kolotransport.Conn.SendDatagram.
func (c *Conn) SendDatagram(p []byte) error { return c.tc.SendDatagram(p) }

// ReceiveDatagram waits for the next datagram from the peer, as kolotransport.Conn.ReceiveDatagram.
func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) { return c.tc.ReceiveDatagram(ctx) }

// Context is canceled when the connection ends; its context.Cause is a kolo-transport error with no peer text.
func (c *Conn) Context() context.Context { return c.tc.Context() }

// LocalAddr returns the local UDP address.
func (c *Conn) LocalAddr() net.Addr { return c.tc.LocalAddr() }

// RemoteAddr returns the peer's UDP address.
func (c *Conn) RemoteAddr() net.Addr { return c.tc.RemoteAddr() }

// Close closes the connection with code 0.
func (c *Conn) Close() error { return c.tc.Close() }

// CloseWithError closes the connection, sending code and msg to the peer, as kolotransport.Conn.CloseWithError.
func (c *Conn) CloseWithError(code uint64, msg string) error { return c.tc.CloseWithError(code, msg) }
