package kolosecure

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"time"
)

// memConn is copied from kolo-transport's listener_test.go: one end of an in-memory datagram pipe that reports *net.UDPAddr addresses.
type memConn struct {
	local    *net.UDPAddr
	peer     *memConn
	in       chan memPacket
	readErr  chan error
	writeErr error
	done     chan struct{}
	once     sync.Once

	mu       sync.Mutex
	deadline time.Time
	kick     chan struct{}
}

type memPacket struct {
	data []byte
	from net.Addr
}

func newMemConn(ip net.IP, port int) *memConn {
	return &memConn{
		local:   &net.UDPAddr{IP: ip, Port: port},
		in:      make(chan memPacket, 256),
		readErr: make(chan error, 1),
		done:    make(chan struct{}),
		kick:    make(chan struct{}),
	}
}

func memPair() (*memConn, *memConn) {
	a, b := newMemConn(net.IPv4(10, 0, 0, 1).To4(), 1001), newMemConn(net.IPv4(10, 0, 0, 2).To4(), 1002)
	a.peer, b.peer = b, a
	return a, b
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func (c *memConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		deadline, kick := c.deadline, c.kick
		c.mu.Unlock()
		var timer <-chan time.Time
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, nil, timeoutError{}
			}
			timer = time.After(d)
		}
		select {
		case pk := <-c.in:
			return copy(p, pk.data), pk.from, nil
		case err := <-c.readErr:
			return 0, nil, err
		case <-c.done:
			return 0, nil, net.ErrClosed
		case <-kick:
		case <-timer:
		}
	}
}

func (c *memConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	select {
	case c.peer.in <- memPacket{data: bytes.Clone(p), from: c.local}:
	default:
	}
	return len(p), nil
}

func (c *memConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

func (c *memConn) LocalAddr() net.Addr              { return c.local }
func (c *memConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }
func (c *memConn) SetReadBuffer(int) error          { return nil }
func (c *memConn) SetWriteBuffer(int) error         { return nil }
func (c *memConn) addrPort() netip.AddrPort         { return c.local.AddrPort() }
func (c *memConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	close(c.kick)
	c.kick = make(chan struct{})
	c.mu.Unlock()
	return nil
}
