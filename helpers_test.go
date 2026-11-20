package kolosecure

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// checkGoroutines fails the test if goroutines started during it outlive its cleanups.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			var leaked []string
			for id, stack := range goroutines() {
				if _, ok := before[id]; !ok {
					leaked = append(leaked, stack)
				}
			}
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutines leaked:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func goroutines() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := make(map[string]string)
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if id, _, ok := strings.Cut(strings.TrimPrefix(stack, "goroutine "), " "); ok {
			out[id] = stack
		}
	}
	return out
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func shortCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func newIdentity(t *testing.T) *koloid.Identity {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func listen(t *testing.T, id *koloid.Identity, cfg *Config) *Listener {
	t.Helper()
	l, err := Listen(testCtx(t), "127.0.0.1:0", id, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func dial(t *testing.T, addr string, id *koloid.Identity, remote []byte, cfg *Config) *Conn {
	t.Helper()
	var c *Conn
	var err error
	if remote == nil {
		c, err = DialAny(testCtx(t), addr, id, cfg)
	} else {
		c, err = Dial(testCtx(t), addr, id, remote, cfg)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func accept(t *testing.T, l *Listener) *Conn {
	t.Helper()
	c, err := l.Accept(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func rawListen(t *testing.T) *kolotransport.Listener {
	t.Helper()
	l, err := kolotransport.Listen(testCtx(t), "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func rawDial(t *testing.T, addr string) *kolotransport.Conn {
	t.Helper()
	c, err := kolotransport.Dial(testCtx(t), addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func rawAccept(t *testing.T, l *kolotransport.Listener) *kolotransport.Conn {
	t.Helper()
	c, err := l.Accept(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// rawPair returns both ends of a kolo-transport connection with no kolo-secure handshake.
func rawPair(t *testing.T) (client, server *kolotransport.Conn) {
	t.Helper()
	l := rawListen(t)
	client = rawDial(t, l.Addr().String())
	server = rawAccept(t, l)
	return client, server
}

// runSecure runs the kolo-secure handshake on c in the background and returns its result.
func runSecure(t *testing.T, c *kolotransport.Conn, id *koloid.Identity, dialer bool, want []byte) <-chan error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	out := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := secure(ctx, c, defaultHandshakeTimeout, id, dialer, want)
		out <- err
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return out
}

func wait(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("timed out")
		return nil
	}
}

func ekm(t *testing.T, c *kolotransport.Conn) [32]byte {
	t.Helper()
	k, err := c.ExportKey(exporterLabel)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, id *koloid.Identity, msg []byte) []byte {
	t.Helper()
	sig, err := id.Sign(proofContext, msg)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func frame(body []byte) []byte {
	var b strings.Builder
	writeFrame(&b, body)
	return []byte(b.String())
}

func sendRaw(t *testing.T, c *kolotransport.Conn, data []byte) *kolotransport.Stream {
	t.Helper()
	s, err := c.OpenStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(data); err != nil {
		t.Fatal(err)
	}
	s.Close()
	return s
}

func readBody(t *testing.T, s *kolotransport.Stream) []byte {
	t.Helper()
	b, err := readFrame(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
