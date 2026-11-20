package kolosecure

import (
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func growthCfg() *Config {
	return &Config{Transport: &kolotransport.Config{WindowGrowth: true}}
}

// delayLink relays UDP from a loopback socket to target with a fixed one-way delay each way, so every test sees the same round trip.
// A window grows only when it is read faster than a few round trips, and plain loopback has none to speak of.
func delayLink(t *testing.T, target string, oneWay time.Duration) string {
	t.Helper()
	dst, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	type packet struct {
		from *net.UDPAddr
		data []byte
		at   time.Time
	}
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		closed bool
		up     = map[string]*net.UDPConn{}
		upQ    = make(chan packet, 8192)
		downQ  = make(chan packet, 8192)
		done   = make(chan struct{})
	)
	push := func(q chan packet, p packet) {
		p.at = time.Now().Add(oneWay)
		select {
		case q <- p:
		default:
		}
	}
	drain := func(q chan packet, send func(packet)) {
		defer wg.Done()
		for {
			select {
			case p := <-q:
				select {
				case <-time.After(time.Until(p.at)):
					send(p)
				case <-done:
					return
				}
			case <-done:
				return
			}
		}
	}
	upstream := func(from *net.UDPAddr) *net.UDPConn {
		mu.Lock()
		defer mu.Unlock()
		if c := up[from.String()]; c != nil || closed {
			return c
		}
		c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, dst)
		if err != nil {
			return nil
		}
		up[from.String()] = c
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				push(downQ, packet{from: from, data: append([]byte(nil), buf[:n]...)})
			}
		}()
		return c
	}
	wg.Add(3)
	go drain(upQ, func(p packet) {
		if c := upstream(p.from); c != nil {
			c.Write(p.data)
		}
	})
	go drain(downQ, func(p packet) { front.WriteToUDP(p.data, p.from) })
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			upstream(from)
			push(upQ, packet{from: from, data: append([]byte(nil), buf[:n]...)})
		}
	}()
	t.Cleanup(func() {
		close(done)
		front.Close()
		mu.Lock()
		closed = true
		for _, c := range up {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return front.LocalAddr().String()
}

// pump sends size bytes from sender on a new stream and has receiver read them all at once, the traffic that makes the windows grow.
func pump(t *testing.T, sender, receiver *Conn, size int) {
	t.Helper()
	ctx := testCtx(t)
	st, err := sender.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 64<<10)
		for left := size; left > 0; left -= len(buf) {
			if _, err := st.Write(buf[:min(len(buf), left)]); err != nil {
				return
			}
		}
		st.Close()
	}()
	rs, err := receiver.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := io.Copy(io.Discard, rs); err != nil || int(n) != size {
		t.Fatalf("read %d of %d bytes: %v", n, size, err)
	}
}

// credit is how many bytes writer can put into its peer's connection while the peer reads nothing.
func credit(t *testing.T, writer *Conn) int {
	t.Helper()
	n, streams := probe(t, writer)
	for _, w := range streams {
		w.Close()
	}
	return n
}

// probe writes on six streams at once, each with its own credit, until the peer's connection window blocks them, and
// returns what they took and the open streams.
func probe(t *testing.T, writer *Conn) (int, []*kolotransport.Stream) {
	t.Helper()
	ctx := testCtx(t)
	var streams []*kolotransport.Stream
	for range 6 {
		w, err := writer.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, w)
	}
	var sent atomic.Int64
	var wg sync.WaitGroup
	deadline := time.Now().Add(time.Second)
	for _, w := range streams {
		wg.Go(func() {
			w.SetWriteDeadline(deadline)
			n, err := w.Write(make([]byte, 1<<20))
			if err != os.ErrDeadlineExceeded {
				t.Errorf("write: %v", err)
			}
			sent.Add(int64(n))
		})
	}
	wg.Wait()
	return int(sent.Load()), streams
}

// growWait bounds how long a test waits for a window to grow. quic-go doubles a window only when the reader consumes it
// within about three round trips, which a busy machine can delay for a long time but not prevent for good.
const growWait = 60 * time.Second

// growCredit pumps from sender to receiver, read as fast as it comes, and measures sender's credit after each round
// until it is above min or growWait has passed. A window never shrinks, so a slow round only costs another round.
func growCredit(t *testing.T, sender, receiver *Conn, min int) int {
	t.Helper()
	deadline := time.Now().Add(growWait)
	for {
		pump(t, sender, receiver, 8<<20)
		n, streams := probe(t, sender)
		for _, w := range streams {
			w.Close()
		}
		if n > min || !time.Now().Before(deadline) {
			return n
		}
		ctx := testCtx(t)
		for range streams {
			rs, err := receiver.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, rs)
		}
	}
}

// linkDelay is the one-way delay of the growth tests: at a 50 ms round trip a reader of about 5 MB/s doubles a 1 MiB window,
// well under what the loopback gives even on a busy machine.
const linkDelay = 25 * time.Millisecond

func TestAllowWindowGrowthIsOffByDefault(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)
	l := listen(t, lid, nil)
	client := dial(t, delayLink(t, l.Addr().String(), linkDelay), did, lid.PublicKey(), nil)
	server := accept(t, l)
	if client.AllowWindowGrowth() || server.AllowWindowGrowth() {
		t.Fatal("AllowWindowGrowth succeeded with WindowGrowth off")
	}
	pump(t, client, server, 6<<20)
	if n := credit(t, client); n > 512<<10 {
		t.Fatalf("a peer wrote %d bytes into a 512 KiB connection window", n)
	}
}

func TestAllowWindowGrowthDelegates(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)
	l := listen(t, lid, growthCfg())
	client := dial(t, delayLink(t, l.Addr().String(), linkDelay), did, lid.PublicKey(), growthCfg())
	server := accept(t, l)
	for range 2 {
		if !server.AllowWindowGrowth() || !client.AllowWindowGrowth() {
			t.Fatal("AllowWindowGrowth is false or not idempotent")
		}
	}
	if n := growCredit(t, client, server, 1<<20); n <= 1<<20 {
		t.Fatalf("the accepted Conn took only %d bytes: its window did not grow", n)
	}
	if n := growCredit(t, server, client, 1<<20); n <= 1<<20 {
		t.Fatalf("the dialed Conn took only %d bytes: its window did not grow", n)
	}
}

func TestAllowWindowGrowthIsPerConn(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)
	l := listen(t, lid, growthCfg())
	client := dial(t, delayLink(t, l.Addr().String(), linkDelay), did, lid.PublicKey(), growthCfg())
	server := accept(t, l)
	if !server.AllowWindowGrowth() {
		t.Fatal("AllowWindowGrowth is false")
	}
	if n := growCredit(t, client, server, 1<<20); n <= 1<<20 {
		t.Fatalf("the marked Conn took only %d bytes: its window did not grow", n)
	}
	pump(t, server, client, 8<<20)
	if n := credit(t, server); n > 512<<10 {
		t.Fatalf("the unmarked Conn took %d bytes into a 512 KiB connection window", n)
	}
}

func TestListenerDialAllowsGrowth(t *testing.T) {
	checkGoroutines(t)
	a, b := newIdentity(t), newIdentity(t)
	la, lb := listen(t, a, growthCfg()), listen(t, b, growthCfg())
	ap, err := netip.ParseAddrPort(delayLink(t, lb.Addr().String(), linkDelay))
	if err != nil {
		t.Fatal(err)
	}
	c, err := la.Dial(testCtx(t), ap, b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s := accept(t, lb)
	if !c.AllowWindowGrowth() {
		t.Fatal("a Conn from Listener.Dial cannot be marked")
	}
	if n := growCredit(t, s, c, 1<<20); n <= 1<<20 {
		t.Fatalf("the Conn from Listener.Dial took only %d bytes: its window did not grow", n)
	}
}

func TestUnmarkedConnNeverGrows(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)
	l := listen(t, lid, growthCfg())
	client := dial(t, delayLink(t, l.Addr().String(), linkDelay), did, lid.PublicKey(), growthCfg())
	server := accept(t, l)
	pump(t, client, server, 8<<20)
	pump(t, server, client, 8<<20)
	if n := credit(t, client); n > 512<<10 {
		t.Fatalf("an unmarked Conn took %d bytes into a 512 KiB connection window", n)
	}
	if n := credit(t, server); n > 512<<10 {
		t.Fatalf("an unmarked Conn took %d bytes into a 512 KiB connection window", n)
	}
}

func TestAllowWindowGrowthAfterClose(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)
	l := listen(t, lid, growthCfg())
	client := dial(t, l.Addr().String(), did, lid.PublicKey(), growthCfg())
	server := accept(t, l)
	server.Close()
	client.Close()
	if server.AllowWindowGrowth() || client.AllowWindowGrowth() {
		t.Fatal("a closed Conn was marked")
	}
}
