package kolosecure

import (
	"context"
	"errors"
	"testing"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// exchange sends p from one end until the other receives it: a datagram may be lost, even on loopback.
func exchange(t *testing.T, from, to *Conn, p string) {
	t.Helper()
	for range 50 {
		if err := from.SendDatagram([]byte(p)); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(testCtx(t), 200*time.Millisecond)
		got, err := to.ReceiveDatagram(ctx)
		cancel()
		if err == nil {
			if string(got) != p {
				t.Fatalf("received %q, want %q", got, p)
			}
			return
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	}
	t.Fatal("datagram never arrived")
}

func TestDatagrams(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)
	on := &Config{Transport: &kolotransport.Config{Datagrams: true}}
	l := listen(t, lid, on)
	client := dial(t, l.Addr().String(), did, lid.PublicKey(), on)
	server := accept(t, l)
	if !client.SupportsDatagrams() || !server.SupportsDatagrams() {
		t.Fatal("datagrams not supported with both ends on")
	}
	exchange(t, client, server, "ping")
	exchange(t, server, client, "pong")
}

func TestDatagramsNeedBothEnds(t *testing.T) {
	checkGoroutines(t)
	lid, did := newIdentity(t), newIdentity(t)
	l := listen(t, lid, &Config{Transport: &kolotransport.Config{Datagrams: true}})
	client := dial(t, l.Addr().String(), did, lid.PublicKey(), nil)
	server := accept(t, l)
	for _, c := range []*Conn{client, server} {
		if c.SupportsDatagrams() {
			t.Fatal("SupportsDatagrams is true with one end off")
		}
		if err := c.SendDatagram([]byte("x")); !errors.Is(err, kolotransport.ErrDatagramsUnsupported) {
			t.Fatalf("SendDatagram: %v", err)
		}
		if _, err := c.ReceiveDatagram(testCtx(t)); !errors.Is(err, kolotransport.ErrDatagramsUnsupported) {
			t.Fatalf("ReceiveDatagram: %v", err)
		}
	}
}
