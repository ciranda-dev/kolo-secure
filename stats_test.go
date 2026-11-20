package kolosecure

import (
	"io"
	"net/netip"
	"testing"

	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func TestStatsOfEveryKindOfConnection(t *testing.T) {
	checkGoroutines(t)
	for _, cc := range []string{"reno", "cubic", "bbr"} {
		t.Run(cc, func(t *testing.T) {
			cfg := &Config{Transport: &kolotransport.Config{CongestionControl: cc}}
			srvID, cliID := newIdentity(t), newIdentity(t)
			l := listen(t, srvID, cfg)
			dialed := dial(t, l.Addr().String(), cliID, srvID.PublicKey(), cfg)
			accepted := accept(t, l)
			anyDialed := dial(t, l.Addr().String(), cliID, nil, cfg)
			accept(t, l)
			other := listen(t, cliID, cfg)
			ap, err := netip.ParseAddrPort(l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			fromListener, err := other.Dial(testCtx(t), ap, srvID.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { fromListener.Close() })
			accept(t, l)

			for name, c := range map[string]*Conn{"Dial": dialed, "Accept": accepted, "DialAny": anyDialed, "Listener.Dial": fromListener} {
				s := c.Stats()
				if s.CongestionController != cc {
					t.Errorf("%s: controller %q, want %q", name, s.CongestionController, cc)
				}
				if s.SmoothedRTT <= 0 || s.MinRTT <= 0 || s.CongestionWindow == 0 || s.MaxDatagramSize == 0 {
					t.Errorf("%s: %+v", name, s)
				}
				if s.BytesSent == 0 || s.BytesReceived == 0 || s.PacketsSent == 0 || s.PacketsReceived == 0 {
					t.Errorf("%s: the handshake left no traffic in %+v", name, s)
				}
			}
		})
	}
}

func TestStatsCountStreamTrafficAndEndWithTheConnection(t *testing.T) {
	checkGoroutines(t)
	srvID, cliID := newIdentity(t), newIdentity(t)
	l := listen(t, srvID, nil)
	client := dial(t, l.Addr().String(), cliID, srvID.PublicKey(), nil)
	server := accept(t, l)
	before := server.Stats()

	const size = 256 << 10
	ctx := testCtx(t)
	st, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		st.Write(make([]byte, size))
		st.Close()
	}()
	rx, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := io.Copy(io.Discard, rx); err != nil || n != size {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	if got := server.Stats().BytesReceived - before.BytesReceived; got < size {
		t.Fatalf("the server counted %d new bytes for a %d byte stream", got, size)
	}

	client.Close()
	if s := client.Stats(); s != (kolotransport.ConnStats{}) {
		t.Fatalf("closed end: %+v", s)
	}
	<-server.Context().Done()
	if s := server.Stats(); s != (kolotransport.ConnStats{}) {
		t.Fatalf("end the peer closed: %+v", s)
	}
}
