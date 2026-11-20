package kolosecure

import (
	"bytes"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
)

func FuzzDecode(f *testing.F) {
	key := bytes.Repeat([]byte{3}, 32)
	sig := bytes.Repeat([]byte{4}, 64)
	f.Add(uint8(0), encodeHello(key))
	f.Add(uint8(1), encodeProof(key, sig))
	f.Add(uint8(2), encodeFinish(sig))
	f.Add(uint8(0), []byte{typeHello, 0x80, 0x00})
	f.Add(uint8(1), []byte{})
	f.Fuzz(func(t *testing.T, kind uint8, in []byte) {
		var out []byte
		switch kind % 3 {
		case 0:
			k, err := decodeHello(in)
			if err != nil {
				return
			}
			out = encodeHello(k)
		case 1:
			k, s, err := decodeProof(in)
			if err != nil {
				return
			}
			out = encodeProof(k, s)
		case 2:
			s, err := decodeFinish(in)
			if err != nil {
				return
			}
			out = encodeFinish(s)
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("decoded %x but re-encodes to %x", in, out)
		}
	})
}

func FuzzReadFrame(f *testing.F) {
	f.Add(frame(encodeHello(make([]byte, 32))))
	f.Add([]byte{0x81, 0x02})
	f.Add([]byte{0x80, 0x02, 1, 2})
	f.Add([]byte{0xff, 0xff, 0xff, 0x0f})
	f.Fuzz(func(t *testing.T, in []byte) {
		body, err := readFrame(bytes.NewReader(in))
		if err != nil {
			return
		}
		if len(body) == 0 || len(body) > maxMessageSize {
			t.Fatalf("frame of %d bytes accepted", len(body))
		}
		if !bytes.HasPrefix(in, frame(body)) {
			t.Fatalf("frame %x is not a prefix of %x", frame(body), in)
		}
	})
}

type memStream struct {
	*bytes.Reader
	bytes.Buffer
}

func (m *memStream) Read(p []byte) (int, error)  { return m.Reader.Read(p) }
func (m *memStream) Write(p []byte) (int, error) { return m.Buffer.Write(p) }
func (m *memStream) Close() error                { return nil }

func FuzzHandshake(f *testing.F) {
	lid, err := koloid.FromSeed(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		f.Fatal(err)
	}
	did, err := koloid.FromSeed(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		f.Fatal(err)
	}
	var ekm [32]byte
	sigL, err := lid.Sign(proofContext, transcript(roleListener, ekm, did.PublicKey(), lid.PublicKey()))
	if err != nil {
		f.Fatal(err)
	}
	sigD, err := did.Sign(proofContext, transcript(roleDialer, ekm, did.PublicKey(), lid.PublicKey()))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(false, append(frame(encodeHello(did.PublicKey())), frame(encodeFinish(sigD))...))
	f.Add(true, frame(encodeProof(lid.PublicKey(), sigL)))
	f.Add(false, frame(encodeHello(smallOrderKeys[2])))
	f.Fuzz(func(t *testing.T, dialer bool, in []byte) {
		var ekm [32]byte
		ekm[0] = 1
		s := &memStream{Reader: bytes.NewReader(in)}
		var err error
		if dialer {
			_, err = dialerHandshake(s, did, ekm, nil)
		} else {
			_, err = listenerHandshake(s, lid, ekm)
		}
		if err == nil {
			t.Fatalf("handshake on a fresh exporter accepted %x", in)
		}
	})
}
