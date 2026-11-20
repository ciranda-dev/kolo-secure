package kolosecure

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// toListener sends raw bytes as the dialer's side of the handshake stream and returns the listener's error.
func toListener(t *testing.T, raw []byte) error {
	t.Helper()
	client, server := rawPair(t)
	result := runSecure(t, server, newIdentity(t), false, nil)
	sendRaw(t, client, raw)
	return wait(t, result)
}

// toDialer answers the dialer's hello with raw bytes and returns the dialer's error.
func toDialer(t *testing.T, raw []byte) error {
	t.Helper()
	client, server := rawPair(t)
	result := runSecure(t, client, newIdentity(t), true, nil)
	s, err := server.AcceptStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, s)
	s.Write(raw)
	s.Close()
	return wait(t, result)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func body(fields ...any) []byte {
	var e kolocodec.Encoder
	for _, f := range fields {
		switch v := f.(type) {
		case int:
			e.PutUvarint(uint64(v))
		case []byte:
			e.PutFixed(v)
		}
	}
	return e.Bytes()
}

func TestMalformedMessages(t *testing.T) {
	checkGoroutines(t)
	key := bytes.Repeat([]byte{9}, 32)
	sig := make([]byte, 64)
	hello := frame(encodeHello(key))

	toL := map[string][]byte{
		"nothing":            nil,
		"empty frame":        {0x00},
		"length 257":         {0x81, 0x02},
		"3-byte length":      {0x80, 0x80, 0x01},
		"non-canonical":      {0x80, 0x00},
		"length only":        {0x22},
		"truncated":          hello[:10],
		"wrong type":         frame(encodeFinish(sig)),
		"unknown type":       frame(body(9, 0, key)),
		"huge type":          frame(bytes.Repeat([]byte{0xff}, 12)),
		"short key":          frame(body(typeHello, version, key[:31])),
		"trailing in body":   frame(cat(encodeHello(key), []byte{0})),
		"no finish":          hello,
		"finish wrong type":  cat(hello, frame(encodeHello(key))),
		"short finish":       cat(hello, frame(body(typeFinish, sig[:63]))),
		"bytes after finish": cat(hello, frame(encodeFinish(sig)), []byte{0}),
	}
	for name, raw := range toL {
		t.Run("listener/"+name, func(t *testing.T) {
			if err := toListener(t, raw); !errors.Is(err, ErrProtocol) {
				t.Fatalf("got %v, want ErrProtocol", err)
			}
		})
	}

	toD := map[string][]byte{
		"nothing":          nil,
		"empty frame":      {0x00},
		"length 257":       {0x81, 0x02},
		"truncated":        frame(encodeProof(key, sig))[:40],
		"wrong type":       frame(encodeHello(key)),
		"short signature":  frame(body(typeProof, version, key, sig[:63])),
		"trailing in body": frame(cat(encodeProof(key, sig), []byte{0})),
		"bytes after":      cat(frame(encodeProof(key, sig)), []byte{0}),
	}
	for name, raw := range toD {
		t.Run("dialer/"+name, func(t *testing.T) {
			if err := toDialer(t, raw); !errors.Is(err, ErrProtocol) {
				t.Fatalf("got %v, want ErrProtocol", err)
			}
		})
	}
}

func TestBadSignature(t *testing.T) {
	checkGoroutines(t)
	key := newIdentity(t).PublicKey()
	sig := make([]byte, 64)
	hello := frame(encodeHello(key))
	if err := toListener(t, cat(hello, frame(encodeFinish(sig)))); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("listener: got %v, want ErrAuthentication", err)
	}
	if err := toDialer(t, frame(encodeProof(key, sig))); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("dialer: got %v, want ErrAuthentication", err)
	}
}

func TestUnsupportedVersion(t *testing.T) {
	checkGoroutines(t)
	key := newIdentity(t).PublicKey()
	sig := make([]byte, 64)
	for _, v := range []int{1, 2, 1 << 20} {
		if err := toListener(t, frame(body(typeHello, v, key))); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("listener, version %d: got %v", v, err)
		}
		if err := toListener(t, frame(body(typeHello, v))); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("listener, version %d with another layout: got %v", v, err)
		}
		if err := toDialer(t, frame(body(typeProof, v, key, sig))); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("dialer, version %d: got %v", v, err)
		}
	}
}

const largeCode = 1234567890123

func TestErrorsHaveNoPeerContent(t *testing.T) {
	checkGoroutines(t)
	marker := []byte("PEERTEXT-PEERTEXT-PEERTEXT-PEERT")
	sig := bytes.Repeat(marker, 2)
	cases := map[string]func(t *testing.T) error{
		"listener protocol": func(t *testing.T) error { return toListener(t, frame(cat(encodeHello(marker), marker))) },
		"listener version":  func(t *testing.T) error { return toListener(t, frame(body(typeHello, 7, marker))) },
		"listener auth": func(t *testing.T) error {
			return toListener(t, cat(frame(encodeHello(marker)), frame(encodeFinish(sig))))
		},
		"dialer protocol": func(t *testing.T) error { return toDialer(t, frame(cat(marker, marker))) },
		"dialer auth":     func(t *testing.T) error { return toDialer(t, frame(encodeProof(marker, sig))) },
		"dialer key": func(t *testing.T) error {
			client, server := rawPair(t)
			result := runSecure(t, client, newIdentity(t), true, newIdentity(t).PublicKey())
			s, err := server.AcceptStream(testCtx(t))
			if err != nil {
				t.Fatal(err)
			}
			readBody(t, s)
			s.Write(frame(encodeProof(marker, sig)))
			s.Close()
			return wait(t, result)
		},
		"peer closes with a message": func(t *testing.T) error {
			client, server := rawPair(t)
			result := runSecure(t, client, newIdentity(t), true, nil)
			s, err := server.AcceptStream(testCtx(t))
			if err != nil {
				t.Fatal(err)
			}
			readBody(t, s)
			server.CloseWithError(7, string(marker))
			return wait(t, result)
		},
		"peer closes with a large code": func(t *testing.T) error {
			client, server := rawPair(t)
			result := runSecure(t, client, newIdentity(t), true, nil)
			s, err := server.AcceptStream(testCtx(t))
			if err != nil {
				t.Fatal(err)
			}
			readBody(t, s)
			server.CloseWithError(largeCode, string(marker))
			err = wait(t, result)
			var e *kolotransport.Error
			if !errors.As(err, &e) || e.Code != largeCode || !strings.Contains(err.Error(), "1234567890123") {
				t.Fatalf("got %v, want the numeric code %d", err, uint64(largeCode))
			}
			return err
		},
	}
	sentinels := []error{
		ErrProtocol, ErrUnsupportedVersion, ErrUnexpectedPeer, ErrAuthentication, ErrTimeout,
		kolotransport.ErrPeerClosed,
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			err := run(t)
			if err == nil {
				t.Fatal("no error")
			}
			msg := err.Error()
			for _, bad := range []string{"PEERTEXT", hex.EncodeToString(marker[:8]), fmt.Sprintf("%x", marker[:8])} {
				if strings.Contains(msg, bad) {
					t.Fatalf("error %q contains peer content", msg)
				}
			}
			known := false
			for _, s := range sentinels {
				known = known || errors.Is(err, s)
			}
			if !known {
				t.Fatalf("error %q is not a sentinel", msg)
			}
		})
	}
}

// stdVerify is crypto/ed25519 without kolo-id's small-order check, to show the forgery is real.
func stdVerify(pub, msg, sig []byte) bool {
	return ed25519.VerifyWithOptions(pub, msg, sig, &ed25519.Options{Context: proofContext}) == nil
}

func TestSmallOrderTable(t *testing.T) {
	if len(smallOrderKeys) != 14 {
		t.Fatalf("%d small-order encodings, want 14", len(smallOrderKeys))
	}
	seen := map[string]bool{}
	for _, k := range smallOrderKeys {
		if len(k) != ed25519.PublicKeySize || seen[string(k)] {
			t.Fatalf("bad entry %x", k)
		}
		seen[string(k)] = true
		if !smallOrder(k) {
			t.Fatalf("%x not detected", k)
		}
	}
	// Every listed key admits a signature made without any private key: R a small-order point, S = 0.
	for _, pub := range smallOrderKeys {
		forged := false
		for i := 0; i < 64 && !forged; i++ {
			msg := []byte{byte(i)}
			for _, r := range smallOrderKeys {
				sig := append(bytes.Clone(r), make([]byte, 32)...)
				if stdVerify(pub, msg, sig) {
					if koloid.Verify(pub, proofContext, msg, sig) {
						t.Fatalf("kolo-id accepts a forgery for %x", pub)
					}
					forged = true
					break
				}
			}
		}
		if !forged {
			t.Errorf("no forgery found for %x", pub)
		}
	}
	for range 1000 {
		if smallOrder(newIdentity(t).PublicKey()) {
			t.Fatal("a generated key is listed")
		}
	}
}

func TestTranscriptBindsEveryField(t *testing.T) {
	a, b := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	var k1, k2 [32]byte
	k2[0] = 1
	base := transcript(roleDialer, k1, a, b)
	for name, other := range map[string][]byte{
		"role":     transcript(roleListener, k1, a, b),
		"exporter": transcript(roleDialer, k2, a, b),
		"keys":     transcript(roleDialer, k1, b, a),
	} {
		if bytes.Equal(base, other) {
			t.Errorf("%s does not change the transcript", name)
		}
	}
	want := cat([]byte{version, roleDialer}, k1[:], a, b)
	if !bytes.Equal(base, want) {
		t.Fatalf("transcript %x, want %x", base, want)
	}
}

func TestWireFormat(t *testing.T) {
	key := bytes.Repeat([]byte{0xaa}, 32)
	sig := bytes.Repeat([]byte{0xbb}, 64)
	cases := map[string]struct{ got, want []byte }{
		"hello":  {frame(encodeHello(key)), cat([]byte{34, typeHello, version}, key)},
		"proof":  {frame(encodeProof(key, sig)), cat([]byte{98, typeProof, version}, key, sig)},
		"finish": {frame(encodeFinish(sig)), cat([]byte{65, typeFinish}, sig)},
	}
	for name, c := range cases {
		if !bytes.Equal(c.got, c.want) {
			t.Errorf("%s: %x, want %x", name, c.got, c.want)
		}
	}
}

func TestRoleSeparatesProofs(t *testing.T) {
	listener, dialer := newIdentity(t), newIdentity(t)
	var ekm [32]byte
	fromListener, err := listener.Sign(proofContext, transcript(roleListener, ekm, dialer.PublicKey(), listener.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	fromDialer, err := dialer.Sign(proofContext, transcript(roleDialer, ekm, dialer.PublicKey(), listener.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	asDialer := transcript(roleDialer, ekm, dialer.PublicKey(), listener.PublicKey())
	asListener := transcript(roleListener, ekm, dialer.PublicKey(), listener.PublicKey())
	if !koloid.Verify(listener.PublicKey(), proofContext, asListener, fromListener) {
		t.Fatal("listener proof does not verify as listener")
	}
	if koloid.Verify(listener.PublicKey(), proofContext, asDialer, fromListener) {
		t.Fatal("listener proof verifies as a dialer finish")
	}
	if !koloid.Verify(dialer.PublicKey(), proofContext, asDialer, fromDialer) {
		t.Fatal("dialer finish does not verify as dialer")
	}
	if koloid.Verify(dialer.PublicKey(), proofContext, asListener, fromDialer) {
		t.Fatal("dialer finish verifies as a listener proof")
	}
}

func TestKoloIDRefusesEverySmallOrderKey(t *testing.T) {
	for _, pub := range smallOrderKeys {
		for _, r := range smallOrderKeys {
			sig := append(bytes.Clone(r), make([]byte, 32)...)
			for i := range 8 {
				if koloid.Verify(pub, proofContext, []byte{byte(i)}, sig) {
					t.Fatalf("kolo-id accepts small-order key %x", pub)
				}
			}
		}
	}
}
