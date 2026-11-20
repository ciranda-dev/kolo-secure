package kolosecure

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"
)

const (
	version        = 0
	exporterLabel  = "EXPERIMENTAL-kolo-secure/channel-binding/v0"
	proofContext   = "kolo-secure/proof/v0"
	maxMessageSize = 256

	roleDialer   = 1
	roleListener = 2

	typeHello  = 1
	typeProof  = 2
	typeFinish = 3
)

// smallOrderKeys lists every encoding crypto/ed25519 decodes to a point of order 1, 2, 4 or 8.
// Anyone can make signatures that verify under such a key, so it proves nothing.
var smallOrderKeys = decodeHex(
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
)

func decodeHex(keys ...string) [][]byte {
	out := make([][]byte, len(keys))
	for i, k := range keys {
		b, err := hex.DecodeString(k)
		if err != nil {
			panic(err)
		}
		out[i] = b
	}
	return out
}

func smallOrder(pub []byte) bool {
	for _, k := range smallOrderKeys {
		if bytes.Equal(pub, k) {
			return true
		}
	}
	return false
}

func transcript(role uint64, ekm [32]byte, dialer, listener []byte) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	e.PutUvarint(role)
	e.PutFixed(ekm[:])
	e.PutFixed(dialer)
	e.PutFixed(listener)
	return e.Bytes()
}

func encodeHello(key []byte) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(typeHello)
	e.PutUvarint(version)
	e.PutFixed(key)
	return e.Bytes()
}

func encodeProof(key, sig []byte) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(typeProof)
	e.PutUvarint(version)
	e.PutFixed(key)
	e.PutFixed(sig)
	return e.Bytes()
}

func encodeFinish(sig []byte) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(typeFinish)
	e.PutFixed(sig)
	return e.Bytes()
}

func decodeHeader(d *kolocodec.Decoder, want uint64, versioned bool) error {
	t, err := d.Uvarint()
	if err != nil || t != want {
		return ErrProtocol
	}
	if !versioned {
		return nil
	}
	v, err := d.Uvarint()
	if err != nil {
		return ErrProtocol
	}
	if v != version {
		return ErrUnsupportedVersion
	}
	return nil
}

func decodeHello(body []byte) (key ed25519.PublicKey, err error) {
	d := kolocodec.NewDecoder(body)
	if err := decodeHeader(d, typeHello, true); err != nil {
		return nil, err
	}
	key, err = d.Fixed(ed25519.PublicKeySize)
	if err != nil || d.Done() != nil {
		return nil, ErrProtocol
	}
	return key, nil
}

func decodeProof(body []byte) (key ed25519.PublicKey, sig []byte, err error) {
	d := kolocodec.NewDecoder(body)
	if err := decodeHeader(d, typeProof, true); err != nil {
		return nil, nil, err
	}
	key, err = d.Fixed(ed25519.PublicKeySize)
	if err != nil {
		return nil, nil, ErrProtocol
	}
	sig, err = d.Fixed(ed25519.SignatureSize)
	if err != nil || d.Done() != nil {
		return nil, nil, ErrProtocol
	}
	return key, sig, nil
}

func decodeFinish(body []byte) (sig []byte, err error) {
	d := kolocodec.NewDecoder(body)
	if err := decodeHeader(d, typeFinish, false); err != nil {
		return nil, err
	}
	sig, err = d.Fixed(ed25519.SignatureSize)
	if err != nil || d.Done() != nil {
		return nil, ErrProtocol
	}
	return sig, nil
}

func writeFrame(w io.Writer, body []byte) error {
	var e kolocodec.Encoder
	e.PutBytes(body)
	_, err := w.Write(e.Bytes())
	return err
}

// readFrame reads at most a 2-byte length and maxMessageSize bytes, so a peer cannot make it allocate more.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:1]); err != nil {
		return nil, readErr(err)
	}
	n := 1
	if hdr[0] >= 0x80 {
		if _, err := io.ReadFull(r, hdr[1:]); err != nil {
			return nil, readErr(err)
		}
		n = 2
	}
	d := kolocodec.NewDecoder(hdr[:n])
	size, err := d.UvarintMax(maxMessageSize)
	if err != nil || d.Done() != nil || size == 0 {
		return nil, ErrProtocol
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, readErr(err)
	}
	return body, nil
}

func expectEOF(r io.Reader) error {
	var b [1]byte
	_, err := io.ReadFull(r, b[:])
	switch {
	case err == io.EOF:
		return nil
	case err == nil:
		return ErrProtocol
	}
	return readErr(err)
}

func readErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrProtocol
	}
	return err
}

func checkPeer(local, peer, want ed25519.PublicKey) error {
	switch {
	case want != nil && !bytes.Equal(peer, want):
		return ErrUnexpectedPeer
	case bytes.Equal(peer, local):
		return ErrUnexpectedPeer
	case smallOrder(peer):
		return ErrAuthentication
	}
	return nil
}

type stream interface {
	io.ReadWriter
	Close() error
}

func dialerHandshake(s stream, id *koloid.Identity, ekm [32]byte, want ed25519.PublicKey) (ed25519.PublicKey, error) {
	local := id.PublicKey()
	if err := writeFrame(s, encodeHello(local)); err != nil {
		return nil, err
	}
	body, err := readFrame(s)
	if err != nil {
		return nil, err
	}
	peer, sig, err := decodeProof(body)
	if err != nil {
		return nil, err
	}
	if err := expectEOF(s); err != nil {
		return nil, err
	}
	if err := checkPeer(local, peer, want); err != nil {
		return nil, err
	}
	if !koloid.Verify(peer, proofContext, transcript(roleListener, ekm, local, peer), sig) {
		return nil, ErrAuthentication
	}
	mine, err := id.Sign(proofContext, transcript(roleDialer, ekm, local, peer))
	if err != nil {
		return nil, err
	}
	if err := writeFrame(s, encodeFinish(mine)); err != nil {
		return nil, err
	}
	return peer, s.Close()
}

func listenerHandshake(s stream, id *koloid.Identity, ekm [32]byte) (ed25519.PublicKey, error) {
	local := id.PublicKey()
	body, err := readFrame(s)
	if err != nil {
		return nil, err
	}
	peer, err := decodeHello(body)
	if err != nil {
		return nil, err
	}
	if err := checkPeer(local, peer, nil); err != nil {
		return nil, err
	}
	mine, err := id.Sign(proofContext, transcript(roleListener, ekm, peer, local))
	if err != nil {
		return nil, err
	}
	if err := writeFrame(s, encodeProof(local, mine)); err != nil {
		return nil, err
	}
	if err := s.Close(); err != nil {
		return nil, err
	}
	if body, err = readFrame(s); err != nil {
		return nil, err
	}
	sig, err := decodeFinish(body)
	if err != nil {
		return nil, err
	}
	if err := expectEOF(s); err != nil {
		return nil, err
	}
	if !koloid.Verify(peer, proofContext, transcript(roleDialer, ekm, peer, local), sig) {
		return nil, ErrAuthentication
	}
	return peer, nil
}
