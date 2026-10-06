package obfuscation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"

	"github.com/mhsanaei/mtg-multi/essentials"
)

// Obfuscator implements the obfuscated2 handshake
// (https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation).
// Set Secret to the MTProxy secret for key-mixed handshakes; leave nil for
// direct DC connections.
type Obfuscator struct {
	Secret []byte
}

// ReadHandshake reads the 64-byte obfuscated2 client handshake from r,
// validates it, and returns the DC the client requested along with a
// transparent en/decrypting wrapper over r.
func (o Obfuscator) ReadHandshake(r essentials.Conn) (int, essentials.Conn, error) {
	raw := handshakeFrame{}

	if _, err := io.ReadFull(r, raw.data[:]); err != nil {
		return 0, nil, fmt.Errorf("cannot read frame: %w", err)
	}

	dc, cn, ok := o.tryFrame(raw, r)
	if !ok {
		return 0, nil, fmt.Errorf("unsupported connection type")
	}

	return dc, cn, nil
}

// tryFrame parses an already read 64-byte frame raw with o.Secret. It works
// on a copy (raw is passed by value), so several keys can be tried against
// the same frame (multi-secret secured mode). ok=false if the key does not
// match (the decrypted connection type is wrong).
func (o Obfuscator) tryFrame(raw handshakeFrame, r essentials.Conn) (int, essentials.Conn, bool) {
	frame := raw // a copy

	hasher := sha256.New()
	recvCipher := o.getCipher(&frame, hasher)

	frame.revert()
	hasher.Reset()
	sendCipher := o.getCipher(&frame, hasher)

	recvCipher.XORKeyStream(frame.data[:], frame.data[:])

	if val := frame.connectionType(); subtle.ConstantTimeCompare(val, hfConnectionType[:]) != 1 {
		return 0, nil, false
	}

	cn := conn{
		Conn:       r,
		recvCipher: recvCipher,
		sendCipher: sendCipher,
	}

	return frame.dc(), cn, true
}

// ReadHandshakeMulti reads a 64-byte obfuscated2 frame once and tries the
// secrets in order: the one whose key yields a valid connection type wins.
// Used for secured ("dd") clients that send obfuscated2 directly, without
// FakeTLS, so the secret is not known in advance. Returns the index of the
// matched secret, the DC, the wrapped connection and the frame key (32 bytes)
// for the anti-replay cache.
func ReadHandshakeMulti(r essentials.Conn, secrets [][]byte) (int, int, essentials.Conn, []byte, error) {
	raw := handshakeFrame{}

	if _, err := io.ReadFull(r, raw.data[:]); err != nil {
		return -1, 0, nil, nil, fmt.Errorf("cannot read frame: %w", err)
	}

	// The frame key is random per connection: use it for anti-replay before decryption.
	replayKey := make([]byte, hfLenKey)
	copy(replayKey, raw.key())

	for i, secret := range secrets {
		obf := Obfuscator{Secret: secret}
		if dc, cn, ok := obf.tryFrame(raw, r); ok {
			return i, dc, cn, replayKey, nil
		}
	}

	return -1, 0, nil, nil, fmt.Errorf("no matching secret for secured handshake")
}

// SendHandshake writes a fresh 64-byte obfuscated2 handshake for the given
// DC to w and returns a transparent en/decrypting wrapper over w.
func (o Obfuscator) SendHandshake(w essentials.Conn, dc int) (essentials.Conn, error) {
	frame := generateHandshake(dc)
	copyFrame := frame
	hasher := sha256.New()

	sendCipher := o.getCipher(&frame, hasher)

	frame.revert()
	hasher.Reset()
	recvCipher := o.getCipher(&frame, hasher)

	sendCipher.XORKeyStream(frame.data[:], frame.data[:])
	copy(frame.key(), copyFrame.key())
	copy(frame.iv(), copyFrame.iv())

	if _, err := w.Write(frame.data[:]); err != nil {
		return nil, fmt.Errorf("cannot send a handshake: %w", err)
	}

	return conn{
		Conn:       w,
		recvCipher: recvCipher,
		sendCipher: sendCipher,
	}, nil
}

func (o Obfuscator) getCipher(f *handshakeFrame, hasher hash.Hash) cipher.Stream {
	blockKey := f.key()

	if o.Secret != nil {
		hasher.Write(blockKey)
		hasher.Write(o.Secret)
		blockKey = hasher.Sum(nil)
	}

	block, _ := aes.NewCipher(blockKey)

	return cipher.NewCTR(block, f.iv())
}
