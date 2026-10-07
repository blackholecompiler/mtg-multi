package obfuscation

import (
	"crypto/rand"
	"encoding/binary"
	"slices"
)

// https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation
const (
	// default DC is nothing is selected
	defaultDC = 2

	// the length of the handshake frame. Always 64 bytes
	hfLen = 64

	hfLenKey            = 32
	hfLenIV             = 16
	hfLenConnectionType = 4

	// A structure of obfuscated handshake frame is following:
	//
	//	[frameOffsetFirst:frameOffsetKey:frameOffsetIV:frameOffsetMagic:frameOffsetDC:frameOffsetEnd].
	//
	//	- 8 bytes of noise
	//	- 32 bytes of AES Key
	//	- 16 bytes of AES IV
	//	- 4 bytes of 'connection type' - this has some setting like a connection type
	//	- 2 bytes of 'DC'. DC is little endian int16
	//	- 2 bytes of noise
	hfOffsetKey            = 8
	hfOffsetIV             = hfOffsetKey + hfLenKey
	hfOffsetConnectionType = hfOffsetIV + hfLenIV
	hfOffsetDC             = hfOffsetConnectionType + hfLenConnectionType
)

// Connection-Type: Secure. We support only fake tls.
var hfConnectionType = [hfLenConnectionType]byte{0xdd, 0xdd, 0xdd, 0xdd}

type handshakeFrame struct {
	data [hfLen]byte
}

func (h *handshakeFrame) key() []byte {
	return h.data[hfOffsetKey : hfOffsetKey+hfLenKey]
}

func (h *handshakeFrame) iv() []byte {
	return h.data[hfOffsetIV : hfOffsetIV+hfLenIV]
}

func (h *handshakeFrame) connectionType() []byte {
	return h.data[hfOffsetConnectionType : hfOffsetConnectionType+hfLenConnectionType]
}

func (h *handshakeFrame) dcSlice() []byte {
	return h.data[hfOffsetDC : hfOffsetDC+2]
}

func (h *handshakeFrame) dc() int {
	idx := int16(binary.LittleEndian.Uint16(h.dcSlice()))

	// Keep the sign: a negative DC id is how a client asks for the media
	// counterpart of that DC (-2 is DC 2 media). Dropping it sends media
	// requests to the regular DC.
	if idx != 0 {
		return int(idx)
	}

	return defaultDC
}

func (h *handshakeFrame) revert() {
	slices.Reverse(h.data[hfOffsetKey:hfOffsetConnectionType])
}

func generateHandshake(dc int) handshakeFrame {
	frame := handshakeFrame{}

	for {
		if _, err := rand.Read(frame.data[:]); err != nil {
			panic(err)
		}

		if IsReservedFramePrefix(frame.data[:4]) {
			continue
		}

		if frame.data[4]|frame.data[5]|frame.data[6]|frame.data[7] == 0 {
			continue
		}

		copy(frame.connectionType(), hfConnectionType[:])
		binary.LittleEndian.PutUint16(frame.dcSlice(), uint16(dc))

		return frame
	}
}

// IsReservedFramePrefix reports whether the first 4 bytes of a connection can
// never start an obfuscated2 handshake frame. Clients regenerate the random
// frame until it does not look like another protocol or transport (see
// generateHandshake and tdlib's TcpTransport), so such a prefix proves that
// the peer is not an obfuscated2 client. Shorter input is never reserved.
func IsReservedFramePrefix(prefix []byte) bool {
	if len(prefix) < 4 { //nolint: mnd
		return false
	}

	// https://github.com/tdlib/td/blob/master/td/mtproto/TcpTransport.cpp#L157-L158.
	if prefix[0] == 0xef { // abridged header
		// https://core.telegram.org/mtproto/mtproto-transports#abridged
		return true
	}

	switch binary.LittleEndian.Uint32(prefix[:4]) {
	case 0x44414548, // HEAD
		0x54534f50, // POST
		0x20544547, // GET
		0x4954504f, // OPTI
		0x02010316, // TLS handshake record, version 3.1
		0xdddddddd, // PaddedIntermediate header
		0xeeeeeeee: // Intermediate header
		return true
	}

	return false
}
