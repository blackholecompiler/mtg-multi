package mtglib

import "testing"

func TestIsFakeTLSHandshake(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		firstBytes [5]byte
		want       bool
	}{
		{
			name:       "fake TLS client hello",
			firstBytes: [5]byte{0x16, 0x03, 0x01, 0x06, 0xe1},
			want:       true,
		},
		{
			name:       "secured obfuscated handshake",
			firstBytes: [5]byte{0x91, 0x82, 0x07, 0x14, 0xfb},
			want:       false,
		},
		{
			name:       "TLS application data is not a client hello",
			firstBytes: [5]byte{0x17, 0x03, 0x03, 0x00, 0x10},
			want:       false,
		},
		{
			name:       "unsupported record version",
			firstBytes: [5]byte{0x16, 0x03, 0x03, 0x00, 0x10},
			want:       false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isFakeTLSHandshake(tt.firstBytes); got != tt.want {
				t.Fatalf("isFakeTLSHandshake() = %v, want %v", got, tt.want)
			}
		})
	}
}
