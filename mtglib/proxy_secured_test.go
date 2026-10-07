package mtglib_test

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/mhsanaei/mtg-multi/antireplay"
	"github.com/mhsanaei/mtg-multi/events"
	"github.com/mhsanaei/mtg-multi/ipblocklist"
	"github.com/mhsanaei/mtg-multi/ipblocklist/files"
	"github.com/mhsanaei/mtg-multi/logger"
	"github.com/mhsanaei/mtg-multi/mtglib"
	"github.com/mhsanaei/mtg-multi/network"
	"github.com/yl2chen/cidranger"
)

const securedTestHandshakeTimeout = 10 * time.Second

// startSecuredProxy runs a proxy with secured clients enabled whose fronting
// host is a local listener. It returns the proxy address and a channel that
// yields every connection accepted by the fronting host.
func startSecuredProxy(t *testing.T, frameTimeout time.Duration) (string, <-chan net.Conn) {
	t.Helper()

	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { front.Close() }) //nolint: errcheck

	frontConns := make(chan net.Conn, 1)

	go func() {
		for {
			conn, err := front.Accept()
			if err != nil {
				return
			}

			frontConns <- conn
		}
	}()

	_, frontPort, _ := net.SplitHostPort(front.Addr().String())
	port, _ := strconv.Atoi(frontPort)

	dialer, err := network.NewDefaultDialer(0, 0)
	if err != nil {
		t.Fatal(err)
	}

	ntw, err := network.NewNetwork(dialer, "mtgtest", "1.1.1.1", 0)
	if err != nil {
		t.Fatal(err)
	}

	allowlist, _ := ipblocklist.NewFireholFromFiles(
		logger.NewNoopLogger(),
		1,
		[]files.File{files.NewMem([]*net.IPNet{cidranger.AllIPv4, cidranger.AllIPv6})},
		nil,
	)

	go allowlist.Run(time.Second)

	for !allowlist.Contains(net.ParseIP("127.0.0.1")) {
		time.Sleep(10 * time.Millisecond)
	}

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Secret:              mtglib.GenerateSecret("example.com"),
		Network:             ntw,
		AntiReplayCache:     antireplay.NewNoop(),
		IPBlocklist:         ipblocklist.NewNoop(),
		IPAllowlist:         allowlist,
		EventStream:         events.NewNoopStream(),
		Logger:              logger.NewNoopLogger(),
		UseTestDCs:          true,
		HandshakeTimeout:    securedTestHandshakeTimeout,
		DomainFrontingHost:  "127.0.0.1",
		DomainFrontingPort:  uint(port), //nolint: gosec
		SecuredEnabled:      true,
		SecuredFrameTimeout: frameTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go proxy.Serve(listener) //nolint: errcheck

	t.Cleanup(func() {
		listener.Close() //nolint: errcheck
		proxy.Shutdown()
	})

	return listener.Addr().String(), frontConns
}

// probeFronting sends a short first message that is neither a TLS ClientHello
// nor a complete obfuscated2 frame and checks that the fronting host gets it
// byte for byte within maxDelay, and that the relay keeps working afterwards
// in both directions.
func probeFronting(t *testing.T, proxyAddr string, frontConns <-chan net.Conn, probe []byte, maxDelay time.Duration) {
	t.Helper()

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint: errcheck

	started := time.Now()

	if _, err := client.Write(probe); err != nil {
		t.Fatal(err)
	}

	var front net.Conn

	select {
	case front = <-frontConns:
	case <-time.After(securedTestHandshakeTimeout):
		t.Fatal("the probe has not reached the fronting host")
	}
	defer front.Close() //nolint: errcheck

	front.SetReadDeadline(time.Now().Add(securedTestHandshakeTimeout)) //nolint: errcheck

	got := make([]byte, len(probe))
	if _, err := io.ReadFull(front, got); err != nil {
		t.Fatalf("cannot read the probe at the fronting host: %v", err)
	}

	if elapsed := time.Since(started); elapsed > maxDelay {
		t.Fatalf("the probe reached the fronting host after %v, want at most %v", elapsed, maxDelay)
	}

	if !bytes.Equal(got, probe) {
		t.Fatalf("fronting host got %q, want %q", got, probe)
	}

	// The relay must survive the short frame deadline: more client bytes get
	// through, and so does the answer of the fronting host.
	more := []byte("more bytes after the probe")
	if _, err := client.Write(more); err != nil {
		t.Fatal(err)
	}

	gotMore := make([]byte, len(more))
	if _, err := io.ReadFull(front, gotMore); err != nil || !bytes.Equal(gotMore, more) {
		t.Fatalf("fronting host got %q (%v), want %q", gotMore, err, more)
	}

	answer := []byte("HTTP/1.1 400 Bad Request\r\n\r\n")
	if _, err := front.Write(answer); err != nil {
		t.Fatal(err)
	}

	client.SetReadDeadline(time.Now().Add(securedTestHandshakeTimeout)) //nolint: errcheck

	gotAnswer := make([]byte, len(answer))
	if _, err := io.ReadFull(client, gotAnswer); err != nil || !bytes.Equal(gotAnswer, answer) {
		t.Fatalf("client got %q (%v), want %q", gotAnswer, err, answer)
	}
}

// An HTTP request can never start an obfuscated2 frame, so it is fronted at
// once, as with secured clients disabled, not after any timeout.
func TestSecuredShortHTTPProbeIsFrontedAtOnce(t *testing.T) {
	t.Parallel()

	// A frame timeout longer than the allowed delay proves that the reserved
	// prefix does not wait for it.
	proxyAddr, frontConns := startSecuredProxy(t, 5*time.Second)

	probeFronting(t, proxyAddr, frontConns, []byte("GET / HTTP/1.1\r\n\r\n"), time.Second)
}

// A short message that may still be the start of a frame waits only for the
// secured frame timeout, well below the handshake timeout, and is then
// fronted byte for byte.
func TestSecuredShortBinaryProbeIsFrontedAfterFrameTimeout(t *testing.T) {
	t.Parallel()

	const frameTimeout = 500 * time.Millisecond

	proxyAddr, frontConns := startSecuredProxy(t, frameTimeout)

	probe := []byte{0x91, 0x82, 0x07, 0x14, 0xfb, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}

	probeFronting(t, proxyAddr, frontConns, probe, frameTimeout+2*time.Second)
}
