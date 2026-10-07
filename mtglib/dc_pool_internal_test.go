package mtglib

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mhsanaei/mtg-multi/essentials"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/dc"
)

// fakePoolConn is a minimal essentials.Conn for pool tests: the pool only
// needs Close/CloseRead/CloseWrite and never calls Read/Write (the embedded nil
// net.Conn is not used).
type fakePoolConn struct {
	net.Conn

	mu     sync.Mutex
	closed bool
}

func (f *fakePoolConn) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()

	return nil
}

func (f *fakePoolConn) CloseRead() error  { return nil }
func (f *fakePoolConn) CloseWrite() error { return nil }

func (f *fakePoolConn) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.closed
}

func testAddr() dc.Addr {
	return dc.Addr{Network: "tcp", Address: "149.154.167.50:443"}
}

// newTestPool builds a dcPool WITHOUT filler goroutines (deterministic unit
// tests of get/topUp).
func newTestPool(dial dcDialFunc, perDC int, maxAge time.Duration) *dcPool {
	return &dcPool{
		dial:     dial,
		logger:   NoopLogger{},
		dcs:      []int{2},
		perDC:    perDC,
		maxAge:   maxAge,
		interval: time.Hour,
		ready:    map[int][]warmConn{},
	}
}

func TestDCPoolTopUpAndGet(t *testing.T) {
	var dials int32

	dial := func(_ context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
		atomic.AddInt32(&dials, 1)

		return &fakePoolConn{}, testAddr(), dcID, nil
	}

	p := newTestPool(dial, 2, 20*time.Second)
	p.topUp(context.Background(), 2)

	if got := atomic.LoadInt32(&dials); got != 2 {
		t.Fatalf("expected 2 warm dials, got %d", got)
	}

	// Two gets in a row return warm connections, the third one is a miss.
	if _, _, ok := p.get(2); !ok {
		t.Fatal("get #1: expected a warm connection")
	}
	if _, _, ok := p.get(2); !ok {
		t.Fatal("get #2: expected a warm connection")
	}
	if _, _, ok := p.get(2); ok {
		t.Fatal("get #3: expected a miss (empty pool)")
	}
}

func TestDCPoolGetEvictsAged(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)

	fresh := &fakePoolConn{}
	aged := &fakePoolConn{}

	// aged is older than maxAge: get closes and skips it, returns the fresh one.
	p.ready[2] = []warmConn{
		{conn: fresh, addr: testAddr(), created: time.Now()},
		{conn: aged, addr: testAddr(), created: time.Now().Add(-time.Hour)},
	}

	conn, _, ok := p.get(2)
	if !ok {
		t.Fatal("expected a fresh connection")
	}
	if !aged.isClosed() {
		t.Fatal("an aged connection must be closed")
	}
	if conn.(*fakePoolConn) != fresh {
		t.Fatal("expected exactly the fresh connection")
	}
}

func TestDCPoolGetEmptyIsMiss(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)

	if _, _, ok := p.get(2); ok {
		t.Fatal("an empty pool must miss (fallback to a cold dial)")
	}
}

func TestDCPoolTopUpDropsDCMismatch(t *testing.T) {
	fake := &fakePoolConn{}

	// dial returned a connection to ANOTHER DC (fallback): it must not be pooled
	// under the requested DC and has to be closed.
	dial := func(_ context.Context, _ int) (essentials.Conn, dc.Addr, int, error) {
		return fake, testAddr(), 999, nil
	}

	p := newTestPool(dial, 1, 20*time.Second)
	p.topUp(context.Background(), 2)

	if len(p.ready[2]) != 0 {
		t.Fatalf("a connection to another DC must not be pooled, pool has %d", len(p.ready[2]))
	}
	if !fake.isClosed() {
		t.Fatal("a connection to another DC must be closed")
	}
}

func TestDCPoolTopUpDialFailureNoStore(t *testing.T) {
	dial := func(_ context.Context, _ int) (essentials.Conn, dc.Addr, int, error) {
		return nil, dc.Addr{}, 0, errors.New("route down")
	}

	p := newTestPool(dial, 2, 20*time.Second)
	p.topUp(context.Background(), 2)

	if len(p.ready[2]) != 0 {
		t.Fatalf("the pool must stay empty after a failed dial, pool has %d", len(p.ready[2]))
	}
}

func TestDCPoolShutdownClosesConns(t *testing.T) {
	var conns []*fakePoolConn
	var mu sync.Mutex

	dial := func(_ context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
		c := &fakePoolConn{}
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()

		return c, testAddr(), dcID, nil
	}

	pool := newDCPool(context.Background(), dial, NoopLogger{}, nil,
		[]int{2}, 2, 20*time.Second, 5*time.Millisecond)

	// Wait until the filler fills the pool (perDC=2). Do NOT take connections via
	// get(): a taken connection belongs to the caller and Shutdown does not close
	// it (which is correct), so the test would fail falsely.
	poolLen := func() int {
		pool.mu.Lock()
		defer pool.mu.Unlock()

		return len(pool.ready[2])
	}

	deadline := time.Now().Add(2 * time.Second)
	for poolLen() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the filler did not fill the pool in 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}

	pool.Shutdown()

	mu.Lock()
	defer mu.Unlock()

	for i, c := range conns {
		if !c.isClosed() {
			t.Fatalf("connection #%d is not closed after Shutdown", i)
		}
	}
}

// recorder collects pool results to check the dc_pool metric.
type recorder struct {
	mu      sync.Mutex
	results []string
}

func (r *recorder) observe(_ int, result string) {
	r.mu.Lock()
	r.results = append(r.results, result)
	r.mu.Unlock()
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.results...)
}

func equalResults(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("results: got %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("results: got %v, want %v", got, want)
		}
	}
}

// A connection that the DC closed while it was pooled is not handed to a
// client: otherwise the first client write fails and the Telegram client goes
// into backoff.
func TestDCPoolGetSkipsDeadConn(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)
	rec := &recorder{}
	p.observe = rec.observe

	alive := &fakePoolConn{}
	dead := &fakePoolConn{}
	p.alive = func(c essentials.Conn) bool { return c.(*fakePoolConn) != dead } //nolint: forcetypeassert

	p.ready[2] = []warmConn{
		{conn: alive, addr: testAddr(), created: time.Now()},
		{conn: dead, addr: testAddr(), created: time.Now()},
	}

	conn, _, ok := p.get(2)
	if !ok || conn.(*fakePoolConn) != alive { //nolint: forcetypeassert
		t.Fatal("expected a live connection")
	}

	if !dead.isClosed() {
		t.Fatal("a dead connection must be closed")
	}

	equalResults(t, rec.all(), []string{DCPoolResultDead, DCPoolResultHit})
}

// All pooled connections are dead: a miss, the client dials cold.
func TestDCPoolGetAllDeadIsMiss(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)
	rec := &recorder{}
	p.observe = rec.observe
	p.alive = func(essentials.Conn) bool { return false }

	p.ready[2] = []warmConn{
		{conn: &fakePoolConn{}, addr: testAddr(), created: time.Now()},
		{conn: &fakePoolConn{}, addr: testAddr(), created: time.Now()},
	}

	if _, _, ok := p.get(2); ok {
		t.Fatal("expected a miss")
	}

	equalResults(t, rec.all(), []string{DCPoolResultDead, DCPoolResultDead, DCPoolResultMiss})
}

// Filler and hand-out results: warm dial, eviction by age, failed warm dial,
// stale at hand-out, miss.
func TestDCPoolReportsResults(t *testing.T) {
	fail := false
	dial := func(_ context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
		if fail {
			return nil, dc.Addr{}, 0, errors.New("dc down")
		}

		return &fakePoolConn{}, testAddr(), dcID, nil
	}

	p := newTestPool(dial, 1, 20*time.Second)
	rec := &recorder{}
	p.observe = rec.observe

	p.topUp(context.Background(), 2) // dial_ok

	p.mu.Lock()
	p.ready[2][0].created = time.Now().Add(-time.Hour)
	p.mu.Unlock()

	fail = true
	p.topUp(context.Background(), 2) // expired + dial_fail

	p.ready[2] = []warmConn{{conn: &fakePoolConn{}, addr: testAddr(), created: time.Now().Add(-time.Hour)}}
	p.get(2) // stale + miss

	equalResults(t, rec.all(), []string{
		DCPoolResultDialOK,
		DCPoolResultExpired, DCPoolResultDialFail,
		DCPoolResultStale, DCPoolResultMiss,
	})
}

// The real probe on net.Pipe: a silent connection is alive; one closed by the
// other side is dead; one where the DC sent data is dead too (this must not
// happen on a stream that has not started). The deadline is reset after the
// probe, so the connection reads normally afterwards.
func TestProbeAlive(t *testing.T) {
	t.Run("silent is alive, deadline reset", func(t *testing.T) {
		local, remote := net.Pipe()
		defer local.Close()  //nolint: errcheck
		defer remote.Close() //nolint: errcheck

		conn := essentials.WrapNetConn(local)
		if !probeAlive(conn) {
			t.Fatal("a silent connection must be alive")
		}

		go remote.Write([]byte{42}) //nolint: errcheck

		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err != nil || buf[0] != 42 {
			t.Fatalf("reads must work after the probe: %v %v", buf, err)
		}
	})

	t.Run("closed by DC is dead", func(t *testing.T) {
		local, remote := net.Pipe()
		defer local.Close() //nolint: errcheck

		remote.Close() //nolint: errcheck

		if probeAlive(essentials.WrapNetConn(local)) {
			t.Fatal("a closed connection must be dead")
		}
	})

	t.Run("data from DC is dead", func(t *testing.T) {
		local, remote := net.Pipe()
		defer local.Close()  //nolint: errcheck
		defer remote.Close() //nolint: errcheck

		go remote.Write([]byte{1}) //nolint: errcheck

		time.Sleep(10 * time.Millisecond)

		if probeAlive(essentials.WrapNetConn(local)) {
			t.Fatal("a connection with unexpected data must be dead")
		}
	})
}
