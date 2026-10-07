package mtglib

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/mhsanaei/mtg-multi/essentials"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/dc"
)

// warmConn is a pre-established connection to a Telegram DC: the TCP dial
// and the obfuscated2 handshake are already done, so it can relay client
// MTProto frames right away. created is used to evict aged connections.
type warmConn struct {
	conn    essentials.Conn
	addr    dc.Addr
	created time.Time
}

// dcDialFunc dials dcID and performs the obfuscated2 handshake. It returns
// the wrapped connection, the chosen address and the actual DC (it may differ
// from the requested one with AllowFallbackOnUnknownDC). Injected from Proxy
// (dialAndHandshake); tests use a fake without network.
type dcDialFunc func(ctx context.Context, dcID int) (essentials.Conn, dc.Addr, int, error)

// Results of pool operations, reported as the result label of the dc_pool
// metric. They show whether the pool actually helps and why clients had to
// dial cold.
const (
	DCPoolResultHit      = "hit"       // a client got a warm connection
	DCPoolResultMiss     = "miss"      // the pool was empty, the client dials cold
	DCPoolResultStale    = "stale"     // a pooled connection was older than maxAge at hand-out
	DCPoolResultDead     = "dead"      // a pooled connection was already closed by the DC
	DCPoolResultExpired  = "expired"   // background eviction by age (normal churn)
	DCPoolResultDialOK   = "dial_ok"   // a filler warmed up a connection
	DCPoolResultDialFail = "dial_fail" // a filler failed to warm up a connection
)

// dcPoolObserver receives pool results (events/metrics in production).
type dcPoolObserver func(dcID int, result string)

// dcPoolLivenessProbe is how long the liveness check waits. Telegram never
// sends first, so a read on a live connection times out, while a connection
// closed by the DC returns EOF/RST immediately. This is the per-client cost.
const dcPoolLivenessProbe = time.Millisecond

// probeAlive checks that the DC has not closed a pooled connection while it
// was waiting. Age alone does not catch that: a DC may close a connection at
// any moment (restart, rotation, network reset), and handing such a
// connection to a client makes its first write fail and triggers the
// Telegram client backoff.
//
// Alive means the read timed out. Any data, EOF or reset means dead: the DC
// must not send anything on an MTProto stream that has not started yet. A
// timed-out read does not advance the obfuscated2 cipher, because the wrapper
// only decrypts bytes that were actually read.
func probeAlive(conn essentials.Conn) bool {
	if err := conn.SetReadDeadline(time.Now().Add(dcPoolLivenessProbe)); err != nil {
		return false
	}

	var buf [1]byte

	_, err := conn.Read(buf[:])

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return false
	}

	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}

// dcPool keeps warm connections to Telegram DCs so that a client connection
// does not pay for a cold dial and handshake.
//
// A cold dial is about one RTT, which is cheap. The real cost shows up when
// the node-to-DC route hiccups (DC address rotation, peering flaps): the
// whole client connection fails, and Telegram clients punish failures with
// an exponential backoff (seconds to minutes). The pool hands out an already
// established connection and absorbs dial failures in the background, where
// clients do not see them.
//
// One filler goroutine per warmed DC keeps perDC ready connections and
// replaces those older than maxAge (well before the DC would close an idle
// connection). A pool miss falls back to a cold dial, so the behaviour is
// never worse than without the pool.
type dcPool struct {
	dial     dcDialFunc
	logger   Logger
	observe  dcPoolObserver
	alive    func(essentials.Conn) bool
	dcs      []int
	perDC    int
	maxAge   time.Duration
	interval time.Duration

	mu    sync.Mutex
	ready map[int][]warmConn

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// newDCPool creates the pool and starts the filler goroutines. ctx is the
// proxy lifetime (cancelled on Shutdown). dcs is the list of DCs to warm.
func newDCPool(ctx context.Context, dial dcDialFunc, logger Logger, observe dcPoolObserver,
	dcs []int, perDC int, maxAge, interval time.Duration,
) *dcPool {
	ctx, cancel := context.WithCancel(ctx)

	p := &dcPool{
		dial:     dial,
		logger:   logger,
		observe:  observe,
		alive:    probeAlive,
		dcs:      dcs,
		perDC:    perDC,
		maxAge:   maxAge,
		interval: interval,
		ready:    make(map[int][]warmConn, len(dcs)),
		cancel:   cancel,
	}

	for _, dcID := range dcs {
		p.wg.Add(1)

		go p.fill(ctx, dcID)
	}

	return p
}

// get returns a warm connection to dcID if there is a fresh and live one.
// Aged connections and connections already closed by the DC are closed and
// skipped. ok=false means the pool had nothing usable and the caller should
// dial cold. The liveness probe runs without holding the mutex: it may wait
// up to dcPoolLivenessProbe, and there is no reason to block the whole pool.
func (p *dcPool) get(dcID int) (essentials.Conn, dc.Addr, bool) {
	for {
		wc, ok := p.pop(dcID)
		if !ok {
			p.report(dcID, DCPoolResultMiss)

			return nil, dc.Addr{}, false
		}

		if time.Since(wc.created) >= p.maxAge {
			wc.conn.Close() //nolint: errcheck
			p.report(dcID, DCPoolResultStale)

			continue
		}

		if p.alive != nil && !p.alive(wc.conn) {
			wc.conn.Close() //nolint: errcheck
			p.report(dcID, DCPoolResultDead)

			continue
		}

		p.report(dcID, DCPoolResultHit)

		return wc.conn, wc.addr, true
	}
}

// pop takes the most recent connection to dcID out of the pool.
func (p *dcPool) pop(dcID int) (warmConn, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	conns := p.ready[dcID]
	if len(conns) == 0 {
		return warmConn{}, false
	}

	wc := conns[len(conns)-1]
	p.ready[dcID] = conns[:len(conns)-1]

	return wc, true
}

// report passes a result to the observer (metrics), if any.
func (p *dcPool) report(dcID int, result string) {
	if p.observe != nil {
		p.observe(dcID, result)
	}
}

// fill is the filler goroutine of one DC: it tops the pool up to perDC and
// evicts aged connections on every tick. A failed dial is not retried in a
// loop (one attempt per tick) to avoid a handshake storm against a sick DC.
func (p *dcPool) fill(ctx context.Context, dcID int) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		p.topUp(ctx, dcID)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// topUp evicts aged connections to dcID and refills the pool up to perDC.
func (p *dcPool) topUp(ctx context.Context, dcID int) {
	p.mu.Lock()

	var live []warmConn

	expired := 0

	for _, wc := range p.ready[dcID] {
		if time.Since(wc.created) >= p.maxAge {
			wc.conn.Close() //nolint: errcheck

			expired++

			continue
		}

		live = append(live, wc)
	}

	p.ready[dcID] = live
	need := p.perDC - len(live)

	p.mu.Unlock()

	for i := 0; i < expired; i++ {
		p.report(dcID, DCPoolResultExpired)
	}

	for i := 0; i < need; i++ {
		if ctx.Err() != nil {
			return
		}

		conn, addr, actualDC, err := p.dial(ctx, dcID)
		if err != nil {
			// DC addresses are not loaded yet or the route is down: try again on
			// the next tick. Clients are not blocked, they fall back to a cold dial.
			p.logger.InfoError("dc pool warm dial failed", err)
			p.report(dcID, DCPoolResultDialFail)

			return
		}

		// With AllowFallbackOnUnknownDC the dial may land on another DC. This
		// does not happen for the warmed DCs 1..5 (their addresses are known),
		// but if it does, the connection is handshaked to the wrong DC and must
		// not be pooled under dcID.
		if actualDC != dcID {
			conn.Close() //nolint: errcheck

			return
		}

		p.mu.Lock()
		p.ready[dcID] = append(p.ready[dcID], warmConn{conn: conn, addr: addr, created: time.Now()})
		p.mu.Unlock()

		p.report(dcID, DCPoolResultDialOK)
	}
}

// Shutdown stops the filler goroutines and closes all warm connections.
func (p *dcPool) Shutdown() {
	p.cancel()
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	for dcID, conns := range p.ready {
		for _, wc := range conns {
			wc.conn.Close() //nolint: errcheck
		}

		p.ready[dcID] = nil
	}
}
