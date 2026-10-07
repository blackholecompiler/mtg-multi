package mtglib

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mhsanaei/mtg-multi/essentials"
	"github.com/mhsanaei/mtg-multi/internal/logthrottle"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/dc"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/doppel"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/middleproxy"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/relay"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/tls"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/tls/fake"
	"github.com/mhsanaei/mtg-multi/mtglib/obfuscation"
	"github.com/panjf2000/ants/v2"
)

// pendingHandshakesLogInterval limits the log line about connections rejected
// by the per-IP pending-handshake limit: one line per interval, with the number
// of suppressed ones.
const pendingHandshakesLogInterval = 10 * time.Second

// errSecuredDenied reports a secured (dd) client whose secret matched but whose
// per-user limits deny the connection; it is fronted like a wrong secret.
var errSecuredDenied = errors.New("connection denied by per-user limit")

// secretSet is an immutable snapshot of the secrets a proxy serves. The proxy
// keeps it behind an atomic pointer so a running handshake always reads a
// single consistent view, and ReloadSecrets can swap the whole set in without
// locking the hot path. secrets, names and hostnames stay index-aligned:
// secrets[i] belongs to names[i]; hostnames is the deduplicated, sorted set of
// secret hosts used for SNI matching.
type secretSet struct {
	secrets   []Secret
	names     []string
	hostnames []string
	// keys[i] is secrets[i].Key as a slice, precomputed for the handshake
	// parsers that try every configured key.
	keys [][]byte
	// adTags[i] is the per-secret advertising tag override for secrets[i], or
	// nil when that secret has no override; globalAdTag applies to any secret
	// without an override, or nil when no advertising is configured.
	adTags      []*[AdTagLength]byte
	globalAdTag *[AdTagLength]byte
	// limits[i] holds the governance limits (quota, expiry, disabled) for
	// secrets[i]; the zero value means the secret is unrestricted.
	limits []SecretLimits
}

// effectiveAdTag returns the advertising tag that applies to secrets[i]: the
// per-secret override if present, otherwise the global tag, otherwise nil (the
// direct-DC path).
func (s *secretSet) effectiveAdTag(i int) *[AdTagLength]byte {
	if i < len(s.adTags) && s.adTags[i] != nil {
		return s.adTags[i]
	}

	return s.globalAdTag
}

// toConfig reconstructs a mutable SecretConfig from the immutable snapshot. It
// is the copy-on-write starting point for the management-API mutators, which
// apply a delta and swap the result back in.
func (s *secretSet) toConfig() SecretConfig {
	secrets := make(map[string]Secret, len(s.names))

	var perSecret map[string][AdTagLength]byte

	var limits map[string]SecretLimits

	for i, name := range s.names {
		secrets[name] = s.secrets[i]

		if s.adTags[i] != nil {
			if perSecret == nil {
				perSecret = make(map[string][AdTagLength]byte)
			}

			perSecret[name] = *s.adTags[i]
		}

		if i < len(s.limits) && !s.limits[i].IsZero() {
			if limits == nil {
				limits = make(map[string]SecretLimits)
			}

			limits[name] = s.limits[i]
		}
	}

	return SecretConfig{Secrets: secrets, SecretAdTags: perSecret, GlobalAdTag: s.globalAdTag, Limits: limits}
}

// buildSecretSet turns a name->secret map into an immutable, name-sorted
// snapshot. Sorting keeps names[i] and secrets[i] aligned and makes the
// matched index stable across processes for a given secret map. perSecret
// carries optional per-name advertising tags and global is the fallback tag;
// both may be nil. limitsMap carries optional per-name governance limits and
// may be nil.
func buildSecretSet(secretsMap map[string]Secret, perSecret map[string][AdTagLength]byte, global *[AdTagLength]byte, limitsMap map[string]SecretLimits) *secretSet {
	names := make([]string, 0, len(secretsMap))
	for name := range secretsMap {
		names = append(names, name)
	}

	sort.Strings(names)

	secretsList := make([]Secret, 0, len(secretsMap))
	adTags := make([]*[AdTagLength]byte, len(names))
	limits := make([]SecretLimits, len(names))

	for i, name := range names {
		secretsList = append(secretsList, secretsMap[name])

		if tag, ok := perSecret[name]; ok {
			t := tag
			adTags[i] = &t
		}

		if lim, ok := limitsMap[name]; ok {
			limits[i] = lim
		}
	}

	keys := make([][]byte, len(secretsList))
	for i := range secretsList {
		keys[i] = secretsList[i].Key[:]
	}

	hostnameSet := make(map[string]struct{}, len(secretsList))
	for _, s := range secretsList {
		hostnameSet[s.Host] = struct{}{}
	}

	hostnames := make([]string, 0, len(hostnameSet))
	for h := range hostnameSet {
		hostnames = append(hostnames, h)
	}

	sort.Strings(hostnames)

	return &secretSet{
		secrets:     secretsList,
		names:       names,
		hostnames:   hostnames,
		keys:        keys,
		adTags:      adTags,
		globalAdTag: global,
		limits:      limits,
	}
}

// Proxy is an MTPROTO proxy structure.
type Proxy struct {
	ctx             context.Context
	ctxCancel       context.CancelFunc
	streamWaitGroup sync.WaitGroup

	allowFallbackOnUnknownDC    bool
	pendingHandshakes           *pendingHandshakes
	pendingHandshakesPerIP      uint32
	pendingHandshakesDryRun     bool
	pendingHandshakesLog        *logthrottle.Throttle
	securedEnabled              bool
	securedFrameTimeout         time.Duration
	dcPool                      *dcPool
	tolerateTimeSkewness        time.Duration
	idleTimeout                 time.Duration
	handshakeTimeout            time.Duration
	domainFrontingPort          int
	domainFrontingHost          string
	domainFrontingProxyProtocol bool
	workerPool                  *ants.PoolWithFunc
	telegram                    *dc.Telegram
	configUpdater               *dc.PublicConfigUpdater
	doppelGanger                *doppel.Ganger

	middleProxy    *middleproxy.Manager
	ourIPv4        net.IP
	ourIPv6        net.IP
	advertisedPort int

	usageStateFile string
	emitTraffic    bool

	stats           *ProxyStats
	secrets         atomic.Pointer[secretSet]
	reloader        func() (SecretConfig, error)
	reloadMu        sync.Mutex
	liveMu          sync.Mutex
	liveConns       map[string]map[*streamContext]struct{}
	network         Network
	antiReplayCache AntiReplayCache
	blocklist       IPBlocklist
	allowlist       IPBlocklist
	eventStream     EventStream
	logger          Logger
}

// DomainFrontingAddress returns a host:port pair for a fronting domain.
// If a fronting host (literal IP or hostname) is configured, it is used
// instead of the secret's hostname. When secrets use different hostnames,
// pass the matched secret's host to front the correct domain.
func (p *Proxy) DomainFrontingAddress() string {
	return p.domainFrontingAddressForHost(p.secrets.Load().secrets[0].Host)
}

func (p *Proxy) domainFrontingAddressForHost(host string) string {
	if p.domainFrontingHost != "" {
		host = p.domainFrontingHost
	}

	return net.JoinHostPort(host, strconv.Itoa(p.domainFrontingPort))
}

// ServeConn serves a connection. We do not check IP blocklist and concurrency
// limit here.
func (p *Proxy) ServeConn(conn essentials.Conn) {
	p.streamWaitGroup.Add(1)
	defer p.streamWaitGroup.Done()

	ctx := newStreamContext(p.ctx, p.logger, conn)
	defer ctx.Close()

	ctx.handshakeDeadline = time.Now().Add(p.handshakeTimeout)

	if err := ctx.clientConn.SetDeadline(ctx.handshakeDeadline); err != nil {
		ctx.logger.WarningError("cannot set handshake timeout", err)
		return
	}

	stop := context.AfterFunc(ctx, func() {
		ctx.Close()
	})
	defer stop()

	p.eventStream.Send(ctx, NewEventStart(ctx.streamID, ctx.ClientIP()))
	ctx.logger.Info("Stream has been started")

	defer func() {
		p.eventStream.Send(ctx, NewEventFinish(ctx.streamID))
		ctx.logger.Info("Stream has been finished")
	}()

	// Per-IP limit on pending (unauthenticated) handshakes. The slot is
	// released as soon as the secret is verified or the connection goes to the
	// fronting domain, so authenticated sessions never hold it.
	release, action, admitted := p.pendingHandshakes.acquire(
		ctx.ClientIP(), p.pendingHandshakesPerIP, p.pendingHandshakesDryRun)
	if action != "" {
		p.eventStream.Send(ctx, NewEventPendingHandshakeLimit(ctx.streamID, action))
	}

	if !admitted {
		// Under a flood every connection is rejected here: the event above
		// counts each of them, the log line is rate limited.
		if ok, suppressed := p.pendingHandshakesLog.Allow(); ok {
			ctx.logger.BindInt("suppressed", suppressed).Info("too many pending handshakes from this ip")
		}

		return
	}

	if release != nil {
		defer release()

		ctx.releasePendingHandshake = release
	}

	if !p.doFakeTLSHandshake(ctx) {
		return
	}

	ctx.finishPendingHandshake()

	if !p.stats.CanConnect(ctx.secretName) {
		ctx.logger.Info("connection throttled")
		p.eventStream.Send(ctx, NewEventThrottled(ctx.streamID, ctx.secretName))

		return
	}

	p.stats.OnConnect(ctx.secretName)
	p.stats.UpdateLastSeen(ctx.secretName)

	defer p.stats.OnDisconnect(ctx.secretName)

	if !p.registerConn(ctx) {
		ctx.logger.Info("secret was removed, changed or denied by a concurrent reload")
		return
	}
	defer p.unregisterConn(ctx)

	// FakeTLS specifics: the doppelganger wrapper and a separate obfuscated2
	// handshake inside the unwrapped TLS stream. A secured client has already
	// done its obfuscated2 handshake in doSecuredHandshake.
	if !ctx.secured {
		clientConn, err := p.doppelGanger.NewConn(ctx.clientConn)
		if err != nil {
			ctx.logger.InfoError("cannot wrap into doppelganger connection", err)
			return
		}
		defer clientConn.Stop()

		ctx.clientConn = clientConn

		if err := p.doObfuscatedHandshake(ctx); err != nil {
			ctx.logger.InfoError("obfuscated handshake is failed", err)
			return
		}
	}

	if err := ctx.clientConn.SetDeadline(time.Time{}); err != nil {
		ctx.logger.WarningError("cannot set deadline", err)
		return
	}

	if err := p.doTelegramCall(ctx); err != nil {
		ctx.logger.WarningError("cannot dial to telegram", err)
		return
	}

	tracker := newIdleTracker(p.idleTimeout)

	relay.Relay(
		ctx,
		ctx.logger.Named("relay"),
		connIdleTimeout{Conn: ctx.telegramConn, tracker: tracker},
		newCountingConn(connIdleTimeout{Conn: ctx.clientConn, tracker: tracker}, p.stats, ctx.secretName),
	)
}

// Serve starts a proxy on a given listener.
func (p *Proxy) Serve(listener net.Listener) error {
	p.streamWaitGroup.Add(1)
	defer p.streamWaitGroup.Done()

	for {
		conn, err := acceptWithRetry(p.ctx, listener, p.logger)
		if err != nil {
			select {
			case <-p.ctx.Done():
				return nil
			default:
				return fmt.Errorf("cannot accept a new connection: %w", err)
			}
		}

		ipAddr := conn.RemoteAddr().(*net.TCPAddr).IP //nolint: forcetypeassert
		logger := p.logger.BindStr("ip", ipAddr.String())

		if !p.allowlist.Contains(ipAddr) {
			conn.Close() //nolint: errcheck
			logger.Info("ip was rejected by allowlist")
			p.eventStream.Send(p.ctx, NewEventIPAllowlisted(ipAddr))

			continue
		}

		if p.blocklist.Contains(ipAddr) {
			conn.Close() //nolint: errcheck
			logger.Info("ip was blacklisted")
			p.eventStream.Send(p.ctx, NewEventIPBlocklisted(ipAddr))

			continue
		}

		err = p.workerPool.Invoke(conn)

		switch {
		case err == nil:
		case errors.Is(err, ants.ErrPoolClosed):
			return nil
		case errors.Is(err, ants.ErrPoolOverload):
			conn.Close() //nolint: errcheck
			logger.Info("connection was concurrency limited")
			p.eventStream.Send(p.ctx, NewEventConcurrencyLimited())
		}
	}
}

// Shutdown 'gracefully' shutdowns all connections. Please remember that it
// does not close an underlying listener.
func (p *Proxy) Shutdown() {
	p.ctxCancel()
	p.streamWaitGroup.Wait()
	p.workerPool.Release()
	p.configUpdater.Wait()
	p.doppelGanger.Shutdown()

	p.allowlist.Shutdown()
	p.blocklist.Shutdown()

	if p.usageStateFile != "" {
		if err := p.stats.FlushUsage(p.usageStateFile); err != nil {
			p.logger.WarningError("cannot flush usage state on shutdown", err)
		}
	}

	if p.dcPool != nil {
		p.dcPool.Shutdown()
	}
}

// ReloadSecrets re-reads the secret set through the configured reloader and
// swaps it in atomically, so a client add, removal, disable or re-key takes
// effect without restarting the process. Connections whose secret disappeared
// or was re-keyed are closed; every other live stream keeps running, and the
// /stats counters carry across the swap. It returns ErrReloaderNotConfigured
// when the proxy was built without a SecretsReloader, and an error (leaving the
// current set active) when the reloader fails or yields no valid secret.
func (p *Proxy) ReloadSecrets() error {
	if p.reloader == nil {
		return ErrReloaderNotConfigured
	}

	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	cfg, err := p.reloader()
	if err != nil {
		return fmt.Errorf("cannot reload secrets: %w", err)
	}

	return p.swapSecretConfigLocked(cfg)
}

// swapSecretConfigLocked validates cfg, builds a fresh immutable snapshot,
// swaps it in atomically, pre-registers stats for every name, and closes stale
// connections. It is the single mutation point shared by ReloadSecrets and the
// management-API mutators; the caller MUST hold reloadMu.
func (p *Proxy) swapSecretConfigLocked(cfg SecretConfig) error {
	if len(cfg.Secrets) == 0 {
		return ErrSecretInvalid
	}

	for _, s := range cfg.Secrets {
		if !s.Valid() {
			return ErrSecretInvalid
		}
	}

	newSet := buildSecretSet(cfg.Secrets, cfg.SecretAdTags, cfg.GlobalAdTag, cfg.Limits)
	oldSet := p.secrets.Swap(newSet)

	for _, name := range newSet.names {
		p.stats.PreRegister(name)
	}

	p.closeStaleConns(oldSet, newSet)
	p.closeDeniedConns()

	return nil
}

// registerConn adds the stream to the live set, unless its secret is no longer
// valid in the current snapshot: removed, re-keyed, moved to another host, or
// disabled/expired. The handshake matched against the snapshot it loaded, and
// a reload may have swapped the set and run closeStaleConns/closeDeniedConns
// since then; such a stream would never be closed. The check runs under liveMu
// after the swap is visible: either the stream is registered before the
// cleanup takes liveMu (and the cleanup closes it), or it sees the new set
// here and is rejected.
func (p *Proxy) registerConn(ctx *streamContext) bool {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	if !p.sessionStillValid(ctx) {
		return false
	}

	conns := p.liveConns[ctx.secretName]
	if conns == nil {
		conns = make(map[*streamContext]struct{})
		p.liveConns[ctx.secretName] = conns
	}

	conns[ctx] = struct{}{}

	return true
}

// sessionStillValid reports whether the stream's secret is unchanged in the
// current snapshot and not denied by its limits. Quota is not checked, as in
// closeDeniedConns: it was checked by the handshake and is enforced on the
// traffic itself.
func (p *Proxy) sessionStillValid(ctx *streamContext) bool {
	set := p.secrets.Load()

	idx := sort.SearchStrings(set.names, ctx.secretName)
	if idx >= len(set.names) || set.names[idx] != ctx.secretName || set.secrets[idx] != ctx.matchedSecret {
		return false
	}

	allowed, reason := p.checkLimits(ctx.secretName, set.limits[idx])

	return allowed || reason == DenyQuota
}

func (p *Proxy) unregisterConn(ctx *streamContext) {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	conns := p.liveConns[ctx.secretName]
	if conns == nil {
		return
	}

	delete(conns, ctx)

	if len(conns) == 0 {
		delete(p.liveConns, ctx.secretName)
	}
}

// closeStaleConns closes every live stream whose secret was dropped from the
// new set or changed since the old set (a re-key or a new host), and leaves
// the rest connected. Streams are snapshotted under the lock and closed outside
// it, so each stream's own unregister (which also takes the lock) cannot
// deadlock.
func (p *Proxy) closeStaleConns(oldSet, newSet *secretSet) {
	newSecrets := make(map[string]Secret, len(newSet.names))
	for i, name := range newSet.names {
		newSecrets[name] = newSet.secrets[i]
	}

	oldSecrets := make(map[string]Secret)
	if oldSet != nil {
		for i, name := range oldSet.names {
			oldSecrets[name] = oldSet.secrets[i]
		}
	}

	var stale []*streamContext

	p.liveMu.Lock()
	for name, conns := range p.liveConns {
		if newSecret, kept := newSecrets[name]; kept {
			if oldSecret, had := oldSecrets[name]; had && oldSecret == newSecret {
				continue
			}
		}

		for sc := range conns {
			stale = append(stale, sc)
		}
	}
	p.liveMu.Unlock()

	for _, sc := range stale {
		sc.Close()
	}
}

// checkLimits reports whether a new connection for the named secret is allowed
// by its governance limits, combining the snapshot limit (disabled flag, expiry
// deadline, quota ceiling) with the live usage counter held in stats. The
// returned DenyReason is DenyNone when allowed.
func (p *Proxy) checkLimits(name string, lim SecretLimits) (bool, DenyReason) {
	if lim.Disabled {
		return false, DenyDisabled
	}

	if !lim.ExpiresAt.IsZero() && !time.Now().Before(lim.ExpiresAt) {
		return false, DenyExpired
	}

	if lim.QuotaBytes > 0 && p.stats.QuotaUsed(name, lim.QuotaReset) >= lim.QuotaBytes {
		return false, DenyQuota
	}

	return true, DenyNone
}

// closeDeniedConns closes every live stream whose secret is now denied because
// it was disabled or has expired, so such a change applied via a reload or the
// API takes effect immediately instead of only blocking new connections. A
// quota overrun does not close live streams — consistent with the throttle,
// existing connections are never killed mid-flight.
func (p *Proxy) closeDeniedConns() {
	set := p.secrets.Load()

	limitByName := make(map[string]SecretLimits, len(set.names))
	for i, name := range set.names {
		limitByName[name] = set.limits[i]
	}

	var denied []*streamContext

	p.liveMu.Lock()
	for name, conns := range p.liveConns {
		lim, ok := limitByName[name]
		if !ok {
			continue
		}

		if allowed, reason := p.checkLimits(name, lim); allowed || reason == DenyQuota {
			continue
		}

		for sc := range conns {
			denied = append(denied, sc)
		}
	}
	p.liveMu.Unlock()

	for _, sc := range denied {
		sc.Close()
	}
}

// rolloverAllQuotas applies a monthly quota rollover to every secret whose
// policy is monthly, keeping the persisted and displayed usage fresh even for
// secrets that no client is currently hitting.
func (p *Proxy) rolloverAllQuotas() {
	set := p.secrets.Load()
	now := time.Now()

	for i, name := range set.names {
		if set.limits[i].QuotaReset == QuotaResetMonthly {
			p.stats.rollover(name, set.limits[i].QuotaReset, now)
		}
	}
}

// startUsagePersistence periodically rolls quota periods over and flushes the
// usage counters to usageStateFile until ctx is cancelled.
func (p *Proxy) startUsagePersistence(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(usageFlushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.rolloverAllQuotas()

				if err := p.stats.FlushUsage(p.usageStateFile); err != nil {
					p.logger.WarningError("cannot flush usage state", err)
				}
			}
		}
	}()
}

func (p *Proxy) doFakeTLSHandshake(ctx *streamContext) bool {
	rewind := newConnRewind(ctx.clientConn)

	// Read the active secret snapshot once so a concurrent ReloadSecrets swap
	// cannot desync the key list, hostnames and matched index mid-handshake.
	set := p.secrets.Load()

	if p.securedEnabled {
		// Classify the transport before invoking a parser. A TLS ClientHello with
		// an invalid HMAC is an active probe and must reach the mask host byte for
		// byte; parsing its first 64 bytes as a secured handshake would consume and
		// corrupt the fallback stream.
		firstBytes := [5]byte{}
		if _, err := io.ReadFull(rewind, firstBytes[:]); err != nil {
			ctx.logger.InfoError("cannot read initial handshake bytes", err)
			p.doDomainFrontingForHost(ctx, rewind, set.secrets[0].Host)

			return false
		}

		rewind.Rewind()

		if !isFakeTLSHandshake(firstBytes) {
			// No obfuscated2 client starts with these bytes (an HTTP request,
			// for example): front right away, as with the option off, instead
			// of waiting for a 64-byte frame that will never come.
			if obfuscation.IsReservedFramePrefix(firstBytes[:4]) {
				ctx.logger.Info("first bytes cannot start a secured handshake")
				p.doDomainFrontingForHost(ctx, rewind, set.secrets[0].Host)

				return false
			}

			if err := p.doSecuredHandshake(ctx, rewind, set); err != nil {
				ctx.logger.InfoError("cannot process secured handshake", err)
				p.doDomainFrontingForHost(ctx, rewind, set.secrets[0].Host)

				return false
			}

			return true
		}
	}

	result, err := fake.ReadClientHelloMulti(
		rewind,
		set.keys,
		set.hostnames,
		p.tolerateTimeSkewness,
	)
	if err != nil {
		p.logger.InfoError("cannot read client hello", err)

		frontHost := set.secrets[0].Host
		if result != nil && result.MatchedHost != "" {
			frontHost = result.MatchedHost
		}

		p.doDomainFrontingForHost(ctx, rewind, frontHost)

		return false
	}

	if p.antiReplayCache.SeenBefore(result.Hello.SessionID) {
		p.logger.Warning("replay attack has been detected!")
		p.eventStream.Send(p.ctx, NewEventReplayAttack(ctx.streamID))
		p.doDomainFrontingForHost(ctx, rewind, result.MatchedHost)

		return false
	}

	matchedSecret := set.secrets[result.MatchedIndex]
	ctx.matchedSecret = matchedSecret
	ctx.secretName = set.names[result.MatchedIndex]
	ctx.adTag = set.effectiveAdTag(result.MatchedIndex)
	ctx.logger = ctx.logger.BindStr("secret_name", ctx.secretName)

	// Enforce per-user governance limits before we speak TLS back. A denied
	// user (disabled, expired, or over quota) is routed to the cover site just
	// like a wrong secret, so the outcome is indistinguishable to a prober.
	if allowed, reason := p.checkLimits(ctx.secretName, set.limits[result.MatchedIndex]); !allowed {
		ctx.logger.BindStr("deny_reason", reason.String()).
			Info("connection denied by per-user limit; routing to fronting")
		p.doDomainFrontingForHost(ctx, rewind, result.MatchedHost)

		return false
	}

	gangerNoise := p.doppelGanger.NoiseParams()
	noiseParams := fake.NoiseParams{Mean: gangerNoise.Mean, Jitter: gangerNoise.Jitter}

	if err := fake.SendServerHello(ctx.clientConn, matchedSecret.Key[:], result.Hello, noiseParams); err != nil {
		p.logger.InfoError("cannot send welcome packet", err)
		return false
	}

	ctx.clientConn = tls.New(ctx.clientConn, true, false)

	return true
}

// isFakeTLSHandshake reports whether the first bytes look like a TLS 1.x
// ClientHello record (handshake type, version 3.1), which is what FakeTLS
// clients send.
func isFakeTLSHandshake(firstBytes [5]byte) bool {
	return firstBytes[0] == tls.TypeHandshake &&
		firstBytes[1] == 3 &&
		firstBytes[2] == 1
}

// doSecuredHandshake handles a secured ("dd") client: plain obfuscated2
// without FakeTLS. The secret is found by trying the keys of all configured
// secrets against the handshake frame (dd and ee secrets share the key). set
// is the snapshot the caller already loaded, so the whole handshake works with
// one consistent view of the secrets.
func (p *Proxy) doSecuredHandshake(ctx *streamContext, rewind *connRewind, set *secretSet) error {
	rewind.Rewind()

	idx, dcIdx, cn, replayKey, err := p.readSecuredFrame(ctx, rewind, set.keys)
	if err != nil {
		return err
	}

	if p.antiReplayCache.SeenBefore(replayKey) {
		p.logger.Warning("replay attack has been detected (secured)!")
		p.eventStream.Send(p.ctx, NewEventReplayAttack(ctx.streamID))

		return errors.New("replay attack has been detected")
	}

	name := set.names[idx]

	// Per-user governance limits apply to dd clients exactly as to FakeTLS
	// ones: a denied user (disabled, expired, over quota) is fronted like a
	// wrong secret. The history is still recorded at this point, so the caller
	// can replay the original bytes to the fronting host.
	if allowed, reason := p.checkLimits(name, set.limits[idx]); !allowed {
		ctx.logger.BindStr("secret_name", name).BindStr("deny_reason", reason.String()).
			Info("connection denied by per-user limit; routing to fronting")

		return errSecuredDenied
	}

	// Authenticated: stop recording the stream for replay.
	rewind.Commit()

	ctx.secured = true
	ctx.dc = dcIdx
	ctx.clientConn = cn
	ctx.matchedSecret = set.secrets[idx]
	ctx.secretName = name
	ctx.adTag = set.effectiveAdTag(idx)
	ctx.logger = ctx.logger.BindStr("secret_name", ctx.secretName).BindInt("dc", dcIdx)

	return nil
}

// readSecuredFrame reads the 64-byte obfuscated2 frame of a possible secured
// client under a short read deadline (securedFrameTimeout, capped by the
// handshake deadline). A real client sends the frame in one go, so a peer that
// stalls below 64 bytes is a probe and must reach the fronting host about as
// fast as with a real site, not after the whole handshake timeout. The bytes
// read so far stay in the rewind buffer for the fronting replay. The handshake
// deadline is restored in every case, so neither the fronting relay nor the
// secured session inherits the short one.
func (p *Proxy) readSecuredFrame(
	ctx *streamContext,
	rewind *connRewind,
	secretKeys [][]byte,
) (int, int, essentials.Conn, []byte, error) {
	deadline := time.Now().Add(p.securedFrameTimeout)
	if !ctx.handshakeDeadline.IsZero() && ctx.handshakeDeadline.Before(deadline) {
		deadline = ctx.handshakeDeadline
	}

	if err := ctx.clientConn.SetReadDeadline(deadline); err != nil {
		return -1, 0, nil, nil, fmt.Errorf("cannot set secured frame deadline: %w", err)
	}

	defer ctx.clientConn.SetReadDeadline(ctx.handshakeDeadline) //nolint: errcheck

	idx, dcIdx, cn, replayKey, err := obfuscation.ReadHandshakeMulti(rewind, secretKeys)
	if err != nil {
		return -1, 0, nil, nil, fmt.Errorf("cannot read secured handshake: %w", err)
	}

	return idx, dcIdx, cn, replayKey, nil
}

func (p *Proxy) doObfuscatedHandshake(ctx *streamContext) error {
	// Use the secret key that was matched during the FakeTLS handshake.
	obfs := obfuscation.Obfuscator{
		Secret: ctx.matchedSecret.Key[:],
	}

	dc, conn, err := obfs.ReadHandshake(ctx.clientConn)
	if err != nil {
		return fmt.Errorf("cannot process client handshake: %w", err)
	}

	ctx.dc = dc
	ctx.clientConn = conn
	ctx.logger = ctx.logger.BindInt("dc", dc)

	return nil
}

// wrapTraffic wraps conn so per-read/write byte counts are emitted as
// EventTraffic, but only when a metrics observer is configured (emitTraffic).
// EventTraffic is consumed solely by the statsd/prometheus observers, so when
// none is enabled the wrapper is skipped entirely — avoiding a heap allocation
// (plus time.Now, a streamID hash and a channel send) on every relay read and
// write.
func (p *Proxy) wrapTraffic(conn essentials.Conn, ctx *streamContext) essentials.Conn {
	if !p.emitTraffic {
		return conn
	}

	return connTraffic{
		Conn:     conn,
		streamID: ctx.streamID,
		stream:   p.eventStream,
		ctx:      ctx,
	}
}

func (p *Proxy) doTelegramCall(ctx *streamContext) error {
	// When this stream carries an advertising tag, route it through a Telegram
	// middle proxy so a sponsored channel appears. On any failure we log and
	// fall through to the direct path so the client stays online (availability
	// is favored over the sponsored channel).
	if ctx.adTag != nil && p.middleProxy != nil {
		if err := p.doMiddleProxyCall(ctx); err != nil {
			ctx.logger.WarningError("cannot route through middle proxy, using direct connection", err)
		} else {
			return nil
		}
	}

	dcid := ctx.dc

	// Warm pool: if there is a ready connection to this DC, use it and skip the
	// cold dial and handshake (and the Telegram client backoff when the
	// node-to-DC route flaps).
	if p.dcPool != nil {
		if conn, addr, ok := p.dcPool.get(dcid); ok {
			p.attachTelegramConn(ctx, conn, addr)

			return nil
		}
	}

	conn, foundAddr, actualDC, err := p.dialAndHandshake(ctx, dcid)
	if err != nil {
		return err
	}

	if actualDC != dcid {
		ctx.logger = ctx.logger.BindInt("original_dc", dcid)
		ctx.logger.Warning("unknown DC, fallbacks")
		ctx.dc = actualDC
	}

	p.attachTelegramConn(ctx, conn, foundAddr)

	return nil
}

// dialAndHandshake dials dcID and performs the obfuscated2 handshake. It
// returns the wrapped connection (ready to relay), the chosen address and the
// actual DC (it may differ from the requested one with
// AllowFallbackOnUnknownDC). It does not touch streamContext, so both the
// client path and the dcPool fillers (which have no stream) use it.
func (p *Proxy) dialAndHandshake(ctx context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
	// Media DCs come with a negative id. Addresses are kept per absolute DC
	// number, but the sign must survive into the handshake with Telegram.
	lookupDC := dcID
	if lookupDC < 0 {
		lookupDC = -lookupDC
	}

	addresses := p.telegram.GetAddresses(lookupDC)
	if len(addresses) == 0 && p.allowFallbackOnUnknownDC {
		if dcID < 0 {
			dcID = -dc.DefaultDC
		} else {
			dcID = dc.DefaultDC
		}

		addresses = p.telegram.GetAddresses(dc.DefaultDC)
	}

	var (
		conn      essentials.Conn
		err       error
		foundAddr dc.Addr
	)

	for _, addr := range addresses {
		conn, err = p.network.DialContext(ctx, addr.Network, addr.Address)
		if err == nil {
			foundAddr = addr
			break
		}
	}
	if err != nil {
		return nil, dc.Addr{}, 0, fmt.Errorf("no addresses to call: %w", err)
	}
	if conn == nil {
		return nil, dc.Addr{}, 0, fmt.Errorf("no available addresses for DC %d", dcID)
	}

	// The dial respects ctx, the handshake write does not: bound it by the ctx
	// deadline, if any (the dcPool fillers set one).
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		conn.SetWriteDeadline(deadline) //nolint: errcheck
	}

	tgConn, err := foundAddr.Obfuscator.SendHandshake(conn, dcID)
	if err != nil {
		conn.Close() // nolint: errcheck

		return nil, dc.Addr{}, 0, fmt.Errorf("cannot perform server handshake: %w", err)
	}

	if hasDeadline {
		conn.SetWriteDeadline(time.Time{}) //nolint: errcheck
	}

	return tgConn, foundAddr, dcID, nil
}

// attachTelegramConn puts a ready (dialed and handshaked) DC connection on the
// stream and emits EventConnectedToDC. Shared tail of the cold dial and the
// warm pool paths.
func (p *Proxy) attachTelegramConn(ctx *streamContext, conn essentials.Conn, addr dc.Addr) {
	ctx.telegramConn = p.wrapTraffic(conn, ctx)

	if telegramHost, _, err := net.SplitHostPort(addr.Address); err == nil {
		p.eventStream.Send(
			ctx,
			NewEventConnectedToDC(ctx.streamID,
				net.ParseIP(telegramHost),
				ctx.dc),
		)
	}
}

// doMiddleProxyCall dials a Telegram middle proxy for the stream's DC and sets
// ctx.telegramConn to an RPC stream that carries the client's traffic together
// with the advertising tag. It returns an error (leaving ctx.telegramConn
// unset) if the middle proxy cannot be reached, so the caller can fall back to
// a direct connection.
func (p *Proxy) doMiddleProxyCall(ctx *streamContext) error {
	clientAddr, _ := ctx.clientConn.RemoteAddr().(*net.TCPAddr)

	stream, middleIP, err := p.middleProxy.DialProxyStream(p.network, middleproxy.DialParams{
		DC:             ctx.dc,
		ClientAddr:     clientAddr,
		PublicIPv4:     p.ourIPv4,
		PublicIPv6:     p.ourIPv6,
		AdvertisedPort: p.advertisedPort,
		AdTag:          *ctx.adTag,
	})
	if err != nil {
		return fmt.Errorf("cannot dial middle proxy: %w", err)
	}

	ctx.telegramConn = p.wrapTraffic(stream, ctx)

	p.eventStream.Send(ctx, NewEventConnectedToDC(ctx.streamID, middleIP, ctx.dc))

	return nil
}

func (p *Proxy) doDomainFrontingForHost(ctx *streamContext, conn *connRewind, host string) {
	// The handshake is over: a fronted connection must not hold a pending slot.
	ctx.finishPendingHandshake()

	p.eventStream.Send(p.ctx, NewEventDomainFronting(ctx.streamID))
	// No more protocol detection after this point: replay the recorded bytes
	// once and stop recording.
	conn.FinalRewind()

	nativeDialer := p.network.NativeDialer()
	fConn, err := nativeDialer.DialContext(ctx, "tcp", p.domainFrontingAddressForHost(host))
	if err != nil {
		p.logger.WarningError("cannot dial to the fronting domain", err)

		return
	}

	frontConn := essentials.WrapNetConn(fConn)

	if p.domainFrontingProxyProtocol {
		frontConn = newConnProxyProtocol(ctx.clientConn, frontConn)
	}

	frontConn = p.wrapTraffic(frontConn, ctx)

	tracker := newIdleTracker(p.idleTimeout)

	relay.Relay(
		ctx,
		ctx.logger.Named("domain-fronting"),
		connIdleTimeout{Conn: frontConn, tracker: tracker},
		connIdleTimeout{Conn: conn, tracker: tracker},
	)
}

// NewProxy makes a new proxy instance.
func NewProxy(opts ProxyOpts) (*Proxy, error) {
	if err := opts.valid(); err != nil {
		return nil, fmt.Errorf("invalid settings: %w", err)
	}

	tg, err := dc.New(opts.getPreferIP())
	if err != nil {
		return nil, fmt.Errorf("cannot build telegram dc fetcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := opts.getLogger("proxy")
	updatersLogger := logger.Named("telegram-updaters")

	initialSet := buildSecretSet(opts.getSecrets(), opts.SecretAdTags, opts.GlobalAdTag, opts.SecretLimits)

	stats := NewProxyStats()
	for _, name := range initialSet.names {
		stats.PreRegister(name)
	}

	if opts.UsageStateFile != "" {
		if err := stats.LoadUsage(opts.UsageStateFile); err != nil {
			logger.WarningError("cannot load usage state", err)
		}
	}

	if opts.ThrottleMaxConnections > 0 {
		stats.SetThrottle(int64(opts.ThrottleMaxConnections), opts.getThrottleCheckInterval())
		stats.startThrottleLoop(ctx, logger)
	}

	if opts.DomainFrontingIP != "" {
		logger.Warning("mtglib.ProxyOpts.DomainFrontingIP is deprecated and ignored; use DomainFrontingHost instead")
	}

	proxy := &Proxy{
		ctx:                      ctx,
		ctxCancel:                cancel,
		stats:                    stats,
		reloader:                 opts.SecretsReloader,
		liveConns:                make(map[string]map[*streamContext]struct{}),
		network:                  opts.Network,
		antiReplayCache:          opts.AntiReplayCache,
		blocklist:                opts.IPBlocklist,
		allowlist:                opts.IPAllowlist,
		eventStream:              opts.EventStream,
		logger:                   logger,
		domainFrontingPort:       opts.getDomainFrontingPort(),
		domainFrontingHost:       opts.DomainFrontingHost,
		tolerateTimeSkewness:     opts.getTolerateTimeSkewness(),
		idleTimeout:              opts.getIdleTimeout(),
		handshakeTimeout:         opts.getHandshakeTimeout(),
		allowFallbackOnUnknownDC: opts.AllowFallbackOnUnknownDC,
		pendingHandshakes:        newPendingHandshakes(),
		pendingHandshakesPerIP:   uint32(min(opts.PendingHandshakesPerIP, math.MaxUint32)), //nolint: gosec
		pendingHandshakesDryRun:  opts.PendingHandshakesDryRun,
		pendingHandshakesLog:     logthrottle.New(pendingHandshakesLogInterval),
		securedEnabled:           opts.SecuredEnabled,
		securedFrameTimeout:      opts.getSecuredFrameTimeout(),
		telegram:                 tg,
		doppelGanger: doppel.NewGanger(
			ctx,
			opts.Network,
			logger.Named("doppelganger"),
			opts.DoppelGangerEach,
			int(opts.DoppelGangerPerRaid),
			opts.DoppelGangerURLs,
			opts.DoppelGangerDRS,
		),
		configUpdater: dc.NewPublicConfigUpdater(
			tg,
			updatersLogger.Named("public-config"),
			opts.Network.MakeHTTPClient(nil),
		),
		domainFrontingProxyProtocol: opts.DomainFrontingProxyProtocol,
		ourIPv4:                     opts.PublicIPv4,
		ourIPv6:                     opts.PublicIPv6,
		advertisedPort:              opts.AdvertisedPort,
		usageStateFile:              opts.UsageStateFile,
		emitTraffic:                 opts.EmitTraffic,
	}

	// The middle-proxy manager is always available so advertising can be
	// enabled at runtime via the API. It fetches Telegram's proxy secret and
	// middle-proxy list lazily (nothing happens until an ad-tagged stream is
	// dialed), so a proxy without advertising never touches the network. When
	// advertising is already configured, warm it so the first client is fast.
	proxy.middleProxy = middleproxy.NewManager(
		ctx,
		opts.Network.MakeHTTPClient(nil),
		updatersLogger.Named("middle-proxy"),
		opts.getPreferIP(),
	)

	if opts.GlobalAdTag != nil || len(opts.SecretAdTags) > 0 {
		proxy.middleProxy.Warm()
	}

	proxy.secrets.Store(initialSet)

	// Start the management API only now that the proxy exists, so the routes
	// can drive ReloadSecrets and the secrets/adtag mutators. /stats, /reload,
	// /secrets and /adtag share the api-bind-to listener; reload is a
	// no-op-with-error when no reloader was supplied.
	if opts.APIBindTo != "" {
		proxy.startAPIServer(ctx, opts.APIBindTo, opts.APIToken)
	}

	if opts.UsageStateFile != "" {
		proxy.startUsagePersistence(ctx)
	}

	proxy.doppelGanger.Run()

	if opts.AutoUpdate {
		proxy.configUpdater.Run(ctx, dc.PublicConfigUpdateURLv4, "tcp4")
		proxy.configUpdater.Run(ctx, dc.PublicConfigUpdateURLv6, "tcp6")
	}

	// Warm DC connection pool, opt-in. Fillers start right away and retry until
	// AutoUpdate brings DC addresses; clients are never blocked by it (a miss
	// falls back to a cold dial).
	if opts.DCPoolEnabled {
		proxy.dcPool = newDCPool(
			ctx,
			proxy.dialAndHandshake,
			logger.Named("dc-pool"),
			func(dcID int, result string) {
				proxy.eventStream.Send(proxy.ctx, NewEventDCPool(dcID, result))
			},
			opts.getDCPoolDCs(),
			opts.getDCPoolSize(),
			DCPoolConnMaxAge,
			DCPoolRefreshInterval,
		)
	}

	pool, err := ants.NewPoolWithFunc(opts.getConcurrency(),
		func(arg any) {
			proxy.ServeConn(arg.(essentials.Conn)) //nolint: forcetypeassert
		},
		ants.WithLogger(opts.getLogger("ants")),
		ants.WithNonblocking(true))
	if err != nil {
		panic(err)
	}

	proxy.workerPool = pool

	return proxy, nil
}
