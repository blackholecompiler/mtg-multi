package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mhsanaei/mtg-multi/logger"
	"github.com/mhsanaei/mtg-multi/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeReloader stands in for *mtglib.Proxy: each ReloadSecrets call swaps in
// the next prepared set (the last one repeats), or fails with err.
type fakeReloader struct {
	mu      sync.Mutex
	current []mtglib.SecretInfo
	next    [][]mtglib.SecretInfo
	reloads int
	err     error
}

func (f *fakeReloader) ReloadSecrets() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.reloads++

	if f.err != nil {
		return f.err
	}

	if len(f.next) > 0 {
		f.current = f.next[0]
		if len(f.next) > 1 {
			f.next = f.next[1:]
		}
	}

	return nil
}

func (f *fakeReloader) SnapshotSecrets() []mtglib.SecretInfo {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]mtglib.SecretInfo(nil), f.current...)
}

func (f *fakeReloader) reloadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.reloads
}

func infos(pairs ...string) []mtglib.SecretInfo {
	out := make([]mtglib.SecretInfo, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, mtglib.SecretInfo{Name: pairs[i], Host: pairs[i+1]})
	}

	return out
}

// runWatchReload starts watchReload and returns a stop function that waits
// for it to exit.
func runWatchReload(t *testing.T, reloader secretsReloader, resolver hostResolver, log mtglib.Logger) (chan<- os.Signal, func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		watchReload(ctx, signals, reloader, resolver, log)
	}()

	return signals, func() {
		cancel()
		<-done
	}
}

func TestWatchReloadOnSignal(t *testing.T) {
	t.Parallel()

	reloader := &fakeReloader{current: infos("alice", "example.com")}
	signals, stop := runWatchReload(t, reloader, newFakeResolver("example.com"), logger.NewNoopLogger())

	signals <- syscall.SIGHUP
	signals <- syscall.SIGHUP

	require.Eventually(t, func() bool { return reloader.reloadCount() == 2 }, time.Second, 5*time.Millisecond)

	stop()
}

// A failed reload (for example a half-written config) keeps the current
// secrets, is reported, and the watcher keeps serving later signals.
func TestWatchReloadReportsErrorAndContinues(t *testing.T) {
	t.Parallel()

	reloader := &fakeReloader{err: errors.New("broken config")}
	log := newRecordingLogger()
	signals, stop := runWatchReload(t, reloader, newFakeResolver(), log)

	signals <- syscall.SIGHUP
	signals <- syscall.SIGHUP

	require.Eventually(t, func() bool { return reloader.reloadCount() == 2 }, time.Second, 5*time.Millisecond)
	stop()

	warnings := log.recorded()
	require.Len(t, warnings, 2)
	assert.Contains(t, warnings[0], "keeping current secrets")
	assert.Contains(t, warnings[0], "broken config")
}

// simple-run has no config file: the signal is ignored with a warning instead
// of terminating the process.
func TestWatchReloadWithoutConfigFile(t *testing.T) {
	t.Parallel()

	reloader := &fakeReloader{err: fmt.Errorf("wrapped: %w", mtglib.ErrReloaderNotConfigured)}
	log := newRecordingLogger()
	signals, stop := runWatchReload(t, reloader, newFakeResolver(), log)

	signals <- syscall.SIGHUP

	require.Eventually(t, func() bool { return len(log.recorded()) == 1 }, time.Second, 5*time.Millisecond)
	stop()

	assert.Contains(t, log.recorded()[0], "not supported without a config file")
}

// fakeResolver resolves the hostnames it knows and fails on the rest. It
// records every lookup.
type fakeResolver struct {
	known   map[string]bool
	lookups *[]string
	mu      *sync.Mutex
}

func newFakeResolver(known ...string) fakeResolver {
	r := fakeResolver{known: map[string]bool{}, lookups: &[]string{}, mu: &sync.Mutex{}}
	for _, host := range known {
		r.known[host] = true
	}

	return r
}

func (r fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	*r.lookups = append(*r.lookups, host)
	r.mu.Unlock()

	if r.known[host] {
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
	}

	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (r fakeResolver) lookedUp() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), *r.lookups...)
}

// recordingLogger records warnings together with their bound strings.
type recordingLogger struct {
	mtglib.Logger

	binds    []string
	mu       *sync.Mutex
	warnings *[]string
}

func newRecordingLogger() recordingLogger {
	return recordingLogger{Logger: logger.NewNoopLogger(), mu: &sync.Mutex{}, warnings: &[]string{}}
}

func (l recordingLogger) Named(_ string) mtglib.Logger          { return l }
func (l recordingLogger) BindInt(_ string, _ int) mtglib.Logger { return l }

func (l recordingLogger) BindStr(name, value string) mtglib.Logger {
	l.binds = append(append([]string(nil), l.binds...), name+"="+value)

	return l
}

func (l recordingLogger) Warning(msg string) { l.record(msg) }

func (l recordingLogger) WarningError(msg string, err error) {
	l.record(fmt.Sprintf("%s: %v", msg, err))
}

func (l recordingLogger) record(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	*l.warnings = append(*l.warnings, strings.Join(append(append([]string(nil), l.binds...), msg), " "))
}

func (l recordingLogger) recorded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), *l.warnings...)
}

func TestWarnUnresolvedHostsChecksOnlyNewHosts(t *testing.T) {
	t.Parallel()

	resolver := newFakeResolver("new.example.com")
	log := newRecordingLogger()

	warnUnresolvedHosts(context.Background(), resolver,
		infos("alice", "old.example.com", "bob", "old.example.com"),
		infos("alice", "old.example.com", "bob", "tpyo.example.com",
			"carol", "tpyo.example.com", "dave", "new.example.com"),
		log)

	// old.example.com was in use before the reload and is not looked up
	// again; a hostname shared by several users is looked up once.
	assert.ElementsMatch(t, []string{"new.example.com", "tpyo.example.com"}, resolver.lookedUp())

	warnings := log.recorded()
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "hostname=tpyo.example.com")
	assert.Contains(t, warnings[0], "users=bob,carol")
	assert.Contains(t, warnings[0], "does not resolve")
}

func TestWarnUnresolvedHostsSilentWhenAllResolve(t *testing.T) {
	t.Parallel()

	resolver := newFakeResolver("a.example.com", "b.example.com")
	log := newRecordingLogger()

	warnUnresolvedHosts(context.Background(), resolver, nil,
		infos("alice", "a.example.com", "bob", "b.example.com"), log)

	assert.Len(t, resolver.lookedUp(), 2)
	assert.Empty(t, log.recorded())
}

// A hostname that does not resolve is reported, but the new secrets are
// applied anyway, and the next reload compares against them.
func TestWatchReloadWarnsAboutUnresolvedHostAndApplies(t *testing.T) {
	t.Parallel()

	reloader := &fakeReloader{
		current: infos("alice", "good.example.com"),
		next:    [][]mtglib.SecretInfo{infos("alice", "good.example.com", "bob", "tpyo.example.com")},
	}
	resolver := newFakeResolver("good.example.com")
	log := newRecordingLogger()
	signals, stop := runWatchReload(t, reloader, resolver, log)

	signals <- syscall.SIGHUP

	require.Eventually(t, func() bool { return len(resolver.lookedUp()) == 1 }, time.Second, 5*time.Millisecond)

	// The same config again: tpyo.example.com is now in use and is not
	// looked up a second time.
	signals <- syscall.SIGHUP

	require.Eventually(t, func() bool { return reloader.reloadCount() == 2 }, time.Second, 5*time.Millisecond)
	stop()

	assert.Equal(t, []string{"tpyo.example.com"}, resolver.lookedUp())

	unresolved := 0

	for _, w := range log.recorded() {
		if strings.Contains(w, "does not resolve") {
			unresolved++

			assert.Contains(t, w, "users=bob")
		}
	}

	assert.Equal(t, 1, unresolved)
}
