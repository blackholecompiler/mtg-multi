package mtglib

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mhsanaei/mtg-multi/essentials"
	"github.com/mhsanaei/mtg-multi/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tcpPair(t *testing.T) (server, client *net.TCPConn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() }) //nolint: errcheck

	accepted := make(chan net.Conn, 1)

	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	s := <-accepted
	require.NotNil(t, s)
	t.Cleanup(func() { s.Close(); c.Close() }) //nolint: errcheck

	return s.(*net.TCPConn), c.(*net.TCPConn) //nolint: forcetypeassert
}

// securedSession runs a real secured (dd) handshake for secret against the
// proxy's current snapshot, the way doFakeTLSHandshake does with [secured]
// enabled. It returns the stream and the client side of its connection.
func securedSession(t *testing.T, p *Proxy, secret Secret) (*streamContext, *net.TCPConn) {
	t.Helper()

	frame := &recordingConn{}
	_, err := (obfuscation.Obfuscator{Secret: secret.Key[:]}).SendHandshake(frame, 2)
	require.NoError(t, err)

	server, client := tcpPair(t)
	_, err = client.Write(frame.buf.Bytes())
	require.NoError(t, err)

	stream := newStreamContext(context.Background(), NoopLogger{}, essentials.WrapNetConn(server))
	t.Cleanup(stream.ctxCancel)

	require.NoError(t, p.doSecuredHandshake(stream, newConnRewind(stream.clientConn), p.secrets.Load()))
	require.True(t, stream.secured)

	return stream, client
}

func newSecuredReloadTestProxy(secrets map[string]Secret) *Proxy {
	p := newReloadTestProxy(secrets)
	p.ctx = context.Background()
	p.logger = NoopLogger{}
	p.eventStream = &countingEventStream{}
	p.antiReplayCache = &mapAntiReplayCache{seen: map[string]bool{}}
	p.securedFrameTimeout = time.Second

	return p
}

// A dd session is registered under the user whose key matched, with the
// whole secret of that user from the same snapshot, and is closed when the
// user is removed. The session's clientConn is the obfuscated2 wrapper, so
// the close must reach the original connection.
func TestReloadClosesSecuredSession(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")
	p := newSecuredReloadTestProxy(map[string]Secret{"alice": alice, "bob": bob})
	p.reloader = func() (SecretConfig, error) {
		return SecretConfig{Secrets: map[string]Secret{"bob": bob}}, nil
	}

	aliceStream, aliceClient := securedSession(t, p, alice)
	assert.Equal(t, "alice", aliceStream.secretName)
	assert.Equal(t, alice, aliceStream.matchedSecret)
	require.True(t, p.registerConn(aliceStream))

	bobStream, _ := securedSession(t, p, bob)
	assert.Equal(t, "bob", bobStream.secretName)
	require.True(t, p.registerConn(bobStream))

	require.NoError(t, p.ReloadSecrets())

	assert.ErrorIs(t, aliceStream.Err(), context.Canceled)
	assert.NoError(t, bobStream.Err())

	require.NoError(t, aliceClient.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err := aliceClient.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

// A dd handshake that matched a user against the old snapshot must not
// register a session after the user has been removed.
func TestRegisterSecuredSessionAfterSecretRemoved(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	p := newSecuredReloadTestProxy(map[string]Secret{"alice": alice})
	p.reloader = func() (SecretConfig, error) {
		return SecretConfig{Secrets: map[string]Secret{"bob": GenerateSecret("example.com")}}, nil
	}

	stream, _ := securedSession(t, p, alice)

	require.NoError(t, p.ReloadSecrets())

	assert.False(t, p.registerConn(stream))

	p.liveMu.Lock()
	assert.Empty(t, p.liveConns)
	p.liveMu.Unlock()
}
