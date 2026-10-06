package obfuscation_test

import (
	"bytes"
	"testing"

	"github.com/mhsanaei/mtg-multi/internal/testlib"
	"github.com/mhsanaei/mtg-multi/mtglib"
	"github.com/mhsanaei/mtg-multi/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ObfuscatorTestSuite struct {
	SnapshotTestSuite

	secret *mtglib.Secret
}

func (s *ObfuscatorTestSuite) SetupSuite() {
	s.Setup("", "client-handshake")

	secret := mtglib.GenerateSecret("hostname.com")
	s.secret = &secret
}

func (s *ObfuscatorTestSuite) TestSnapshot() {
	for name, snapshot := range s.snapshots {
		s.T().Run(name, func(t *testing.T) {
			obfs := obfuscation.Obfuscator{
				Secret: snapshot.Secret.data,
			}

			connMock := &testlib.EssentialsConnMock{}

			connMockReadBuffer := &bytes.Buffer{}
			connMockReadBuffer.Write(snapshot.Frame.data)
			connMockReadBuffer.Write(snapshot.Decrypted.Cipher.data)

			connMockWriteBuffer := &bytes.Buffer{}

			connMock.
				On("Read", mock.AnythingOfType("[]uint8")).
				Return(64, nil).
				Run(func(args mock.Arguments) {
					arr := args.Get(0).([]byte)
					_, err := connMockReadBuffer.Read(arr)
					require.NoError(t, err)
				})

			dc, cn, err := obfs.ReadHandshake(connMock)
			assert.EqualValues(t, 2, dc)
			assert.NoError(t, err)

			connMock.Calls = []mock.Call{}
			connMock.ExpectedCalls = []*mock.Call{}

			connMock.
				On("Read", mock.AnythingOfType("[]uint8")).
				Return(len(snapshot.Decrypted.Cipher.data), nil).
				Run(func(args mock.Arguments) {
					arr := args.Get(0).([]byte)
					_, err := connMockReadBuffer.Read(arr)
					require.NoError(t, err)
				})
			connMock.
				On("Write", mock.AnythingOfType("[]uint8")).
				Return(len(snapshot.Encrypted.Cipher.data), nil).
				Run(func(args mock.Arguments) {
					arr := args.Get(0).([]byte)
					_, err := connMockWriteBuffer.Write(arr)
					require.NoError(t, err)
				})

			readBuf := make([]byte, len(snapshot.Decrypted.Text.data))
			_, err = cn.Read(readBuf)
			assert.NoError(t, err)
			assert.Equal(t, readBuf, snapshot.Decrypted.Text.data)

			_, err = cn.Write(snapshot.Encrypted.Text.data)
			assert.NoError(t, err)
			assert.Equal(t, connMockWriteBuffer.Bytes(), snapshot.Encrypted.Cipher.data)

			connMock.AssertExpectations(t)
		})
	}
}

func (s *ObfuscatorTestSuite) TestReadHandshakeMulti() {
	for name, snapshot := range s.snapshots {
		s.T().Run(name, func(t *testing.T) {
			read := func(secrets [][]byte) (int, int, error) {
				connMock := &testlib.EssentialsConnMock{}
				buf := bytes.NewBuffer(append([]byte(nil), snapshot.Frame.data...))

				connMock.
					On("Read", mock.AnythingOfType("[]uint8")).
					Return(64, nil).
					Run(func(args mock.Arguments) {
						_, err := buf.Read(args.Get(0).([]byte))
						require.NoError(t, err)
					})

				idx, dc, _, replayKey, err := obfuscation.ReadHandshakeMulti(connMock, secrets)
				if err == nil {
					assert.Len(t, replayKey, 32)
				}

				return idx, dc, err
			}

			other := mtglib.GenerateSecret("other.com")

			// The matching secret is found among several, its index is returned.
			idx, dc, err := read([][]byte{other.Key[:], snapshot.Secret.data})
			require.NoError(t, err)
			assert.Equal(t, 1, idx)
			assert.EqualValues(t, 2, dc)

			// No matching secret - an error, not a guess.
			_, _, err = read([][]byte{other.Key[:]})
			assert.Error(t, err)
		})
	}
}

func TestObfuscator(t *testing.T) {
	t.Parallel()
	suite.Run(t, &ObfuscatorTestSuite{})
}
