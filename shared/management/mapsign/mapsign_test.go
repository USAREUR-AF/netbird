package mapsign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return priv
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func sampleMap() *mgmProto.NetworkMap {
	return &mgmProto.NetworkMap{
		Serial:      42,
		PeerConfig:  &mgmProto.PeerConfig{Address: "198.51.100.1/24"},
		RemotePeers: []*mgmProto.RemotePeerConfig{{WgPubKey: "peer-b", AllowedIps: []string{"198.51.100.2/32"}}},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := newKey(t)
	s, err := NewSigner("goatnet-1", key, 0)
	require.NoError(t, err)
	fixed := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }

	signed, err := s.Sign("peer-a", sampleMap())
	require.NoError(t, err)
	assert.Equal(t, KeyID(pub(key)), signed.KeyID)

	ts, err := NewTrustSet("goatnet-1", pub(key))
	require.NoError(t, err)
	env, err := ts.Verify("peer-a", signed)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), env.Serial)
	assert.Equal(t, "peer-a", env.IssuedTo)
	assert.Equal(t, fixed, env.IssuedAt().UTC())
	assert.Equal(t, int64(DefaultRefreshInterval/time.Second), env.RefreshIntervalSeconds)
	assert.True(t, proto.Equal(sampleMap(), env.Map()))
}

func TestVerifyRefusals(t *testing.T) {
	key := newKey(t)
	s, err := NewSigner("goatnet-1", key, time.Hour)
	require.NoError(t, err)
	signed, err := s.Sign("peer-a", sampleMap())
	require.NoError(t, err)
	ts, err := NewTrustSet("goatnet-1", pub(key))
	require.NoError(t, err)

	t.Run("unsigned", func(t *testing.T) {
		_, err := ts.Verify("peer-a", nil)
		assert.ErrorIs(t, err, ErrUnsigned)
	})
	t.Run("untrusted key", func(t *testing.T) {
		other, err := NewSigner("goatnet-1", newKey(t), time.Hour)
		require.NoError(t, err)
		forged, err := other.Sign("peer-a", sampleMap())
		require.NoError(t, err)
		_, err = ts.Verify("peer-a", forged)
		assert.ErrorIs(t, err, ErrUnknownKey)
	})
	t.Run("signature by another key under a trusted key ID", func(t *testing.T) {
		other, err := NewSigner("goatnet-1", newKey(t), time.Hour)
		require.NoError(t, err)
		forged, err := other.Sign("peer-a", sampleMap())
		require.NoError(t, err)
		forged.KeyID = signed.KeyID
		_, err = ts.Verify("peer-a", forged)
		assert.ErrorIs(t, err, ErrBadSignature)
	})
	t.Run("envelope edited after signing", func(t *testing.T) {
		env, err := Open(signed)
		require.NoError(t, err)
		nm := env.Map()
		nm.RemotePeers = append(nm.RemotePeers, &mgmProto.RemotePeerConfig{WgPubKey: "intruder", AllowedIps: []string{"198.51.100.66/32"}})
		env.NetworkMap, err = proto.Marshal(nm)
		require.NoError(t, err)
		b, err := json.Marshal(env)
		require.NoError(t, err)
		edited := *signed
		edited.Envelope = b
		_, err = ts.Verify("peer-a", &edited)
		assert.ErrorIs(t, err, ErrBadSignature)
	})
	t.Run("another peer", func(t *testing.T) {
		_, err := ts.Verify("peer-z", signed)
		assert.ErrorIs(t, err, ErrWrongPeer)
	})
	t.Run("another goatnet", func(t *testing.T) {
		other, err := NewTrustSet("goatnet-2", pub(key))
		require.NoError(t, err)
		_, err = other.Verify("peer-a", signed)
		assert.ErrorIs(t, err, ErrWrongGoatnet)
	})
}

func TestSignSyncResponseMovesMapIntoEnvelope(t *testing.T) {
	key := newKey(t)
	s, err := NewSigner("goatnet-1", key, time.Hour)
	require.NoError(t, err)
	resp := &mgmProto.SyncResponse{NetbirdConfig: &mgmProto.NetbirdConfig{}, NetworkMap: sampleMap()}

	out, err := s.SignSyncResponse("peer-a", resp)
	require.NoError(t, err)
	assert.Nil(t, out.GetNetworkMap())
	assert.NotNil(t, out.GetNetbirdConfig())
	assert.NotNil(t, resp.GetNetworkMap(), "the input response is not modified")

	ts, err := NewTrustSet("goatnet-1", pub(key))
	require.NoError(t, err)
	// Through the wire: encode and decode the response as the management and client do.
	wire, err := proto.Marshal(out)
	require.NoError(t, err)
	decoded := &mgmProto.SyncResponse{}
	require.NoError(t, proto.Unmarshal(wire, decoded))
	assert.Nil(t, decoded.GetNetworkMap())
	signed, err := FromSyncResponse(decoded)
	require.NoError(t, err)
	require.NotNil(t, signed, "the signed map survives encoding as an undeclared field")
	env, err := ts.Verify("peer-a", signed)
	require.NoError(t, err)
	assert.True(t, proto.Equal(sampleMap(), env.Map()))

	// Attaching again replaces the field instead of adding a second one.
	require.NoError(t, Attach(decoded, signed))
	require.NoError(t, Attach(decoded, signed))
	count := 0
	for b := decoded.ProtoReflect().GetUnknown(); len(b) > 0; {
		num, typ, n := protowire.ConsumeTag(b)
		m := protowire.ConsumeFieldValue(num, typ, b[n:])
		if num == SyncResponseField {
			count++
		}
		b = b[n+m:]
	}
	assert.Equal(t, 1, count)

	none, err := FromSyncResponse(&mgmProto.SyncResponse{})
	require.NoError(t, err)
	assert.Nil(t, none)

	noMap := &mgmProto.SyncResponse{NetbirdConfig: &mgmProto.NetbirdConfig{}}
	same, err := s.SignSyncResponse("peer-a", noMap)
	require.NoError(t, err)
	assert.Same(t, noMap, same)

	var nilSigner *Signer
	same, err = nilSigner.SignSyncResponse("peer-a", resp)
	require.NoError(t, err)
	assert.Same(t, resp, same)
}

func TestKeyAndTrustFiles(t *testing.T) {
	dir := t.TempDir()
	key := newKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "map-signing.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))

	s, err := NewSignerFromFile("goatnet-1", keyPath, 0)
	require.NoError(t, err)
	assert.Equal(t, KeyID(pub(key)), s.KeyID())

	second := newKey(t)
	data, err := MarshalTrustFile("goatnet-1", pub(key), pub(second))
	require.NoError(t, err)
	trustPath := filepath.Join(dir, "map-trust.json")
	require.NoError(t, os.WriteFile(trustPath, data, 0o644))
	ts, err := LoadTrustFile(trustPath)
	require.NoError(t, err)

	signed, err := s.Sign("peer-a", sampleMap())
	require.NoError(t, err)
	_, err = ts.Verify("peer-a", signed)
	require.NoError(t, err, "a trust set may hold several signers")

	bad := []byte(`{"goatnet_id":"goatnet-1","signers":[{"key_id":"ed25519-0000000000000000","public_key":"` + mustB64(pub(key)) + `"}]}`)
	require.NoError(t, os.WriteFile(trustPath, bad, 0o644))
	_, err = LoadTrustFile(trustPath)
	assert.Error(t, err, "a key_id that does not match its key is refused")

	require.NoError(t, os.WriteFile(trustPath, []byte(`{"goatnet_id":"goatnet-1","signers":[]}`), 0o644))
	_, err = LoadTrustFile(trustPath)
	assert.Error(t, err, "an empty trust set is refused")

	_, err = NewSignerFromFile("goatnet-1", filepath.Join(dir, "missing.pem"), 0)
	assert.True(t, errors.Is(err, os.ErrNotExist))
	_, err = NewSigner("", key, 0)
	assert.Error(t, err)
}

func mustB64(k ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(k)
}
