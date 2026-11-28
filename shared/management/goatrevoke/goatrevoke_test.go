package goatrevoke

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/shared/management/mapsign"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func revoke(t *testing.T, key ed25519.PrivateKey, goatnet, peerKey string, issued time.Time) *Signed {
	t.Helper()
	s, err := Sign(&Revocation{GoatnetID: goatnet, PeerKey: peerKey, IssuedAtUnixNano: issued.UnixNano()}, key)
	require.NoError(t, err)
	b, err := s.Marshal()
	require.NoError(t, err)
	parsed, err := Parse(b)
	require.NoError(t, err)
	return parsed
}

func TestVerify(t *testing.T) {
	pub, priv := keyPair(t)
	ts, err := mapsign.NewTrustSet("goatnet-1", pub)
	require.NoError(t, err)

	good := revoke(t, priv, "goatnet-1", "peer-c", time.Now())
	require.NoError(t, Verify(ts, good))

	_, other := keyPair(t)
	assert.ErrorIs(t, Verify(ts, revoke(t, other, "goatnet-1", "peer-c", time.Now())), ErrBadSignature, "signed by a key the trust set does not hold")
	assert.ErrorIs(t, Verify(ts, revoke(t, priv, "goatnet-2", "peer-c", time.Now())), ErrOtherGoatnet)

	edited := *good
	r := *good.Rev()
	r.PeerKey = "peer-a"
	edited.Revocation, err = json.Marshal(&r)
	require.NoError(t, err)
	edited.rev = &r
	assert.ErrorIs(t, Verify(ts, &edited), ErrBadSignature, "a revocation edited after signing")

	_, err = Parse(make([]byte, MaxMessageSize+1))
	assert.ErrorIs(t, err, ErrMalformed, "an oversized message is refused before decoding")
}

func TestRevokedIsAbsorbing(t *testing.T) {
	_, priv := keyPair(t)
	list := []*Signed{revoke(t, priv, "goatnet-1", "peer-c", time.Now().Add(-365*24*time.Hour))}
	assert.True(t, Revoked(list, "peer-c"), "a revocation never expires")
	assert.False(t, Revoked(list, "peer-a"), "another peer")
}

func TestStoreIsDurableAndDeduplicates(t *testing.T) {
	_, priv := keyPair(t)
	path := filepath.Join(t.TempDir(), "state.goat-revocations.json")
	s, err := OpenStore(path)
	require.NoError(t, err)

	r := revoke(t, priv, "goatnet-1", "peer-c", time.Now())
	added, err := s.Add(r)
	require.NoError(t, err)
	assert.True(t, added)
	added, err = s.Add(r)
	require.NoError(t, err)
	assert.False(t, added, "a revocation already held is not added again (this ends a flood)")

	fi, err := os.Stat(path)
	require.NoError(t, err)
	if os.PathSeparator == '/' {
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}

	reopened, err := OpenStore(path)
	require.NoError(t, err)
	require.Len(t, reopened.All(), 1, "a stored revocation survives a restart")
	assert.Equal(t, r.ID(), reopened.All()[0].ID())

	old := revoke(t, priv, "goatnet-1", "peer-d", time.Now().Add(-100*time.Hour))
	_, err = reopened.Add(old)
	require.NoError(t, err)
	again, err := OpenStore(path)
	require.NoError(t, err)
	require.Len(t, again.All(), 2, "an old revocation is kept: revocations are absorbing")
}

func TestSyncResponseField(t *testing.T) {
	_, priv := keyPair(t)
	list := []*Signed{revoke(t, priv, "goatnet-1", "peer-c", time.Now()), revoke(t, priv, "goatnet-1", "peer-d", time.Now())}
	resp := &mgmProto.SyncResponse{NetworkMap: &mgmProto.NetworkMap{Serial: 1}}
	require.NoError(t, Attach(resp, list))
	require.NoError(t, Attach(resp, list))
	wire, err := proto.Marshal(resp)
	require.NoError(t, err)
	decoded := &mgmProto.SyncResponse{}
	require.NoError(t, proto.Unmarshal(wire, decoded))
	got := FromSyncResponse(decoded)
	require.Len(t, got, 2, "attaching twice leaves one list")
	assert.Equal(t, "peer-c", got[0].Rev().PeerKey)
	assert.Empty(t, FromSyncResponse(&mgmProto.SyncResponse{}))
}

// TestSyncResponseRevocationFieldUndeclaredUpstream fails when upstream's
// SyncResponse declares or reserves field 1003.
func TestSyncResponseRevocationFieldUndeclaredUpstream(t *testing.T) {
	src, err := os.ReadFile("../proto/management.proto")
	require.NoError(t, err)
	body := regexp.MustCompile(`(?s)\nmessage\s+SyncResponse\s*\{(.*?)\n\}`).FindStringSubmatch(string(src))
	require.Len(t, body, 2, "management.proto declares SyncResponse")
	field := regexp.MustCompile(`=\s*(\d+)\s*[;\[]`)
	numbers := map[int]bool{}
	for _, m := range field.FindAllStringSubmatch(body[1], -1) {
		n, _ := strconv.Atoi(m[1])
		numbers[n] = true
	}
	require.True(t, numbers[5], "the parser sees the NetworkMap field (5)")
	require.False(t, numbers[int(SyncResponseField)], "upstream SyncResponse now declares field %d; move the revocation list to an unused number", SyncResponseField)
	require.NotRegexp(t, `reserved[^;]*\b1003\b`, body[1])
}
