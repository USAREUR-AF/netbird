package goatmember

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
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

func cert(t *testing.T, key ed25519.PrivateKey, goatnet, peer string, at time.Time, window time.Duration) *Signed {
	t.Helper()
	s, err := Sign(&Certificate{GoatnetID: goatnet, PeerKey: peer, IssuedAtUnixNano: at.UnixNano(), WindowSeconds: int64(window / time.Second)}, key)
	require.NoError(t, err)
	b, err := s.Marshal()
	require.NoError(t, err)
	parsed, err := Parse(b)
	require.NoError(t, err)
	return parsed
}

func TestVerifyAndAgree(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ts, err := mapsign.NewTrustSet("goatnet-1", pub)
	require.NoError(t, err)
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

	a := cert(t, priv, "goatnet-1", "peer-a", now, 30*time.Minute)
	require.NoError(t, Verify(ts, a, "peer-a"))
	assert.ErrorIs(t, Verify(ts, a, "peer-b"), ErrWrongPeer)
	assert.ErrorIs(t, Verify(ts, cert(t, priv, "goatnet-2", "peer-a", now, time.Minute), "peer-a"), ErrOtherGoatnet)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	assert.ErrorIs(t, Verify(ts, cert(t, other, "goatnet-1", "peer-a", now, time.Minute), "peer-a"), ErrBadSignature)

	edited := *a
	c := *a.Cert()
	c.IssuedAtUnixNano = now.Add(time.Hour).UnixNano()
	edited.Certificate, err = json.Marshal(&c)
	require.NoError(t, err)
	edited.cert = &c
	assert.ErrorIs(t, Verify(ts, &edited, "peer-a"), ErrBadSignature, "a certificate edited to look fresher")

	assert.True(t, Agree(a.Cert(), cert(t, priv, "goatnet-1", "peer-b", now.Add(29*time.Minute), 30*time.Minute).Cert()))
	assert.True(t, Agree(a.Cert(), cert(t, priv, "goatnet-1", "peer-b", now.Add(-30*time.Minute), 30*time.Minute).Cert()), "the window is symmetric and inclusive")
	assert.False(t, Agree(a.Cert(), cert(t, priv, "goatnet-1", "peer-b", now.Add(31*time.Minute), 30*time.Minute).Cert()))

	// Relative, not wall-clock: two certificates issued long ago, close together, still agree.
	old := now.Add(-30 * 24 * time.Hour)
	assert.True(t, Agree(cert(t, priv, "goatnet-1", "peer-a", old, time.Minute).Cert(), cert(t, priv, "goatnet-1", "peer-b", old.Add(30*time.Second), time.Minute).Cert()))
}

func TestSyncResponseFields(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	own := cert(t, priv, "goatnet-1", "peer-a", now, time.Minute)
	remote := []*Signed{cert(t, priv, "goatnet-1", "peer-b", now, time.Minute), cert(t, priv, "goatnet-1", "peer-c", now, time.Minute)}
	resp := &mgmProto.SyncResponse{NetworkMap: &mgmProto.NetworkMap{Serial: 1}}
	require.NoError(t, Attach(resp, own, remote))
	require.NoError(t, Attach(resp, own, remote))
	wire, err := proto.Marshal(resp)
	require.NoError(t, err)
	decoded := &mgmProto.SyncResponse{}
	require.NoError(t, proto.Unmarshal(wire, decoded))
	gotOwn, gotRemote := FromSyncResponse(decoded)
	require.NotNil(t, gotOwn)
	assert.Equal(t, "peer-a", gotOwn.Cert().PeerKey)
	require.Len(t, gotRemote, 2, "attaching twice leaves one list")
	gotOwn, gotRemote = FromSyncResponse(&mgmProto.SyncResponse{})
	assert.Nil(t, gotOwn)
	assert.Empty(t, gotRemote)
}

// TestSyncResponseMembershipFieldsUndeclaredUpstream fails when upstream's
// SyncResponse declares or reserves field 1004 or 1005.
func TestSyncResponseMembershipFieldsUndeclaredUpstream(t *testing.T) {
	src, err := os.ReadFile("../proto/management.proto")
	require.NoError(t, err)
	body := regexp.MustCompile(`(?s)\nmessage\s+SyncResponse\s*\{(.*?)\n\}`).FindStringSubmatch(string(src))
	require.Len(t, body, 2, "management.proto declares SyncResponse")
	numbers := map[int]bool{}
	for _, m := range regexp.MustCompile(`=\s*(\d+)\s*[;\[]`).FindAllStringSubmatch(body[1], -1) {
		n, _ := strconv.Atoi(m[1])
		numbers[n] = true
	}
	require.True(t, numbers[5], "the parser sees the NetworkMap field (5)")
	for _, f := range []int{int(OwnField), int(RemoteField)} {
		require.False(t, numbers[f], "upstream SyncResponse now declares field %d; move the membership certificates to an unused number", f)
		require.NotRegexp(t, `reserved[^;]*\b`+strconv.Itoa(f)+`\b`, body[1])
	}
}
