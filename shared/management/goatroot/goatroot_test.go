package goatroot

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return k
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func doc(version uint64, root []ed25519.PrivateKey, signers ...ed25519.PrivateKey) *Document {
	d := &Document{Format: FormatVersion, GoatnetID: "goatnet-1", Version: version, MapMaxAgeSeconds: int64((72 * time.Hour).Seconds())}
	for _, k := range root {
		d.RootKeys = append(d.RootKeys, NewKey(pubOf(k)))
	}
	for _, k := range signers {
		d.MapSigners = append(d.MapSigners, NewKey(pubOf(k)))
	}
	return d
}

func TestFirstDocument(t *testing.T) {
	root, siteA := key(t), key(t)
	first, err := Sign(doc(1, []ed25519.PrivateKey{root}, siteA), root)
	require.NoError(t, err)
	require.NoError(t, VerifyFirst(first))

	ts, err := first.Doc().TrustSet()
	require.NoError(t, err)
	assert.Equal(t, "goatnet-1", ts.GoatnetID)
	assert.Equal(t, 72*time.Hour, first.Doc().MapMaxAge())

	notSelf, err := Sign(doc(1, []ed25519.PrivateKey{root}, siteA), key(t))
	require.NoError(t, err)
	assert.ErrorIs(t, VerifyFirst(notSelf), ErrNotSigned, "a first document not signed by its own root key")
}

func TestSuccessorRules(t *testing.T) {
	root, nextRoot, siteA, siteB := key(t), key(t), key(t), key(t)
	held, err := Sign(doc(1, []ed25519.PrivateKey{root}, siteA), root)
	require.NoError(t, err)

	t.Run("a higher version signed by a held root key replaces it, and may hand over to a new root key", func(t *testing.T) {
		next, err := Sign(doc(2, []ed25519.PrivateKey{nextRoot}, siteA, siteB), root)
		require.NoError(t, err)
		require.NoError(t, Successor(held, next))

		third, err := Sign(doc(3, []ed25519.PrivateKey{nextRoot}, siteB), nextRoot)
		require.NoError(t, err)
		require.NoError(t, Successor(next, third), "the new root key signs the version after")
		assert.ErrorIs(t, Successor(held, third), ErrNotSigned, "a version may not skip the root key handover")
	})
	t.Run("same or lower version is refused", func(t *testing.T) {
		same, err := Sign(doc(1, []ed25519.PrivateKey{root}, siteB), root)
		require.NoError(t, err)
		assert.ErrorIs(t, Successor(held, same), ErrNotNewer)
	})
	t.Run("signed only by the candidate's own new root key is refused", func(t *testing.T) {
		grab, err := Sign(doc(2, []ed25519.PrivateKey{nextRoot}, siteB), nextRoot)
		require.NoError(t, err)
		assert.ErrorIs(t, Successor(held, grab), ErrNotSigned)
	})
	t.Run("another goatnet is refused", func(t *testing.T) {
		d := doc(2, []ed25519.PrivateKey{root}, siteA)
		d.GoatnetID = "goatnet-2"
		other, err := Sign(d, root)
		require.NoError(t, err)
		assert.ErrorIs(t, Successor(held, other), ErrOtherGoatnet)
	})
	t.Run("an edited document is refused", func(t *testing.T) {
		next, err := Sign(doc(2, []ed25519.PrivateKey{root}, siteA), root)
		require.NoError(t, err)
		b, err := next.Marshal()
		require.NoError(t, err)
		parsed, err := Parse(b)
		require.NoError(t, err)
		edited, err := Sign(doc(2, []ed25519.PrivateKey{root}, siteA, siteB))
		require.NoError(t, err)
		edited.Signatures = parsed.Signatures
		assert.ErrorIs(t, Successor(held, edited), ErrNotSigned)
	})
}

func TestFormatRules(t *testing.T) {
	root, siteA := key(t), key(t)
	for name, edit := range map[string]func(*Document){
		"no signers":   func(d *Document) { d.MapSigners = nil },
		"no root keys": func(d *Document) { d.RootKeys = nil },
		"no max age":   func(d *Document) { d.MapMaxAgeSeconds = 0 },
		"version 0":    func(d *Document) { d.Version = 0 },
		"bad key id":   func(d *Document) { d.MapSigners[0].KeyID = "ed25519-0000000000000000" },
		"other format": func(d *Document) { d.Format = 9 },
	} {
		t.Run(name, func(t *testing.T) {
			d := doc(1, []ed25519.PrivateKey{root}, siteA)
			edit(d)
			_, err := Sign(d, root)
			assert.ErrorIs(t, err, ErrMalformed)
		})
	}
}

func TestStoreLoadAndSyncResponseField(t *testing.T) {
	root, siteA := key(t), key(t)
	s, err := Sign(doc(4, []ed25519.PrivateKey{root}, siteA), root)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "goatnet-root.json")
	require.NoError(t, Store(path, s))
	loaded, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, uint64(4), loaded.Doc().Version)

	resp := &mgmProto.SyncResponse{NetworkMap: &mgmProto.NetworkMap{Serial: 1}}
	require.NoError(t, Attach(resp, s))
	require.NoError(t, Attach(resp, s))
	wire, err := proto.Marshal(resp)
	require.NoError(t, err)
	decoded := &mgmProto.SyncResponse{}
	require.NoError(t, proto.Unmarshal(wire, decoded))
	got, err := FromSyncResponse(decoded)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, uint64(4), got.Doc().Version)
	require.NoError(t, VerifyFirst(got))

	none, err := FromSyncResponse(&mgmProto.SyncResponse{})
	require.NoError(t, err)
	assert.Nil(t, none)
}
