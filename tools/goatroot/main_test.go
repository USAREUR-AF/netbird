package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/goatrevoke"
	"github.com/netbirdio/netbird/shared/management/goatroot"
)

func TestIssueChain(t *testing.T) {
	dir := t.TempDir()
	path := func(n string) string { return filepath.Join(dir, n) }
	keyEntry := func(name string) goatroot.Key {
		var out bytes.Buffer
		require.NoError(t, run([]string{"keygen", "-out", path(name)}, &out))
		var k goatroot.Key
		require.NoError(t, json.Unmarshal(out.Bytes(), &k))
		return k
	}
	root, next, site := keyEntry("root.pem"), keyEntry("next.pem"), keyEntry("site.pem")

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path("root.pem"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "a key file is owner-only")
	}

	writeDoc := func(name string, version uint64, rootKey goatroot.Key) {
		d := goatroot.Document{Format: 1, GoatnetID: "goatnet-1", Version: version, MapMaxAgeSeconds: 259200,
			MapSigners: []goatroot.Key{site}, RootKeys: []goatroot.Key{rootKey}}
		b, err := json.Marshal(d)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path(name), b, 0o644))
	}
	writeDoc("v1.json", 1, root)
	writeDoc("v2.json", 2, next)
	writeDoc("v3.json", 3, next)

	require.NoError(t, run([]string{"sign", "-doc", path("v1.json"), "-key", path("root.pem"), "-out", path("v1.signed.json")}, &bytes.Buffer{}))
	require.NoError(t, run([]string{"sign", "-doc", path("v2.json"), "-key", path("root.pem"), "-out", path("v2.signed.json")}, &bytes.Buffer{}))
	require.NoError(t, run([]string{"sign", "-doc", path("v3.json"), "-key", path("root.pem"), "-out", path("v3.bad.json")}, &bytes.Buffer{}))
	require.NoError(t, run([]string{"sign", "-doc", path("v2.json"), "-key", path("next.pem"), "-out", path("v2.self.json")}, &bytes.Buffer{}))

	var out bytes.Buffer
	require.NoError(t, run([]string{"verify", "-held", path("v1.signed.json")}, &out))
	assert.Contains(t, out.String(), "version 1")
	require.NoError(t, run([]string{"verify", "-held", path("v1.signed.json"), "-candidate", path("v2.signed.json")}, &bytes.Buffer{}))
	assert.Error(t, run([]string{"verify", "-held", path("v2.self.json"), "-candidate", path("v3.bad.json")}, &bytes.Buffer{}), "version 3 must be signed by the root key version 2 lists")
	assert.Error(t, run([]string{"verify", "-held", path("v1.signed.json"), "-candidate", path("v1.signed.json")}, &bytes.Buffer{}), "not newer")
	assert.Error(t, run([]string{"keygen", "-out", path("root.pem")}, &bytes.Buffer{}), "keygen never overwrites a key")
}

func TestRevokeAppendsToTheList(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	require.NoError(t, run([]string{"keygen", "-out", filepath.Join(dir, "signer.pem")}, &out))
	list := filepath.Join(dir, "revocations.json")
	for _, peer := range []string{"peer-c", "peer-d"} {
		require.NoError(t, run([]string{"revoke", "-key", filepath.Join(dir, "signer.pem"), "-goatnet", "goatnet-1", "-peer", peer, "-list", list}, &bytes.Buffer{}))
	}
	got, err := goatrevoke.LoadList(list)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "peer-d", got[1].Rev().PeerKey)
	assert.Error(t, run([]string{"revoke", "-key", filepath.Join(dir, "signer.pem"), "-goatnet", "goatnet-1", "-list", list}, &bytes.Buffer{}), "a peer key is required")
}
