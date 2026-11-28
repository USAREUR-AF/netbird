package mapcache

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/shared/management/goatroot"
	"github.com/netbirdio/netbird/shared/management/mapsign"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

type fakeClock struct {
	wall    time.Time
	boot    time.Duration
	bootID  string
	hasBoot bool
}

func (c *fakeClock) Wall() time.Time { return c.wall }

func (c *fakeClock) Boot() (time.Duration, string, bool) { return c.boot, c.bootID, c.hasBoot }

func (c *fakeClock) advance(d time.Duration) {
	c.wall = c.wall.Add(d)
	c.boot += d
}

var testBinding = Binding{ManagementURL: "https://management.example:443", PeerKey: "peer-key-a"}

func testMap(serial uint64, peers ...string) *mgmProto.NetworkMap {
	nm := &mgmProto.NetworkMap{Serial: serial, PeerConfig: &mgmProto.PeerConfig{Address: "198.51.100.1/24", Fqdn: "a.example"}}
	for i, p := range peers {
		nm.RemotePeers = append(nm.RemotePeers, &mgmProto.RemotePeerConfig{WgPubKey: p, AllowedIps: []string{"198.51.100." + string(rune('2'+i)) + "/32"}})
	}
	return nm
}

func newClock() *fakeClock {
	return &fakeClock{wall: time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC), boot: 10 * time.Minute, bootID: "boot-1", hasBoot: true}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.goat-map.json")
	clock := newClock()
	s := NewStore(path, testBinding, clock)

	s.SetLogin(&mgmProto.LoginResponse{
		NetbirdConfig: &mgmProto.NetbirdConfig{
			Signal: &mgmProto.HostConfig{Uri: "signal.example:443", Protocol: mgmProto.HostConfig_HTTPS},
			Relay:  &mgmProto.RelayConfig{Urls: []string{"rels://relay.example:443"}, TokenPayload: "payload", TokenSignature: "sig"},
			Turns:  []*mgmProto.ProtectedHostConfig{{HostConfig: &mgmProto.HostConfig{Uri: "turn:turn.example"}, User: "u", Password: "p"}},
			Flow:   &mgmProto.FlowConfig{Url: "flow.example", TokenPayload: "fp", TokenSignature: "fs"},
		},
		PeerConfig: &mgmProto.PeerConfig{Address: "198.51.100.1/24"},
	})
	s.SetEndpoint("peer-b", &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51820})
	require.NoError(t, s.SaveMap(testMap(7, "peer-b", "peer-c"), nil))

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "cache file must be owner-only")
	}

	e, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, e.Check(testBinding, DefaultMaxAge, clock))

	nm, err := e.Map()
	require.NoError(t, err)
	assert.Equal(t, uint64(7), nm.GetSerial())
	assert.Len(t, nm.GetRemotePeers(), 2)

	login, err := e.LoginResponse()
	require.NoError(t, err)
	assert.Equal(t, "signal.example:443", login.GetNetbirdConfig().GetSignal().GetUri())
	assert.Equal(t, []string{"rels://relay.example:443"}, login.GetNetbirdConfig().GetRelay().GetUrls())
	assert.Empty(t, login.GetNetbirdConfig().GetRelay().GetTokenPayload(), "relay token must not be cached")
	assert.Empty(t, login.GetNetbirdConfig().GetRelay().GetTokenSignature(), "relay token must not be cached")
	assert.Empty(t, login.GetNetbirdConfig().GetFlow().GetTokenPayload(), "flow token must not be cached")
	assert.Empty(t, login.GetNetbirdConfig().GetTurns()[0].GetPassword(), "TURN password must not be cached")
	assert.Equal(t, "a.example", login.GetPeerConfig().GetFqdn(), "peer config follows the latest map")

	eps := e.DirectEndpoints()
	require.Contains(t, eps, "peer-b")
	assert.Equal(t, "192.0.2.10:51820", eps["peer-b"].String())
}

func TestEndpointRecordedAfterSaveRewritesCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.goat-map.json")
	clock := newClock()
	s := NewStore(path, testBinding, clock)
	require.NoError(t, s.SaveMap(testMap(1, "peer-b"), nil))

	clock.advance(time.Minute)
	s.SetEndpoint("peer-b", &net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: 51820})
	s.SetEndpoint("peer-b", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}) // proxied: ignored

	e, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.20:51820", e.Endpoints["peer-b"])
	age, err := e.Age(clock)
	require.NoError(t, err)
	assert.Equal(t, time.Minute, age, "recording an endpoint does not refresh the receive time")
}

func TestEndpointsDroppedForPeersNoLongerInMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.goat-map.json")
	s := NewStore(path, testBinding, newClock())
	s.SetEndpoint("peer-b", &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51820})
	s.SetEndpoint("peer-c", &net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 51820})
	require.NoError(t, s.SaveMap(testMap(2, "peer-c"), nil))

	e, err := Load(path)
	require.NoError(t, err)
	assert.NotContains(t, e.Endpoints, "peer-b")
	assert.Contains(t, e.Endpoints, "peer-c")
}

func TestCheckRefusesOtherBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.goat-map.json")
	clock := newClock()
	require.NoError(t, NewStore(path, testBinding, clock).SaveMap(testMap(1), nil))

	cases := map[string]Binding{
		"other management URL": {ManagementURL: "https://other.example:443", PeerKey: testBinding.PeerKey},
		"other peer key":       {ManagementURL: testBinding.ManagementURL, PeerKey: "peer-key-z"},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			e, err := Load(path)
			require.NoError(t, err)
			assert.ErrorIs(t, e.Check(b, DefaultMaxAge, clock), ErrBinding)
		})
	}

	_, err := LoadUsable(path, cases["other peer key"], DefaultMaxAge, clock, nil)
	assert.ErrorIs(t, err, ErrBinding)
	_, err = os.Stat(path)
	assert.True(t, errors.Is(err, os.ErrNotExist), "a cache refused for its binding is deleted")
}

func TestAgeOnBootClockIgnoresWallClockSteps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.goat-map.json")
	clock := newClock()
	require.NoError(t, NewStore(path, testBinding, clock).SaveMap(testMap(1), nil))
	e, err := Load(path)
	require.NoError(t, err)

	// Same boot: the wall clock is stepped back a year, the boot clock moves 2 h.
	clock.boot += 2 * time.Hour
	clock.wall = clock.wall.Add(-365 * 24 * time.Hour)
	age, err := e.Age(clock)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Hour, age)

	// Same boot: the wall clock is stepped forward far past the bound; the boot clock decides.
	clock.wall = clock.wall.Add(10 * 365 * 24 * time.Hour)
	assert.NoError(t, e.Check(testBinding, DefaultMaxAge, clock))
}

func TestAgeAcrossRebootUsesSystemClockAndRefusesNegative(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.goat-map.json")
	clock := newClock()
	require.NoError(t, NewStore(path, testBinding, clock).SaveMap(testMap(1), nil))
	e, err := Load(path)
	require.NoError(t, err)

	// Reboot: new boot ID, the boot clock restarts near zero.
	clock.bootID = "boot-2"
	clock.boot = 30 * time.Second
	clock.wall = clock.wall.Add(5 * time.Hour)
	age, err := e.Age(clock)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Hour, age)

	// A cold boot without a real-time clock reads a time before the receive time.
	clock.wall = time.Date(1970, 1, 1, 0, 0, 30, 0, time.UTC)
	_, err = e.Age(clock)
	assert.ErrorIs(t, err, ErrClockBehind)
	assert.ErrorIs(t, e.Check(testBinding, DefaultMaxAge, clock), ErrClockBehind)

	// A clock that is behind does not delete the cache: it may be corrected.
	_, err = LoadUsable(path, testBinding, DefaultMaxAge, clock, nil)
	assert.ErrorIs(t, err, ErrClockBehind)
	_, err = os.Stat(path)
	assert.NoError(t, err)
}

func TestNoBootClockUsesSystemClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.goat-map.json")
	clock := newClock()
	clock.hasBoot = false
	require.NoError(t, NewStore(path, testBinding, clock).SaveMap(testMap(1), nil))
	e, err := Load(path)
	require.NoError(t, err)
	assert.Empty(t, e.BootID)
	clock.wall = clock.wall.Add(3 * time.Hour)
	age, err := e.Age(clock)
	require.NoError(t, err)
	assert.Equal(t, 3*time.Hour, age)
}

func TestMapOlderThanBoundIsRefusedAndDeleted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.goat-map.json")
	clock := newClock()
	require.NoError(t, NewStore(path, testBinding, clock).SaveMap(testMap(1), nil))

	clock.advance(DefaultMaxAge - time.Second)
	_, err := LoadUsable(path, testBinding, DefaultMaxAge, clock, nil)
	require.NoError(t, err, "inside the bound")

	clock.advance(2 * time.Second)
	_, err = LoadUsable(path, testBinding, DefaultMaxAge, clock, nil)
	assert.ErrorIs(t, err, ErrTooOld)
	_, err = os.Stat(path)
	assert.True(t, errors.Is(err, os.ErrNotExist), "a cache refused for age is deleted")
}

func TestFreshMapReplacesCachedOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.goat-map.json")
	clock := newClock()
	s := NewStore(path, testBinding, clock)
	require.NoError(t, s.SaveMap(testMap(9, "peer-b"), nil))

	clock.advance(48 * time.Hour)
	// A fresh map, even with a lower serial (a management whose serial was reset), replaces it.
	require.NoError(t, s.SaveMap(testMap(3, "peer-c"), nil))

	e, err := Load(path)
	require.NoError(t, err)
	nm, err := e.Map()
	require.NoError(t, err)
	assert.Equal(t, uint64(3), nm.GetSerial())
	age, err := e.Age(clock)
	require.NoError(t, err)
	assert.Zero(t, age, "receive time is that of the fresh map")
}

func TestLoadMissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(filepath.Join(dir, "none.json"))
	assert.ErrorIs(t, err, ErrNotFound)

	bad := filepath.Join(dir, "bad.goat-map.json")
	require.NoError(t, os.WriteFile(bad, []byte("{not json"), 0o600))
	_, err = LoadUsable(bad, testBinding, DefaultMaxAge, newClock(), nil)
	assert.ErrorIs(t, err, ErrFormat)
	_, err = os.Stat(bad)
	assert.True(t, errors.Is(err, os.ErrNotExist), "an unreadable cache is deleted")

	other := filepath.Join(dir, "v9.goat-map.json")
	require.NoError(t, os.WriteFile(other, []byte(`{"version":9}`), 0o600))
	_, err = Load(other)
	assert.ErrorIs(t, err, ErrFormat)
}

func TestParseMaxAge(t *testing.T) {
	d, err := ParseMaxAge("24h")
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, d)

	for _, v := range []string{"30m", "721h", "-1h", "abc", "0"} {
		_, err := ParseMaxAge(v)
		assert.Error(t, err, v)
	}

	t.Setenv(EnvMaxAge, "")
	d, err = MaxAgeFromEnv()
	require.NoError(t, err)
	assert.Equal(t, DefaultMaxAge, d)
}

func TestPathForState(t *testing.T) {
	assert.Equal(t, filepath.Join("var", "lib", "netbird", "state.goat-map.json"), PathForState(filepath.Join("var", "lib", "netbird", "state.json")))
	assert.Equal(t, "", PathForState(""))
}

func TestNilStoreIsSafe(t *testing.T) {
	var s *Store
	s.SetLogin(&mgmProto.LoginResponse{})
	s.SetNetbirdConfig(&mgmProto.NetbirdConfig{})
	s.SetEndpoint("k", &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1})
	s.Seed(&Entry{})
	assert.NoError(t, s.SaveMap(testMap(1), nil))
	assert.NoError(t, s.Remove())
	assert.Equal(t, "", s.Path())
}

func TestSystemBootClock(t *testing.T) {
	reading, id, ok := SystemClock.Boot()
	if runtime.GOOS != "linux" {
		assert.False(t, ok)
		return
	}
	require.True(t, ok)
	assert.NotEmpty(t, id)
	assert.Positive(t, reading)
}

func signedTestMap(t *testing.T, signer *mapsign.Signer, peerKey string, nm *mgmProto.NetworkMap) *mapsign.SignedMap {
	t.Helper()
	signed, err := signer.Sign(peerKey, nm)
	require.NoError(t, err)
	return signed
}

func TestSignedCacheVerifiesAtLoad(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := mapsign.NewSigner("goatnet-1", key, time.Hour)
	require.NoError(t, err)
	trust, err := mapsign.NewTrustSet("goatnet-1", key.Public().(ed25519.PublicKey))
	require.NoError(t, err)

	t.Run("a signed map verifies and is read from its envelope", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		nm := testMap(5, "peer-b")
		require.NoError(t, NewStore(path, testBinding, SystemClock).SaveMap(nm, signedTestMap(t, signer, testBinding.PeerKey, nm)))
		e, err := LoadUsable(path, testBinding, DefaultMaxAge, SystemClock, trust)
		require.NoError(t, err)
		assert.Empty(t, e.NetworkMap, "the map is kept once, inside the signed envelope")
		got, err := e.Map()
		require.NoError(t, err)
		assert.Equal(t, uint64(5), got.GetSerial())
	})

	t.Run("an unsigned map is refused and deleted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		require.NoError(t, NewStore(path, testBinding, SystemClock).SaveMap(testMap(5), nil))
		_, err := LoadUsable(path, testBinding, DefaultMaxAge, SystemClock, trust)
		assert.ErrorIs(t, err, ErrUnverified)
		assert.ErrorIs(t, err, mapsign.ErrUnsigned)
		_, statErr := os.Stat(path)
		assert.True(t, errors.Is(statErr, os.ErrNotExist))
	})

	t.Run("a map signed by an untrusted key is refused", func(t *testing.T) {
		_, other, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		otherSigner, err := mapsign.NewSigner("goatnet-1", other, time.Hour)
		require.NoError(t, err)
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		nm := testMap(5)
		require.NoError(t, NewStore(path, testBinding, SystemClock).SaveMap(nm, signedTestMap(t, otherSigner, testBinding.PeerKey, nm)))
		_, err = LoadUsable(path, testBinding, DefaultMaxAge, SystemClock, trust)
		assert.ErrorIs(t, err, mapsign.ErrUnknownKey)
	})

	t.Run("a map edited on disk is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		nm := testMap(5, "peer-b")
		signed := signedTestMap(t, signer, testBinding.PeerKey, nm)
		require.NoError(t, NewStore(path, testBinding, SystemClock).SaveMap(nm, signed))

		e, err := Load(path)
		require.NoError(t, err)
		env, err := mapsign.Open(signed)
		require.NoError(t, err)
		edited := env.Map()
		edited.RemotePeers = append(edited.RemotePeers, &mgmProto.RemotePeerConfig{WgPubKey: "intruder", AllowedIps: []string{"198.51.100.66/32"}})
		env.NetworkMap, err = proto.Marshal(edited)
		require.NoError(t, err)
		signed.Envelope, err = json.Marshal(env)
		require.NoError(t, err)
		e.SignedMap, err = signed.Marshal()
		require.NoError(t, err)
		require.NoError(t, write(path, e))

		_, err = LoadUsable(path, testBinding, DefaultMaxAge, SystemClock, trust)
		assert.ErrorIs(t, err, mapsign.ErrBadSignature)
	})

	t.Run("a map for another peer is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		nm := testMap(5)
		require.NoError(t, NewStore(path, testBinding, SystemClock).SaveMap(nm, signedTestMap(t, signer, "peer-key-z", nm)))
		_, err := LoadUsable(path, testBinding, DefaultMaxAge, SystemClock, trust)
		assert.ErrorIs(t, err, mapsign.ErrWrongPeer)
	})

	t.Run("a map signed longer ago than the bound is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		nm := testMap(5)
		signed := signedTestMap(t, signer, testBinding.PeerKey, nm)
		require.NoError(t, NewStore(path, testBinding, SystemClock).SaveMap(nm, signed))
		later := &fakeClock{wall: time.Now().Add(2 * time.Hour)}
		// Received just now by its own record, but signed two hours before the clock reads.
		e, err := Load(path)
		require.NoError(t, err)
		e.ReceivedWall = later.wall
		e.BootID = ""
		require.NoError(t, write(path, e))
		_, err = LoadUsable(path, testBinding, time.Hour, later, trust)
		assert.ErrorIs(t, err, ErrTooOld)
	})
}

func TestTrustConfigFromEnv(t *testing.T) {
	_, root, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signerPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	doc := &goatroot.Document{
		Format: goatroot.FormatVersion, GoatnetID: "goatnet-1", Version: 1, MapMaxAgeSeconds: int64((24 * time.Hour).Seconds()),
		RootKeys:   []goatroot.Key{goatroot.NewKey(root.Public().(ed25519.PublicKey))},
		MapSigners: []goatroot.Key{goatroot.NewKey(signerPub)},
	}
	signed, err := goatroot.Sign(doc, root)
	require.NoError(t, err)
	rootPath := filepath.Join(t.TempDir(), "goatnet-root.json")
	require.NoError(t, goatroot.Store(rootPath, signed))

	t.Run("nothing declared", func(t *testing.T) {
		t.Setenv(EnvRootFile, "")
		t.Setenv(EnvTrustFile, "")
		t.Setenv(EnvMaxAge, "")
		cfg, err := TrustConfigFromEnv()
		require.NoError(t, err)
		assert.Nil(t, cfg.Trust)
		assert.Equal(t, DefaultMaxAge, cfg.MaxAge)
	})
	t.Run("root document sets signers and maximum age", func(t *testing.T) {
		t.Setenv(EnvRootFile, rootPath)
		t.Setenv(EnvMaxAge, "")
		cfg, err := TrustConfigFromEnv()
		require.NoError(t, err)
		require.NotNil(t, cfg.Trust)
		assert.Equal(t, 24*time.Hour, cfg.MaxAge)
		assert.Equal(t, uint64(1), cfg.Root.Doc().Version)
	})
	t.Run("a client maximum age only shortens the root document's", func(t *testing.T) {
		t.Setenv(EnvRootFile, rootPath)
		t.Setenv(EnvMaxAge, "2h")
		cfg, err := TrustConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, 2*time.Hour, cfg.MaxAge)
		t.Setenv(EnvMaxAge, "200h")
		cfg, err = TrustConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, 24*time.Hour, cfg.MaxAge)
	})
	t.Run("an unreadable root document is an error", func(t *testing.T) {
		t.Setenv(EnvRootFile, filepath.Join(t.TempDir(), "missing.json"))
		_, err := TrustConfigFromEnv()
		assert.Error(t, err)
	})
	t.Run("an invalid maximum age is flagged", func(t *testing.T) {
		t.Setenv(EnvRootFile, "")
		t.Setenv(EnvMaxAge, "5m")
		cfg, err := TrustConfigFromEnv()
		require.NoError(t, err)
		assert.True(t, cfg.MaxAgeInvalid)
	})
}
