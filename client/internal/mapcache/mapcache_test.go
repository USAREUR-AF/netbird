package mapcache

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	require.NoError(t, s.SaveMap(testMap(7, "peer-b", "peer-c")))

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
	require.NoError(t, s.SaveMap(testMap(1, "peer-b")))

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
	require.NoError(t, s.SaveMap(testMap(2, "peer-c")))

	e, err := Load(path)
	require.NoError(t, err)
	assert.NotContains(t, e.Endpoints, "peer-b")
	assert.Contains(t, e.Endpoints, "peer-c")
}

func TestCheckRefusesOtherBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.goat-map.json")
	clock := newClock()
	require.NoError(t, NewStore(path, testBinding, clock).SaveMap(testMap(1)))

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

	_, err := LoadUsable(path, cases["other peer key"], DefaultMaxAge, clock)
	assert.ErrorIs(t, err, ErrBinding)
	_, err = os.Stat(path)
	assert.True(t, errors.Is(err, os.ErrNotExist), "a cache refused for its binding is deleted")
}

func TestAgeOnBootClockIgnoresWallClockSteps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.goat-map.json")
	clock := newClock()
	require.NoError(t, NewStore(path, testBinding, clock).SaveMap(testMap(1)))
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
	require.NoError(t, NewStore(path, testBinding, clock).SaveMap(testMap(1)))
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
	_, err = LoadUsable(path, testBinding, DefaultMaxAge, clock)
	assert.ErrorIs(t, err, ErrClockBehind)
	_, err = os.Stat(path)
	assert.NoError(t, err)
}

func TestNoBootClockUsesSystemClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.goat-map.json")
	clock := newClock()
	clock.hasBoot = false
	require.NoError(t, NewStore(path, testBinding, clock).SaveMap(testMap(1)))
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
	require.NoError(t, NewStore(path, testBinding, clock).SaveMap(testMap(1)))

	clock.advance(DefaultMaxAge - time.Second)
	_, err := LoadUsable(path, testBinding, DefaultMaxAge, clock)
	require.NoError(t, err, "inside the bound")

	clock.advance(2 * time.Second)
	_, err = LoadUsable(path, testBinding, DefaultMaxAge, clock)
	assert.ErrorIs(t, err, ErrTooOld)
	_, err = os.Stat(path)
	assert.True(t, errors.Is(err, os.ErrNotExist), "a cache refused for age is deleted")
}

func TestFreshMapReplacesCachedOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.goat-map.json")
	clock := newClock()
	s := NewStore(path, testBinding, clock)
	require.NoError(t, s.SaveMap(testMap(9, "peer-b")))

	clock.advance(48 * time.Hour)
	// A fresh map, even with a lower serial (a management whose serial was reset), replaces it.
	require.NoError(t, s.SaveMap(testMap(3, "peer-c")))

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
	_, err = LoadUsable(bad, testBinding, DefaultMaxAge, newClock())
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
	assert.NoError(t, s.SaveMap(testMap(1)))
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
