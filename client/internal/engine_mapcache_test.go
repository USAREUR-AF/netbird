package internal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/mapcache"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/management/internals/server/config"
	mgmt "github.com/netbirdio/netbird/shared/management/client"
	"github.com/netbirdio/netbird/shared/management/goatroot"
	"github.com/netbirdio/netbird/shared/management/mapsign"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signal "github.com/netbirdio/netbird/shared/signal/client"
	"github.com/netbirdio/netbird/util"
)

// tcpGate forwards a local TCP address to a target and can be taken down and
// brought back on the same address, to make a service unreachable to clients
// without stopping it.
type tcpGate struct {
	addr   string
	target string

	mu    sync.Mutex
	ln    net.Listener
	conns map[net.Conn]struct{}
}

func newTCPGate(t *testing.T, target string) *tcpGate {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	g := &tcpGate{addr: ln.Addr().String(), target: target, conns: map[net.Conn]struct{}{}}
	g.serve(ln)
	t.Cleanup(g.down)
	return g
}

func (g *tcpGate) up(t *testing.T) {
	t.Helper()
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ {
		if ln, err = net.Listen("tcp", g.addr); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.NoError(t, err)
	g.serve(ln)
}

func (g *tcpGate) serve(ln net.Listener) {
	g.mu.Lock()
	g.ln = ln
	g.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go g.forward(c)
		}
	}()
}

func (g *tcpGate) forward(c net.Conn) {
	u, err := net.Dial("tcp", g.target)
	if err != nil {
		_ = c.Close()
		return
	}
	g.mu.Lock()
	g.conns[c] = struct{}{}
	g.conns[u] = struct{}{}
	g.mu.Unlock()
	go func() { _, _ = io.Copy(u, c); _ = u.Close() }()
	_, _ = io.Copy(c, u)
	_ = c.Close()
}

func (g *tcpGate) down() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ln != nil {
		_ = g.ln.Close()
		g.ln = nil
	}
	for c := range g.conns {
		_ = c.Close()
	}
	g.conns = map[net.Conn]struct{}{}
}

type cacheTestPeer struct {
	key       wgtypes.Key
	index     int
	address   string
	cachePath string
	binding   mapcache.Binding
	engine    *Engine
	cancel    context.CancelFunc

	// trust, maxAge and ageCheck configure map verification for the next start.
	trust    *mapsign.TrustSet
	maxAge   time.Duration
	ageCheck time.Duration
	root     *goatroot.Signed
	rootPath string
}

func (p *cacheTestPeer) ifaceName() string {
	return fmt.Sprintf("wtmc%d", p.index)
}

// start creates and starts the peer's engine. With entry set, the engine starts
// from it and its management and signal clients connect in the background.
func (p *cacheTestPeer) start(t *testing.T, parent context.Context, mgmtAddr, signalAddr string, entry *mapcache.Entry) {
	t.Helper()
	// Each engine has its own client context: an engine that loses management
	// cancels its client context, which must not stop the other peer.
	ctx, cancel := context.WithCancel(parent)
	p.cancel = cancel
	var (
		mgmClient    *mgmt.GrpcClient
		signalClient *signal.GrpcClient
		err          error
	)
	if entry != nil {
		mgmClient, err = mgmt.NewClientLazy(ctx, mgmtAddr, p.key, false)
		require.NoError(t, err)
		signalClient, err = signal.NewClientLazy(ctx, signalAddr, p.key, false)
		require.NoError(t, err)
	} else {
		mgmClient, err = mgmt.NewClient(ctx, mgmtAddr, p.key, false)
		require.NoError(t, err)
		signalClient, err = signal.NewClient(ctx, signalAddr, p.key, false)
		require.NoError(t, err)
	}

	store := mapcache.NewStore(p.cachePath, p.binding, nil)
	if entry != nil {
		store.Seed(entry)
	}

	conf := &EngineConfig{
		WgIfaceName:  p.ifaceName(),
		WgAddr:       wgaddr.MustParseWGAddress(p.address),
		WgPrivateKey: p.key,
		WgPort:       33300 + p.index,
		MTU:          iface.DefaultMTU,
	}
	relayMgr := relayClient.NewManager(ctx, nil, p.key.PublicKey().String(), iface.DefaultMTU)
	e := NewEngine(ctx, cancel, conf, EngineServices{
		SignalClient:     signalClient,
		MgmClient:        mgmClient,
		RelayManager:     relayMgr,
		StatusRecorder:   peer.NewRecorder("https://mgm"),
		MapCache:         store,
		MapTrust:         p.trust,
		MapMaxAge:        p.maxAge,
		RootDocument:     p.root,
		RootDocumentPath: p.rootPath,
	}, MobileDependency{})
	if p.ageCheck > 0 {
		e.mapAgeCheckInterval = p.ageCheck
	}
	e.ctx = ctx
	e.dnsServer = &dns.MockServer{}
	if entry != nil {
		e.SetCachedStart(entry)
	}
	require.NoError(t, e.Start(nil, nil))
	p.engine = e
}

func (p *cacheTestPeer) stop(t *testing.T) {
	t.Helper()
	if p.engine == nil {
		return
	}
	_ = p.engine.Stop()
	_ = p.engine.mgmClient.Close()
	p.cancel()
	p.engine = nil
}

// wgPeer returns the WireGuard view of remote on p's interface.
func (p *cacheTestPeer) wgPeer(remote wgtypes.Key) (endpoint string, lastHandshake time.Time, ok bool) {
	if p.engine == nil || p.engine.wgInterface == nil {
		return "", time.Time{}, false
	}
	stats, err := p.engine.wgInterface.FullStats()
	if err != nil {
		return "", time.Time{}, false
	}
	for _, wp := range stats.Peers {
		if wp.PublicKey == remote.PublicKey().String() {
			return wp.Endpoint.String(), wp.LastHandshake, true
		}
	}
	return "", time.Time{}, false
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

// TestEngine_StartFromCachedMap restarts one of two connected peers while
// management and signal are unreachable. The restarted peer starts from its
// cached network map, WireGuard completes a handshake on the last direct
// endpoint in both directions, and the first map from management replaces the
// cached one when management is reachable again.
func TestEngine_StartFromCachedMap(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs Linux WireGuard interfaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to create WireGuard interfaces")
	}

	ctx, cancel := context.WithCancel(CtxInitState(context.Background()))
	defer cancel()

	sigServer, signalAddr, err := startSignal(t)
	require.NoError(t, err)
	defer sigServer.Stop()
	mgmtServer, mgmtAddr, err := startManagement(t, t.TempDir(), "../testdata/store.sql")
	require.NoError(t, err)
	defer mgmtServer.GracefulStop()

	mgmtGate := newTCPGate(t, mgmtAddr)
	signalGate := newTCPGate(t, signalAddr)

	setupKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
	dir := t.TempDir()
	peers := make([]*cacheTestPeer, 2)
	for i := range peers {
		key, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)
		reg, err := mgmt.NewClient(ctx, mgmtGate.addr, key, false)
		require.NoError(t, err)
		resp, err := reg.Register(setupKey, "", system.GetInfo(ctx), nil, nil)
		require.NoError(t, err)
		_ = reg.Close()

		peers[i] = &cacheTestPeer{
			key:       key,
			index:     i,
			address:   resp.GetPeerConfig().GetAddress(),
			cachePath: filepath.Join(dir, fmt.Sprintf("peer%d.goat-map.json", i)),
			binding:   mapcache.Binding{ManagementURL: "http://" + mgmtGate.addr, PeerKey: key.PublicKey().String()},
		}
		peers[i].start(t, ctx, mgmtGate.addr, signalGate.addr, nil)
	}
	a, b := peers[0], peers[1]
	defer a.stop(t)
	defer b.stop(t)

	// 1. Both peers connect over ICE and record each other's direct endpoint.
	waitFor(t, 60*time.Second, "both peers connected", func() bool {
		return getConnectedPeers(a.engine) == 1 && getConnectedPeers(b.engine) == 1
	})
	var cachedEndpoint string
	waitFor(t, 30*time.Second, "peer A's cache to hold peer B's direct endpoint", func() bool {
		e, err := mapcache.Load(a.cachePath)
		if err != nil {
			return false
		}
		cachedEndpoint = e.Endpoints[b.key.PublicKey().String()]
		return cachedEndpoint != ""
	})
	t.Logf("peer A cached peer B's direct endpoint %s", cachedEndpoint)

	// 2. Management and signal become unreachable. Peer A stops; peer B notices.
	mgmtGate.down()
	signalGate.down()
	a.stop(t)
	waitFor(t, 60*time.Second, "peer B to see peer A disconnected", func() bool {
		return getConnectedPeers(b.engine) == 0
	})

	// 3. Peer A restarts from its cached map, with management and signal still unreachable.
	entry, err := mapcache.LoadUsable(a.cachePath, a.binding, mapcache.DefaultMaxAge, mapcache.SystemClock, nil)
	require.NoError(t, err, "the cached map is usable")
	restartedAt := time.Now()
	a.start(t, ctx, mgmtGate.addr, signalGate.addr, entry)
	assert.True(t, a.engine.RunningFromCache(), "peer A runs from the cached map")
	assert.Equal(t, 1, getPeers(a.engine), "peer A has peer B from the cached map")

	// 4. WireGuard completes a handshake on the cached direct endpoint, in both directions.
	waitFor(t, 60*time.Second, "a WireGuard handshake between A and B after the restart", func() bool {
		endpointAB, handshakeAB, foundAB := a.wgPeer(b.key)
		_, handshakeBA, foundBA := b.wgPeer(a.key)
		return foundAB && foundBA && endpointAB == cachedEndpoint && handshakeAB.After(restartedAt) && handshakeBA.After(restartedAt)
	})
	endpointAB, handshakeAB, _ := a.wgPeer(b.key)
	_, handshakeBA, _ := b.wgPeer(a.key)
	t.Logf("after restart: A->B endpoint %s handshake +%s; B->A handshake +%s; 1 of 1 peers reached directly",
		endpointAB, handshakeAB.Sub(restartedAt).Round(time.Millisecond), handshakeBA.Sub(restartedAt).Round(time.Millisecond))
	assert.False(t, managementReachable(a.engine), "management was unreachable throughout")

	before, err := mapcache.Load(a.cachePath)
	require.NoError(t, err)

	// 5. Management and signal come back: the first map from management replaces the cached one.
	mgmtGate.up(t)
	signalGate.up(t)
	waitFor(t, 90*time.Second, "peer A to apply a map from management", func() bool {
		return !a.engine.RunningFromCache()
	})
	waitFor(t, 30*time.Second, "peer A's cache to be rewritten from the fresh map", func() bool {
		after, err := mapcache.Load(a.cachePath)
		return err == nil && after.ReceivedWall.After(before.ReceivedWall)
	})
	waitFor(t, 90*time.Second, "both peers connected again over ICE", func() bool {
		return getConnectedPeers(a.engine) == 1 && getConnectedPeers(b.engine) == 1
	})
}

func managementReachable(e *Engine) bool {
	return e.statusRecorder.GetManagementState().Connected
}

// TestUsableCachedMap covers the refusals at start: a map older than the
// bound, a map for another management URL or peer key, and an invalid bound.
func TestUsableCachedMap(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	binding := mapcache.Binding{ManagementURL: "https://management.example:443", PeerKey: key.PublicKey().String()}

	writeAged := func(t *testing.T, path string, age time.Duration) {
		t.Helper()
		past := &staticClock{wall: time.Now().Add(-age)}
		s := mapcache.NewStore(path, binding, past)
		require.NoError(t, s.SaveMap(&mgmProto.NetworkMap{Serial: 1}, nil))
	}

	t.Run("inside the bound", func(t *testing.T) {
		t.Setenv(mapcache.EnvMaxAge, "2h")
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		writeAged(t, path, time.Hour)
		assert.NotNil(t, usableCachedMap(path, binding, envTrustConfig(t)))
	})

	t.Run("older than the bound is refused and deleted", func(t *testing.T) {
		t.Setenv(mapcache.EnvMaxAge, "1h")
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		writeAged(t, path, 2*time.Hour)
		assert.Nil(t, usableCachedMap(path, binding, envTrustConfig(t)))
		_, err := os.Stat(path)
		assert.True(t, errors.Is(err, os.ErrNotExist))
	})

	t.Run("another management URL is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		writeAged(t, path, time.Minute)
		other := binding
		other.ManagementURL = "https://other.example:443"
		assert.Nil(t, usableCachedMap(path, other, envTrustConfig(t)))
	})

	t.Run("another peer key is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		writeAged(t, path, time.Minute)
		other := binding
		other.PeerKey = "other"
		assert.Nil(t, usableCachedMap(path, other, envTrustConfig(t)))
	})

	t.Run("an invalid bound refuses every cache", func(t *testing.T) {
		t.Setenv(mapcache.EnvMaxAge, "10m")
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		writeAged(t, path, time.Second)
		assert.Nil(t, usableCachedMap(path, binding, envTrustConfig(t)))
	})

	t.Run("disabled", func(t *testing.T) {
		t.Setenv(mapcache.EnvDisable, "true")
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		writeAged(t, path, time.Second)
		assert.Nil(t, usableCachedMap(path, binding, envTrustConfig(t)))
	})
}

type staticClock struct{ wall time.Time }

func (c *staticClock) Wall() time.Time { return c.wall }

func (c *staticClock) Boot() (time.Duration, string, bool) { return 0, "", false }

// writeSigningKey writes a new Ed25519 map signing key and returns its path and public key.
func writeSigningKey(t *testing.T, dir string) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	path := filepath.Join(dir, "map-signing.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return path, pub
}

// TestEngine_SignedMaps runs two peers against a management that signs every
// map. The peers verify every map and cache it signed; management re-signs on
// the refresh interval; a restart from the signed cache with management and
// signal unreachable reaches the other peer directly; when the last verified
// map passes the maximum age the running engine removes its peers, and a fresh
// verified map restores them.
func TestEngine_SignedMaps(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs Linux WireGuard interfaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to create WireGuard interfaces")
	}

	ctx, cancel := context.WithCancel(CtxInitState(context.Background()))
	defer cancel()

	dir := t.TempDir()
	keyPath, signerPub := writeSigningKey(t, dir)
	trust, err := mapsign.NewTrustSet("goatnet-test", signerPub)
	require.NoError(t, err)
	const refresh = 2 * time.Second

	sigServer, signalAddr, err := startSignal(t)
	require.NoError(t, err)
	defer sigServer.Stop()
	mgmtServer, mgmtAddr, err := startManagementWithConfig(t, t.TempDir(), "../testdata/store.sql", func(c *config.Config) {
		c.GoatMapSigning = &config.GoatMapSigning{GoatnetID: "goatnet-test", KeyFile: keyPath, RefreshInterval: util.Duration{Duration: refresh}}
	})
	require.NoError(t, err)
	defer mgmtServer.GracefulStop()

	mgmtGate := newTCPGate(t, mgmtAddr)
	signalGate := newTCPGate(t, signalAddr)

	setupKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
	peers := make([]*cacheTestPeer, 2)
	for i := range peers {
		key, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)
		reg, err := mgmt.NewClient(ctx, mgmtGate.addr, key, false)
		require.NoError(t, err)
		resp, err := reg.Register(setupKey, "", system.GetInfo(ctx), nil, nil)
		require.NoError(t, err)
		_ = reg.Close()

		peers[i] = &cacheTestPeer{
			key:       key,
			index:     10 + i,
			address:   resp.GetPeerConfig().GetAddress(),
			cachePath: filepath.Join(dir, fmt.Sprintf("peer%d.goat-map.json", i)),
			binding:   mapcache.Binding{ManagementURL: "http://" + mgmtGate.addr, PeerKey: key.PublicKey().String()},
			trust:     trust,
		}
		peers[i].start(t, ctx, mgmtGate.addr, signalGate.addr, nil)
	}
	a, b := peers[0], peers[1]
	defer a.stop(t)
	defer b.stop(t)

	// 1. Signed maps apply: both peers connect.
	waitFor(t, 60*time.Second, "both peers connected on signed maps", func() bool {
		return getConnectedPeers(a.engine) == 1 && getConnectedPeers(b.engine) == 1
	})

	// 2. The cache holds the map only inside the signed envelope, and it verifies.
	var cachedEndpoint string
	waitFor(t, 30*time.Second, "peer A's signed cache to hold peer B's direct endpoint", func() bool {
		e, err := mapcache.Load(a.cachePath)
		if err != nil {
			return false
		}
		cachedEndpoint = e.Endpoints[b.key.PublicKey().String()]
		return cachedEndpoint != "" && len(e.SignedMap) > 0 && len(e.NetworkMap) == 0
	})
	first, err := mapcache.LoadUsable(a.cachePath, a.binding, mapcache.DefaultMaxAge, mapcache.SystemClock, trust)
	require.NoError(t, err, "the signed cache verifies against the trust set")

	// 3. Management re-signs the map on the refresh interval while nothing changes.
	issuedAt := func(e *mapcache.Entry) time.Time {
		signed, err := e.Signed()
		require.NoError(t, err)
		env, err := mapsign.Open(signed)
		require.NoError(t, err)
		return env.IssuedAt()
	}
	firstIssued := issuedAt(first)
	refreshes := 0
	waitFor(t, 30*time.Second, "two refreshed signatures", func() bool {
		e, err := mapcache.Load(a.cachePath)
		if err != nil || len(e.SignedMap) == 0 {
			return false
		}
		if at := issuedAt(e); at.After(firstIssued) {
			refreshes++
			firstIssued = at
		}
		return refreshes >= 2
	})
	t.Logf("management re-signed peer A's map %d times at a %s refresh interval", refreshes, refresh)

	// 4. Management and signal become unreachable; peer A restarts from the signed cache.
	mgmtGate.down()
	signalGate.down()
	a.stop(t)
	waitFor(t, 60*time.Second, "peer B to see peer A disconnected", func() bool {
		return getConnectedPeers(b.engine) == 0
	})
	entry, err := mapcache.LoadUsable(a.cachePath, a.binding, mapcache.DefaultMaxAge, mapcache.SystemClock, trust)
	require.NoError(t, err)
	age, err := entry.Age(mapcache.SystemClock)
	require.NoError(t, err)
	// The restarted engine trusts its map for 10 s more than the map's age, checked every 250 ms.
	a.maxAge = age + 10*time.Second
	a.ageCheck = 250 * time.Millisecond
	restartedAt := time.Now()
	a.start(t, ctx, mgmtGate.addr, signalGate.addr, entry)
	waitFor(t, 30*time.Second, "a WireGuard handshake between A and B from the signed cache", func() bool {
		endpointAB, handshakeAB, foundAB := a.wgPeer(b.key)
		_, handshakeBA, foundBA := b.wgPeer(a.key)
		return foundAB && foundBA && endpointAB == cachedEndpoint && handshakeAB.After(restartedAt) && handshakeBA.After(restartedAt)
	})
	t.Logf("restart from the signed cache: handshake on %s within %s", cachedEndpoint, time.Since(restartedAt).Round(time.Millisecond))

	// 5. The last verified map passes the maximum age: the running engine removes its peers.
	waitFor(t, 30*time.Second, "peer A to remove its peers when its map expires", func() bool {
		_, _, ok := a.wgPeer(b.key)
		return getPeers(a.engine) == 0 && !ok
	})
	t.Logf("peer A removed its peers %s after the restart (maximum age %s)", time.Since(restartedAt).Round(time.Second), a.maxAge.Round(time.Second))

	// 6. Management comes back: a fresh verified map restores the peers.
	mgmtGate.up(t)
	signalGate.up(t)
	waitFor(t, 90*time.Second, "peer A to restore its peers from a fresh verified map", func() bool {
		return getPeers(a.engine) == 1
	})
	waitFor(t, 90*time.Second, "both peers connected again", func() bool {
		return getConnectedPeers(a.engine) == 1 && getConnectedPeers(b.engine) == 1
	})
}

// TestEngine_NetworkMapFromSync covers the refusals of a client that holds a trust set.
func TestEngine_NetworkMapFromSync(t *testing.T) {
	wgKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey := wgKey.PublicKey().String()

	_, signerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := mapsign.NewSigner("goatnet-test", signerKey, time.Hour)
	require.NoError(t, err)
	trust, err := mapsign.NewTrustSet("goatnet-test", signerKey.Public().(ed25519.PublicKey))
	require.NoError(t, err)

	nm := &mgmProto.NetworkMap{Serial: 3}
	signedResp := func(s *mapsign.Signer, to string) *mgmProto.SyncResponse {
		resp, err := s.SignSyncResponse(to, &mgmProto.SyncResponse{NetworkMap: nm})
		require.NoError(t, err)
		return resp
	}

	verifying := &Engine{config: &EngineConfig{WgPrivateKey: wgKey}, mapTrust: trust, mapMaxAge: time.Hour}
	open := &Engine{config: &EngineConfig{WgPrivateKey: wgKey}}

	got, signed, err := verifying.networkMapFromSync(signedResp(signer, peerKey))
	require.NoError(t, err)
	assert.Equal(t, uint64(3), got.GetSerial())
	assert.NotNil(t, signed)

	_, _, err = verifying.networkMapFromSync(&mgmProto.SyncResponse{NetworkMap: nm})
	assert.ErrorIs(t, err, mapsign.ErrUnsigned, "an unsigned map is refused")

	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	other, err := mapsign.NewSigner("goatnet-test", otherKey, time.Hour)
	require.NoError(t, err)
	_, _, err = verifying.networkMapFromSync(signedResp(other, peerKey))
	assert.ErrorIs(t, err, mapsign.ErrUnknownKey, "a map by an untrusted signer is refused")

	_, _, err = verifying.networkMapFromSync(signedResp(signer, "another-peer"))
	assert.ErrorIs(t, err, mapsign.ErrWrongPeer, "a map issued to another peer is refused")

	stale := &Engine{config: &EngineConfig{WgPrivateKey: wgKey}, mapTrust: trust, mapMaxAge: time.Millisecond}
	staleResp := signedResp(signer, peerKey)
	// Wait past the maximum age by more than the coarsest system clock tick (Windows).
	time.Sleep(50 * time.Millisecond)
	_, _, err = stale.networkMapFromSync(staleResp)
	assert.Error(t, err, "a map signed longer ago than the maximum age is refused")

	got, _, err = verifying.networkMapFromSync(&mgmProto.SyncResponse{NetbirdConfig: &mgmProto.NetbirdConfig{}})
	require.NoError(t, err, "an update without a map is not refused")
	assert.Nil(t, got)

	got, signed, err = open.networkMapFromSync(signedResp(other, peerKey))
	require.NoError(t, err, "without a trust set a signed map is opened")
	assert.Equal(t, uint64(3), got.GetSerial())
	assert.NotNil(t, signed)
	got, _, err = open.networkMapFromSync(&mgmProto.SyncResponse{NetworkMap: nm})
	require.NoError(t, err, "without a trust set an unsigned map is accepted")
	assert.Equal(t, uint64(3), got.GetSerial())
}

func envTrustConfig(t *testing.T) *mapcache.TrustConfig {
	t.Helper()
	cfg, err := mapcache.TrustConfigFromEnv()
	require.NoError(t, err)
	return cfg
}

func rootDoc(t *testing.T, version uint64, root ed25519.PrivateKey, maxAge time.Duration, signers ...ed25519.PublicKey) *goatroot.Document {
	t.Helper()
	d := &goatroot.Document{
		Format:           goatroot.FormatVersion,
		GoatnetID:        "goatnet-test",
		Version:          version,
		RootKeys:         []goatroot.Key{goatroot.NewKey(root.Public().(ed25519.PublicKey))},
		MapMaxAgeSeconds: int64(maxAge / time.Second),
	}
	for _, k := range signers {
		d.MapSigners = append(d.MapSigners, goatroot.NewKey(k))
	}
	return d
}

func signRoot(t *testing.T, d *goatroot.Document, keys ...ed25519.PrivateKey) *goatroot.Signed {
	t.Helper()
	s, err := goatroot.Sign(d, keys...)
	require.NoError(t, err)
	return s
}

// TestEngine_ApplyRootDocument covers a client holding a root document: a newer
// version from management replaces it on disk and in the engine, adding and
// removing map signers; an older, foreign or wrongly signed version is ignored.
func TestEngine_ApplyRootDocument(t *testing.T) {
	wgKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey := wgKey.PublicKey().String()
	_, root, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, siteA, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, siteB, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubA, pubB := siteA.Public().(ed25519.PublicKey), siteB.Public().(ed25519.PublicKey)

	v1 := signRoot(t, rootDoc(t, 1, root, 72*time.Hour, pubA), root)
	path := filepath.Join(t.TempDir(), "goatnet-root.json")
	require.NoError(t, goatroot.Store(path, v1))
	t.Setenv(mapcache.EnvRootFile, path)
	t.Setenv(mapcache.EnvMaxAge, "")
	cfg, err := mapcache.TrustConfigFromEnv()
	require.NoError(t, err)
	assert.Equal(t, 72*time.Hour, cfg.MaxAge)

	e := &Engine{
		config:         &EngineConfig{WgPrivateKey: wgKey},
		statusRecorder: peer.NewRecorder("https://mgm"),
		mapTrust:       cfg.Trust,
		mapMaxAge:      cfg.MaxAge,
		rootDoc:        cfg.Root,
		rootDocPath:    cfg.RootPath,
	}
	signerA, err := mapsign.NewSigner("goatnet-test", siteA, time.Hour)
	require.NoError(t, err)
	signerB, err := mapsign.NewSigner("goatnet-test", siteB, time.Hour)
	require.NoError(t, err)
	update := func(signer *mapsign.Signer, doc *goatroot.Signed) *mgmProto.SyncResponse {
		resp, err := signer.SignSyncResponse(peerKey, &mgmProto.SyncResponse{NetworkMap: &mgmProto.NetworkMap{Serial: 1}})
		require.NoError(t, err)
		if doc != nil {
			require.NoError(t, goatroot.Attach(resp, doc))
		}
		return resp
	}
	accepts := func(resp *mgmProto.SyncResponse) error {
		e.applyRootDocument(resp)
		_, _, err := e.networkMapFromSync(resp)
		return err
	}

	assert.ErrorIs(t, accepts(update(signerB, nil)), mapsign.ErrUnknownKey, "site B is not a signer in version 1")

	v2 := signRoot(t, rootDoc(t, 2, root, 24*time.Hour, pubA, pubB), root)
	require.NoError(t, accepts(update(signerB, v2)), "version 2 adds site B in the same update")
	assert.Equal(t, uint64(2), e.rootDoc.Doc().Version)
	assert.Equal(t, 24*time.Hour, e.mapMaxAge, "the maximum age follows the root document")
	onDisk, err := goatroot.Load(path)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), onDisk.Doc().Version, "version 2 is written to the held file")

	stale := signRoot(t, rootDoc(t, 1, root, 72*time.Hour, pubA), root)
	e.applyRootDocument(update(signerA, stale))
	assert.Equal(t, uint64(2), e.rootDoc.Doc().Version, "an older version is ignored")

	_, intruder, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	forged := signRoot(t, rootDoc(t, 9, intruder, 720*time.Hour, intruder.Public().(ed25519.PublicKey)), intruder)
	e.applyRootDocument(update(signerA, forged))
	assert.Equal(t, uint64(2), e.rootDoc.Doc().Version, "a version not signed by a held root key is ignored")

	// Version 3 severs site A: its maps are refused from then on.
	v3 := signRoot(t, rootDoc(t, 3, root, 24*time.Hour, pubB), root)
	assert.ErrorIs(t, accepts(update(signerA, v3)), mapsign.ErrUnknownKey, "site A's map is refused once version 3 removes it")
	require.NoError(t, accepts(update(signerB, nil)))

	// A client-declared maximum age only shortens the document's.
	e.mapMaxAgeOverride = 2 * time.Hour
	assert.Equal(t, 2*time.Hour, EffectiveMapMaxAge(v3.Doc(), e.mapMaxAgeOverride))
	assert.Equal(t, 24*time.Hour, EffectiveMapMaxAge(v3.Doc(), 48*time.Hour))
}

func heldRootVersion(e *Engine) uint64 {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()
	return e.rootDoc.Doc().Version
}

func lastVerifiedMap(e *Engine) time.Time {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()
	return e.lastVerifiedMap
}

// TestEngine_RootDocument runs two peers that hold version 1 of a goatnet root
// document against a management that signs with site A's key and serves the
// root document from a file. Version 2 (adding site B) reaches both peers and
// is written to their held files. Version 3 removes site A: the peers take it
// and from then on refuse site A's maps, so their last verified map stops
// advancing while management keeps sending maps.
func TestEngine_RootDocument(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs Linux WireGuard interfaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to create WireGuard interfaces")
	}

	ctx, cancel := context.WithCancel(CtxInitState(context.Background()))
	defer cancel()

	dir := t.TempDir()
	keyPath, pubA := writeSigningKey(t, dir)
	_, root, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	v1 := signRoot(t, rootDoc(t, 1, root, 72*time.Hour, pubA), root)
	v2 := signRoot(t, rootDoc(t, 2, root, 72*time.Hour, pubA, pubB), root)
	v3 := signRoot(t, rootDoc(t, 3, root, 72*time.Hour, pubB), root)
	served := filepath.Join(dir, "served-root.json")
	require.NoError(t, goatroot.Store(served, v2))

	const refresh = 2 * time.Second
	sigServer, signalAddr, err := startSignal(t)
	require.NoError(t, err)
	defer sigServer.Stop()
	mgmtServer, mgmtAddr, err := startManagementWithConfig(t, t.TempDir(), "../testdata/store.sql", func(c *config.Config) {
		c.GoatMapSigning = &config.GoatMapSigning{GoatnetID: "goatnet-test", KeyFile: keyPath, RefreshInterval: util.Duration{Duration: refresh}, RootDocumentFile: served}
	})
	require.NoError(t, err)
	defer mgmtServer.GracefulStop()

	setupKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
	peers := make([]*cacheTestPeer, 2)
	for i := range peers {
		key, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)
		reg, err := mgmt.NewClient(ctx, mgmtAddr, key, false)
		require.NoError(t, err)
		resp, err := reg.Register(setupKey, "", system.GetInfo(ctx), nil, nil)
		require.NoError(t, err)
		_ = reg.Close()

		rootPath := filepath.Join(dir, fmt.Sprintf("peer%d-root.json", i))
		require.NoError(t, goatroot.Store(rootPath, v1))
		held, err := goatroot.Load(rootPath)
		require.NoError(t, err)
		trust, err := held.Doc().TrustSet()
		require.NoError(t, err)
		peers[i] = &cacheTestPeer{
			key:       key,
			index:     20 + i,
			address:   resp.GetPeerConfig().GetAddress(),
			cachePath: filepath.Join(dir, fmt.Sprintf("peer%d.goat-map.json", i)),
			binding:   mapcache.Binding{ManagementURL: "http://" + mgmtAddr, PeerKey: key.PublicKey().String()},
			trust:     trust,
			root:      held,
			rootPath:  rootPath,
		}
		peers[i].start(t, ctx, mgmtAddr, signalAddr, nil)
	}
	defer peers[0].stop(t)
	defer peers[1].stop(t)

	// 1. Version 2 reaches both peers, is written to their held files, and the peers connect.
	waitFor(t, 60*time.Second, "both peers to hold root document version 2 and connect", func() bool {
		return heldRootVersion(peers[0].engine) == 2 && heldRootVersion(peers[1].engine) == 2 &&
			getConnectedPeers(peers[0].engine) == 1 && getConnectedPeers(peers[1].engine) == 1
	})
	for i, p := range peers {
		onDisk, err := goatroot.Load(p.rootPath)
		require.NoError(t, err)
		assert.Equal(t, uint64(2), onDisk.Doc().Version, "peer %d wrote version 2", i)
	}

	// 2. Management serves version 3, which removes site A, the key it signs with.
	require.NoError(t, goatroot.Store(served, v3))
	waitFor(t, 30*time.Second, "both peers to hold root document version 3", func() bool {
		return heldRootVersion(peers[0].engine) == 3 && heldRootVersion(peers[1].engine) == 3
	})
	severedAt := []time.Time{lastVerifiedMap(peers[0].engine), lastVerifiedMap(peers[1].engine)}

	// 3. Over three refresh intervals management keeps sending site A's maps; neither peer verifies one.
	time.Sleep(3*refresh + refresh/2)
	for i, p := range peers {
		assert.Equal(t, severedAt[i], lastVerifiedMap(p.engine), "peer %d verified no map signed by the removed site", i)
	}
	t.Logf("root document versions 1 -> 2 -> 3 applied on 2 of 2 peers; 0 maps from the removed signer verified over %s", 3*refresh+refresh/2)
}
