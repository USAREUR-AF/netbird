package internal

import (
	"context"
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
	mgmt "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signal "github.com/netbirdio/netbird/shared/signal/client"
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
		SignalClient:   signalClient,
		MgmClient:      mgmClient,
		RelayManager:   relayMgr,
		StatusRecorder: peer.NewRecorder("https://mgm"),
		MapCache:       store,
	}, MobileDependency{})
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
	entry, err := mapcache.LoadUsable(a.cachePath, a.binding, mapcache.DefaultMaxAge, mapcache.SystemClock)
	require.NoError(t, err, "the cached map is usable")
	restartedAt := time.Now()
	a.start(t, ctx, mgmtGate.addr, signalGate.addr, entry)
	assert.True(t, a.engine.RunningFromCache(), "peer A runs from the cached map")
	assert.Equal(t, 1, getPeers(a.engine), "peer A has peer B from the cached map")

	// 4. WireGuard completes a handshake on the cached direct endpoint, in both directions.
	waitFor(t, 60*time.Second, "a WireGuard handshake between A and B after the restart", func() bool {
		epA, hsA, okA := a.wgPeer(b.key)
		_, hsB, okB := b.wgPeer(a.key)
		return okA && okB && epA == cachedEndpoint && hsA.After(restartedAt) && hsB.After(restartedAt)
	})
	epA, hsA, _ := a.wgPeer(b.key)
	_, hsB, _ := b.wgPeer(a.key)
	t.Logf("after restart: A->B endpoint %s handshake +%s; B->A handshake +%s; 1 of 1 peers reached directly",
		epA, hsA.Sub(restartedAt).Round(time.Millisecond), hsB.Sub(restartedAt).Round(time.Millisecond))
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
		require.NoError(t, s.SaveMap(&mgmProto.NetworkMap{Serial: 1}))
	}

	t.Run("inside the bound", func(t *testing.T) {
		t.Setenv(mapcache.EnvMaxAge, "2h")
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		writeAged(t, path, time.Hour)
		assert.NotNil(t, usableCachedMap(path, binding))
	})

	t.Run("older than the bound is refused and deleted", func(t *testing.T) {
		t.Setenv(mapcache.EnvMaxAge, "1h")
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		writeAged(t, path, 2*time.Hour)
		assert.Nil(t, usableCachedMap(path, binding))
		_, err := os.Stat(path)
		assert.True(t, errors.Is(err, os.ErrNotExist))
	})

	t.Run("another management URL is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		writeAged(t, path, time.Minute)
		other := binding
		other.ManagementURL = "https://other.example:443"
		assert.Nil(t, usableCachedMap(path, other))
	})

	t.Run("another peer key is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		writeAged(t, path, time.Minute)
		other := binding
		other.PeerKey = "other"
		assert.Nil(t, usableCachedMap(path, other))
	})

	t.Run("an invalid bound refuses every cache", func(t *testing.T) {
		t.Setenv(mapcache.EnvMaxAge, "10m")
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		writeAged(t, path, time.Second)
		assert.Nil(t, usableCachedMap(path, binding))
	})

	t.Run("disabled", func(t *testing.T) {
		t.Setenv(mapcache.EnvDisable, "true")
		path := filepath.Join(t.TempDir(), "state.goat-map.json")
		writeAged(t, path, time.Second)
		assert.Nil(t, usableCachedMap(path, binding))
	})
}

type staticClock struct{ wall time.Time }

func (c *staticClock) Wall() time.Time { return c.wall }

func (c *staticClock) Boot() (time.Duration, string, bool) { return 0, "", false }
