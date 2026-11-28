package embed

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/mapcache"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// silentServer accepts TCP connections and never answers, the way a
// management behind a dead link looks to a dialer: a connection that never
// completes its handshake.
func silentServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

// TestStartFromCachedMapIsQuick: with a usable cached map and a management
// that accepts connections but never answers, Start comes up from the cache
// after one short dial for the login and one for the engine, instead of the
// minutes of 30 s attempts a client without a cache spends.
func TestStartFromCachedMapIsQuick(t *testing.T) {
	// Not t.TempDir: the stopped client may still finish writing its state file
	// for a moment, and t.TempDir fails the test when its removal races that.
	dir, err := os.MkdirTemp("", "cached-start-")
	require.NoError(t, err)
	t.Cleanup(func() {
		for i := 0; i < 50; i++ {
			if os.RemoveAll(dir) == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	mgmtAddr := silentServer(t)
	signalAddr := silentServer(t)
	configPath := filepath.Join(dir, "config.json")
	statePath := filepath.Join(dir, "state.json")

	c, err := New(Options{
		DeviceName:    "cached-start",
		SetupKey:      "11111111-1111-1111-1111-111111111111",
		ManagementURL: "http://" + mgmtAddr,
		ConfigPath:    configPath,
		StatePath:     statePath,
	})
	require.NoError(t, err)

	cfg, err := profilemanager.ReadConfig(configPath)
	require.NoError(t, err)
	key, err := wgtypes.ParseKey(cfg.PrivateKey)
	require.NoError(t, err)
	store := mapcache.NewStore(mapcache.PathForState(statePath), mapcache.Binding{
		ManagementURL: cfg.ManagementURL.String(),
		PeerKey:       key.PublicKey().String(),
	}, nil)
	peerConfig := &mgmProto.PeerConfig{Address: "198.51.100.5/24", Fqdn: "cached-start.example"}
	store.SetLogin(&mgmProto.LoginResponse{
		PeerConfig:    peerConfig,
		NetbirdConfig: &mgmProto.NetbirdConfig{Signal: &mgmProto.HostConfig{Uri: signalAddr, Protocol: mgmProto.HostConfig_HTTP}},
	})
	require.NoError(t, store.SaveMap(&mgmProto.NetworkMap{Serial: 1, PeerConfig: peerConfig, RemotePeersIsEmpty: true}, nil))
	require.True(t, internal.HasUsableCachedMap(cfg, statePath), "the cache is usable")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	started := time.Now()
	require.NoError(t, c.Start(ctx))
	took := time.Since(started)
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = c.Stop(stopCtx)
	})
	t.Logf("came up from the cached map %s after Start, management silent", took.Round(time.Millisecond))
	require.Less(t, took, 4*internal.CachedStartDialTimeout, "two short dials, not the 30 s attempts")
}
