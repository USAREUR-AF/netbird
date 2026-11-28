package internal

// A test harness that runs each peer as its own process in its own Linux
// network namespace, so peers reach each other only over a veth link and
// their WireGuard tunnel, the way separate hosts do. Management and signal
// run in the test process and are reached through TCP gates on the bridge
// that joins the namespaces, so a test can make them unreachable.
//
// Layout: bridge mcbr0 holds 192.0.2.254/24 in the test's namespace; peer i
// runs in namespace mcns<i> with 192.0.2.<i+1>/24 on veth mcp<i>.
//
// A peer process is this test binary re-run with -test.run TestNetnsHelperPeer
// and its settings in the environment. It writes its state to a JSON file
// every 250 ms and stops on SIGTERM.

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

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
	"github.com/netbirdio/netbird/shared/management/goatrevoke"
	"github.com/netbirdio/netbird/shared/management/mapsign"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signal_ "github.com/netbirdio/netbird/shared/signal/client"
	"github.com/netbirdio/netbird/util"
)

const (
	netnsBridge     = "mcbr0"
	netnsBridgeAddr = "192.0.2.254"
	envHelper       = "MC_NETNS_HELPER"
)

// helperSettings is what the test hands a peer process.
type helperSettings struct {
	Management string `json:"management"`
	Signal     string `json:"signal"`
	PrivateKey string `json:"private_key"`
	Address    string `json:"address"`
	Iface      string `json:"iface"`
	Port       int    `json:"port"`
	CachePath  string `json:"cache_path"`
	StatusPath string `json:"status_path"`
	FromCache  bool   `json:"from_cache"`
	// Extra holds settings for later phases, passed through unchanged.
	Extra map[string]string `json:"extra,omitempty"`
}

// helperWGPeer is one WireGuard peer as a peer process sees it.
type helperWGPeer struct {
	Key           string `json:"key"`
	Endpoint      string `json:"endpoint"`
	LastHandshake int64  `json:"last_handshake_unix_nano"`
}

// helperStatus is what a peer process reports.
type helperStatus struct {
	Running          bool           `json:"running"`
	RunningFromCache bool           `json:"running_from_cache"`
	Peers            int            `json:"peers"`
	Connected        int            `json:"connected"`
	WireGuard        []helperWGPeer `json:"wireguard"`
	Error            string         `json:"error,omitempty"`
	Extra            map[string]any `json:"extra,omitempty"`
}

// helperStatusHooks lets later phases add their own fields to the status.
var helperStatusHooks []func(e *Engine, extra map[string]any)

// helperEngineHooks lets later phases configure the engine before Start.
var helperEngineHooks []func(e *Engine, s *helperSettings)

func netnsAvailable(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("network namespaces are Linux only")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to create network namespaces")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs the ip command (iproute2)")
	}
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("needs the ping command")
	}
	if out, err := exec.Command("ip", "netns", "add", "mcprobe").CombinedOutput(); err != nil {
		t.Skipf("cannot create a network namespace here: %v: %s", err, out)
	}
	_ = exec.Command("ip", "netns", "del", "mcprobe").Run()
}

func run(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	require.NoError(t, err, "%s: %s", strings.Join(args, " "), out)
}

// netnsTopology creates the bridge and n namespaces and removes them at cleanup.
func netnsTopology(t *testing.T, n int) {
	t.Helper()
	_ = exec.Command("ip", "link", "del", netnsBridge).Run()
	run(t, "ip", "link", "add", netnsBridge, "type", "bridge")
	run(t, "ip", "addr", "add", netnsBridgeAddr+"/24", "dev", netnsBridge)
	run(t, "ip", "link", "set", netnsBridge, "up")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", netnsBridge).Run() })
	for i := 0; i < n; i++ {
		ns, host, inner := fmt.Sprintf("mcns%d", i), fmt.Sprintf("mcv%d", i), fmt.Sprintf("mcp%d", i)
		_ = exec.Command("ip", "netns", "del", ns).Run()
		_ = exec.Command("ip", "link", "del", host).Run()
		run(t, "ip", "netns", "add", ns)
		t.Cleanup(func() {
			_ = exec.Command("ip", "link", "del", host).Run()
			_ = exec.Command("ip", "netns", "del", ns).Run()
		})
		run(t, "ip", "link", "add", host, "type", "veth", "peer", "name", inner)
		run(t, "ip", "link", "set", inner, "netns", ns)
		run(t, "ip", "link", "set", host, "master", netnsBridge)
		run(t, "ip", "link", "set", host, "up")
		run(t, "ip", "-n", ns, "addr", "add", fmt.Sprintf("192.0.2.%d/24", i+1), "dev", inner)
		run(t, "ip", "-n", ns, "link", "set", inner, "up")
		run(t, "ip", "-n", ns, "link", "set", "lo", "up")
	}
}

// netnsPeer is a peer process the test controls.
type netnsPeer struct {
	index    int
	key      wgtypes.Key
	address  string // overlay address with prefix, as management assigned it
	settings helperSettings
	cmd      *exec.Cmd
	logPath  string
}

func (p *netnsPeer) namespace() string { return fmt.Sprintf("mcns%d", p.index) }

// overlayIP is the peer's overlay address without its prefix.
func (p *netnsPeer) overlayIP() string { return strings.SplitN(p.address, "/", 2)[0] }

// newNetnsPeer registers a new peer with management and prepares its settings.
func newNetnsPeer(t *testing.T, dir string, index int, mgmtAddr, signalAddr string) *netnsPeer {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reg, err := mgmt.NewClient(ctx, mgmtAddr, key, false)
	require.NoError(t, err)
	resp, err := reg.Register("A2C8E62B-38F5-4553-B31E-DD66C696CEBB", "", system.GetInfo(ctx), nil, nil)
	require.NoError(t, err)
	_ = reg.Close()
	p := &netnsPeer{index: index, key: key, address: resp.GetPeerConfig().GetAddress()}
	p.settings = helperSettings{
		Management: mgmtAddr,
		Signal:     signalAddr,
		PrivateKey: key.String(),
		Address:    p.address,
		Iface:      fmt.Sprintf("wtns%d", index),
		Port:       51820,
		CachePath:  filepath.Join(dir, fmt.Sprintf("peer%d.goat-map.json", index)),
		StatusPath: filepath.Join(dir, fmt.Sprintf("peer%d.status.json", index)),
	}
	p.logPath = filepath.Join(dir, fmt.Sprintf("peer%d.log", index))
	return p
}

// start runs the peer process in its namespace.
func (p *netnsPeer) start(t *testing.T) {
	t.Helper()
	_ = os.Remove(p.settings.StatusPath)
	b, err := json.Marshal(p.settings)
	require.NoError(t, err)
	logFile, err := os.OpenFile(p.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	cmd := exec.Command("ip", "netns", "exec", p.namespace(), os.Args[0], "-test.run", "^TestNetnsHelperPeer$", "-test.v", "-test.timeout", "30m")
	cmd.Env = append(os.Environ(), envHelper+"="+string(b))
	cmd.Stdout, cmd.Stderr = logFile, logFile
	require.NoError(t, cmd.Start())
	p.cmd = cmd
	t.Cleanup(func() { p.stop(t) })
}

// stop ends the peer process and waits for it.
func (p *netnsPeer) stop(t *testing.T) {
	t.Helper()
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = p.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
	}
	p.cmd = nil
}

// status reads the peer's last reported state.
func (p *netnsPeer) status() helperStatus {
	var s helperStatus
	b, err := os.ReadFile(p.settings.StatusPath)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(b, &s)
	return s
}

// wg returns the WireGuard view of remote on this peer.
func (p *netnsPeer) wg(remote *netnsPeer) (helperWGPeer, bool) {
	for _, w := range p.status().WireGuard {
		if w.Key == remote.key.PublicKey().String() {
			return w, true
		}
	}
	return helperWGPeer{}, false
}

// ping sends one ICMP echo from this peer's namespace to ip.
func (p *netnsPeer) ping(ip string) bool {
	return exec.Command("ip", "netns", "exec", p.namespace(), "ping", "-c", "1", "-W", "1", ip).Run() == nil
}

// logs returns the peer process's log, for failure messages.
func (p *netnsPeer) logs() string {
	b, _ := os.ReadFile(p.logPath)
	if len(b) > 6000 {
		b = b[len(b)-6000:]
	}
	return string(b)
}

// netnsServices starts signal and management in the test process and gates
// on the bridge address through which the peer namespaces reach them.
func netnsServices(t *testing.T, startMgmt func() (string, error)) (mgmtGate, signalGate *tcpGate) {
	t.Helper()
	sigServer, signalAddr, err := startSignal(t)
	require.NoError(t, err)
	t.Cleanup(sigServer.Stop)
	mgmtAddr, err := startMgmt()
	require.NoError(t, err)
	return newTCPGateOn(t, netnsBridgeAddr+":0", mgmtAddr), newTCPGateOn(t, netnsBridgeAddr+":0", signalAddr)
}

// TestNetnsHelperPeer is the peer process. It does nothing unless the test
// harness started it.
func TestNetnsHelperPeer(t *testing.T) {
	raw := os.Getenv(envHelper)
	if raw == "" {
		t.Skip("run by the network namespace harness only")
	}
	var s helperSettings
	require.NoError(t, json.Unmarshal([]byte(raw), &s))
	key, err := wgtypes.ParseKey(s.PrivateKey)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(CtxInitState(context.Background()))
	defer cancel()

	binding := mapcache.Binding{ManagementURL: "http://" + s.Management, PeerKey: key.PublicKey().String()}
	var entry *mapcache.Entry
	if s.FromCache {
		entry, err = mapcache.LoadUsable(s.CachePath, binding, mapcache.DefaultMaxAge, mapcache.SystemClock, nil)
		require.NoError(t, err, "cached map usable")
	}
	var (
		mgmClient *mgmt.GrpcClient
		sigClient *signal_.GrpcClient
	)
	if s.FromCache {
		mgmClient, err = mgmt.NewClientLazy(ctx, s.Management, key, false)
		require.NoError(t, err)
		sigClient, err = signal_.NewClientLazy(ctx, s.Signal, key, false)
	} else {
		mgmClient, err = mgmt.NewClient(ctx, s.Management, key, false)
		require.NoError(t, err)
		sigClient, err = signal_.NewClient(ctx, s.Signal, key, false)
	}
	require.NoError(t, err)

	store := mapcache.NewStore(s.CachePath, binding, nil)
	store.Seed(entry)
	conf := &EngineConfig{
		WgIfaceName:  s.Iface,
		WgAddr:       wgaddr.MustParseWGAddress(s.Address),
		WgPrivateKey: key,
		WgPort:       s.Port,
		MTU:          iface.DefaultMTU,
	}
	e := NewEngine(ctx, cancel, conf, EngineServices{
		SignalClient:   sigClient,
		MgmClient:      mgmClient,
		RelayManager:   relayClient.NewManager(ctx, nil, key.PublicKey().String(), iface.DefaultMTU),
		StatusRecorder: peer.NewRecorder("https://mgm"),
		MapCache:       store,
	}, MobileDependency{})
	e.ctx = ctx
	e.dnsServer = &dns.MockServer{}
	for _, hook := range helperEngineHooks {
		hook(e, &s)
	}
	if entry != nil {
		e.SetCachedStart(entry)
	}
	require.NoError(t, e.Start(nil, nil))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		writeHelperStatus(e, s.StatusPath)
		select {
		case <-stop:
			_ = e.Stop()
			_ = mgmClient.Close()
			return
		case <-ticker.C:
		}
	}
}

func writeHelperStatus(e *Engine, path string) {
	st := helperStatus{Running: true, Peers: getPeers(e), Connected: getConnectedPeers(e), RunningFromCache: e.RunningFromCache()}
	if stats, err := e.wgInterface.FullStats(); err == nil {
		for _, p := range stats.Peers {
			st.WireGuard = append(st.WireGuard, helperWGPeer{Key: p.PublicKey, Endpoint: p.Endpoint.String(), LastHandshake: p.LastHandshake.UnixNano()})
		}
	}
	if len(helperStatusHooks) > 0 {
		st.Extra = map[string]any{}
		for _, hook := range helperStatusHooks {
			hook(e, st.Extra)
		}
	}
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}

// newTCPGateOn is newTCPGate on a chosen listen address.
func newTCPGateOn(t *testing.T, listen, target string) *tcpGate {
	t.Helper()
	ln, err := net.Listen("tcp", listen)
	require.NoError(t, err)
	g := &tcpGate{addr: ln.Addr().String(), target: target, conns: map[net.Conn]struct{}{}}
	g.serve(ln)
	t.Cleanup(g.down)
	return g
}

// TestNetns_RestartFromCachedMap is the harness's first check, and a stronger
// form of TestEngine_StartFromCachedMap: two peers in separate namespaces
// reach each other's overlay address through WireGuard; with management and
// signal unreachable, peer A restarts from its cached map and the overlay
// ping works again, over a WireGuard handshake on the cached direct endpoint.
func TestNetns_RestartFromCachedMap(t *testing.T) {
	netnsAvailable(t)
	netnsTopology(t, 2)
	dir := t.TempDir()

	mgmtGate, signalGate := netnsServices(t, func() (string, error) {
		_, addr, err := startManagement(t, t.TempDir(), "../testdata/store.sql")
		return addr, err
	})
	a := newNetnsPeer(t, dir, 0, mgmtGate.addr, signalGate.addr)
	b := newNetnsPeer(t, dir, 1, mgmtGate.addr, signalGate.addr)
	a.start(t)
	b.start(t)

	waitFor(t, 90*time.Second, "both peers connected", func() bool {
		return a.status().Connected == 1 && b.status().Connected == 1
	})
	waitFor(t, 30*time.Second, "overlay ping A to B and B to A", func() bool {
		return a.ping(b.overlayIP()) && b.ping(a.overlayIP())
	})
	var cachedEndpoint string
	waitFor(t, 30*time.Second, "A's cache to hold B's direct endpoint", func() bool {
		e, err := mapcache.Load(a.settings.CachePath)
		if err != nil {
			return false
		}
		cachedEndpoint = e.Endpoints[b.key.PublicKey().String()]
		return cachedEndpoint != ""
	})
	require.True(t, strings.HasPrefix(cachedEndpoint, "192.0.2.2:"), "B's direct endpoint is its veth address, got %s", cachedEndpoint)

	mgmtGate.down()
	signalGate.down()
	a.stop(t)
	waitFor(t, 60*time.Second, "B to see A disconnected", func() bool { return b.status().Connected == 0 })

	restarted := time.Now()
	a.settings.FromCache = true
	a.start(t)
	waitFor(t, 60*time.Second, "A to run from its cached map", func() bool {
		s := a.status()
		return s.Running && s.RunningFromCache
	})
	waitFor(t, 60*time.Second, "overlay ping A to B after the restart, management and signal down", func() bool {
		return a.ping(b.overlayIP()) && b.ping(a.overlayIP())
	})
	w, ok := a.wg(b)
	require.True(t, ok)
	require.Equal(t, cachedEndpoint, w.Endpoint, "A reaches B on the cached direct endpoint\n%s", a.logs())
	require.Greater(t, w.LastHandshake, restarted.UnixNano(), "a new handshake after the restart")
	t.Logf("separate namespaces: overlay ping both ways %s after A restarted from its cache, endpoint %s", time.Since(restarted).Round(time.Millisecond), w.Endpoint)
}

// Settings for a peer process that verifies maps and keeps revocations.
const (
	extraTrustFile = "trust_file"
	extraRevStore  = "revocation_store"
	statusRevs     = "revocations"
)

func init() {
	helperEngineHooks = append(helperEngineHooks, func(e *Engine, s *helperSettings) {
		if s.Extra[extraTrustFile] == "" {
			return
		}
		trust, err := mapsign.LoadTrustFile(s.Extra[extraTrustFile])
		if err != nil {
			panic(err)
		}
		store, err := goatrevoke.OpenStore(s.Extra[extraRevStore])
		if err != nil {
			panic(err)
		}
		e.mapTrust, e.revStore = trust, store
	})
	helperStatusHooks = append(helperStatusHooks, func(e *Engine, extra map[string]any) {
		if e.revStore != nil {
			extra[statusRevs] = len(e.revStore.All())
		}
	})
}

// TestNetns_RevocationFloods: three peers in separate namespaces on a signing
// management. Peer B loses its path to management. A revocation of peer C is
// added to management's list; peer A receives it from management, removes C,
// and floods it over the overlay to B, which removes C although it cannot
// reach management. B keeps the revocation on disk: restarted from its cached
// map with management still unreachable, it leaves C out.
func TestNetns_RevocationFloods(t *testing.T) {
	netnsAvailable(t)
	netnsTopology(t, 3)
	dir := t.TempDir()

	keyPath, signerPub := writeSigningKey(t, dir)
	trustData, err := mapsign.MarshalTrustFile("goatnet-test", signerPub)
	require.NoError(t, err)
	trustPath := filepath.Join(dir, "map-trust.json")
	require.NoError(t, os.WriteFile(trustPath, trustData, 0o644))
	revList := filepath.Join(dir, "revocations.json")
	require.NoError(t, os.WriteFile(revList, []byte("[]"), 0o644))

	var mgmtAddr string
	sigServer, signalAddr, err := startSignal(t)
	require.NoError(t, err)
	t.Cleanup(sigServer.Stop)
	_, mgmtAddr, err = startManagementWithConfig(t, t.TempDir(), "../testdata/store.sql", func(c *config.Config) {
		c.GoatMapSigning = &config.GoatMapSigning{GoatnetID: "goatnet-test", KeyFile: keyPath, RefreshInterval: util.Duration{Duration: 2 * time.Second}, RevocationsFile: revList}
	})
	require.NoError(t, err)
	signalGate := newTCPGateOn(t, netnsBridgeAddr+":0", signalAddr)

	peers := make([]*netnsPeer, 3)
	gates := make([]*tcpGate, 3)
	for i := range peers {
		gates[i] = newTCPGateOn(t, netnsBridgeAddr+":0", mgmtAddr)
		peers[i] = newNetnsPeer(t, dir, i, gates[i].addr, signalGate.addr)
		peers[i].settings.Extra = map[string]string{
			extraTrustFile: trustPath,
			extraRevStore:  filepath.Join(dir, fmt.Sprintf("peer%d.goat-revocations.json", i)),
		}
		peers[i].start(t)
	}
	a, b, c := peers[0], peers[1], peers[2]
	revs := func(p *netnsPeer) int {
		v, _ := p.status().Extra[statusRevs].(float64)
		return int(v)
	}

	waitFor(t, 120*time.Second, "all three peers connected to each other", func() bool {
		return a.status().Connected == 2 && b.status().Connected == 2 && c.status().Connected == 2
	})
	waitFor(t, 30*time.Second, "overlay pings B to A and B to C", func() bool { return b.ping(a.overlayIP()) && b.ping(c.overlayIP()) })

	// B loses management. Then management's list gains a revocation of C,
	// with a threshold an hour ahead so management's next maps, which still
	// list C, do not reinstate it during the test.
	gates[1].down()
	signer, err := readSigningKey(keyPath)
	require.NoError(t, err)
	rev, err := goatrevoke.Sign(&goatrevoke.Revocation{GoatnetID: "goatnet-test", PeerKey: c.key.PublicKey().String(), ThresholdUnixNano: time.Now().Add(time.Hour).UnixNano(), IssuedAtUnixNano: time.Now().UnixNano()}, signer)
	require.NoError(t, err)
	revBytes, err := rev.Marshal()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(revList, []byte("["+string(revBytes)+"]"), 0o644))
	revokedAt := time.Now()

	waitFor(t, 30*time.Second, "A to take the revocation from management and remove C", func() bool {
		_, hasC := a.wg(c)
		return revs(a) == 1 && !hasC
	})
	waitFor(t, 30*time.Second, "B to receive the revocation from a peer and remove C", func() bool {
		_, hasC := b.wg(c)
		return revs(b) == 1 && !hasC && b.status().Peers == 1
	})
	t.Logf("revocation of C reached B, which has no path to management, %s after it was issued", time.Since(revokedAt).Round(time.Millisecond))
	require.False(t, b.ping(c.overlayIP()), "B no longer reaches C")
	require.True(t, b.ping(a.overlayIP()), "B still reaches A")

	// B restarts from its cached map with management unreachable: the stored revocation still applies.
	b.stop(t)
	b.settings.FromCache = true
	b.start(t)
	waitFor(t, 60*time.Second, "B to run from its cached map with A only", func() bool {
		s := b.status()
		_, hasC := b.wg(c)
		return s.Running && s.RunningFromCache && s.Peers == 1 && !hasC && revs(b) == 1
	})
	waitFor(t, 30*time.Second, "B reaches A after the restart", func() bool { return b.ping(a.overlayIP()) })
	require.False(t, b.ping(c.overlayIP()), "after the restart B still does not reach C")
}

func readSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return k.(ed25519.PrivateKey), nil
}
