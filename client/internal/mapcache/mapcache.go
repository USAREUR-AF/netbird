// Package mapcache keeps the last network map a client received from
// management on disk, so that the client can start its engine from it when
// management cannot be reached.
//
// The cache is written only from maps applied after an authenticated login or
// sync. It is refused when it belongs to another management URL or another
// peer key, and when it is older than the declared maximum age. Age is
// measured on the boot clock while the host has not rebooted, and on the
// system clock across a reboot; a system clock that reads earlier than the
// receive time is refused.
package mapcache

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/shared/management/goatroot"
	"github.com/netbirdio/netbird/shared/management/mapsign"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

const (
	// FormatVersion is the on-disk format version of an Entry.
	FormatVersion = 1

	// DefaultMaxAge is how long a cached map may be used after it was received.
	DefaultMaxAge = 72 * time.Hour
	// MinMaxAge and MaxMaxAge bound a declared maximum age. A value outside
	// the range is refused, not clamped.
	MinMaxAge = time.Hour
	MaxMaxAge = 30 * 24 * time.Hour

	// EnvMaxAge declares the maximum age as a Go duration, e.g. "24h".
	EnvMaxAge = "NB_MAP_CACHE_MAX_AGE"
	// EnvDisable turns the cache off when set to "true": nothing is written
	// and nothing is read.
	EnvDisable = "NB_MAP_CACHE_DISABLE"

	// EnvTrustFile names a map trust file (see mapsign.LoadTrustFile). When set,
	// every network map, fresh or cached, must be signed by a signer it lists.
	EnvTrustFile = "NB_MAP_TRUST_FILE"
	// EnvRootFile names the held goatnet root document (see goatroot). When set
	// it takes the place of EnvTrustFile, and newer versions from management
	// are written to it.
	EnvRootFile = "NB_GOATNET_ROOT_FILE"

	fileSuffix = ".goat-map.json"
)

var (
	// ErrNotFound means no cache file exists.
	ErrNotFound = errors.New("no cached network map")
	// ErrBinding means the cache belongs to another management URL or peer key.
	ErrBinding = errors.New("cached network map belongs to another management URL or peer key")
	// ErrTooOld means the cache is older than the maximum age.
	ErrTooOld = errors.New("cached network map is older than the maximum age")
	// ErrClockBehind means the system clock reads earlier than the receive time.
	ErrClockBehind = errors.New("system clock reads earlier than the cached network map's receive time")
	// ErrUnverified means the cached map does not verify against the trust set.
	ErrUnverified = errors.New("cached network map does not verify")
	// ErrFormat means the file could not be parsed or has another format version.
	ErrFormat = errors.New("cached network map has an unknown format")
)

// Binding is what a cache must match to be used.
type Binding struct {
	ManagementURL string
	PeerKey       string
}

// Entry is the on-disk content.
type Entry struct {
	Version       int    `json:"version"`
	ManagementURL string `json:"management_url"`
	PeerKey       string `json:"peer_key"`

	// Login is a LoginResponse in protobuf wire form, with the relay token
	// removed. It carries the peer config, the signal and relay URLs, and
	// the posture checks.
	Login []byte `json:"login"`
	// NetworkMap is the last applied NetworkMap in protobuf wire form. Empty
	// when the map arrived signed: it is then read from SignedMap.
	NetworkMap []byte `json:"network_map,omitempty"`
	// SignedMap is the signed map the network map arrived in (mapsign.SignedMap),
	// kept as received so its signature can be checked again at load.
	SignedMap []byte `json:"signed_map,omitempty"`
	// Endpoints maps a remote peer's WireGuard key to the last direct
	// (not relayed, not proxied) WireGuard endpoint seen for it.
	Endpoints map[string]string `json:"endpoints,omitempty"`

	ReceivedWall time.Time `json:"received_wall"`
	// ReceivedBoot is the boot clock reading at receive time, valid only
	// when BootID is set and matches the current boot.
	ReceivedBoot time.Duration `json:"received_boot,omitempty"`
	BootID       string        `json:"boot_id,omitempty"`
}

// LoginResponse decodes the cached login.
func (e *Entry) LoginResponse() (*mgmProto.LoginResponse, error) {
	resp := &mgmProto.LoginResponse{}
	if err := proto.Unmarshal(e.Login, resp); err != nil {
		return nil, fmt.Errorf("decode cached login: %w", err)
	}
	return resp, nil
}

// Signed decodes the signed map the cached map arrived in, or returns nil when it arrived unsigned.
func (e *Entry) Signed() (*mapsign.SignedMap, error) {
	if len(e.SignedMap) == 0 {
		return nil, nil //nolint:nilnil // the map arrived unsigned
	}
	return mapsign.UnmarshalSignedMap(e.SignedMap)
}

// VerifySigned checks the cached map against a trust set: it must have arrived
// signed by a trusted signer, for this goatnet and peer, and its signed issue
// time must be within maxAge of the system clock.
func (e *Entry) VerifySigned(ts *mapsign.TrustSet, maxAge time.Duration, c Clock) error {
	signed, err := e.Signed()
	if err != nil {
		return err
	}
	if signed == nil {
		return fmt.Errorf("%w: %w", ErrUnverified, mapsign.ErrUnsigned)
	}
	env, err := ts.Verify(e.PeerKey, signed)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	if issuedAge := c.Wall().Sub(env.IssuedAt()); issuedAge > maxAge {
		return fmt.Errorf("%w: signed %s ago, maximum %s", ErrTooOld, issuedAge.Round(time.Second), maxAge)
	}
	return nil
}

// Map decodes the cached network map.
func (e *Entry) Map() (*mgmProto.NetworkMap, error) {
	if len(e.SignedMap) > 0 {
		signed, err := e.Signed()
		if err != nil {
			return nil, err
		}
		env, err := mapsign.Open(signed)
		if err != nil {
			return nil, err
		}
		return env.Map(), nil
	}
	nm := &mgmProto.NetworkMap{}
	if err := proto.Unmarshal(e.NetworkMap, nm); err != nil {
		return nil, fmt.Errorf("decode cached network map: %w", err)
	}
	return nm, nil
}

// DirectEndpoints returns the parsed direct endpoints. Unparsable entries are skipped.
func (e *Entry) DirectEndpoints() map[string]*net.UDPAddr {
	out := make(map[string]*net.UDPAddr, len(e.Endpoints))
	for k, v := range e.Endpoints {
		addr, err := net.ResolveUDPAddr("udp", v)
		if err != nil || addr.IP == nil || addr.Port == 0 {
			continue
		}
		out[k] = addr
	}
	return out
}

// Clock reads the clocks used for age.
type Clock interface {
	Wall() time.Time
	// Boot returns the boot clock reading and the boot ID. ok is false when
	// the platform has no boot clock.
	Boot() (reading time.Duration, bootID string, ok bool)
}

type systemClock struct{}

func (systemClock) Wall() time.Time { return time.Now() }

func (systemClock) Boot() (time.Duration, string, bool) { return bootClock() }

// SystemClock is the host's clock.
var SystemClock Clock = systemClock{}

// Age returns how long ago the entry was received, by the rule in the package comment.
func (e *Entry) Age(c Clock) (time.Duration, error) {
	if reading, bootID, ok := c.Boot(); ok && e.BootID != "" && bootID == e.BootID {
		age := reading - e.ReceivedBoot
		if age < 0 {
			return 0, ErrClockBehind
		}
		return age, nil
	}
	age := c.Wall().Sub(e.ReceivedWall)
	if age < 0 {
		return 0, ErrClockBehind
	}
	return age, nil
}

// Check returns nil when the entry may be used for b within maxAge.
func (e *Entry) Check(b Binding, maxAge time.Duration, c Clock) error {
	if e.Version != FormatVersion {
		return ErrFormat
	}
	if e.ManagementURL != b.ManagementURL || e.PeerKey != b.PeerKey {
		return ErrBinding
	}
	age, err := e.Age(c)
	if err != nil {
		return err
	}
	if age > maxAge {
		return fmt.Errorf("%w: age %s, maximum %s", ErrTooOld, age.Round(time.Second), maxAge)
	}
	return nil
}

// MaxAgeFromEnv returns the declared maximum age, or DefaultMaxAge when none is declared.
func MaxAgeFromEnv() (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(EnvMaxAge))
	if v == "" {
		return DefaultMaxAge, nil
	}
	return ParseMaxAge(v)
}

// ParseMaxAge parses and range-checks a maximum age.
func ParseMaxAge(v string) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", EnvMaxAge, v, err)
	}
	if d < MinMaxAge || d > MaxMaxAge {
		return 0, fmt.Errorf("%s=%s is outside %s to %s", EnvMaxAge, d, MinMaxAge, MaxMaxAge)
	}
	return d, nil
}

// TrustConfig is how a client checks network maps.
type TrustConfig struct {
	// Trust is the set of accepted map signers; nil accepts unsigned maps.
	Trust *mapsign.TrustSet
	// MaxAge is the effective maximum age of a map.
	MaxAge time.Duration
	// MaxAgeOverride is the maximum age declared on the client, zero when none is.
	MaxAgeOverride time.Duration
	// MaxAgeInvalid is true when the declared maximum age could not be used;
	// the cache is then not started from.
	MaxAgeInvalid bool
	// Root is the held goatnet root document, nil when none is declared.
	Root *goatroot.Signed
	// RootPath is where the root document is held.
	RootPath string
}

// TrustConfigFromEnv reads the client's declarations: NB_GOATNET_ROOT_FILE (the
// held root document, which names the map signers and the maximum age),
// otherwise NB_MAP_TRUST_FILE (a list of signers), and NB_MAP_CACHE_MAX_AGE,
// which may only shorten the root document's maximum age.
func TrustConfigFromEnv() (*TrustConfig, error) {
	cfg := &TrustConfig{MaxAge: DefaultMaxAge}
	if v := strings.TrimSpace(os.Getenv(EnvMaxAge)); v != "" {
		d, err := ParseMaxAge(v)
		if err != nil {
			log.Errorf("ignoring the declared maximum map age: %v", err)
			cfg.MaxAgeInvalid = true
		} else {
			cfg.MaxAgeOverride = d
			cfg.MaxAge = d
		}
	}

	if path := strings.TrimSpace(os.Getenv(EnvRootFile)); path != "" {
		root, err := goatroot.Load(path)
		if err != nil {
			return nil, err
		}
		trust, err := root.Doc().TrustSet()
		if err != nil {
			return nil, err
		}
		cfg.Root, cfg.RootPath, cfg.Trust = root, path, trust
		cfg.MaxAge = root.Doc().MapMaxAge()
		if cfg.MaxAgeOverride > 0 && cfg.MaxAgeOverride < cfg.MaxAge {
			cfg.MaxAge = cfg.MaxAgeOverride
		}
		return cfg, nil
	}

	if path := strings.TrimSpace(os.Getenv(EnvTrustFile)); path != "" {
		trust, err := mapsign.LoadTrustFile(path)
		if err != nil {
			return nil, err
		}
		cfg.Trust = trust
	}
	return cfg, nil
}

// Disabled reports whether the cache is turned off.
func Disabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(EnvDisable)), "true")
}

// PathForState returns the cache path that belongs to a client state file.
func PathForState(statePath string) string {
	if statePath == "" {
		return ""
	}
	return strings.TrimSuffix(statePath, filepath.Ext(statePath)) + fileSuffix
}

// Load reads the cache file at path.
func Load(path string) (*Entry, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read cached network map: %w", err)
	}
	e := &Entry{}
	if err := json.Unmarshal(data, e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if e.Version != FormatVersion {
		return nil, ErrFormat
	}
	return e, nil
}

// LoadUsable loads the cache at path and checks it. With a trust set the map
// must also verify (VerifySigned). It deletes a cache that fails the binding,
// age or signature check, so a refused cache is never tried again.
func LoadUsable(path string, b Binding, maxAge time.Duration, c Clock, ts *mapsign.TrustSet) (*Entry, error) {
	e, err := Load(path)
	if err != nil {
		if errors.Is(err, ErrFormat) {
			_ = Remove(path)
		}
		return nil, err
	}
	if err := e.Check(b, maxAge, c); err != nil {
		if !errors.Is(err, ErrClockBehind) {
			_ = Remove(path)
		}
		return nil, err
	}
	if ts != nil {
		if err := e.VerifySigned(ts, maxAge, c); err != nil {
			_ = Remove(path)
			return nil, err
		}
	}
	return e, nil
}

// Remove deletes the cache file. A missing file is not an error.
func Remove(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove cached network map: %w", err)
	}
	return nil
}

// write stores e at path atomically, readable by the owner only.
func write(path string, e *Entry) error {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode cached network map: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary cache file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("restrict temporary cache file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary cache file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary cache file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace cached network map: %w", err)
	}
	return nil
}

// Store owns one cache file and the in-memory copy being built for it.
// It is safe for concurrent use. A nil *Store does nothing.
type Store struct {
	path    string
	binding Binding
	clock   Clock

	mu        sync.Mutex
	login     *mgmProto.LoginResponse
	endpoints map[string]string
	entry     *Entry
}

// NewStore returns a Store writing to path for binding b.
func NewStore(path string, b Binding, c Clock) *Store {
	if c == nil {
		c = SystemClock
	}
	return &Store{path: path, binding: b, clock: c, endpoints: map[string]string{}}
}

// Path returns the cache file path.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Seed starts the store from an entry loaded from disk, keeping its login
// and endpoints, so a map later saved from the engine keeps them.
func (s *Store) Seed(e *Entry) {
	if s == nil || e == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if login, err := e.LoginResponse(); err == nil {
		s.login = login
	}
	for k, v := range e.Endpoints {
		s.endpoints[k] = v
	}
}

// SetLogin records the login response of an authenticated login.
func (s *Store) SetLogin(resp *mgmProto.LoginResponse) {
	if s == nil || resp == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.login = stripSecrets(resp)
}

// SetNetbirdConfig replaces the signal, relay and other service settings
// with those of a sync response.
func (s *Store) SetNetbirdConfig(cfg *mgmProto.NetbirdConfig) {
	if s == nil || cfg == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.login == nil {
		s.login = &mgmProto.LoginResponse{}
	}
	s.login = stripSecrets(&mgmProto.LoginResponse{
		NetbirdConfig: cfg,
		PeerConfig:    s.login.GetPeerConfig(),
		Checks:        s.login.GetChecks(),
	})
}

// SaveMap writes the cache with nm as the network map, received now. signed is
// the signed map nm was read from, or nil when it arrived unsigned.
func (s *Store) SaveMap(nm *mgmProto.NetworkMap, signed *mapsign.SignedMap) error {
	if s == nil || nm == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	login := s.login
	if login == nil {
		login = &mgmProto.LoginResponse{}
	}
	if nm.GetPeerConfig() != nil {
		login = proto.Clone(login).(*mgmProto.LoginResponse)
		login.PeerConfig = nm.GetPeerConfig()
	}
	loginBytes, err := proto.Marshal(login)
	if err != nil {
		return fmt.Errorf("encode login: %w", err)
	}
	var mapBytes, signedBytes []byte
	if signed != nil {
		signedBytes, err = signed.Marshal()
		if err != nil {
			return fmt.Errorf("encode signed network map: %w", err)
		}
	} else {
		mapBytes, err = proto.Marshal(nm)
		if err != nil {
			return fmt.Errorf("encode network map: %w", err)
		}
	}

	// Keep endpoints only for peers still in the map.
	keep := make(map[string]string, len(s.endpoints))
	for _, p := range nm.GetRemotePeers() {
		if ep, ok := s.endpoints[p.GetWgPubKey()]; ok {
			keep[p.GetWgPubKey()] = ep
		}
	}
	s.endpoints = keep

	e := &Entry{
		Version:       FormatVersion,
		ManagementURL: s.binding.ManagementURL,
		PeerKey:       s.binding.PeerKey,
		Login:         loginBytes,
		NetworkMap:    mapBytes,
		SignedMap:     signedBytes,
		Endpoints:     copyMap(keep),
		ReceivedWall:  s.clock.Wall(),
	}
	if reading, bootID, ok := s.clock.Boot(); ok {
		e.ReceivedBoot = reading
		e.BootID = bootID
	}
	s.entry = e
	return write(s.path, e)
}

// SetEndpoint records the last direct endpoint of a remote peer and rewrites
// the cache when it changed. It does not change the receive time.
func (s *Store) SetEndpoint(peerKey string, addr *net.UDPAddr) {
	if s == nil || addr == nil || addr.IP == nil || addr.IP.IsLoopback() || addr.Port == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := addr.String()
	if s.endpoints[peerKey] == v {
		return
	}
	s.endpoints[peerKey] = v
	if s.entry == nil {
		return
	}
	e := *s.entry
	e.Endpoints = copyMap(s.endpoints)
	s.entry = &e
	if err := write(s.path, &e); err != nil {
		log.Warnf("failed to record the direct endpoint of peer %s in the cached network map: %v", peerKey, err)
	}
}

// Remove deletes the cache file and forgets the in-memory copy.
func (s *Store) Remove() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entry = nil
	return Remove(s.path)
}

func stripSecrets(resp *mgmProto.LoginResponse) *mgmProto.LoginResponse {
	out := proto.Clone(resp).(*mgmProto.LoginResponse)
	if r := out.GetNetbirdConfig().GetRelay(); r != nil {
		r.TokenPayload = ""
		r.TokenSignature = ""
	}
	if f := out.GetNetbirdConfig().GetFlow(); f != nil {
		f.TokenPayload = ""
		f.TokenSignature = ""
	}
	for _, t := range out.GetNetbirdConfig().GetTurns() {
		t.User = ""
		t.Password = ""
	}
	return out
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
