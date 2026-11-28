// Package goatrevoke is a signed revocation of one peer in a goatnet
// (USAREUR-AF/goatcore ADR 1273, phase 4).
//
// A revocation names a peer's WireGuard key and a threshold time. It means:
// refuse this peer in every network map signed at or before the threshold.
// A map signed after the threshold that lists the peer again reinstates it,
// since management has decided again. A revocation is signed by a map signer
// of the goatnet, so it verifies against the same trust set as a map, and it
// may arrive from management or from any peer: the signature carries the
// trust, not the carrier.
package goatrevoke

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/netbirdio/netbird/shared/management/mapsign"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Domain is prefixed (with a zero byte) to the revocation bytes before signing.
const Domain = "goat-revocation-v1"

// SyncResponseField is the SyncResponse field number that carries the revocation list.
const SyncResponseField protowire.Number = 1003

// MaxMessageSize bounds one revocation as it travels between peers.
const MaxMessageSize = 4096

var (
	// ErrBadSignature means the signature does not verify against the trust set.
	ErrBadSignature = errors.New("revocation signature does not verify")
	// ErrOtherGoatnet means the revocation is for another goatnet.
	ErrOtherGoatnet = errors.New("revocation is for another goatnet")
	// ErrMalformed means the revocation could not be decoded.
	ErrMalformed = errors.New("revocation is malformed")
)

// Revocation is the signed content.
type Revocation struct {
	GoatnetID         string `json:"goatnet_id"`
	PeerKey           string `json:"peer_key"`
	ThresholdUnixNano int64  `json:"threshold_unix_nano"`
	IssuedAtUnixNano  int64  `json:"issued_at_unix_nano"`
	Reason            string `json:"reason,omitempty"`
}

// Threshold returns the revocation's threshold time.
func (r *Revocation) Threshold() time.Time { return time.Unix(0, r.ThresholdUnixNano) }

// Signed is a revocation as encoded once by its signer.
type Signed struct {
	Revocation []byte `json:"revocation"`
	Signature  []byte `json:"signature"`
	KeyID      string `json:"key_id"`

	rev *Revocation
}

// Rev returns the decoded revocation (after Parse or Sign).
func (s *Signed) Rev() *Revocation { return s.rev }

// ID identifies a revocation: the first 16 bytes of SHA-256 of its bytes, in hex.
func (s *Signed) ID() string {
	sum := sha256.Sum256(s.Revocation)
	return hex.EncodeToString(sum[:16])
}

func signedBytes(b []byte) []byte {
	out := make([]byte, 0, len(Domain)+1+len(b))
	out = append(out, Domain...)
	out = append(out, 0)
	return append(out, b...)
}

// Sign encodes r once and signs it with key.
func Sign(r *Revocation, key ed25519.PrivateKey) (*Signed, error) {
	if r.GoatnetID == "" || r.PeerKey == "" || r.ThresholdUnixNano == 0 {
		return nil, fmt.Errorf("%w: goatnet, peer key and threshold are required", ErrMalformed)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	return &Signed{Revocation: b, Signature: ed25519.Sign(key, signedBytes(b)), KeyID: mapsign.KeyID(pub), rev: r}, nil
}

// Marshal encodes a signed revocation.
func (s *Signed) Marshal() ([]byte, error) { return json.Marshal(s) }

// Parse decodes a signed revocation without checking its signature.
func Parse(b []byte) (*Signed, error) {
	if len(b) > MaxMessageSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrMalformed, len(b))
	}
	s := &Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	r := &Revocation{}
	if err := json.Unmarshal(s.Revocation, r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if r.PeerKey == "" || r.ThresholdUnixNano == 0 {
		return nil, fmt.Errorf("%w: no peer key or threshold", ErrMalformed)
	}
	s.rev = r
	return s, nil
}

// Verify checks s against the goatnet's map signers.
func Verify(ts *mapsign.TrustSet, s *Signed) error {
	if s.rev == nil {
		return ErrMalformed
	}
	if s.rev.GoatnetID != ts.GoatnetID {
		return fmt.Errorf("%w: %q", ErrOtherGoatnet, s.rev.GoatnetID)
	}
	if !ts.VerifyBytes(s.KeyID, signedBytes(s.Revocation), s.Signature) {
		return ErrBadSignature
	}
	return nil
}

// Attach puts the revocation list into resp's field 1003.
func Attach(resp *mgmProto.SyncResponse, list []*Signed) error {
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	m := resp.ProtoReflect()
	unknown := protowire.AppendTag(dropField(m.GetUnknown(), SyncResponseField), SyncResponseField, protowire.BytesType)
	m.SetUnknown(protowire.AppendBytes(unknown, b))
	return nil
}

// FromSyncResponse returns the revocation list in resp's field 1003. A
// revocation that does not decode is skipped.
func FromSyncResponse(resp *mgmProto.SyncResponse) []*Signed {
	if resp == nil {
		return nil
	}
	b := resp.ProtoReflect().GetUnknown()
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil
		}
		m := protowire.ConsumeFieldValue(num, typ, b[n:])
		if m < 0 {
			return nil
		}
		if num == SyncResponseField && typ == protowire.BytesType {
			v, _ := protowire.ConsumeBytes(b[n:])
			return parseList(v)
		}
		b = b[n+m:]
	}
	return nil
}

func parseList(b []byte) []*Signed {
	var raw []json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	out := make([]*Signed, 0, len(raw))
	for _, r := range raw {
		if s, err := Parse(r); err == nil {
			out = append(out, s)
		}
	}
	return out
}

// LoadList reads a JSON array of signed revocations (the management-side file).
func LoadList(path string) ([]*Signed, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	out := make([]*Signed, 0, len(raw))
	for _, r := range raw {
		s, err := Parse(r)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Store is a client's durable set of verified revocations. A revocation is
// written to disk before Add returns, so it outlives a restart.
type Store struct {
	path string

	mu   sync.Mutex
	byID map[string]*Signed
}

// OpenStore loads the store at path; a missing file is an empty store.
// Entries are kept as received and checked again by the caller.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, byID: map[string]*Signed{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	for _, r := range parseList(b) {
		s.byID[r.ID()] = r
	}
	return s, nil
}

// Add records r. It returns false when r was already held.
func (s *Store) Add(r *Signed) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[r.ID()]; ok {
		return false, nil
	}
	s.byID[r.ID()] = r
	if err := s.write(); err != nil {
		delete(s.byID, r.ID())
		return false, err
	}
	return true, nil
}

// All returns the held revocations, oldest threshold first.
func (s *Store) All() []*Signed {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Signed, 0, len(s.byID))
	for _, r := range s.byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rev.ThresholdUnixNano < out[j].rev.ThresholdUnixNano })
	return out
}

// Expire drops revocations whose threshold is older than maxAge: every map
// signed before such a threshold is itself too old to be used.
func (s *Store) Expire(now time.Time, maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for id, r := range s.byID {
		if now.Sub(r.rev.Threshold()) > maxAge {
			delete(s.byID, id)
			changed = true
		}
	}
	if changed {
		_ = s.write()
	}
}

func (s *Store) write() error {
	if s.path == "" {
		return nil
	}
	list := make([]*Signed, 0, len(s.byID))
	for _, r := range s.byID {
		list = append(list, r)
	}
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

// Revoked reports whether peerKey is revoked for a map signed at signedAt.
// A zero signedAt (an unsigned or cached map with no signing time) counts as
// signed before every threshold.
func Revoked(list []*Signed, peerKey string, signedAt time.Time) bool {
	for _, r := range list {
		if r.rev.PeerKey != peerKey {
			continue
		}
		if signedAt.IsZero() || !signedAt.After(r.rev.Threshold()) {
			return true
		}
	}
	return false
}

func dropField(b []byte, field protowire.Number) []byte {
	var out []byte
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return out
		}
		m := protowire.ConsumeFieldValue(num, typ, b[n:])
		if m < 0 {
			return out
		}
		if num != field {
			out = append(out, b[:n+m]...)
		}
		b = b[n+m:]
	}
	return out
}
