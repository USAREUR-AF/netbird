// Package goatroot is the goatnet root document: one signed, versioned
// document per goatnet that names its network map signers (one per site
// management), the maximum age of a map, the service endpoints, and the root
// keys allowed to sign the next version.
//
// A client holds one version on disk. A newer version replaces it only when it
// names the same goatnet, has a higher version, and is signed by a root key the
// held version lists. The first version is installed with the client (the
// enrollment bundle) and is checked to be signed by one of its own root keys.
// The signature, not the carrier, carries the trust, so a document may arrive
// from management, from a peer, or from a file.
package goatroot

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/netbirdio/netbird/shared/management/mapsign"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Domain is prefixed (with a zero byte) to the document bytes before signing.
const Domain = "goat-root-document-v1"

// FormatVersion is the document format version.
const FormatVersion = 1

// SyncResponseField is the SyncResponse field number that carries a signed root document.
const SyncResponseField protowire.Number = 1002

var (
	// ErrOtherGoatnet means the document names another goatnet.
	ErrOtherGoatnet = errors.New("root document is for another goatnet")
	// ErrNotNewer means the document's version is not higher than the held one.
	ErrNotNewer = errors.New("root document is not newer than the held one")
	// ErrNotSigned means no signature is by a root key the held document lists.
	ErrNotSigned = errors.New("root document is not signed by a held root key")
	// ErrMalformed means the document could not be decoded or breaks a format rule.
	ErrMalformed = errors.New("root document is malformed")
)

// Key is an Ed25519 public key with its mapsign key ID.
type Key struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// NewKey returns the document form of pub.
func NewKey(pub ed25519.PublicKey) Key {
	return Key{KeyID: mapsign.KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub)}
}

func (k Key) parse() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: key %q is not an Ed25519 public key", ErrMalformed, k.KeyID)
	}
	pub := ed25519.PublicKey(raw)
	if mapsign.KeyID(pub) != k.KeyID {
		return nil, fmt.Errorf("%w: key_id %q does not match its public key", ErrMalformed, k.KeyID)
	}
	return pub, nil
}

// Endpoints lists the goatnet's service endpoints.
type Endpoints struct {
	Management []string `json:"management,omitempty"`
	Signal     []string `json:"signal,omitempty"`
	Relay      []string `json:"relay,omitempty"`
}

// Document is the content of one version.
type Document struct {
	Format           int       `json:"format"`
	GoatnetID        string    `json:"goatnet_id"`
	Version          uint64    `json:"version"`
	IssuedAtUnixNano int64     `json:"issued_at_unix_nano"`
	MapSigners       []Key     `json:"map_signers"`
	RootKeys         []Key     `json:"root_keys"`
	MapMaxAgeSeconds int64     `json:"map_max_age_seconds"`
	Endpoints        Endpoints `json:"endpoints"`
}

// MapMaxAge returns the declared maximum age of a map.
func (d *Document) MapMaxAge() time.Duration { return time.Duration(d.MapMaxAgeSeconds) * time.Second }

// TrustSet returns the map signers as a mapsign trust set.
func (d *Document) TrustSet() (*mapsign.TrustSet, error) {
	keys := make([]ed25519.PublicKey, 0, len(d.MapSigners))
	for _, k := range d.MapSigners {
		pub, err := k.parse()
		if err != nil {
			return nil, err
		}
		keys = append(keys, pub)
	}
	return mapsign.NewTrustSet(d.GoatnetID, keys...)
}

func (d *Document) rootKeys() (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey, len(d.RootKeys))
	for _, k := range d.RootKeys {
		pub, err := k.parse()
		if err != nil {
			return nil, err
		}
		out[k.KeyID] = pub
	}
	return out, nil
}

func (d *Document) check() error {
	switch {
	case d.Format != FormatVersion:
		return fmt.Errorf("%w: format %d", ErrMalformed, d.Format)
	case d.GoatnetID == "":
		return fmt.Errorf("%w: no goatnet ID", ErrMalformed)
	case d.Version == 0:
		return fmt.Errorf("%w: version 0", ErrMalformed)
	case len(d.MapSigners) == 0:
		return fmt.Errorf("%w: no map signers", ErrMalformed)
	case len(d.RootKeys) == 0:
		return fmt.Errorf("%w: no root keys", ErrMalformed)
	case d.MapMaxAgeSeconds <= 0:
		return fmt.Errorf("%w: no map maximum age", ErrMalformed)
	}
	if _, err := d.TrustSet(); err != nil {
		return err
	}
	_, err := d.rootKeys()
	return err
}

// Signature is one root key's signature over the document bytes.
type Signature struct {
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}

// Signed is a document as encoded once by its issuer, with its signatures.
type Signed struct {
	Document   []byte      `json:"document"`
	Signatures []Signature `json:"signatures"`

	doc *Document
}

// Doc returns the decoded document.
func (s *Signed) Doc() *Document { return s.doc }

func signedBytes(doc []byte) []byte {
	out := make([]byte, 0, len(Domain)+1+len(doc))
	out = append(out, Domain...)
	out = append(out, 0)
	return append(out, doc...)
}

// Sign encodes doc once and signs it with each of keys.
func Sign(doc *Document, keys ...ed25519.PrivateKey) (*Signed, error) {
	if err := doc.check(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("encode root document: %w", err)
	}
	s := &Signed{Document: b, doc: doc}
	for _, k := range keys {
		pub, _ := k.Public().(ed25519.PublicKey)
		s.Signatures = append(s.Signatures, Signature{KeyID: mapsign.KeyID(pub), Signature: ed25519.Sign(k, signedBytes(b))})
	}
	return s, nil
}

// Parse decodes a signed document and its content, without checking signatures.
func Parse(b []byte) (*Signed, error) {
	s := &Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	doc := &Document{}
	if err := json.Unmarshal(s.Document, doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := doc.check(); err != nil {
		return nil, err
	}
	s.doc = doc
	return s, nil
}

// Marshal encodes a signed document.
func (s *Signed) Marshal() ([]byte, error) { return json.Marshal(s) }

func (s *Signed) signedBy(keys map[string]ed25519.PublicKey) bool {
	msg := signedBytes(s.Document)
	for _, sig := range s.Signatures {
		if pub, ok := keys[sig.KeyID]; ok && ed25519.Verify(pub, msg, sig.Signature) {
			return true
		}
	}
	return false
}

// VerifyFirst checks a document installed with the client: it must be signed
// by one of its own root keys.
func VerifyFirst(s *Signed) error {
	keys, err := s.doc.rootKeys()
	if err != nil {
		return err
	}
	if !s.signedBy(keys) {
		return ErrNotSigned
	}
	return nil
}

// Successor checks that candidate may replace held.
func Successor(held, candidate *Signed) error {
	if candidate.doc.GoatnetID != held.doc.GoatnetID {
		return fmt.Errorf("%w: %q", ErrOtherGoatnet, candidate.doc.GoatnetID)
	}
	if candidate.doc.Version <= held.doc.Version {
		return fmt.Errorf("%w: version %d, held %d", ErrNotNewer, candidate.doc.Version, held.doc.Version)
	}
	keys, err := held.doc.rootKeys()
	if err != nil {
		return err
	}
	if !candidate.signedBy(keys) {
		return ErrNotSigned
	}
	return nil
}

// Load reads and checks the held document at path (VerifyFirst).
func Load(path string) (*Signed, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read root document: %w", err)
	}
	s, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if err := VerifyFirst(s); err != nil {
		return nil, err
	}
	return s, nil
}

// Store writes s to path atomically.
func Store(path string, s *Signed) error {
	b, err := s.Marshal()
	if err != nil {
		return fmt.Errorf("encode root document: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary root document: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o644); err != nil {
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
	return os.Rename(name, path)
}

// Attach puts s into resp's field 1002.
func Attach(resp *mgmProto.SyncResponse, s *Signed) error {
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	m := resp.ProtoReflect()
	unknown := protowire.AppendTag(dropField(m.GetUnknown(), SyncResponseField), SyncResponseField, protowire.BytesType)
	m.SetUnknown(protowire.AppendBytes(unknown, b))
	return nil
}

// FromSyncResponse returns the signed document in resp's field 1002, or nil when there is none.
func FromSyncResponse(resp *mgmProto.SyncResponse) (*Signed, error) {
	if resp == nil {
		return nil, nil //nolint:nilnil // no response, no document
	}
	b := resp.ProtoReflect().GetUnknown()
	var found []byte
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, protowire.ParseError(n))
		}
		m := protowire.ConsumeFieldValue(num, typ, b[n:])
		if m < 0 {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, protowire.ParseError(m))
		}
		if num == SyncResponseField && typ == protowire.BytesType {
			v, _ := protowire.ConsumeBytes(b[n:])
			found = v
		}
		b = b[n+m:]
	}
	if found == nil {
		return nil, nil //nolint:nilnil // the response carries no document
	}
	return Parse(found)
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
