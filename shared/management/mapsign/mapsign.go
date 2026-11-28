// Package mapsign signs network maps on the management side and verifies them
// on the client side.
//
// A signed map is an envelope (the goatnet ID, the receiving peer's WireGuard
// key, the serial, the signer's clock, the refresh interval and the network map
// in protobuf wire form) encoded once by the signer as JSON. The Ed25519
// signature (FIPS 186-5) covers exactly those bytes behind a domain string, so
// the client never re-encodes what it verifies.
//
// The signed map travels in field 1001 of the SyncResponse as a field the
// upstream schema does not declare. Protobuf keeps undeclared fields through
// decoding and encoding, so the fork changes no generated code and upstream
// clients ignore the field.
package mapsign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Domain is prefixed (with a zero byte) to the envelope bytes before signing,
// so a signature over a network map cannot be taken for one over anything else.
const Domain = "goat-network-map-v1"

// SyncResponseField is the SyncResponse field number that carries a signed map.
const SyncResponseField protowire.Number = 1001

// DefaultRefreshInterval is how often a signer re-signs a connected peer's map.
const DefaultRefreshInterval = time.Hour

var (
	// ErrUnsigned means a map arrived without a signature where one is required.
	ErrUnsigned = errors.New("network map is not signed")
	// ErrUnknownKey means the map is signed by a key that is not trusted.
	ErrUnknownKey = errors.New("network map is signed by an untrusted key")
	// ErrBadSignature means the signature does not verify.
	ErrBadSignature = errors.New("network map signature does not verify")
	// ErrWrongGoatnet means the envelope names another goatnet.
	ErrWrongGoatnet = errors.New("network map is for another goatnet")
	// ErrWrongPeer means the envelope is issued to another peer.
	ErrWrongPeer = errors.New("network map is issued to another peer")
	// ErrMalformed means the signed map or its envelope could not be decoded.
	ErrMalformed = errors.New("signed network map is malformed")
)

// SignedMap is a signed envelope.
type SignedMap struct {
	Envelope  []byte `json:"envelope"`
	Signature []byte `json:"signature"`
	KeyID     string `json:"key_id"`
}

// Envelope binds a network map to the goatnet and the peer it is issued to.
type Envelope struct {
	GoatnetID              string `json:"goatnet_id"`
	IssuedTo               string `json:"issued_to"`
	Serial                 uint64 `json:"serial"`
	IssuedAtUnixNano       int64  `json:"issued_at_unix_nano"`
	RefreshIntervalSeconds int64  `json:"refresh_interval_seconds"`
	// NetworkMap is the map in protobuf wire form.
	NetworkMap []byte `json:"network_map"`

	networkMap *mgmProto.NetworkMap
}

// Map returns the envelope's network map.
func (e *Envelope) Map() *mgmProto.NetworkMap { return e.networkMap }

// IssuedAt returns the signer's clock at signing time.
func (e *Envelope) IssuedAt() time.Time { return time.Unix(0, e.IssuedAtUnixNano) }

// Marshal encodes a signed map.
func (s *SignedMap) Marshal() ([]byte, error) { return json.Marshal(s) }

// UnmarshalSignedMap decodes a signed map.
func UnmarshalSignedMap(b []byte) (*SignedMap, error) {
	s := &SignedMap{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return s, nil
}

// KeyID returns the identifier of an Ed25519 public key: "ed25519-" and the
// first 8 bytes of its SHA-256, in hex.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519-" + hex.EncodeToString(sum[:8])
}

func signedBytes(envelope []byte) []byte {
	out := make([]byte, 0, len(Domain)+1+len(envelope))
	out = append(out, Domain...)
	out = append(out, 0)
	return append(out, envelope...)
}

// Signer signs network maps for one goatnet with one key.
type Signer struct {
	goatnetID       string
	key             ed25519.PrivateKey
	keyID           string
	refreshInterval time.Duration
	now             func() time.Time
}

// NewSigner returns a signer. refreshInterval is carried in each envelope; zero means DefaultRefreshInterval.
func NewSigner(goatnetID string, key ed25519.PrivateKey, refreshInterval time.Duration) (*Signer, error) {
	if goatnetID == "" {
		return nil, errors.New("map signer needs a goatnet ID")
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("map signer needs an Ed25519 private key")
	}
	if refreshInterval <= 0 {
		refreshInterval = DefaultRefreshInterval
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	return &Signer{goatnetID: goatnetID, key: key, keyID: KeyID(pub), refreshInterval: refreshInterval, now: time.Now}, nil
}

// NewSignerFromFile reads a PKCS#8 PEM Ed25519 private key.
func NewSignerFromFile(goatnetID, path string, refreshInterval time.Duration) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read map signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("map signing key is not a PEM PRIVATE KEY")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse map signing key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("map signing key is not Ed25519")
	}
	return NewSigner(goatnetID, key, refreshInterval)
}

// KeyID returns the signer's key identifier.
func (s *Signer) KeyID() string { return s.keyID }

// GoatnetID returns the goatnet the signer signs for.
func (s *Signer) GoatnetID() string { return s.goatnetID }

// PublicKey returns the signer's public key.
func (s *Signer) PublicKey() ed25519.PublicKey {
	pub, _ := s.key.Public().(ed25519.PublicKey)
	return pub
}

// SignBytes signs msg with the signer's key. Other signed goatnet objects
// (membership certificates) use it; msg must already carry its own domain string.
func (s *Signer) SignBytes(msg []byte) []byte { return ed25519.Sign(s.key, msg) }

// RefreshInterval is how often a connected peer's map is re-signed.
func (s *Signer) RefreshInterval() time.Duration { return s.refreshInterval }

// Sign returns nm signed for the peer with WireGuard public key peerKey.
func (s *Signer) Sign(peerKey string, nm *mgmProto.NetworkMap) (*SignedMap, error) {
	mapBytes, err := proto.Marshal(nm)
	if err != nil {
		return nil, fmt.Errorf("encode network map: %w", err)
	}
	env, err := json.Marshal(&Envelope{
		GoatnetID:              s.goatnetID,
		IssuedTo:               peerKey,
		Serial:                 nm.GetSerial(),
		IssuedAtUnixNano:       s.now().UnixNano(),
		RefreshIntervalSeconds: int64(s.refreshInterval / time.Second),
		NetworkMap:             mapBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("encode network map envelope: %w", err)
	}
	return &SignedMap{Envelope: env, Signature: ed25519.Sign(s.key, signedBytes(env)), KeyID: s.keyID}, nil
}

// SignSyncResponse returns a copy of resp whose network map travels only in a
// signed envelope for peerKey. A response without a network map, or a nil
// signer, returns resp unchanged.
func (s *Signer) SignSyncResponse(peerKey string, resp *mgmProto.SyncResponse) (*mgmProto.SyncResponse, error) {
	if s == nil || resp.GetNetworkMap() == nil {
		return resp, nil
	}
	signed, err := s.Sign(peerKey, resp.GetNetworkMap())
	if err != nil {
		return nil, err
	}
	out := proto.Clone(resp).(*mgmProto.SyncResponse)
	out.NetworkMap = nil
	if err := Attach(out, signed); err != nil {
		return nil, err
	}
	return out, nil
}

// Attach puts signed into resp's field 1001, replacing one already there.
func Attach(resp *mgmProto.SyncResponse, signed *SignedMap) error {
	b, err := signed.Marshal()
	if err != nil {
		return fmt.Errorf("encode signed network map: %w", err)
	}
	m := resp.ProtoReflect()
	unknown := withoutField(m.GetUnknown(), SyncResponseField)
	unknown = protowire.AppendTag(unknown, SyncResponseField, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, b)
	m.SetUnknown(unknown)
	return nil
}

// FromSyncResponse returns the signed map in resp's field 1001, or nil when there is none.
func FromSyncResponse(resp *mgmProto.SyncResponse) (*SignedMap, error) {
	if resp == nil {
		return nil, nil //nolint:nilnil // no response, no signed map
	}
	b := resp.ProtoReflect().GetUnknown()
	var found []byte
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, protowire.ParseError(n))
		}
		b = b[n:]
		if num == SyncResponseField && typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil, fmt.Errorf("%w: %v", ErrMalformed, protowire.ParseError(m))
			}
			found = v
			b = b[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, protowire.ParseError(m))
		}
		b = b[m:]
	}
	if found == nil {
		return nil, nil //nolint:nilnil // the response carries no signed map
	}
	return UnmarshalSignedMap(found)
}

func withoutField(b []byte, field protowire.Number) []byte {
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

// TrustSet is the set of map signers a client accepts for one goatnet.
type TrustSet struct {
	GoatnetID string
	keys      map[string]ed25519.PublicKey
}

// NewTrustSet returns a trust set for goatnetID holding keys.
func NewTrustSet(goatnetID string, keys ...ed25519.PublicKey) (*TrustSet, error) {
	if goatnetID == "" {
		return nil, errors.New("trust set needs a goatnet ID")
	}
	ts := &TrustSet{GoatnetID: goatnetID, keys: map[string]ed25519.PublicKey{}}
	for _, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			return nil, errors.New("trust set key is not an Ed25519 public key")
		}
		ts.keys[KeyID(k)] = k
	}
	if len(ts.keys) == 0 {
		return nil, errors.New("trust set has no keys")
	}
	return ts, nil
}

type trustSigner struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// trustFile is the on-disk form of a trust set.
type trustFile struct {
	GoatnetID string        `json:"goatnet_id"`
	Signers   []trustSigner `json:"signers"`
}

// LoadTrustFile reads a trust set: {"goatnet_id": ..., "signers": [{"key_id": ..., "public_key": <base64>}]}.
// A key_id that does not match its public key is refused.
func LoadTrustFile(path string) (*TrustSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read map trust file: %w", err)
	}
	var tf trustFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("parse map trust file: %w", err)
	}
	keys := make([]ed25519.PublicKey, 0, len(tf.Signers))
	for _, s := range tf.Signers {
		raw, err := base64.StdEncoding.DecodeString(s.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("map trust file: signer %q has no valid Ed25519 public key", s.KeyID)
		}
		pub := ed25519.PublicKey(raw)
		if KeyID(pub) != s.KeyID {
			return nil, fmt.Errorf("map trust file: key_id %q does not match its public key (%s)", s.KeyID, KeyID(pub))
		}
		keys = append(keys, pub)
	}
	return NewTrustSet(tf.GoatnetID, keys...)
}

// MarshalTrustFile returns the on-disk form of a trust set for goatnetID and keys.
func MarshalTrustFile(goatnetID string, keys ...ed25519.PublicKey) ([]byte, error) {
	tf := trustFile{GoatnetID: goatnetID}
	for _, k := range keys {
		tf.Signers = append(tf.Signers, trustSigner{KeyID: KeyID(k), PublicKey: base64.StdEncoding.EncodeToString(k)})
	}
	return json.MarshalIndent(tf, "", "  ")
}

// VerifyBytes reports whether sig is a valid signature of msg by the trusted
// key keyID. Other signed goatnet objects (revocations) use it.
func (t *TrustSet) VerifyBytes(keyID string, msg, sig []byte) bool {
	pub, ok := t.keys[keyID]
	return ok && ed25519.Verify(pub, msg, sig)
}

// Verify checks signed against the trust set for the peer peerKey and returns its envelope.
func (t *TrustSet) Verify(peerKey string, signed *SignedMap) (*Envelope, error) {
	if signed == nil || len(signed.Envelope) == 0 {
		return nil, ErrUnsigned
	}
	pub, ok := t.keys[signed.KeyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, signed.KeyID)
	}
	if !ed25519.Verify(pub, signedBytes(signed.Envelope), signed.Signature) {
		return nil, ErrBadSignature
	}
	env, err := Open(signed)
	if err != nil {
		return nil, err
	}
	if env.GoatnetID != t.GoatnetID {
		return nil, fmt.Errorf("%w: %q", ErrWrongGoatnet, env.GoatnetID)
	}
	if env.IssuedTo != peerKey {
		return nil, ErrWrongPeer
	}
	return env, nil
}

// Open decodes the envelope of signed without verifying it. A client uses it
// directly only when it holds no trust set, so maps from a signing management
// still apply.
func Open(signed *SignedMap) (*Envelope, error) {
	if signed == nil {
		return nil, ErrUnsigned
	}
	env := &Envelope{}
	if err := json.Unmarshal(signed.Envelope, env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	nm := &mgmProto.NetworkMap{}
	if err := proto.Unmarshal(env.NetworkMap, nm); err != nil {
		return nil, fmt.Errorf("%w: network map: %v", ErrMalformed, err)
	}
	env.networkMap = nm
	return env, nil
}
