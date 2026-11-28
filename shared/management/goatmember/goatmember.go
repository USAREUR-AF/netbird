// Package goatmember is a peer's membership certificate and the relative time
// window peers check it against (USAREUR-AF/goatcore ADR 1273, phase 5: K1, K2).
//
// Management issues each peer a short certificate (goatnet, the peer's
// WireGuard key, the issue time, the window) with every sync response, and
// sends with it the latest certificate it issued to each of the peer's remote
// peers. Peers also send their own certificate to each other over the overlay.
// A peer accepts another while the two certificates were issued within the
// window of each other. The comparison is between issue times, never against
// the receiver's clock: peers cut off from management together keep accepting
// each other, and a peer whose last certificate is older than the others' by
// more than the window is refused until it gets a fresh one.
package goatmember

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/netbirdio/netbird/shared/management/mapsign"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Domain is prefixed (with a zero byte) to the certificate bytes before signing.
const Domain = "goat-membership-v1"

// OwnField is the SyncResponse field number of the receiving peer's own certificate.
const OwnField protowire.Number = 1004

// RemoteField is the SyncResponse field number of the remote peers' latest certificates.
const RemoteField protowire.Number = 1005

var (
	// ErrBadSignature means the signature does not verify against the trust set.
	ErrBadSignature = errors.New("membership certificate signature does not verify")
	// ErrOtherGoatnet means the certificate is for another goatnet.
	ErrOtherGoatnet = errors.New("membership certificate is for another goatnet")
	// ErrWrongPeer means the certificate is issued to another peer.
	ErrWrongPeer = errors.New("membership certificate is issued to another peer")
	// ErrMalformed means the certificate could not be decoded.
	ErrMalformed = errors.New("membership certificate is malformed")
)

// Certificate is the signed content.
type Certificate struct {
	GoatnetID        string `json:"goatnet_id"`
	PeerKey          string `json:"peer_key"`
	IssuedAtUnixNano int64  `json:"issued_at_unix_nano"`
	WindowSeconds    int64  `json:"window_seconds"`
}

// IssuedAt returns the certificate's issue time.
func (c *Certificate) IssuedAt() time.Time { return time.Unix(0, c.IssuedAtUnixNano) }

// Window returns the certificate's window.
func (c *Certificate) Window() time.Duration { return time.Duration(c.WindowSeconds) * time.Second }

// Signed is a certificate as encoded once by its signer.
type Signed struct {
	Certificate []byte `json:"certificate"`
	Signature   []byte `json:"signature"`
	KeyID       string `json:"key_id"`

	cert *Certificate
}

// Cert returns the decoded certificate.
func (s *Signed) Cert() *Certificate { return s.cert }

func signedBytes(b []byte) []byte {
	out := append([]byte(Domain), 0)
	return append(out, b...)
}

// Sign encodes c once and signs it with key.
func Sign(c *Certificate, key ed25519.PrivateKey) (*Signed, error) {
	if c.GoatnetID == "" || c.PeerKey == "" || c.WindowSeconds <= 0 {
		return nil, fmt.Errorf("%w: goatnet, peer key and window are required", ErrMalformed)
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	return &Signed{Certificate: b, Signature: ed25519.Sign(key, signedBytes(b)), KeyID: mapsign.KeyID(pub), cert: c}, nil
}

// SignBy encodes c once and signs it with a management map signer.
func SignBy(c *Certificate, signer *mapsign.Signer) (*Signed, error) {
	if c.GoatnetID == "" || c.PeerKey == "" || c.WindowSeconds <= 0 {
		return nil, fmt.Errorf("%w: goatnet, peer key and window are required", ErrMalformed)
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return &Signed{Certificate: b, Signature: signer.SignBytes(signedBytes(b)), KeyID: signer.KeyID(), cert: c}, nil
}

// Marshal encodes a signed certificate.
func (s *Signed) Marshal() ([]byte, error) { return json.Marshal(s) }

// Parse decodes a signed certificate without checking its signature.
func Parse(b []byte) (*Signed, error) {
	s := &Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	c := &Certificate{}
	if err := json.Unmarshal(s.Certificate, c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if c.PeerKey == "" || c.WindowSeconds <= 0 {
		return nil, fmt.Errorf("%w: no peer key or window", ErrMalformed)
	}
	s.cert = c
	return s, nil
}

// Verify checks s against the goatnet's map signers and that it is issued to peerKey.
func Verify(ts *mapsign.TrustSet, s *Signed, peerKey string) error {
	if s == nil || s.cert == nil {
		return ErrMalformed
	}
	if s.cert.GoatnetID != ts.GoatnetID {
		return fmt.Errorf("%w: %q", ErrOtherGoatnet, s.cert.GoatnetID)
	}
	if !ts.VerifyBytes(s.KeyID, signedBytes(s.Certificate), s.Signature) {
		return ErrBadSignature
	}
	if s.cert.PeerKey != peerKey {
		return ErrWrongPeer
	}
	return nil
}

// Agree reports whether two certificates were issued within mine's window of each other.
func Agree(mine, theirs *Certificate) bool {
	d := mine.IssuedAt().Sub(theirs.IssuedAt())
	if d < 0 {
		d = -d
	}
	return d <= mine.Window()
}

// Attach puts the peer's own certificate and its remote peers' certificates into resp.
func Attach(resp *mgmProto.SyncResponse, own *Signed, remote []*Signed) error {
	m := resp.ProtoReflect()
	unknown := dropField(dropField(m.GetUnknown(), OwnField), RemoteField)
	if own != nil {
		b, err := own.Marshal()
		if err != nil {
			return err
		}
		unknown = protowire.AppendBytes(protowire.AppendTag(unknown, OwnField, protowire.BytesType), b)
	}
	if len(remote) > 0 {
		b, err := json.Marshal(remote)
		if err != nil {
			return err
		}
		unknown = protowire.AppendBytes(protowire.AppendTag(unknown, RemoteField, protowire.BytesType), b)
	}
	m.SetUnknown(unknown)
	return nil
}

// FromSyncResponse returns the peer's own certificate and the remote peers'
// certificates in resp. A certificate that does not decode is skipped.
func FromSyncResponse(resp *mgmProto.SyncResponse) (own *Signed, remote []*Signed) {
	if resp == nil {
		return nil, nil
	}
	b := resp.ProtoReflect().GetUnknown()
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return own, remote
		}
		m := protowire.ConsumeFieldValue(num, typ, b[n:])
		if m < 0 {
			return own, remote
		}
		if typ == protowire.BytesType {
			v, _ := protowire.ConsumeBytes(b[n:])
			switch num {
			case OwnField:
				own, _ = Parse(v)
			case RemoteField:
				var raw []json.RawMessage
				if json.Unmarshal(v, &raw) == nil {
					for _, r := range raw {
						if s, err := Parse(r); err == nil {
							remote = append(remote, s)
						}
					}
				}
			}
		}
		b = b[n+m:]
	}
	return own, remote
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
