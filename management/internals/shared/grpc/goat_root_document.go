package grpc

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/netbirdio/netbird/shared/management/goatmember"
	"github.com/netbirdio/netbird/shared/management/goatrevoke"
	"github.com/netbirdio/netbird/shared/management/goatroot"
	"github.com/netbirdio/netbird/shared/management/mapsign"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// rootDocumentFile holds the goatnet root document read from a file and reads
// it again when the file's modification time or size changes.
type rootDocumentFile struct {
	path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	doc     *goatroot.Signed
}

func (r *rootDocumentFile) get() (*goatroot.Signed, error) {
	fi, err := os.Stat(r.path)
	if err != nil {
		return nil, fmt.Errorf("stat root document: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.doc != nil && fi.ModTime().Equal(r.modTime) && fi.Size() == r.size {
		return r.doc, nil
	}
	b, err := os.ReadFile(r.path)
	if err != nil {
		return nil, fmt.Errorf("read root document: %w", err)
	}
	doc, err := goatroot.Parse(b)
	if err != nil {
		return nil, err
	}
	r.doc, r.modTime, r.size = doc, fi.ModTime(), fi.Size()
	return doc, nil
}

// revocationsFile holds the signed revocation list read from a file and reads
// it again when the file's modification time or size changes.
type revocationsFile struct {
	path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	list    []*goatrevoke.Signed
	loaded  bool
}

func (r *revocationsFile) get() ([]*goatrevoke.Signed, error) {
	fi, err := os.Stat(r.path)
	if err != nil {
		return nil, fmt.Errorf("stat revocations: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loaded && fi.ModTime().Equal(r.modTime) && fi.Size() == r.size {
		return r.list, nil
	}
	list, err := goatrevoke.LoadList(r.path)
	if err != nil {
		return nil, err
	}
	r.list, r.modTime, r.size, r.loaded = list, fi.ModTime(), fi.Size(), true
	return list, nil
}

// membershipIssuer issues each peer a membership certificate on every sync
// response and remembers the latest one, so the certificates of a peer's
// remote peers can be sent with its map.
type membershipIssuer struct {
	signer *mapsign.Signer
	window time.Duration

	mu     sync.Mutex
	latest map[string]*goatmember.Signed
}

func newMembershipIssuer(signer *mapsign.Signer, window time.Duration) *membershipIssuer {
	return &membershipIssuer{signer: signer, window: window, latest: map[string]*goatmember.Signed{}}
}

// attach issues peerKey a certificate now and puts it, with the latest
// certificates of the remote peers in nm, into out.
func (m *membershipIssuer) attach(peerKey string, nm *proto.NetworkMap, out *proto.SyncResponse) error {
	if m.signer == nil {
		return nil
	}
	own, err := goatmember.SignBy(&goatmember.Certificate{
		GoatnetID:        m.signer.GoatnetID(),
		PeerKey:          peerKey,
		IssuedAtUnixNano: time.Now().UnixNano(),
		WindowSeconds:    int64(m.window / time.Second),
	}, m.signer)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.latest[peerKey] = own
	remote := make([]*goatmember.Signed, 0, len(nm.GetRemotePeers()))
	for _, p := range nm.GetRemotePeers() {
		if c, ok := m.latest[p.GetWgPubKey()]; ok {
			remote = append(remote, c)
		}
	}
	m.mu.Unlock()
	return goatmember.Attach(out, own, remote)
}
