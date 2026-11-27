package grpc

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/netbirdio/netbird/shared/management/goatroot"
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
