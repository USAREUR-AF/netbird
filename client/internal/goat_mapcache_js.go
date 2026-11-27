//go:build js

package internal

import (
	"net"

	"github.com/netbirdio/netbird/client/internal/mapcache"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/shared/management/mapsign"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// The browser client keeps no state on disk: no cached map, no trust file and
// no root document. It still opens a signed map from management (networkMapFromSync).

func loadTrustConfig() (*mapcache.TrustConfig, error) {
	return &mapcache.TrustConfig{MaxAge: mapcache.DefaultMaxAge}, nil
}

func newMapStore(string, mapcache.Binding) *mapcache.Store { return nil }

func (e *Engine) persistMap(*mgmProto.SyncResponse, *mgmProto.NetworkMap, *mapsign.SignedMap) {}

func (e *Engine) directEndpointHook() func(string, *net.UDPAddr) { return nil }

func usableCachedMap(string, mapcache.Binding, *mapcache.TrustConfig) *mapcache.Entry { return nil }

// HasUsableCachedMap is always false in the browser client.
func HasUsableCachedMap(*profilemanager.Config, string) bool { return false }

func (e *Engine) applyRootDocument(*mgmProto.SyncResponse) {}
