//go:build !js

package internal

import (
	"errors"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/mapcache"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	cProto "github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/shared/management/goatroot"
	"github.com/netbirdio/netbird/shared/management/mapsign"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// The network map cache, map verification and the goatnet root document
// (USAREUR-AF/goatcore ADR 1273). The browser client (js) has no state
// directory and builds the stubs in goat_mapcache_js.go instead.

func loadTrustConfig() (*mapcache.TrustConfig, error) {
	return mapcache.TrustConfigFromEnv()
}

func newMapStore(path string, b mapcache.Binding) *mapcache.Store {
	return mapcache.NewStore(path, b, nil)
}

// persistMap writes an applied network map to the cache.
func (e *Engine) persistMap(update *mgmProto.SyncResponse, nm *mgmProto.NetworkMap, signed *mapsign.SignedMap) {
	e.mapCache.SetNetbirdConfig(update.GetNetbirdConfig())
	if err := e.mapCache.SaveMap(nm, signed); err != nil {
		log.Warnf("failed to write the cached network map: %v", err)
	}
}

// directEndpointHook records each peer's direct endpoint in the cache.
func (e *Engine) directEndpointHook() func(string, *net.UDPAddr) {
	if e.mapCache == nil {
		return nil
	}
	return e.mapCache.SetEndpoint
}

// usableCachedMap returns the cached network map at path when it may be used for b,
// or nil with the reason logged.
func usableCachedMap(path string, b mapcache.Binding, cfg *mapcache.TrustConfig) *mapcache.Entry {
	if path == "" || mapcache.Disabled() {
		return nil
	}
	if cfg.MaxAgeInvalid {
		log.Errorf("not using the cached network map: %s is not a usable maximum age", mapcache.EnvMaxAge)
		return nil
	}
	entry, err := mapcache.LoadUsable(path, b, cfg.MaxAge, mapcache.SystemClock, cfg.Trust)
	if err != nil {
		if !errors.Is(err, mapcache.ErrNotFound) {
			log.Warnf("not using the cached network map %s: %v", path, err)
		}
		return nil
	}
	return entry
}

// HasUsableCachedMap reports whether a client with config could start from its
// cached network map now. statePath is the client's state file.
func HasUsableCachedMap(config *profilemanager.Config, statePath string) bool {
	if config == nil || config.ManagementURL == nil {
		return false
	}
	key, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil {
		return false
	}
	cfg, err := mapcache.TrustConfigFromEnv()
	if err != nil {
		log.Errorf("not using the cached network map: %v", err)
		return false
	}
	return usableCachedMap(mapcache.PathForState(statePath), mapcache.Binding{
		ManagementURL: config.ManagementURL.String(),
		PeerKey:       key.PublicKey().String(),
	}, cfg) != nil
}

// applyRootDocument replaces the held root document with the one in update when
// it is a valid successor, writes it to disk, and takes the map signers and the
// maximum age from it. The caller holds syncMsgMux.
func (e *Engine) applyRootDocument(update *mgmProto.SyncResponse) {
	if e.rootDoc == nil {
		return
	}
	candidate, err := goatroot.FromSyncResponse(update)
	if err != nil {
		log.Warnf("ignoring the goatnet root document from management: %v", err)
		return
	}
	if candidate == nil {
		return
	}
	if err := goatroot.Successor(e.rootDoc, candidate); err != nil {
		if !errors.Is(err, goatroot.ErrNotNewer) {
			log.Warnf("refusing the goatnet root document version %d from management: %v", candidate.Doc().Version, err)
		}
		return
	}
	trust, err := candidate.Doc().TrustSet()
	if err != nil {
		log.Warnf("refusing the goatnet root document version %d: %v", candidate.Doc().Version, err)
		return
	}
	if e.rootDocPath != "" {
		if err := goatroot.Store(e.rootDocPath, candidate); err != nil {
			log.Errorf("failed to write the goatnet root document version %d: %v", candidate.Doc().Version, err)
			return
		}
	}
	msg := fmt.Sprintf("goatnet root document version %d replaces version %d: %d map signers, maximum map age %s",
		candidate.Doc().Version, e.rootDoc.Doc().Version, len(candidate.Doc().MapSigners), candidate.Doc().MapMaxAge())
	log.Info(msg)
	e.rootDoc = candidate
	e.mapTrust = trust
	e.mapMaxAge = EffectiveMapMaxAge(candidate.Doc(), e.mapMaxAgeOverride)
	e.statusRecorder.PublishEvent(cProto.SystemEvent_INFO, cProto.SystemEvent_SYSTEM, "Goatnet root document updated", msg, nil)
}
