//go:build !js

package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	nbnetstack "github.com/netbirdio/netbird/client/iface/netstack"
	cProto "github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/shared/management/goatrevoke"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Signed revocations, stored on disk and flooded once between peers
// (USAREUR-AF/goatcore ADR 1273, phase 4). They need a trust set: a client
// without one neither keeps nor forwards revocations.

// peerMessage is what peers send each other on the revocation port.
type peerMessage struct {
	Kind string          `json:"kind"`
	Body json.RawMessage `json:"body"`
}

const peerMessageRevocation = "revocation"

// peerMessageHandlers handle the other kinds of peer message (later phases).
// They run without syncMsgMux held.
var peerMessageHandlers []func(e *Engine, msg peerMessage, from netip.Addr)

// DefaultRevocationPort is the UDP port on each peer's overlay address that
// receives revocations from other peers.
const DefaultRevocationPort = 33073

// startRevocations opens the revocation listener on the overlay address and
// applies stored revocations to the current peers. The caller holds syncMsgMux.
func (e *Engine) startRevocations() error {
	if e.revStore == nil || e.mapTrust == nil {
		return nil
	}
	port := e.revPort
	if port == 0 {
		port = DefaultRevocationPort
	}
	addr := net.UDPAddr{IP: e.wgInterface.Address().IP.AsSlice(), Port: port}
	var conn net.PacketConn
	var err error
	if nbnetstack.IsEnabled() {
		nsnet := e.wgInterface.GetNet()
		if nsnet == nil {
			return errors.New("revocation listener: no netstack")
		}
		conn, err = nsnet.ListenUDP(&addr)
	} else {
		conn, err = net.ListenUDP("udp", &addr)
	}
	if err != nil {
		return fmt.Errorf("revocation listener on %s: %w", addr.String(), err)
	}
	e.revConn = conn
	e.shutdownWg.Add(1)
	go func() {
		defer e.shutdownWg.Done()
		e.receiveRevocations(conn)
	}()
	go func() {
		<-e.ctx.Done()
		_ = conn.Close()
	}()
	log.Infof("receiving revocations from peers on %s", addr.String())
	return nil
}

func (e *Engine) receiveRevocations(conn net.PacketConn) {
	buf := make([]byte, goatrevoke.MaxMessageSize+1)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var msg peerMessage
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			continue
		}
		fromIP, _ := netip.ParseAddrPort(from.String())
		switch msg.Kind {
		case peerMessageRevocation:
			r, err := goatrevoke.Parse(msg.Body)
			if err != nil {
				continue
			}
			e.syncMsgMux.Lock()
			e.acceptRevocation(r, fromIP.Addr())
			e.syncMsgMux.Unlock()
		default:
			for _, h := range peerMessageHandlers {
				h(e, msg, fromIP.Addr())
			}
		}
	}
}

// acceptRevocations takes the revocations a sync response carries. The caller holds syncMsgMux.
func (e *Engine) acceptRevocations(update *mgmProto.SyncResponse) {
	if e.revStore == nil || e.mapTrust == nil {
		return
	}
	for _, r := range goatrevoke.FromSyncResponse(update) {
		e.acceptRevocation(r, netip.Addr{})
	}
}

// acceptRevocation verifies r, stores it before acting on it, removes the
// revoked peer, and forwards r once to every peer except the one it came from.
// A revocation already held is dropped, which ends the flood. The caller holds syncMsgMux.
func (e *Engine) acceptRevocation(r *goatrevoke.Signed, from netip.Addr) {
	if e.revStore == nil || e.mapTrust == nil {
		return
	}
	if err := goatrevoke.Verify(e.mapTrust, r); err != nil {
		log.Debugf("dropping a revocation: %v", err)
		return
	}
	added, err := e.revStore.Add(r)
	if err != nil {
		log.Errorf("failed to store revocation %s: %v", r.ID(), err)
		return
	}
	if !added {
		return
	}
	source := "management"
	if from.IsValid() {
		source = "peer " + from.String()
	}
	revoked := r.Rev().PeerKey
	if _, ok := e.peerStore.PeerConn(revoked); ok {
		if err := e.removePeer(revoked); err != nil {
			log.Warnf("failed to remove revoked peer %s: %v", revoked, err)
		}
		e.statusRecorder.FinishPeerListModifications()
	}
	msg := fmt.Sprintf("revocation %s of peer %s (signed %s) from %s; the key stays revoked", r.ID(), revoked, r.Rev().IssuedAt().UTC().Format(time.RFC3339), source)
	log.Info(msg)
	e.statusRecorder.PublishEvent(cProto.SystemEvent_WARNING, cProto.SystemEvent_SYSTEM, "Peer revoked", msg, nil)
	e.forwardRevocation(r, from)
}

// forwardRevocation sends r to the overlay address of every peer except from.
func (e *Engine) forwardRevocation(r *goatrevoke.Signed, from netip.Addr) {
	if e.revConn == nil {
		return
	}
	body, err := r.Marshal()
	if err != nil {
		return
	}
	b, err := json.Marshal(peerMessage{Kind: peerMessageRevocation, Body: body})
	if err != nil || len(b) > goatrevoke.MaxMessageSize {
		return
	}
	port := e.revPort
	if port == 0 {
		port = DefaultRevocationPort
	}
	sent := 0
	for _, key := range e.peerStore.PeersPubKey() {
		conn, ok := e.peerStore.PeerConn(key)
		if !ok || len(conn.WgConfig().AllowedIps) == 0 {
			continue
		}
		ip := conn.WgConfig().AllowedIps[0].Addr()
		if ip == from {
			continue
		}
		if _, err := e.revConn.WriteTo(b, &net.UDPAddr{IP: ip.AsSlice(), Port: port}); err == nil {
			sent++
		}
	}
	log.Debugf("forwarded revocation %s to %d peers", r.ID(), sent)
}

// newRevocationStore opens the revocation store beside the cached map.
func newRevocationStore(cachePath string) *goatrevoke.Store {
	if cachePath == "" {
		return nil
	}
	path := strings.TrimSuffix(cachePath, ".goat-map.json") + ".goat-revocations.json"
	store, err := goatrevoke.OpenStore(path)
	if err != nil {
		log.Errorf("revocation store %s: %v", path, err)
		return nil
	}
	return store
}

// revokedNow reports whether peerKey is revoked. A map that still lists a
// revoked key is refused for that peer, and the refusal is counted.
func (e *Engine) revokedNow(peerKey string) bool {
	if e.revStore == nil || e.mapTrust == nil {
		return false
	}
	if !goatrevoke.Revoked(e.revStore.All(), peerKey) {
		return false
	}
	e.revokedListings++
	log.Warnf("the network map lists revoked peer %s; leaving it out (%d such listings refused)", peerKey, e.revokedListings)
	return true
}

// RevokedListings is how many times a network map listed a revoked peer and
// the peer was left out.
func (e *Engine) RevokedListings() uint64 {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()
	return e.revokedListings
}
