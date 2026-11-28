//go:build !js

package internal

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"

	cProto "github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/shared/management/goatmember"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Membership certificates checked between peers against a relative window
// (USAREUR-AF/goatcore ADR 1273, phase 5). They need a trust set and a
// management that issues certificates; without them nothing here acts.

const peerMessageCertificate = "certificate"

func init() {
	peerMessageHandlers = append(peerMessageHandlers, func(e *Engine, msg peerMessage, from netip.Addr) {
		if msg.Kind != peerMessageCertificate {
			return
		}
		c, err := goatmember.Parse(msg.Body)
		if err != nil {
			return
		}
		e.syncMsgMux.Lock()
		defer e.syncMsgMux.Unlock()
		key, ok := e.peerKeyForOverlay(from)
		if !ok {
			return
		}
		e.holdCertificate(key, c)
	})
}

// memberState is the engine's certificate bookkeeping. Protected by syncMsgMux.
type memberState struct {
	own     *goatmember.Signed
	held    map[string]*goatmember.Signed // remote peer key -> newest verified certificate
	added   map[string]time.Time          // remote peer key -> when it was added, for the grace period
	refused map[string]string             // remote peer key -> why it is refused
	lastMap *mgmProto.NetworkMap          // last map applied, to re-admit a peer without a new map
}

// peerKeyForOverlay returns the key of the peer whose first allowed IP is ip.
// WireGuard only delivers a packet from ip if it came through that peer's tunnel.
func (e *Engine) peerKeyForOverlay(ip netip.Addr) (string, bool) {
	for _, key := range e.peerStore.PeersPubKey() {
		conn, ok := e.peerStore.PeerConn(key)
		if ok && len(conn.WgConfig().AllowedIps) > 0 && conn.WgConfig().AllowedIps[0].Addr() == ip {
			return key, true
		}
	}
	return "", false
}

// acceptCertificates takes this peer's certificate and its remote peers'
// certificates from a sync response. The caller holds syncMsgMux.
func (e *Engine) acceptCertificates(update *mgmProto.SyncResponse) {
	if e.mapTrust == nil {
		return
	}
	own, remote := goatmember.FromSyncResponse(update)
	me := e.config.WgPrivateKey.PublicKey().String()
	if own != nil {
		if err := goatmember.Verify(e.mapTrust, own, me); err != nil {
			log.Warnf("ignoring this peer's membership certificate: %v", err)
		} else {
			e.member.own = own
		}
	}
	for _, c := range remote {
		e.holdCertificate(c.Cert().PeerKey, c)
	}
}

// holdCertificate keeps c for peerKey when it verifies and is newer than the one held.
func (e *Engine) holdCertificate(peerKey string, c *goatmember.Signed) {
	if e.mapTrust == nil {
		return
	}
	if err := goatmember.Verify(e.mapTrust, c, peerKey); err != nil {
		return
	}
	if e.member.held == nil {
		e.member.held = map[string]*goatmember.Signed{}
	}
	if prev, ok := e.member.held[peerKey]; ok && !c.Cert().IssuedAt().After(prev.Cert().IssuedAt()) {
		return
	}
	e.member.held[peerKey] = c
}

// certificateRefusal returns why peerKey is refused, or "" when it is accepted.
func (e *Engine) certificateRefusal(peerKey string, now time.Time) string {
	own := e.member.own
	if own == nil {
		return ""
	}
	if c, ok := e.member.held[peerKey]; ok {
		if !goatmember.Agree(own.Cert(), c.Cert()) {
			return fmt.Sprintf("certificate issued %s apart from ours, window %s",
				own.Cert().IssuedAt().Sub(c.Cert().IssuedAt()).Abs().Round(time.Second), own.Cert().Window())
		}
		return ""
	}
	if added, ok := e.member.added[peerKey]; ok && now.Sub(added) > 2*own.Cert().Window() {
		return "no certificate within twice the window"
	}
	return ""
}

// refusedByCertificate reports whether peerKey is refused, for updateNetworkMap.
func (e *Engine) refusedByCertificate(peerKey string) bool {
	_, refused := e.member.refused[peerKey]
	return refused
}

// noteMap records the map being applied and when each of its peers first appeared.
func (e *Engine) noteMap(nm *mgmProto.NetworkMap) {
	e.member.lastMap = nm
	if e.member.added == nil {
		e.member.added = map[string]time.Time{}
	}
	present := map[string]bool{}
	for _, p := range nm.GetRemotePeers() {
		present[p.GetWgPubKey()] = true
		if _, ok := e.member.added[p.GetWgPubKey()]; !ok {
			e.member.added[p.GetWgPubKey()] = time.Now()
		}
	}
	for k := range e.member.added {
		if !present[k] {
			delete(e.member.added, k)
		}
	}
}

// runMembership sends this peer's certificate to its peers and checks theirs.
func (e *Engine) runMembership() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastSent := time.Time{}
	for {
		select {
		case <-e.ctx.Done():
			return
		case now := <-ticker.C:
			e.syncMsgMux.Lock()
			own := e.member.own
			if own != nil && now.Sub(lastSent) >= sendInterval(own.Cert().Window()) {
				e.sendCertificate(own)
				lastSent = now
			}
			e.checkCertificates(now)
			e.syncMsgMux.Unlock()
		}
	}
}

func sendInterval(window time.Duration) time.Duration {
	if d := window / 3; d > time.Second {
		return d
	}
	return time.Second
}

func (e *Engine) sendCertificate(own *goatmember.Signed) {
	if e.revConn == nil {
		return
	}
	body, err := own.Marshal()
	if err != nil {
		return
	}
	b, err := json.Marshal(peerMessage{Kind: peerMessageCertificate, Body: body})
	if err != nil {
		return
	}
	port := e.revPort
	if port == 0 {
		port = DefaultRevocationPort
	}
	for _, key := range e.peerStore.PeersPubKey() {
		conn, ok := e.peerStore.PeerConn(key)
		if !ok || len(conn.WgConfig().AllowedIps) == 0 {
			continue
		}
		_, _ = e.revConn.WriteTo(b, &net.UDPAddr{IP: conn.WgConfig().AllowedIps[0].Addr().AsSlice(), Port: port})
	}
}

// checkCertificates refuses peers whose certificate does not agree with ours
// and re-admits refused peers whose newest certificate now agrees. The
// caller holds syncMsgMux.
func (e *Engine) checkCertificates(now time.Time) {
	if e.member.own == nil || e.member.lastMap == nil {
		return
	}
	if e.member.refused == nil {
		e.member.refused = map[string]string{}
	}
	readmit := false
	for _, p := range e.member.lastMap.GetRemotePeers() {
		key := p.GetWgPubKey()
		why := e.certificateRefusal(key, now)
		_, wasRefused := e.member.refused[key]
		switch {
		case why != "" && !wasRefused:
			e.member.refused[key] = why
			if _, ok := e.peerStore.PeerConn(key); ok {
				if err := e.removePeer(key); err != nil {
					log.Warnf("failed to remove peer %s: %v", key, err)
				}
				e.statusRecorder.FinishPeerListModifications()
			}
			msg := fmt.Sprintf("peer %s refused: %s", key, why)
			log.Warn(msg)
			e.statusRecorder.PublishEvent(cProto.SystemEvent_WARNING, cProto.SystemEvent_SYSTEM, "Peer refused by membership certificate", msg, nil)
		case why == "" && wasRefused:
			delete(e.member.refused, key)
			log.Infof("peer %s accepted again: its certificate agrees with ours", key)
			readmit = true
		}
	}
	if readmit {
		e.networkSerial = 0
		if err := e.updateNetworkMap(e.member.lastMap); err != nil {
			log.Warnf("failed to re-admit peers: %v", err)
		}
	}
}

// startMembership starts the certificate loop when the engine verifies maps.
func (e *Engine) startMembership() {
	if e.mapTrust == nil {
		return
	}
	e.shutdownWg.Add(1)
	go func() {
		defer e.shutdownWg.Done()
		e.runMembership()
	}()
}
