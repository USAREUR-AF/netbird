//go:build !js

package client

import (
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/shared/relay/client/dialer"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/quic"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/ws"
)

// getDialers returns the list of dialers to use for connecting to the relay server.
//
// goat M-003 force-QUIC patch: skip the WebSocket dialer entirely so the race
// dialer has only QUIC to choose from. Used for head-to-head QUIC-vs-WS
// throughput measurement on the existing relay binary; reverts cleanly when
// the patch branch is dropped. See docs/measurements/M-003-… and F-016 in the
// goat repo.
func (c *Client) getDialers() []dialer.DialeFn {
	if c.mtu > 0 && c.mtu > iface.DefaultMTU {
		c.log.Infof("MTU %d exceeds default (%d), forcing WebSocket transport to avoid DATAGRAM frame size issues", c.mtu, iface.DefaultMTU)
		return []dialer.DialeFn{ws.Dialer{}}
	}
	c.log.Infof("goat M-003: force-QUIC build — WebSocket dialer disabled, QUIC only")
	return []dialer.DialeFn{quic.Dialer{}}
}
