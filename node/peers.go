package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// peerBook is the on-disk address book: multiaddrs of peers we have met,
// each one ending in /p2p/<peerID> so it carries both where and who.
type peerBook struct {
	path string
}

func newPeerBook(path string) *peerBook {
	return &peerBook{path: path}
}

// load reads the saved addresses. A missing file is not an error: it just
// means this is our first run and we have not met anyone yet.
func (b *peerBook) load() []string {
	data, err := os.ReadFile(b.path)
	if err != nil {
		return nil
	}
	var addrs []string
	if err := json.Unmarshal(data, &addrs); err != nil {
		return nil
	}
	return addrs
}

// save appends one address, skipping duplicates.
func (b *peerBook) save(addr string) error {
	addrs := b.load()
	for _, a := range addrs {
		if a == addr {
			return nil // already known
		}
	}
	addrs = append(addrs, addr)

	data, err := json.MarshalIndent(addrs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(b.path, data, 0644)
}

// Remember records a peer we are connected to, so we can redial it after a
// restart.
//
// The subtlety: for an INBOUND connection the remote address libp2p first sees
// is the dialer's ephemeral source port, which nothing is listening on. Redialing
// it would fail. libp2p's identify protocol fixes this a moment after connecting,
// when the peer tells us its real listen addresses. So we keep only addresses
// that identify has confirmed are dialable, and skip the ephemeral ones.
func (b *peerBook) Remember(h host.Host, p peer.ID) {
	if p == h.ID() {
		return // never save ourselves
	}
	for _, a := range h.Peerstore().Addrs(p) {
		full := fmt.Sprintf("%s/p2p/%s", a, p)
		if err := b.save(full); err != nil {
			fmt.Println("peerbook save failed:", err)
		}
	}
}

// Watch records every peer that connects to us, inbound or outbound, so a node
// that never dials anyone still builds an address book. We wait briefly before
// recording, to give identify time to report the peer's real listen addresses
// rather than the ephemeral source port of an inbound dial.
func (b *peerBook) Watch(h host.Host) {
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, c network.Conn) {
			p := c.RemotePeer()
			go func() {
				time.Sleep(2 * time.Second) // let identify complete
				b.Remember(h, p)
			}()
		},
	})
}

// KeepConnected retries the address book forever in the background.
//
// A single reconnect attempt at boot is not enough: whichever node starts first
// finds the others down and would give up permanently. Peers restart at
// arbitrary times, so rejoining has to be a continuous effort, not a one-shot.
// This is the difference between a demo and something that survives churn.
func (b *peerBook) KeepConnected(ctx context.Context, h host.Host, every time.Duration) {
	go func() {
		for {
			// only bother with peers we are not already talking to
			for _, a := range b.load() {
				info, err := peer.AddrInfoFromString(a)
				if err != nil || info.ID == h.ID() {
					continue
				}
				if h.Network().Connectedness(info.ID) == network.Connected {
					continue
				}
				if err := h.Connect(ctx, *info); err == nil {
					fmt.Printf("\n[peers] reconnected to %s\n", info.ID.String()[:12])
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(every):
			}
		}
	}()
}

// Reconnect dials every peer we remember. Failures are expected and ignored:
// peers move, go offline, or change ports. Returns how many came back.
func (b *peerBook) Reconnect(ctx context.Context, h host.Host) int {
	addrs := b.load()
	if len(addrs) == 0 {
		return 0
	}

	connected := 0
	for _, a := range addrs {
		info, err := peer.AddrInfoFromString(a)
		if err != nil {
			continue
		}
		if info.ID == h.ID() {
			continue
		}
		if err := h.Connect(ctx, *info); err != nil {
			continue // peer is gone; that is normal
		}
		connected++
		fmt.Printf("[peers] reconnected to %s\n", info.ID.String()[:12])
	}
	fmt.Printf("[peers] knew %d, reconnected %d\n", len(addrs), connected)
	return connected
}
