package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const StoreProtocol = "/chat/store/1.0.0"

// RegisterStoreServer answers history queries from other nodes.
func RegisterStoreServer(h host.Host, s *Store) {
	h.SetStreamHandler(StoreProtocol, func(stream network.Stream) {
		defer stream.Close()

		var q StoreQuery
		if err := json.NewDecoder(stream).Decode(&q); err != nil {
			return
		}

		msgs := s.Query(q)
		fmt.Printf("\n[store] served %d messages to %s\n",
			len(msgs), stream.Conn().RemotePeer().String()[:12])

		json.NewEncoder(stream).Encode(StoreResponse{Messages: msgs})
	})
}

// FetchFromAllPeers asks every connected peer for history and merges the
// answers. Overlap costs nothing because Put dedups on the content hash, so
// asking several peers is pure redundancy: if one is missing messages or
// lying, another may still have them.
func FetchFromAllPeers(ctx context.Context, h host.Host, s *Store, since int64) {
	peers := h.Network().Peers()
	if len(peers) == 0 {
		fmt.Println("[history] no peers to ask")
		return
	}

	total, added := 0, 0
	for _, p := range peers {
		msgs, err := FetchHistory(ctx, h, p, since)
		if err != nil {
			continue // peer may not speak the store protocol
		}
		total += len(msgs)
		for _, m := range msgs {
			if s.Put(m) {
				added++
				fmt.Printf("[history] %s", string(m.Payload))
			}
		}
	}
	fmt.Printf("[history] asked %d peers, got %d, new %d, total %d\n",
		len(peers), total, added, s.Count())
}

func FetchHistory(ctx context.Context, h host.Host, p peer.ID, since int64) ([]StoredMessage, error) {
	stream, err := h.NewStream(ctx, p, StoreProtocol)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	q := StoreQuery{Topic: "chat-room", Since: since, Limit: 100}
	if err := json.NewEncoder(stream).Encode(q); err != nil {
		return nil, err
	}

	var resp StoreResponse
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		return nil, err
	}
	return resp.Messages, nil
}
