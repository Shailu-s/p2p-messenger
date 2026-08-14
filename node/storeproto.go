package main

import (
	"context"
	"encoding/json"
	"errors"
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

		resp, err := s.Query(q)
		if err != nil {
			resp.Error = err.Error()
		}
		fmt.Printf("\n[store] served %d messages to %s\n",
			len(resp.Messages), stream.Conn().RemotePeer().String()[:12])

		json.NewEncoder(stream).Encode(resp)
	})
}

func FetchFromAllPeers(ctx context.Context, h host.Host, s *Store, cursors *CursorBook, topics []string, sm *SessionManager) {
	peers := h.Network().Peers()
	if len(peers) == 0 {
		fmt.Println("[history] no peers to ask")
		return
	}
	if len(topics) == 0 {
		fmt.Println("[history] no content topics to ask for")
		return
	}

	total, added := 0, 0
	for _, p := range peers {
		for _, topic := range topics {
			cursor := ""
			if cursors != nil {
				cursor = cursors.Cursor(p, topic)
			}
			resp, err := FetchHistory(ctx, h, p, topic, cursor)
			if err != nil {
				continue // peer may not speak the store protocol
			}
			total += len(resp.Messages)
			for _, m := range resp.Messages {
				m.Seq = 0
				m.Timestamp = 0
				ok, err := s.Put(m)
				if err != nil {
					fmt.Printf("\n[history] store error: %v\n", err)
					continue
				}
				if ok {
					added++
					printHistoryMessage(sm, m.Payload)
				}
			}
			if cursors != nil {
				if err := cursors.Update(p, topic, resp.NextCursor); err != nil {
					fmt.Printf("\n[history] cursor error: %v\n", err)
				}
			}
		}
	}
	fmt.Printf("[history] asked %d peers, got %d, new %d, total %d\n",
		len(peers), total, added, s.Count())
}

func FetchHistory(ctx context.Context, h host.Host, p peer.ID, topic, cursor string) (StoreResponse, error) {
	stream, err := h.NewStream(ctx, p, StoreProtocol)
	if err != nil {
		return StoreResponse{}, err
	}
	defer stream.Close()

	q := StoreQuery{Topic: topic, Cursor: cursor, Limit: 100}
	if err := json.NewEncoder(stream).Encode(q); err != nil {
		return StoreResponse{}, err
	}

	var resp StoreResponse
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		return StoreResponse{}, err
	}
	if resp.Error != "" {
		return StoreResponse{}, errors.New(resp.Error)
	}
	return resp, nil
}

func printHistoryMessage(sm *SessionManager, payload []byte) {
	if sm != nil {
		if pt, ok := sm.TryDecrypt(payload); ok {
			fmt.Printf("\n[history] %s", string(pt))
			return
		}
	}
	fmt.Printf("\n[history opaque] %d bytes", len(payload))
}
