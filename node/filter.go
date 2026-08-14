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

const FilterProtocol = "/chat/filter/1.0.0"

type FilterRequest struct {
	Topics   []string `json:"topics,omitempty"`
	All      bool     `json:"all,omitempty"`
	Backfill int      `json:"backfill,omitempty"`
}

type FilterEvent struct {
	Ready   bool           `json:"ready,omitempty"`
	Message *StoredMessage `json:"message,omitempty"`
	Error   string         `json:"error,omitempty"`
}

func RegisterFilterServer(h host.Host, s *Store) {
	h.SetStreamHandler(FilterProtocol, func(stream network.Stream) {
		defer stream.Close()

		var req FilterRequest
		if err := json.NewDecoder(stream).Decode(&req); err != nil {
			return
		}
		enc := json.NewEncoder(stream)
		if !req.All && len(req.Topics) == 0 {
			enc.Encode(FilterEvent{Error: "filter requires topics or all=true"})
			return
		}

		topics := req.Topics
		if req.All {
			topics = nil
		}
		if req.All {
			fmt.Printf("\n[filter] %s subscribed to all topics\n", short(stream.Conn().RemotePeer()))
		} else {
			fmt.Printf("\n[filter] %s subscribed to %d topics\n", short(stream.Conn().RemotePeer()), len(topics))
		}

		updates, cancel := s.Subscribe(topics)
		defer cancel()

		if err := enc.Encode(FilterEvent{Ready: true}); err != nil {
			return
		}
		for _, m := range s.Recent(topics, req.Backfill) {
			msg := m
			if err := enc.Encode(FilterEvent{Message: &msg}); err != nil {
				return
			}
		}
		for m := range updates {
			msg := m
			if err := enc.Encode(FilterEvent{Message: &msg}); err != nil {
				return
			}
		}
	})
}

func SubscribeFilter(ctx context.Context, h host.Host, p peer.ID, req FilterRequest) (<-chan StoredMessage, error) {
	if !req.All && len(req.Topics) == 0 {
		return nil, errors.New("filter requires topics or all=true")
	}

	stream, err := h.NewStream(ctx, p, FilterProtocol)
	if err != nil {
		return nil, err
	}
	if err := json.NewEncoder(stream).Encode(req); err != nil {
		stream.Close()
		return nil, err
	}

	dec := json.NewDecoder(stream)
	for {
		var ev FilterEvent
		if err := dec.Decode(&ev); err != nil {
			stream.Close()
			return nil, err
		}
		if ev.Error != "" {
			stream.Close()
			return nil, errors.New(ev.Error)
		}
		if ev.Ready {
			break
		}
	}

	out := make(chan StoredMessage, 32)
	go func() {
		defer close(out)
		defer stream.Close()
		for {
			var ev FilterEvent
			if err := dec.Decode(&ev); err != nil {
				return
			}
			if ev.Message != nil {
				out <- *ev.Message
			}
		}
	}()
	return out, nil
}
