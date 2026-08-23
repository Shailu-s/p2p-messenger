package store

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2pchat/internal/fsatomic"
)

type CursorBook struct {
	mu    sync.Mutex
	path  string
	peers map[string]map[string]string
}

type cursorBookDisk struct {
	Version int                          `json:"version"`
	Peers   map[string]map[string]string `json:"peers"`
}

func OpenCursorBook(path string) (*CursorBook, error) {
	b := &CursorBook{
		path:  path,
		peers: make(map[string]map[string]string),
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return b, nil
	}
	if err != nil {
		return nil, err
	}

	var disk cursorBookDisk
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, err
	}
	if disk.Peers != nil {
		b.peers = disk.Peers
	}
	return b, nil
}

func (b *CursorBook) Cursor(p peer.ID, topic string) string {
	b.mu.Lock()
	defer b.mu.Unlock()

	byTopic := b.peers[p.String()]
	if byTopic == nil {
		return ""
	}
	return byTopic[topic]
}

func (b *CursorBook) Update(p peer.ID, topic, cursor string) error {
	if cursor == "" {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	key := p.String()
	if b.peers[key] == nil {
		b.peers[key] = make(map[string]string)
	}
	if b.peers[key][topic] == cursor {
		return nil
	}
	b.peers[key][topic] = cursor

	data, err := json.MarshalIndent(cursorBookDisk{
		Version: 1,
		Peers:   b.peers,
	}, "", "  ")
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(b.path, data, 0o600)
}
