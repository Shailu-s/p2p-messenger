package main

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

type StoredMessage struct {
	ID        string `json:"id"` // sha256 of the payload
	Topic     string `json:"topic"`
	Timestamp int64  `json:"timestamp"` // when WE received it, not sender-supplied
	Payload   []byte `json:"payload"`   // ciphertext later; plaintext for now
}

type Store struct {
	mu       sync.Mutex
	byID     map[string]StoredMessage // dedup
	ordered  []StoredMessage          // query order
	maxItems int
}

type StoreResponse struct {
	Messages []StoredMessage `json:"messages"`
}

type StoreQuery struct {
	Topic string `json:"topic"`
	Since int64  `json:"since"`
	Limit int    `json:"limit"`
}

func NewStore(maxItems int) *Store {
	return &Store{
		byID:     make(map[string]StoredMessage),
		ordered:  make([]StoredMessage, 0, maxItems),
		maxItems: maxItems,
	}
}

func MessageID(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// Put stores a message. Returns false if we already had it.
func (s *Store) Put(m StoredMessage) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, seen := s.byID[m.ID]; seen {
		return false
	}

	s.byID[m.ID] = m
	s.ordered = append(s.ordered, m)

	// evict oldest when over capacity
	if len(s.ordered) > s.maxItems {
		oldest := s.ordered[0]
		s.ordered = s.ordered[1:]
		delete(s.byID, oldest.ID)
	}
	return true
}

func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ordered)
}

// Query returns stored messages newer than `since`, oldest first.
func (s *Store) Query(q StoreQuery) []StoredMessage {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]StoredMessage, 0)
	for _, m := range s.ordered {
		if m.Topic != q.Topic {
			continue
		}
		if m.Timestamp <= q.Since {
			continue
		}
		out = append(out, m)
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	return out
}
