package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type StoredMessage struct {
	Seq       uint64 `json:"seq"`
	ID        string `json:"id"` // sha256 of the payload
	Topic     string `json:"topic"`
	Timestamp int64  `json:"timestamp"` // when WE received it, not sender-supplied
	Payload   []byte `json:"payload"`   // ciphertext bytes; relays do not decrypt
}

type Store struct {
	mu          sync.Mutex
	byID        map[string]StoredMessage // dedup
	ordered     []StoredMessage          // query order
	maxItems    int
	nextSeq     uint64
	path        string
	nextSubID   uint64
	subscribers map[uint64]storeSubscriber
}

type storeSubscriber struct {
	topics map[string]bool
	ch     chan StoredMessage
}

type StoreResponse struct {
	Messages   []StoredMessage `json:"messages"`
	NextCursor string          `json:"nextCursor"`
	Error      string          `json:"error,omitempty"`
}

type StoreQuery struct {
	Topic  string `json:"topic"`
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit"`
}

type storeDiskState struct {
	Version  int             `json:"version"`
	NextSeq  uint64          `json:"nextSeq"`
	Messages []StoredMessage `json:"messages"`
}

type storeCursor struct {
	Seq uint64 `json:"seq"`
}

func NewStore(maxItems int) *Store {
	return &Store{
		byID:        make(map[string]StoredMessage),
		ordered:     make([]StoredMessage, 0, maxItems),
		maxItems:    maxItems,
		nextSeq:     1,
		subscribers: make(map[uint64]storeSubscriber),
	}
}

func OpenStore(path string, maxItems int) (*Store, error) {
	s := NewStore(maxItems)
	s.path = path

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}

	var disk storeDiskState
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, err
	}

	for _, m := range disk.Messages {
		if m.Seq == 0 {
			m.Seq = s.nextSeq
		}
		if m.Seq >= s.nextSeq {
			s.nextSeq = m.Seq + 1
		}
		if _, seen := s.byID[m.ID]; seen {
			continue
		}
		s.byID[m.ID] = m
		s.ordered = append(s.ordered, m)
	}
	if disk.NextSeq > s.nextSeq {
		s.nextSeq = disk.NextSeq
	}
	s.evictLocked()
	return s, nil
}

func MessageID(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// Put stores a message. Returns false if we already had it.
func (s *Store) Put(m StoredMessage) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, seen := s.byID[m.ID]; seen {
		return false, nil
	}
	if m.Timestamp == 0 {
		m.Timestamp = time.Now().UnixMilli()
	}
	m.Seq = s.nextSeq
	s.nextSeq++

	s.byID[m.ID] = m
	s.ordered = append(s.ordered, m)
	s.evictLocked()

	if err := s.saveLocked(); err != nil {
		return false, err
	}
	s.notifyLocked(m)
	return true, nil
}

func (s *Store) evictLocked() {
	for len(s.ordered) > s.maxItems {
		oldest := s.ordered[0]
		s.ordered = s.ordered[1:]
		delete(s.byID, oldest.ID)
	}
}

func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ordered)
}

// Query returns stored messages after the opaque cursor, oldest first.
func (s *Store) Query(q StoreQuery) (StoreResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	after, err := decodeStoreCursor(q.Cursor)
	if err != nil {
		return StoreResponse{}, err
	}
	limit := q.Limit
	if limit <= 0 || limit > 100 {
		limit = 100
	}

	out := make([]StoredMessage, 0)
	lastSeq := after
	for _, m := range s.ordered {
		if m.Topic != q.Topic {
			continue
		}
		if m.Seq <= after {
			continue
		}
		out = append(out, m)
		lastSeq = m.Seq
		if len(out) >= limit {
			break
		}
	}
	return StoreResponse{
		Messages:   out,
		NextCursor: encodeStoreCursor(lastSeq),
	}, nil
}

func (s *Store) Subscribe(topics []string) (<-chan StoredMessage, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextSubID++
	id := s.nextSubID
	sub := storeSubscriber{
		topics: topicSet(topics),
		ch:     make(chan StoredMessage, 32),
	}
	s.subscribers[id] = sub

	cancel := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if existing, ok := s.subscribers[id]; ok {
			delete(s.subscribers, id)
			close(existing.ch)
		}
	}
	return sub.ch, cancel
}

func (s *Store) Recent(topics []string, limit int) []StoredMessage {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || limit > 100 {
		limit = 100
	}
	filter := topicSet(topics)
	out := make([]StoredMessage, 0, limit)
	for i := len(s.ordered) - 1; i >= 0 && len(out) < limit; i-- {
		m := s.ordered[i]
		if !topicMatches(filter, m.Topic) {
			continue
		}
		out = append(out, m)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *Store) notifyLocked(m StoredMessage) {
	for _, sub := range s.subscribers {
		if !topicMatches(sub.topics, m.Topic) {
			continue
		}
		select {
		case sub.ch <- m:
		default:
		}
	}
}

func topicSet(topics []string) map[string]bool {
	if len(topics) == 0 {
		return nil
	}
	set := make(map[string]bool, len(topics))
	for _, topic := range topics {
		if topic != "" {
			set[topic] = true
		}
	}
	return set
}

func topicMatches(topics map[string]bool, topic string) bool {
	return len(topics) == 0 || topics[topic]
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	disk := storeDiskState{
		Version:  1,
		NextSeq:  s.nextSeq,
		Messages: s.ordered,
	}
	data, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, data, 0o600)
}

func encodeStoreCursor(seq uint64) string {
	data, _ := json.Marshal(storeCursor{Seq: seq})
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeStoreCursor(token string) (uint64, error) {
	if token == "" {
		return 0, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, err
	}
	var c storeCursor
	if err := json.Unmarshal(data, &c); err != nil {
		return 0, err
	}
	return c.Seq, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
