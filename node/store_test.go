package main

import (
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

func stored(topic, payload string) StoredMessage {
	return StoredMessage{
		ID:      MessageID([]byte(payload)),
		Topic:   topic,
		Payload: []byte(payload),
	}
}

func TestStorePersistsMessages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")

	s, err := OpenStore(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Put(stored("chat", "one")); err != nil || !ok {
		t.Fatalf("put one: ok=%v err=%v", ok, err)
	}
	if ok, err := s.Put(stored("chat", "two")); err != nil || !ok {
		t.Fatalf("put two: ok=%v err=%v", ok, err)
	}

	reopened, err := OpenStore(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Count() != 2 {
		t.Fatalf("count after reopen = %d, want 2", reopened.Count())
	}

	resp, err := reopened.Query(StoreQuery{Topic: "chat", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(resp.Messages[0].Payload); got != "one" {
		t.Fatalf("first payload = %q", got)
	}
}

func TestStoreCursorResumesWithoutTimestamp(t *testing.T) {
	s := NewStore(100)

	for _, payload := range []string{"one", "two", "three"} {
		m := stored("chat", payload)
		m.Timestamp = 100
		if ok, err := s.Put(m); err != nil || !ok {
			t.Fatalf("put %s: ok=%v err=%v", payload, ok, err)
		}
	}

	first, err := s.Query(StoreQuery{Topic: "chat", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Messages) != 2 {
		t.Fatalf("first page len = %d, want 2", len(first.Messages))
	}

	second, err := s.Query(StoreQuery{Topic: "chat", Cursor: first.NextCursor, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Messages) != 1 {
		t.Fatalf("second page len = %d, want 1", len(second.Messages))
	}
	if got := string(second.Messages[0].Payload); got != "three" {
		t.Fatalf("second page payload = %q", got)
	}

	third, err := s.Query(StoreQuery{Topic: "chat", Cursor: second.NextCursor, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(third.Messages) != 0 {
		t.Fatalf("third page len = %d, want 0", len(third.Messages))
	}
}

func TestStoreAssignsLocalSequenceForFetchedMessages(t *testing.T) {
	s := NewStore(100)

	m := stored("chat", "from remote")
	m.Seq = 99
	if ok, err := s.Put(m); err != nil || !ok {
		t.Fatalf("put: ok=%v err=%v", ok, err)
	}

	resp, err := s.Query(StoreQuery{Topic: "chat", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Messages[0].Seq != 1 {
		t.Fatalf("stored seq = %d, want local seq 1", resp.Messages[0].Seq)
	}
}

func TestCursorBookPersistsPerPeerAndTopic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cursors.json")
	p1 := peer.ID("peer-one")
	p2 := peer.ID("peer-two")

	book, err := OpenCursorBook(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := book.Update(p1, "topic-a", "cursor-a"); err != nil {
		t.Fatal(err)
	}
	if err := book.Update(p1, "topic-b", "cursor-b"); err != nil {
		t.Fatal(err)
	}
	if err := book.Update(p2, "topic-a", "cursor-c"); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenCursorBook(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Cursor(p1, "topic-a"); got != "cursor-a" {
		t.Fatalf("p1/topic-a = %q", got)
	}
	if got := reopened.Cursor(p1, "topic-b"); got != "cursor-b" {
		t.Fatalf("p1/topic-b = %q", got)
	}
	if got := reopened.Cursor(p2, "topic-a"); got != "cursor-c" {
		t.Fatalf("p2/topic-a = %q", got)
	}
}
