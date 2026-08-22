package node

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2pchat/internal/store"
)

func testHost(t *testing.T) host.Host {
	t.Helper()

	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func connectHosts(t *testing.T, ctx context.Context, from, to host.Host) {
	t.Helper()

	if err := from.Connect(ctx, peer.AddrInfo{ID: to.ID(), Addrs: to.Addrs()}); err != nil {
		t.Fatal(err)
	}
}

func TestFilterProtocolSelectedTopicVsAllTopics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	full := testHost(t)
	selectedLight := testHost(t)
	allLight := testHost(t)
	store := store.NewStore(100)
	RegisterFilterServer(full, store)

	connectHosts(t, ctx, selectedLight, full)
	connectHosts(t, ctx, allLight, full)

	selected, err := SubscribeFilter(ctx, selectedLight, full.ID(), FilterRequest{Topics: []string{"topic-a"}})
	if err != nil {
		t.Fatal(err)
	}
	all, err := SubscribeFilter(ctx, allLight, full.ID(), FilterRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}

	putTestMessage(t, store, "topic-a", "a")
	putTestMessage(t, store, "topic-b", "b")

	if got := receiveMessage(t, selected); got.Topic != "topic-a" {
		t.Fatalf("selected light got topic %q", got.Topic)
	}
	assertNoMessage(t, selected)

	first := receiveMessage(t, all)
	second := receiveMessage(t, all)
	if first.Topic != "topic-a" || second.Topic != "topic-b" {
		t.Fatalf("all light got topics %q, %q", first.Topic, second.Topic)
	}
}

func TestFilterProtocolRejectsEmptySelectedTopics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	full := testHost(t)
	light := testHost(t)
	RegisterFilterServer(full, store.NewStore(100))
	connectHosts(t, ctx, light, full)

	if _, err := SubscribeFilter(ctx, light, full.ID(), FilterRequest{}); err == nil {
		t.Fatal("empty selected-topic request succeeded")
	}
}

func putTestMessage(t *testing.T, s *store.Store, topic, payload string) {
	t.Helper()

	ok, err := s.Put(store.StoredMessage{
		ID:      store.MessageID([]byte(payload)),
		Topic:   topic,
		Payload: []byte(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("duplicate test payload %q", payload)
	}
}

func receiveMessage(t *testing.T, ch <-chan store.StoredMessage) store.StoredMessage {
	t.Helper()

	select {
	case m := <-ch:
		return m
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for filter message")
		return store.StoredMessage{}
	}
}

func assertNoMessage(t *testing.T, ch <-chan store.StoredMessage) {
	t.Helper()

	select {
	case m := <-ch:
		t.Fatalf("unexpected filter message on topic %q", m.Topic)
	case <-time.After(100 * time.Millisecond):
	}
}
