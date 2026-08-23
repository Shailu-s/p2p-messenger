package node

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2pchat/internal/crypto"
)

func managersWithKeys(t *testing.T) (*SessionManager, *SessionManager, peerIDs) {
	t.Helper()

	ids := testPeerIDsWithAliceInitiator(t)
	aliceKey, _ := crypto.GenerateKeyPair()
	bobKey, _ := crypto.GenerateKeyPair()
	carolKey, _ := crypto.GenerateKeyPair()

	alice := NewSessionManager(aliceKey, ids.alice)
	bob := NewSessionManager(bobKey, ids.bob)
	carol := NewSessionManager(carolKey, ids.carol)

	alice.LearnKey(ids.bob, bobKey.Public)
	alice.LearnKey(ids.carol, carolKey.Public)
	bob.LearnKey(ids.alice, aliceKey.Public)
	carol.LearnKey(ids.alice, aliceKey.Public)

	_ = carol
	return alice, bob, ids
}

type peerIDs struct {
	alice, bob, carol peer.ID
}

func testPeerIDsWithAliceInitiator(t *testing.T) peerIDs {
	t.Helper()

	for {
		ids := peerIDs{
			alice: testPeerID(t),
			bob:   testPeerID(t),
			carol: testPeerID(t),
		}
		if ids.alice.String() < ids.bob.String() {
			return ids
		}
	}
}

func TestContentTopicIsPairwiseAndRecipientOpaque(t *testing.T) {
	alice, bob, ids := managersWithKeys(t)

	aliceTopic, err := alice.ContentTopic(ids.bob)
	if err != nil {
		t.Fatal(err)
	}
	bobTopic, err := bob.ContentTopic(ids.alice)
	if err != nil {
		t.Fatal(err)
	}
	if aliceTopic != bobTopic {
		t.Fatalf("topics differ: %q != %q", aliceTopic, bobTopic)
	}

	wire, err := alice.EncryptTo(ids.bob, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte(ids.bob.String())) {
		t.Fatal("outer envelope leaked recipient peer ID")
	}
	if topic, ok := EnvelopeContentTopic(wire); !ok || topic != aliceTopic {
		t.Fatalf("topic = %q ok=%v", topic, ok)
	}
}

func TestNonRecipientIgnoresDifferentContentTopic(t *testing.T) {
	alice, bob, ids := managersWithKeys(t)
	carolKey, _ := crypto.GenerateKeyPair()
	carol := NewSessionManager(carolKey, ids.carol)
	carol.LearnKey(ids.alice, alice.self.Public)

	wire, err := alice.EncryptTo(ids.bob, []byte("hello bob"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, ok := bob.TryDecrypt(wire); !ok || string(pt) != "hello bob" {
		t.Fatalf("bob decrypt = %q ok=%v", pt, ok)
	}
	if pt, ok := carol.TryDecrypt(wire); ok || pt != nil {
		t.Fatalf("carol decrypt = %q ok=%v, want ignored", pt, ok)
	}
}
