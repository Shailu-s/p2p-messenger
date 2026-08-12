package main

import (
	"encoding/json"
	"math/rand"
	"testing"
)

func pair(t *testing.T) (*Session, *Session) {
	t.Helper()

	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shared, err := DH(alice.Private, bob.Public)
	if err != nil {
		t.Fatal(err)
	}

	a, err := NewSessionInitiator(shared, bob.Public)
	if err != nil {
		t.Fatal(err)
	}
	return a, NewSessionResponder(shared, bob)
}

func TestSessionRoundTrip(t *testing.T) {
	a, b := pair(t)

	wire, err := a.EncryptMessage([]byte("hello bob"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := b.DecryptMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello bob" {
		t.Fatalf("got %q", pt)
	}
}

// A full conversation with replies -- this exece each
// reply carries a new ratchet public key.
func TestSessionBackAndForth(t *testing.T) {
	a, b := pair(t)

	for i := 0; i < 20; i++ {
		w, err := a.EncryptMessage([]byte("ping"))
		if err != nil {
			t.Fatalf("a encrypt %d: %v", i, err)
		}
		if pt, err := b.DecryptMessage(w); err != nil || string(pt) != "ping" {
			t.Fatalf("b decrypt %d: %v %q, want %q", i, err, string(pt), "ping")
		}

		w, err = b.EncryptMessage([]byte("pong"))
		if err != nil {
			t.Fatalf("b encrypt %d: %v", i, err)
		}
		if pt, err := a.DecryptMessage(w); err != nil || string(pt) != "pong" {
			t.Fatalf("a decrypt %d: %v %q, want %q", i, err, string(pt), "pong")
		}
	}
}

// THE PROPERTY TEST from the curriculum: encryl decrypt.
func TestOutOfOrderDelivery(t *testing.T) {
	a, b := pair(t)

	const n = 30
	wires := make([][]byte, n)
	for i := range wires {
		w, err := a.EncryptMessage([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		wires[i] = w
	}

	order := rand.Perm(n)
	got := make(map[byte]bool)
	for _, idx := range order {
		pt, err := b.DecryptMessage(wires[idx])
		if err != nil {
			t.Fatalf("message %d failed: %v", idx, err)
		}
		got[pt[0]] = true
	}
	if len(got) != n {
		t.Fatalf("decrypted %d distinct of %d", len(got), n)
	}
}

// Message 7 before message 5 -- the specific c.
func TestSkippedThenLateArrival(t *testing.T) {
	a, b := pair(t)

	wires := make([][]byte, 8)
	for i := range wires {
		wires[i], _ = a.EncryptMessage([]byte{byte(i)})
	}

	if _, err := b.DecryptMessage(wires[7]); err != nil {
		t.Fatalf("message 7: %v", err)
	}
	// 0..6 were skipped and cached; each must decrypt correctly
	for i := 0; i < 7; i++ {
		pt, err := b.DecryptMessage(wires[i])
		if err != nil {
			t.Fatalf("late message %d: %v", i, err)
		}
		if pt[0] != byte(i) {
			t.Fatalf("message %d decrypted as %d, want %d", i, pt[0], byte(i))
		}
	}
}

// A replayed message must not decrypt twice: tse.
func TestReplayFails(t *testing.T) {
	a, b := pair(t)

	w, _ := a.EncryptMessage([]byte("once"))
	if _, err := b.DecryptMessage(w); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DecryptMessage(w); err == nil {
		t.Fatal("replayed message decrypted a second time")
	}
}

// The DoS bound must actually fire.
func TestMaxSkipEnforced(t *testing.T) {
	a, b := pair(t)

	w, _ := a.EncryptMessage([]byte("first"))
	if _, err := b.DecryptMessage(w); err != nil {
		t.Fatal(err)
	}

	// Forge a header claiming a huge N. The DH key must match the one b is
	// already tracking, otherwise b takes the ratchet-step branch and the
	// skip check we are testing is never reached.
	var env Envelope
	env.Header = Header{DHPublic: b.remote, N: 3000000000, PN: 0}
	env.Ciphertext = []byte("garbage")
	wire, _ := json.Marshal(env)

	if _, err := b.DecryptMessage(wire); err == nil {
		t.Fatal("huge N was accepted; MaxSkip is not protecting us")
	}
}

// Tampering with the header must break decryption, since it is authenticated
// as associated data.
func TestHeaderTamperFails(t *testing.T) {
	a, b := pair(t)

	w, _ := a.EncryptMessage([]byte("hello"))

	var env Envelope
	if err := json.Unmarshal(w, &env); err != nil {
		t.Fatal(err)
	}
	env.Header.PN = 99 // attacker edits the header in transit
	tampered, _ := json.Marshal(env)

	if _, err := b.DecryptMessage(tampered); err == nil {
		t.Fatal("tampered header was accepted")
	}
}
