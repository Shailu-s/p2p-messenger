package crypto

import (
	"bytes"
	"testing"
)

// TestDHAgreement is the property the whole protocol rests on: two parties
// reach the same secret from opposite directions, having sent only public keys.
func TestDHAgreement(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("alice keygen: %v", err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("bob keygen: %v", err)
	}

	fromAlice, err := DH(alice.Private, bob.Public)
	if err != nil {
		t.Fatalf("alice DH: %v", err)
	}
	fromBob, err := DH(bob.Private, alice.Public)
	if err != nil {
		t.Fatalf("bob DH: %v", err)
	}

	if fromAlice != fromBob {
		t.Fatal("DH disagreement: the two sides derived different secret")
	}

	// A shared secret of all zeros means the curve operation silently faile
	// Equality alone would still pass in that case, so check its explicitly.
	var zero [32]byte
	if fromAlice == zero {
		t.Fatal("shared secret is all zeros")
	}
}

// Two independent conversations must not collide.
func TestDHDistinctPairs(t *testing.T) {
	a, _ := GenerateKeyPair()
	b, _ := GenerateKeyPair()
	c, _ := GenerateKeyPair()

	ab, _ := DH(a.Private, b.Public)
	ac, _ := DH(a.Private, c.Public)

	if ab == ac {
		t.Fatal("different peers produced the same shared secret")
	}
}

func TestKDFDeterministic(t *testing.T) {
	secret := []byte("a shared secret from DH")

	first, err := KDF(secret, "chain", 2)
	if err != nil {
		t.Fatalf("kdf: %v", err)
	}
	second, err := KDF(secret, "chain", 2)
	if err != nil {
		t.Fatalf("kdf: %v", err)
	}

	// Both sides run this independently and must land on identical keys.
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("kdf not deterministic at output %d", i)
		}
	}

	// The two outputs of one call must be independent of each other.
	if first[0] == first[1] {
		t.Fatal("kdf returned the same key twice")
	}
}

func TestKDFDomainSeparation(t *testing.T) {
	secret := []byte("a shared secret from DH")

	chain, _ := KDF(secret, "chain", 1)
	msg, _ := KDF(secret, "message", 1)

	if chain[0] == msg[0] {
		t.Fatal("different info strings produced the same key")
	}
}

func TestKDFNoTrailingZeros(t *testing.T) {
	secret := []byte("a shared secret from DH")
	keys, _ := KDF(secret, "chain", 1)

	// Catches a short read: the tail of the key silently left unwritten.
	if bytes.Equal(keys[0][24:], make([]byte, 8)) {
		t.Fatal("key ends in zeros, suspect a short read")
	}
}
