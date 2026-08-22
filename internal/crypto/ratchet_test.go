package crypto

import "testing"

// THE GATE from lesson 0027: two chains from one seed, 100 identical keys,
// zero bytes transmitted between them.
func TestChainsAgree(t *testing.T) {
	seed := [32]byte{1, 2, 3}

	alice, err := NewChain(seed)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewChain(seed)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		aKey, aN, err := alice.Next()
		if err != nil {
			t.Fatal(err)
		}
		bKey, bN, err := bob.Next()
		if err != nil {
			t.Fatal(err)
		}

		if aKey != bKey {
			t.Fatalf("message %d: keys differ", i)
		}
		if aN != bN || aN != uint32(i) {
			t.Fatalf("message %d: counters wrong (%d, %d)", i, aN, bN)
		}
	}
}

// Every message key must be distinct. If the chain ever repeats a key, the
// zero-nonce encryption above becomes catastrophically broken.
func TestChainKeysAllDistinct(t *testing.T) {
	c, _ := NewChain([32]byte{9})
	seen := make(map[[32]byte]int)

	for i := 0; i < 500; i++ {
		k, _, err := c.Next()
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[k]; dup {
			t.Fatalf("key repeated at %d and %d", prev, i)
		}
		seen[k] = i
	}
}

// Different seeds must not converge.
func TestChainsFromDifferentSeedsDiffer(t *testing.T) {
	a, _ := NewChain([32]byte{1})
	b, _ := NewChain([32]byte{2})

	aKey, _, _ := a.Next()
	bKey, _, _ := b.Next()

	if aKey == bKey {
		t.Fatal("different seeds produced the same message key")
	}
}

// The chain key must actually change. If Next() failed to overwrite it, every
// message key would be identical -- and TestChainsAgree would still pass.
func TestChainKeyAdvances(t *testing.T) {
	c, _ := NewChain([32]byte{7})
	before := c.Key
	c.Next()
	if c.Key == before {
		t.Fatal("chain key did not advance; forward secrecy is absent")
	}
}

// End to end: derive a key from the chain, encrypt, decrypt on the other side.
func TestEncryptDecryptWithChainKey(t *testing.T) {
	seed := [32]byte{42}
	sender, _ := NewChain(seed)
	receiver, _ := NewChain(seed)

	plaintext := []byte("node B cannot read this")
	ad := []byte("chat-room")

	sKey, _, _ := sender.Next()
	ct, err := Encrypt(sKey, plaintext, ad)
	if err != nil {
		t.Fatal(err)
	}
	if string(ct) == string(plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	rKey, _, _ := receiver.Next()
	pt, err := Decrypt(rKey, ct, ad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("got %q", pt)
	}
}

// Tampering must be detected, not silently decrypted into garbage.
func TestTamperedCiphertextFails(t *testing.T) {
	c, _ := NewChain([32]byte{5})
	k, _, _ := c.Next()

	ct, _ := Encrypt(k, []byte("transfer 10"), []byte("chat-room"))
	ct[3] ^= 0xFF // flip some bits in transit

	d, _ := NewChain([32]byte{5})
	rk, _, _ := d.Next()
	if _, err := Decrypt(rk, ct, []byte("chat-room")); err == nil {
		t.Fatal("tampered ciphertext decrypted successfully")
	}
}

// Wrong associated data must fail too -- this is what stops an attacker
// replaying a message into a different topic.
func TestWrongADFails(t *testing.T) {
	c, _ := NewChain([32]byte{6})
	k, _, _ := c.Next()
	ct, _ := Encrypt(k, []byte("hello"), []byte("chat-room"))

	d, _ := NewChain([32]byte{6})
	rk, _, _ := d.Next()
	if _, err := Decrypt(rk, ct, []byte("other-room")); err == nil {
		t.Fatal("decrypted under the wrong associated data")
	}
}
