package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestDemoEavesdropper is a narrated walkthrough, not really a unit test.
// Run it with:
//
//	go test -v -run TestDemoEavesdropper
//
// It shows what a store node (or anyone on the wire) actually sees.
func TestDemoEavesdropper(t *testing.T) {
	a, b := pair(t)

	fmt.Println("\n=== Alice sends three messages ===")

	msgs := []string{
		"my seed phrase is witch collapse practice",
		"transfer 500 to account 9912",
		"see you at 6",
	}

	wires := make([][]byte, len(msgs))
	for i, m := range msgs {
		w, err := a.EncryptMessage([]byte(m))
		if err != nil {
			t.Fatal(err)
		}
		wires[i] = w

		var env Envelope
		json.Unmarshal(w, &env)

		fmt.Printf("\n  plaintext : %q\n", m)
		fmt.Printf("  on wire   : %x...\n", env.Ciphertext[:24])
		fmt.Printf("  header    : N=%d PN=%d dh=%x...\n",
			env.Header.N, env.Header.PN, env.Header.DHPublic[:8])
	}

	fmt.Println("\n=== What node B stores (it is NOT the recipient) ===")
	fmt.Println("  B holds the bytes above. No key, no plaintext, ever.")

	fmt.Println("\n=== Bob decrypts ===")
	for i, w := range wires {
		pt, err := b.DecryptMessage(w)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		fmt.Printf("  %q\n", pt)
		if string(pt) != msgs[i] {
			t.Fatalf("mismatch at %d", i)
		}
	}

	fmt.Println("\n=== An attacker who steals ONE message key ===")
	// Simulate: attacker obtains the message key for message 0 only.
	fresh1, fresh2 := pair(t)
	w0, _ := fresh1.EncryptMessage([]byte("message zero"))
	w1, _ := fresh1.EncryptMessage([]byte("message one"))

	// The attacker somehow learns key 0 by decrypting normally.
	if _, err := fresh2.DecryptMessage(w0); err != nil {
		t.Fatal(err)
	}
	fmt.Println("  stole the key for message 0 -> can read message 0")
	fmt.Println("  message 1 uses a completely different key, derived forward.")

	if _, err := fresh2.DecryptMessage(w1); err != nil {
		t.Fatal(err)
	}
	fmt.Println("  (Bob reads it with HIS chain; the attacker's stolen key does not.)")

	fmt.Println("\n=== Replay attack ===")
	if _, err := b.DecryptMessage(wires[0]); err != nil {
		fmt.Println("  replaying message 0 -> REJECTED:", err)
	} else {
		t.Fatal("replay succeeded, which is a bug")
	}

	fmt.Println("\n=== Tampering ===")
	var env Envelope
	json.Unmarshal(wires[1], &env)
	env.Ciphertext[5] ^= 0xFF
	bad, _ := json.Marshal(env)
	if _, err := b.DecryptMessage(bad); err != nil {
		fmt.Println("  flipped one bit -> REJECTED:", err)
	} else {
		t.Fatal("tampered message accepted, which is a bug")
	}
	fmt.Println()
}
