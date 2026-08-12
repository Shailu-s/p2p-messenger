package main

import (
	"encoding/hex"
	"os"
	"strings"
)

// The libp2p host identity is an Ed25519 key, used for SIGNING -- proving who
// sent a stream. The ratchet needs an X25519 key, used for DIFFIE-HELLMAN --
// agreeing on a secret. Different jobs, different curves.
//
// There is a standard conversion between the two (they share an underlying
// curve), but keeping a separate file is clearer and avoids using one key for
// two purposes, which is a rule worth following by default.

// loadOrCreateIdentity returns this node's long-term X25519 key pair, creating
// and persisting it on first run.
//
// "Long-term" matters: this key is the anchor a peer uses to start a session
// with us. The per-message ratchet keys are ephemeral and never touch disk;
// only this one is stable across restarts.
func loadOrCreateIdentity(path string) (KeyPair, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var kp KeyPair
		raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err != nil || len(raw) != 32 {
			return KeyPair{}, err
		}
		copy(kp.Private[:], raw)

		// Recompute the public key rather than storing it: one source of
		// truth, and no way for the file to hold a mismatched pair.
		pub, err := DH(kp.Private, basepoint())
		if err != nil {
			return KeyPair{}, err
		}
		kp.Public = pub
		return kp, nil
	}
	if !os.IsNotExist(err) {
		return KeyPair{}, err
	}

	kp, err := GenerateKeyPair()
	if err != nil {
		return KeyPair{}, err
	}

	// 0600: this file IS the node's cryptographic identity. Anyone who can
	// read it can impersonate this node and start sessions as us.
	if err := os.WriteFile(path, []byte(hex.EncodeToString(kp.Private[:])), 0600); err != nil {
		return KeyPair{}, err
	}
	return kp, nil
}

// basepoint returns the Curve25519 generator as a [32]byte, so we can reuse
// DH() to derive a public key from a private one.
func basepoint() [32]byte {
	var b [32]byte
	b[0] = 9 // the Curve25519 basepoint is simply u = 9
	return b
}
