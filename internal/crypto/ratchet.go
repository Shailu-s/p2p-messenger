package crypto

import "golang.org/x/crypto/chacha20poly1305"

// Chain is one direction of a conversation: a sequence of message keys derived
// from a single seed, none of which is ever transmitted.
//
// Alice's sending chain and Bob's receiving chain start from the same seed, so
// they produce the same keys in the same order with no per-message exchange.
type Chain struct {
	// Key is the current chain key, overwritten on every Next call. That
	// deletion is half of forward secrecy; the one-way KDF is the other
	// half. Both are required.
	Key [32]byte

	// N counts the message keys produced so far. It travels with each
	// message so the receiver knows how far to advance when messages arrive
	// out of order or are lost.
	N uint32
}

// NewChain starts a chain from a secret, normally a DH output.
//
// The seed goes through the KDF rather than being used directly, so the raw DH
// output never doubles as a working key: a leaked chain key reveals nothing
// about the secret that produced it.
func NewChain(seed [32]byte) (*Chain, error) {
	keys, err := KDF(seed[:], "chain-init", 1)
	if err != nil {
		return nil, err
	}
	return &Chain{Key: keys[0], N: 0}, nil
}

// Next advances the chain one step and returns this position's message key
// and its index.
//
// The ratchet turns one way only: after Next returns, the previous chain key
// no longer exists in the process and the KDF cannot be run backwards.
func (c *Chain) Next() ([32]byte, uint32, error) {
	// One KDF call, two independent outputs:
	//   keys[0] -> the next chain key (seeds the rest of the chain)
	//   keys[1] -> this message's key (a dead end, used once)
	// Leaking the message key therefore does not expose the chain.
	keys, err := KDF(c.Key[:], "chain-step", 2)
	if err != nil {
		return [32]byte{}, 0, err
	}

	n := c.N

	// This assignment is the deletion: after it, the key that produced this
	// message key is unrecoverable. Copying c.Key anywhere above this line
	// would quietly destroy forward secrecy.
	c.Key = keys[0]
	c.N++

	return keys[1], n, nil
}

// Encrypt seals plaintext under a one-time message key.
//
// The nonce is all zeros. That is normally a serious bug, since reusing a
// nonce under one key breaks AEAD entirely, but every message here gets a
// fresh key from the ratchet, so the (key, nonce) pair never repeats. This
// safety comes from the ratchet and would be lost if a key were ever reused.
//
// ad is associated data: authenticated but not encrypted. Message headers go
// here so an attacker cannot alter the counter or sender key without
// decryption failing.
func Encrypt(key [32]byte, plaintext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

// Decrypt opens a ciphertext. It fails if the key is wrong, the ciphertext was
// tampered with, or the associated data does not match. There is no partial
// success: without the right key, not one byte is readable.
func Decrypt(key [32]byte, ciphertext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Open(nil, nonce, ciphertext, ad)
}
