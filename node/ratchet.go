package main

import "golang.org/x/crypto/chacha20poly1305"

// Chain is one direction of a conversation: a sequence of message keys derived
// from a single seed, without transmitting any of them.
//
// Alice's sending chain and Bob's receiving chain start from the same seed and
// therefore produce the same keys in the same order. That is the whole trick --
// no coordination, no key exchange per message.
type Chain struct {
	// Key is the CURRENT chain key. It is overwritten on every Next() call
	// the old value is gone. That deletion is half of forward secrecy; the
	// one-way KDF is the other half. Both are required.
	Key [32]byte

	// N counts how many message keys this chain has produced so far. It tra
	// with each message on the wire so the receiver can tell how far to adv
	// when messages arrive out of order or get lost.
	N uint32
}

// NewChain starts a chain from a secret, normally the output of DH.
//
// The seed is passed through the KDF rather than used directly so that the raw
// DH output never doubles as a working key. If a chain key later leaks, it
// reveals nothing about the DH secret that produced it.
func NewChain(seed [32]byte) (*Chain, error) {
	keys, err := kdf(seed[:], "chain-init", 1)
	if err != nil {
		return nil, err
	}
	return &Chain{Key: keys[0], N: 0}, nil
}

// Next advances the chain one step and returns the message key for this
// position, along with the index that key belongs to.
//
// The name "ratchet" is literal: this only turns one way. Having called Next,
// the previous chain key no longer exists anywhere in the process, and the KDF
// cannot be run backwards to recover it.
func (c *Chain) Next() ([32]byte, uint32, error) {
	// One KDF call, two independent outputs:
	//   keys[0] -> the next chain key  (the seed for the rest of the chain)
	//   keys[1] -> this message's key  (a dead end, used once)
	// They are independent because HKDF output bytes reveal nothing about e
	// other, so leaking the message key does not expose the chain.
	keys, err := kdf(c.Key[:], "chain-step", 2)
	if err != nil {
		return [32]byte{}, 0, err
	}

	n := c.N

	// Overwrite the current chain key. This assignment IS the deletion: aft
	// it, the key that produced this message key is unrecoverable. Copying
	// c.Key somewhere before this line would quietly destroy forward secrec
	c.Key = keys[0]
	c.N++

	return keys[1], n, nil
}

// Encrypt seals plaintext under a one-time message key.
//
// The nonce is all zeros, which is normally a serious bug -- reusing a nonce
// under the same key breaks AEAD completely. It is safe here for one specific
// reason: every message gets a FRESH key from the ratchet, so the (key, nonce)
// pair is never repeated. The ratchet is what buys us this.
//
// `ad` is associated data: authenticated but not encrypted. Message headers go
// here, so an attacker cannot alter the counter or sender key without the
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
// tampered with, OR the associated data does not match -- there is no partial
// success and no way to read even one byte without the right key.
func Decrypt(key [32]byte, ciphertext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Open(nil, nonce, ciphertext, ad)
}
