package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateKeyPair creates a new X25519 key pair from the OS random source.
// The private key is just 32 random bytes. There is no cleverness to it: the
// security comes from the size of the space (2^256), not from structure.
func GenerateKeyPair() (KeyPair, error) {
	var kp KeyPair

	// crypto/rand, never math/rand. math/rand is seeded predictably and wou
	// make every key on the network guessable.
	if _, err := io.ReadFull(rand.Reader, kp.Private[:]); err != nil {
		return KeyPair{}, err
	}

	// Public = Private * Basepoint on Curve25519. Basepoint is a fixed publ
	// constant that everyone in the world uses, which is what makes two
	// independently generated public keys comparable at all.
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}

	// X25519 returns a []byte; copy it into the fixed-size field.
	copy(kp.Public[:], pub)
	return kp, nil
}

// DH performs the Diffie-Hellman operation: my private key against their
// public key.
//
// The property that makes this useful:
//
//	DH(alice.Private, bob.Public) == DH(bob.Private, alice.Public)
//
// Both sides compute the same 32 bytes, and that value was never transmitted.
// An eavesdropper who saw both public keys cannot compute it.
func DH(myPriv [32]byte, theirPub [32]byte) ([32]byte, error) {
	var shared [32]byte

	secret, err := curve25519.X25519(myPriv[:], theirPub[:])
	if err != nil {
		// X25519 returns an error for low-order points: a hostile peer
		// a crafted public key that forces the shared secret to a known
		// Rejecting here is the defence, so this error must never be sw
		return shared, err
	}

	copy(shared[:], secret)
	return shared, nil
}

// kdf expands a secret into `outputs` independent 32-byte keys.
//
// Why more than one output: the ratchet needs TWO keys from a single input --
// the next chain key and this message's key -- and they must be independent.
// Reading 64 bytes from one HKDF stream gives exactly that: knowing the second
// 32 bytes tells you nothing about the first.
//
// `info` is a domain separator. The same secret with info "chain" and info
// "message" produces unrelated keys. Reusing one info string for different
// purposes collapses that separation, so every call site passes its own.
func KDF(secret []byte, info string, outputs int) ([][32]byte, error) {
	// salt is nil: our inputs are already uniformly random (DH output or a
	// previous KDF output), which is the case where HKDF's salt adds nothin
	r := hkdf.New(sha256.New, secret, nil, []byte(info))

	keys := make([][32]byte, outputs)
	for i := range keys {
		// io.ReadFull, not r.Read. A bare Read may return fewer bytes t
		// buffer length, and a short read here means a key with predict
		// zero bytes at the end.
		if _, err := io.ReadFull(r, keys[i][:]); err != nil {
			return nil, err
		}
	}
	return keys, nil
}
