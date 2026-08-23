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

// GenerateKeyPair creates an X25519 key pair from the OS random source.
// The private key is 32 random bytes; its security comes from the size of the
// space, not from any structure.
func GenerateKeyPair() (KeyPair, error) {
	var kp KeyPair

	// crypto/rand, never math/rand: math/rand is predictably seeded, which
	// would make every key on the network guessable.
	if _, err := io.ReadFull(rand.Reader, kp.Private[:]); err != nil {
		return KeyPair{}, err
	}

	// Public = Private * Basepoint. Basepoint is a fixed public constant
	// shared by every X25519 implementation, which is what makes two
	// independently generated public keys usable together.
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}

	copy(kp.Public[:], pub)
	return kp, nil
}

// DH performs the Diffie-Hellman operation: my private key against their
// public key. Both sides arrive at the same 32 bytes without ever
// transmitting them:
//
//	DH(alice.Private, bob.Public) == DH(bob.Private, alice.Public)
//
// An eavesdropper who saw both public keys cannot derive the result.
func DH(myPriv [32]byte, theirPub [32]byte) ([32]byte, error) {
	var shared [32]byte

	secret, err := curve25519.X25519(myPriv[:], theirPub[:])
	if err != nil {
		// X25519 rejects low-order points. A hostile peer can send a
		// crafted public key that forces the shared secret to a known
		// constant, so this error must never be swallowed.
		return shared, err
	}

	copy(shared[:], secret)
	return shared, nil
}

// KDF expands a secret into `outputs` independent 32-byte keys.
//
// The ratchet needs two keys from one input -- the next chain key and this
// message's key -- and they must be independent. Successive bytes of one HKDF
// stream give exactly that.
//
// info is a domain separator: the same secret under different info strings
// yields unrelated keys, so every call site passes its own.
func KDF(secret []byte, info string, outputs int) ([][32]byte, error) {
	// salt is nil: the inputs are already uniformly random (a DH output or a
	// previous KDF output), the case where HKDF's salt adds nothing.
	r := hkdf.New(sha256.New, secret, nil, []byte(info))

	keys := make([][32]byte, outputs)
	for i := range keys {
		// io.ReadFull, not r.Read: a short read would leave predictable
		// zero bytes at the end of a key.
		if _, err := io.ReadFull(r, keys[i][:]); err != nil {
			return nil, err
		}
	}
	return keys, nil
}
