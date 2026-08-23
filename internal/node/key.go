package node

import (
	"crypto/rand"
	"os"

	"github.com/libp2p/go-libp2p/core/crypto"
)

func LoadOrCreateKey(path string) (crypto.PrivKey, error) {
	// try to read an existing key
	data, err := os.ReadFile(path)
	if err == nil {
		return crypto.UnmarshalPrivateKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, err // a real error, not just "no file yet"
	}

	// no key on disk: make one and save it
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}
	data, err = crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	return priv, nil
}
