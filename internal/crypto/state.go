package crypto

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"

	"p2pchat/internal/fsatomic"
)

type encryptedState struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func LoadOrCreateStateKey(path string) ([32]byte, error) {
	var key [32]byte

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
			return key, err
		}
		if err := fsatomic.WriteFile(path, key[:], 0o600); err != nil {
			return key, err
		}
		return key, nil
	}
	if err != nil {
		return key, err
	}
	if len(data) != len(key) {
		return key, errors.New("bad state key length")
	}
	copy(key[:], data)
	return key, nil
}

func SealState(key [32]byte, plaintext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	disk := encryptedState{
		Version:    1,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, ad),
	}
	return json.MarshalIndent(disk, "", "  ")
}

func OpenState(key [32]byte, data, ad []byte) ([]byte, error) {
	var disk encryptedState
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	if len(disk.Nonce) != aead.NonceSize() {
		return nil, errors.New("bad state nonce length")
	}
	return aead.Open(nil, disk.Nonce, disk.Ciphertext, ad)
}
