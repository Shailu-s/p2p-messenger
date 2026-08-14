package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func testPeerID(t *testing.T) peer.ID {
	t.Helper()

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func persistentManager(t *testing.T, dir string, id peer.ID, self KeyPair) *SessionManager {
	t.Helper()

	m, err := OpenSessionManager(
		self,
		id,
		filepath.Join(dir, id.String()+".sessions.enc"),
		filepath.Join(dir, id.String()+".state.key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSessionManagerPersistsRatchetStateAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	ids := testPeerIDsWithAliceInitiator(t)
	aliceID := ids.alice
	bobID := ids.bob
	aliceKey, _ := GenerateKeyPair()
	bobKey, _ := GenerateKeyPair()

	alice := persistentManager(t, dir, aliceID, aliceKey)
	bob := persistentManager(t, dir, bobID, bobKey)
	alice.LearnKey(bobID, bobKey.Public)
	bob.LearnKey(aliceID, aliceKey.Public)

	first, err := alice.EncryptTo(bobID, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, ok := bob.TryDecrypt(first); !ok || string(pt) != "one" {
		t.Fatalf("first decrypt = %q ok=%v", pt, ok)
	}

	second, err := alice.EncryptTo(bobID, []byte("two"))
	if err != nil {
		t.Fatal(err)
	}

	restartedBob := persistentManager(t, dir, bobID, bobKey)
	pt, ok := restartedBob.TryDecrypt(second)
	if !ok || string(pt) != "two" {
		t.Fatalf("after restart decrypt = %q ok=%v", pt, ok)
	}
}

func TestSessionManagerStateFileIsEncrypted(t *testing.T) {
	dir := t.TempDir()
	ids := testPeerIDsWithAliceInitiator(t)
	aliceID := ids.alice
	bobID := ids.bob
	aliceKey, _ := GenerateKeyPair()
	bobKey, _ := GenerateKeyPair()

	alice := persistentManager(t, dir, aliceID, aliceKey)
	alice.LearnKey(bobID, bobKey.Public)
	if _, err := alice.EncryptTo(bobID, []byte("secret plaintext")); err != nil {
		t.Fatal(err)
	}

	data := readTestFile(t, filepath.Join(dir, aliceID.String()+".sessions.enc"))
	if bytes.Contains(data, []byte("secret plaintext")) {
		t.Fatal("session state file contains plaintext message")
	}
	if bytes.Contains(data, bobKey.Public[:]) {
		t.Fatal("session state file contains raw peer key")
	}
}

func TestHigherPeerIDCanSendFirst(t *testing.T) {
	ids := testPeerIDsWithAliceAfterBob(t)
	aliceKey, _ := GenerateKeyPair()
	bobKey, _ := GenerateKeyPair()
	alice := NewSessionManager(aliceKey, ids.alice)
	bob := NewSessionManager(bobKey, ids.bob)
	alice.LearnKey(ids.bob, bobKey.Public)
	bob.LearnKey(ids.alice, aliceKey.Public)

	wire, err := alice.EncryptTo(ids.bob, []byte("alice sends first"))
	if err != nil {
		t.Fatal(err)
	}
	pt, ok := bob.TryDecrypt(wire)
	if !ok || string(pt) != "alice sends first" {
		t.Fatalf("decrypt = %q ok=%v", pt, ok)
	}
}

func testPeerIDsWithAliceAfterBob(t *testing.T) peerIDs {
	t.Helper()

	for {
		ids := peerIDs{
			alice: testPeerID(t),
			bob:   testPeerID(t),
			carol: testPeerID(t),
		}
		if ids.alice.String() > ids.bob.String() {
			return ids
		}
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
