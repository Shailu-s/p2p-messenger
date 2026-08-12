package main

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
)

// KeyAnnounce is broadcast on a separate topic so peers can learn each other's
// long-term X25519 keys.
//
// This is the crude stand-in for X3DH. The real protocol publishes a bundle of
// PREKEYS in advance, so Alice can start an encrypted conversation with Bob
// while Bob is offline -- the same shape as store-and-forward. Here both nodes
// must be online at the same time at least once. That gap is deliberate and
// worth naming rather than hiding.
type KeyAnnounce struct {
	PeerID    string   `json:"peer"`
	PublicKey [32]byte `json:"pk"`
}

// AddressedEnvelope is one ciphertext plus who it is for.
//
// Recipient is in the clear, which leaks the social graph: an observer learns
// who talks to whom, and when, even without reading content. Real systems fight
// this with sealed sender or per-topic addressing. We accept the leak and say
// so -- Waku's answer is to address by TOPIC rather than recipient.
type AddressedEnvelope struct {
	To   string `json:"to"`
	From string `json:"from"`
	Wire []byte `json:"wire"` // a marshalled Envelope
}

// SessionManager holds one ratchet session per peer.
//
// State is in-memory only. A restart loses every session, meaning messages
// stored before the restart can no longer be decrypted. Persisting ratchet
// state is real future work; it also raises the question of writing key
// material to disk, which needs an answer before it is done casually.
type SessionManager struct {
	mu       sync.Mutex
	self     KeyPair
	selfID   peer.ID
	sessions map[peer.ID]*Session
	keys     map[peer.ID][32]byte // long-term keys learned from announcements
}

func NewSessionManager(self KeyPair, id peer.ID) *SessionManager {
	return &SessionManager{
		self:     self,
		selfID:   id,
		sessions: make(map[peer.ID]*Session),
		keys:     make(map[peer.ID][32]byte),
	}
}

// LearnKey records a peer's long-term public key. Returns true if this is new.
func (m *SessionManager) LearnKey(p peer.ID, pk [32]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.keys[p]; ok {
		// A changed key means either a peer reset its identity file, or
		// someone is impersonating it. We cannot tell the difference without
		// out-of-band verification -- which is exactly what Signal's safety
		// numbers are for. We log and accept; a real system would warn.
		if existing != pk {
			fmt.Printf("\n[crypto] WARNING: %s changed its identity key\n", short(p))
			m.keys[p] = pk
			delete(m.sessions, p) // old session is meaningless now
			return true
		}
		return false
	}

	m.keys[p] = pk
	return true
}

// KnownPeers lists peers we hold a key for, so we know who we can encrypt to.
func (m *SessionManager) KnownPeers() []peer.ID {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]peer.ID, 0, len(m.keys))
	for p := range m.keys {
		out = append(out, p)
	}
	return out
}

// session returns the session for a peer, creating it on first use.
//
// Both sides must agree on who is the initiator, with no negotiation round. We
// break the tie by comparing peer IDs: the lexicographically smaller ID
// initiates. Both sides compute the same answer independently, which is the
// only property that matters.
func (m *SessionManager) session(p peer.ID) (*Session, error) {
	if s, ok := m.sessions[p]; ok {
		return s, nil
	}

	theirKey, ok := m.keys[p]
	if !ok {
		return nil, fmt.Errorf("no key known for %s", short(p))
	}

	shared, err := DH(m.self.Private, theirKey)
	if err != nil {
		return nil, err
	}

	var s *Session
	if m.selfID.String() < p.String() {
		s, err = NewSessionInitiator(shared, theirKey)
		if err != nil {
			return nil, err
		}
	} else {
		s = NewSessionResponder(shared, m.self)
	}

	m.sessions[p] = s
	return s, nil
}

// EncryptTo produces one addressed ciphertext for one peer.
func (m *SessionManager) EncryptTo(p peer.ID, plaintext []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, err := m.session(p)
	if err != nil {
		return nil, err
	}

	wire, err := s.EncryptMessage(plaintext)
	if err != nil {
		return nil, err
	}

	return json.Marshal(AddressedEnvelope{
		To:   p.String(),
		From: m.selfID.String(),
		Wire: wire,
	})
}

// EncryptToAll produces one ciphertext per known peer.
//
// This is the cost of pairwise sessions on a broadcast network: N recipients
// means N copies on the wire, each separately ratcheted. It does not scale to
// large groups, which is why real group messaging uses a different construction
// (sender keys, or MLS). For a handful of nodes it is correct and simple.
func (m *SessionManager) EncryptToAll(plaintext []byte) [][]byte {
	out := [][]byte{}
	for _, p := range m.KnownPeers() {
		if p == m.selfID {
			continue
		}
		blob, err := m.EncryptTo(p, plaintext)
		if err != nil {
			fmt.Printf("\n[crypto] cannot encrypt to %s: %v\n", short(p), err)
			continue
		}
		out = append(out, blob)
	}
	return out
}

// TryDecrypt attempts to open an addressed envelope.
//
// Returns (plaintext, true) if it was for us and opened. Returns (nil, false)
// for messages addressed to someone else -- which is the COMMON case on a
// broadcast network and is not an error. Logging it as one would drown the
// output in noise.
func (m *SessionManager) TryDecrypt(blob []byte) ([]byte, bool) {
	var ae AddressedEnvelope
	if err := json.Unmarshal(blob, &ae); err != nil {
		return nil, false // not an addressed envelope at all
	}

	if ae.To != m.selfID.String() {
		return nil, false // someone else's mail; we relay and store it blindly
	}

	from, err := peer.Decode(ae.From)
	if err != nil {
		return nil, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	s, err := m.session(from)
	if err != nil {
		fmt.Printf("\n[crypto] message from %s but no session: %v\n", short(from), err)
		return nil, false
	}

	pt, err := s.DecryptMessage(ae.Wire)
	if err != nil {
		// A real failure worth showing: right recipient, wrong result. Usually
		// means lost ratchet state after a restart.
		fmt.Printf("\n[crypto] decrypt from %s failed: %v\n", short(from), err)
		return nil, false
	}
	return pt, true
}

func short(p peer.ID) string {
	s := p.String()
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
