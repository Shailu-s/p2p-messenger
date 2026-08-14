package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

// AddressedEnvelope is one ciphertext plus the content topic it belongs to.
//
// The recipient peer ID is not in the clear. Relays can store by topic, while
// only peers that know the pairwise session can connect that topic to a person.
type AddressedEnvelope struct {
	Topic string `json:"topic"`
	From  string `json:"from"`
	Wire  []byte `json:"wire"` // a marshalled Envelope
}

// SessionManager holds one ratchet session per peer.
//
// State is encrypted to disk by OpenSessionManager so store-and-forward
// messages remain decryptable after a restart.
type SessionManager struct {
	mu       sync.Mutex
	self     KeyPair
	selfID   peer.ID
	sessions map[peer.ID]*Session
	keys     map[peer.ID][32]byte // long-term keys learned from announcements

	statePath string
	stateKey  [32]byte
	persist   bool
}

type persistedSessionManager struct {
	Version  int                         `json:"version"`
	Keys     map[string][32]byte         `json:"keys"`
	Sessions map[string]persistedSession `json:"sessions"`
}

type persistedSession struct {
	Self      KeyPair            `json:"self"`
	Remote    [32]byte           `json:"remote"`
	RemoteSet bool               `json:"remoteSet"`
	RootKey   [32]byte           `json:"rootKey"`
	Send      *Chain             `json:"send"`
	Recv      *Chain             `json:"recv"`
	PrevSendN uint32             `json:"prevSendN"`
	Skipped   []persistedSkipped `json:"skipped"`
}

type persistedSkipped struct {
	DH  [32]byte `json:"dh"`
	N   uint32   `json:"n"`
	Key [32]byte `json:"key"`
}

func NewSessionManager(self KeyPair, id peer.ID) *SessionManager {
	return &SessionManager{
		self:     self,
		selfID:   id,
		sessions: make(map[peer.ID]*Session),
		keys:     make(map[peer.ID][32]byte),
	}
}

func OpenSessionManager(self KeyPair, id peer.ID, statePath, stateKeyPath string) (*SessionManager, error) {
	m := NewSessionManager(self, id)
	key, err := loadOrCreateStateKey(stateKeyPath)
	if err != nil {
		return nil, err
	}
	m.statePath = statePath
	m.stateKey = key
	m.persist = true

	data, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	plaintext, err := openState(key, data, []byte("sessions:"+id.String()))
	if err != nil {
		return nil, err
	}

	var disk persistedSessionManager
	if err := json.Unmarshal(plaintext, &disk); err != nil {
		return nil, err
	}
	for idText, pk := range disk.Keys {
		p, err := peer.Decode(idText)
		if err != nil {
			continue
		}
		m.keys[p] = pk
	}
	for idText, ps := range disk.Sessions {
		p, err := peer.Decode(idText)
		if err != nil {
			continue
		}
		m.sessions[p] = ps.session()
	}
	return m, nil
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
			if err := m.persistLocked(); err != nil {
				fmt.Printf("\n[crypto] session save failed: %v\n", err)
			}
			return true
		}
		return false
	}

	m.keys[p] = pk
	if err := m.persistLocked(); err != nil {
		fmt.Printf("\n[crypto] session save failed: %v\n", err)
	}
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

func (m *SessionManager) KnownContentTopics() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]string, 0, len(m.keys))
	for p := range m.keys {
		topic, err := m.contentTopicLocked(p)
		if err == nil {
			out = append(out, topic)
		}
	}
	return out
}

func (m *SessionManager) ContentTopic(p peer.ID) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.contentTopicLocked(p)
}

func (m *SessionManager) contentTopicLocked(p peer.ID) (string, error) {
	theirKey, ok := m.keys[p]
	if !ok {
		return "", fmt.Errorf("no key known for %s", short(p))
	}
	shared, err := DH(m.self.Private, theirKey)
	if err != nil {
		return "", err
	}
	keys, err := kdf(shared[:], "content-topic", 1)
	if err != nil {
		return "", err
	}
	return "/chat/2/" + hex.EncodeToString(keys[0][:16]), nil
}

func (m *SessionManager) sendingSession(p peer.ID) (*Session, error) {
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

	s, err := NewSessionInitiator(shared, theirKey)
	if err != nil {
		return nil, err
	}
	m.sessions[p] = s
	return s, nil
}

func (m *SessionManager) receivingSession(p peer.ID) (*Session, error) {
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

	s := NewSessionResponder(shared, m.self)
	m.sessions[p] = s
	return s, nil
}

// EncryptTo produces one addressed ciphertext for one peer.
func (m *SessionManager) EncryptTo(p peer.ID, plaintext []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, err := m.sendingSession(p)
	if err != nil {
		return nil, err
	}

	wire, err := s.EncryptMessage(plaintext)
	if err != nil {
		return nil, err
	}
	topic, err := m.contentTopicLocked(p)
	if err != nil {
		return nil, err
	}
	if err := m.persistLocked(); err != nil {
		return nil, err
	}

	return json.Marshal(AddressedEnvelope{
		Topic: topic,
		From:  m.selfID.String(),
		Wire:  wire,
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

	from, err := peer.Decode(ae.From)
	if err != nil {
		return nil, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	topic, err := m.contentTopicLocked(from)
	if err != nil || ae.Topic != topic {
		return nil, false
	}

	s, err := m.receivingSession(from)
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
	if err := m.persistLocked(); err != nil {
		fmt.Printf("\n[crypto] session save failed: %v\n", err)
		return nil, false
	}
	return pt, true
}

func EnvelopeContentTopic(blob []byte) (string, bool) {
	var ae AddressedEnvelope
	if err := json.Unmarshal(blob, &ae); err != nil {
		return "", false
	}
	if ae.Topic == "" {
		return "", false
	}
	return ae.Topic, true
}

func (m *SessionManager) persistLocked() error {
	if !m.persist {
		return nil
	}
	disk := persistedSessionManager{
		Version:  1,
		Keys:     make(map[string][32]byte, len(m.keys)),
		Sessions: make(map[string]persistedSession, len(m.sessions)),
	}
	for p, pk := range m.keys {
		disk.Keys[p.String()] = pk
	}
	for p, s := range m.sessions {
		disk.Sessions[p.String()] = persistSession(s)
	}
	plaintext, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	data, err := sealState(m.stateKey, plaintext, []byte("sessions:"+m.selfID.String()))
	if err != nil {
		return err
	}
	return writeFileAtomic(m.statePath, data, 0o600)
}

func persistSession(s *Session) persistedSession {
	ps := persistedSession{
		Self:      s.self,
		Remote:    s.remote,
		RemoteSet: s.remoteSet,
		RootKey:   s.rootKey,
		Send:      s.send,
		Recv:      s.recv,
		PrevSendN: s.prevSendN,
		Skipped:   make([]persistedSkipped, 0, len(s.skipped)),
	}
	for k, mk := range s.skipped {
		ps.Skipped = append(ps.Skipped, persistedSkipped{
			DH:  k.dh,
			N:   k.n,
			Key: mk,
		})
	}
	return ps
}

func (ps persistedSession) session() *Session {
	s := &Session{
		self:      ps.Self,
		remote:    ps.Remote,
		remoteSet: ps.RemoteSet,
		rootKey:   ps.RootKey,
		send:      ps.Send,
		recv:      ps.Recv,
		prevSendN: ps.PrevSendN,
		skipped:   make(map[skippedKey][32]byte, len(ps.Skipped)),
	}
	for _, entry := range ps.Skipped {
		s.skipped[skippedKey{dh: entry.DH, n: entry.N}] = entry.Key
	}
	return s
}

func short(p peer.ID) string {
	s := p.String()
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
