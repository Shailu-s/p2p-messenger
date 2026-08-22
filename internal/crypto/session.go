package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
)

// MaxSkip bounds how many message keys we will derive to catch up with a
// message from the future.
//
// This is a DoS defence, not a tuning knob. A hostile peer can claim N =
// 4000000000; without this bound we would sit in a loop deriving four billion
// keys. Legitimate gaps are small -- a handful of dropped messages -- so 1000
// is generous.
const MaxSkip = 1000

// MaxSkippedKeys bounds the cache of keys for messages that never arrived.
// Unbounded, it is a slow memory leak that an attacker can drive: send
// messages with ever-increasing N and never send the ones in between.
const MaxSkippedKeys = 2000

// Header travels in the clear alongside every ciphertext.
//
// It cannot be encrypted: the receiver needs DHPublic to derive the very key
// that would decrypt it. That is a real metadata leak and worth stating plainly
// rather than hiding -- an observer learns message counts and conversation
// rhythm, though not content.
type Header struct {
	// DHPublic is the sender's current ratchet public key. When it changes,
	// the receiver knows a DH step has happened and reseeds.
	DHPublic [32]byte `json:"dh"`

	// N is this message's index in the current sending chain.
	N uint32 `json:"n"`

	// PN is how many messages went out on the previous chain, before the
	// last DH step. Without it, a receiver that missed the tail of that
	// chain could not tell how many keys to skip before switching over.
	PN uint32 `json:"pn"`
}

// Session is one pairwise conversation. Two exist per pair, one on each side,
// mirroring each other.
type Session struct {
	// Our current ratchet key pair. Replaced on every DH step we initiate.
	self KeyPair

	// Their latest ratchet public key, learned from message headers.
	remote    [32]byte
	remoteSet bool

	// rootKey is the trunk. Each DH step feeds it a fresh shared secret and
	// produces the seed for a new chain. This is where new randomness
	// enters the system, which the symmetric chain alone cannot do.
	rootKey [32]byte

	send *Chain // keys for messages we send
	recv *Chain // keys for messages we receive

	// prevSendN is how many messages went out on the previous sending
	// chain. Sent as Header.PN so the far side can catch up on stragglers.
	prevSendN uint32

	// skipped holds message keys derived ahead of time for messages that
	// have not arrived. Keyed by (their ratchet public key, N), because N
	// alone repeats across chains.
	skipped map[skippedKey][32]byte
}

type skippedKey struct {
	dh [32]byte
	n  uint32
}

// NewSessionInitiator starts a session as the side that speaks first.
//
// It needs the other side's public key in advance, which is the problem X3DH
// solves properly with published prekeys. Here the key is handed over
// directly; the gap is noted rather than hidden.
func NewSessionInitiator(shared [32]byte, theirPub [32]byte) (*Session, error) {
	self, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	s := &Session{
		self:      self,
		remote:    theirPub,
		remoteSet: true,
		rootKey:   shared,
		skipped:   make(map[skippedKey][32]byte),
	}

	// The initiator performs the first DH immediately, so its first message
	// already carries a fresh ratchet key.
	if err := s.dhStep(theirPub, true); err != nil {
		return nil, err
	}
	return s, nil
}

// NewSessionResponder starts a session as the side that waits.
//
// It has no sending chain yet: it cannot build one until it sees the
// initiator's ratchet public key in the first message header.
func NewSessionResponder(shared [32]byte, self KeyPair) *Session {
	return &Session{
		self:    self,
		rootKey: shared,
		skipped: make(map[skippedKey][32]byte),
	}
}

// The DH step — where new randomness enters

// dhStep performs a Diffie-Hellman ratchet step: mix a fresh DH secret into the
// root key and start a new chain from the result.
//
// This is the operation the symmetric chain cannot do. The chain is a closed
// system -- an attacker holding its state follows it forever. Here, new secret
// material that the attacker never saw enters the trunk, and from this point
// their copy of the state is worthless. That is post-compromise security.
func (s *Session) dhStep(theirPub [32]byte, sending bool) error {
	shared, err := DH(s.self.Private, theirPub)
	if err != nil {
		return err // low-order point: reject, do not fall back
	}

	// Two outputs: a new root key, and the seed for the new chain. Deriving
	// the root forward means an attacker who learns one chain seed still
	// cannot walk back up the trunk.
	keys, err := KDF(append(s.rootKey[:], shared[:]...), "dh-ratchet", 2)
	if err != nil {
		return err
	}
	s.rootKey = keys[0]

	chain, err := NewChain(keys[1])
	if err != nil {
		return err
	}

	if sending {
		s.prevSendN = 0
		if s.send != nil {
			s.prevSendN = s.send.N
		}
		s.send = chain
	} else {
		s.recv = chain
	}
	return nil
}

// EncryptMessage seals a plaintext for this session and returns the wire bytes.
func (s *Session) EncryptMessage(plaintext []byte) ([]byte, error) {
	if s.send == nil {
		return nil, errors.New("no sending chain: awaiting their first message")
	}

	msgKey, n, err := s.send.Next()
	if err != nil {
		return nil, err
	}

	h := Header{DHPublic: s.self.Public, N: n, PN: s.prevSendN}
	hBytes, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}

	// The header is associated data: authenticated but not encrypted. An
	// attacker who edits N or PN in transit makes decryption fail rather
	// than silently steering the receiver to a different key.
	ct, err := Encrypt(msgKey, plaintext, hBytes)
	if err != nil {
		return nil, err
	}

	return json.Marshal(Envelope{Header: h, Ciphertext: ct})
}

// Envelope is what actually goes on the wire.
type Envelope struct {
	Header     Header `json:"hdr"`
	Ciphertext []byte `json:"ct"`
}

// DecryptMessage opens a wire message, handling out-of-order arrival and DH
// ratchet steps.
func (s *Session) DecryptMessage(wire []byte) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(wire, &env); err != nil {
		return nil, err
	}
	hBytes, err := json.Marshal(env.Header)
	if err != nil {
		return nil, err
	}

	// 1. A key we set aside earlier for a message that had not arrived yet.
	k := skippedKey{dh: env.Header.DHPublic, n: env.Header.N}
	if mk, ok := s.skipped[k]; ok {
		pt, err := Decrypt(mk, env.Ciphertext, hBytes)
		if err != nil {
			return nil, err
		}
		// Used once, then destroyed: keeping it would undo forward secrecy.
		delete(s.skipped, k)
		return pt, nil
	}

	// 2. Their ratchet key changed, so they performed a DH step. Before
	//    following, cache keys for stragglers still owed on the old chain;
	//    Header.PN says how many that chain produced in total.
	if !s.remoteSet || env.Header.DHPublic != s.remote {
		if err := s.skipTo(env.Header.PN); err != nil {
			return nil, err
		}

		s.remote = env.Header.DHPublic
		s.remoteSet = true

		// Receiving chain first, from their new key against our current
		if err := s.dhStep(env.Header.DHPublic, false); err != nil {
			return nil, err
		}

		// Then a brand new key pair of our own, so our replies carry fr
		// material and they in turn ratchet. This back-and-forth is wha
		// recovery continuous rather than one-off.
		self, err := GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		s.self = self
		if err := s.dhStep(env.Header.DHPublic, true); err != nil {
			return nil, err
		}
	}

	if s.recv == nil {
		return nil, errors.New("no receiving chain")
	}

	// 3. This message is ahead of our chain: derive and cache the keys for
	//    the ones skipped, then take this one.
	if err := s.skipTo(env.Header.N); err != nil {
		return nil, err
	}

	msgKey, _, err := s.recv.Next()
	if err != nil {
		return nil, err
	}
	return Decrypt(msgKey, env.Ciphertext, hBytes)
}

// skipTo advances the receiving chain to index `until`, stashing every message
// key it passes so late arrivals can still be read.
func (s *Session) skipTo(until uint32) error {
	if s.recv == nil {
		return nil
	}
	if s.recv.N >= until {
		return nil // nothing to skip
	}

	// The DoS check. A hostile header claiming a huge N would otherwise
	// spin here deriving keys until the process dies.
	if until-s.recv.N > MaxSkip {
		return fmt.Errorf("skip of %d exceeds MaxSkip %d", until-s.recv.N, MaxSkip)
	}

	for s.recv.N < until {
		mk, n, err := s.recv.Next()
		if err != nil {
			return err
		}
		if len(s.skipped) >= MaxSkippedKeys {
			return errors.New("skipped-key cache full")
		}
		s.skipped[skippedKey{dh: s.remote, n: n}] = mk
	}
	return nil
}

// persistedSession is the on-disk shape of a Session.
//
// Session keeps its fields unexported: a caller that could set rootKey or a
// chain key directly could silently rewind the ratchet and destroy forward
// secrecy. Serialisation therefore lives here rather than in the caller, and
// the state leaves this package only as opaque, already-encrypted bytes.
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

// persistedSkipped flattens the skipped-key map, whose composite struct key
// cannot be a JSON object key.
type persistedSkipped struct {
	DH  [32]byte `json:"dh"`
	N   uint32   `json:"n"`
	Key [32]byte `json:"key"`
}

// MarshalJSON serialises the full ratchet state, including undelivered skipped
// message keys -- dropping those would make already-stored ciphertext
// permanently unreadable after a restart.
func (s *Session) MarshalJSON() ([]byte, error) {
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
		ps.Skipped = append(ps.Skipped, persistedSkipped{DH: k.dh, N: k.n, Key: mk})
	}
	return json.Marshal(ps)
}

// UnmarshalJSON restores a session written by MarshalJSON.
func (s *Session) UnmarshalJSON(data []byte) error {
	var ps persistedSession
	if err := json.Unmarshal(data, &ps); err != nil {
		return err
	}
	s.self = ps.Self
	s.remote = ps.Remote
	s.remoteSet = ps.RemoteSet
	s.rootKey = ps.RootKey
	s.send = ps.Send
	s.recv = ps.Recv
	s.prevSendN = ps.PrevSendN
	s.skipped = make(map[skippedKey][32]byte, len(ps.Skipped))
	for _, e := range ps.Skipped {
		s.skipped[skippedKey{dh: e.DH, n: e.N}] = e.Key
	}
	return nil
}
