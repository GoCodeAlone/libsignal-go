// Package groups implements Signal's sender-key (group messaging) state: the
// per-sender SenderKeyState/SenderKeyRecord and the sender-key distribution
// message (SKDM) create/process flow. It mirrors rust/protocol/src/sender_keys.rs
// and the SKDM portion of rust/protocol/src/group_cipher.rs.
package groups

import (
	"errors"
	"fmt"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/internal/crypto"
	"github.com/GoCodeAlone/libsignal-go/proto"
)

const (
	// MaxSenderKeyStates bounds the per-record state list; adding past the cap
	// evicts the oldest. Mirrors consts::MAX_SENDER_KEY_STATES.
	MaxSenderKeyStates = 5

	// senderKeyMessageVersion is the current SenderKey message version. Stored as
	// message_version in the state; a stored 0 is interpreted as this value, the
	// first SenderKey version. Mirrors SENDERKEY_MESSAGE_CURRENT_VERSION (3).
	senderKeyMessageVersion = 3

	// chainKeyLen is the required length of a sender-key chain key.
	chainKeyLen = 32
	// cipherKeyLen is the length of the per-message AES-256 cipher key.
	cipherKeyLen = 32
	// ivLen is the length of the per-message AES IV.
	ivLen = 16

	// messageKeySeed and chainKeySeed are the HMAC labels that fork a sender
	// chain key into (respectively) a message-key seed and the next chain key.
	// Mirrors SenderChainKey::{MESSAGE_KEY_SEED, CHAIN_KEY_SEED}.
	messageKeySeed = 0x01
	chainKeySeed   = 0x02

	// senderMessageKeyInfo is the HKDF info string for expanding a sender
	// message-key seed into IV || cipher key. Distinct from the 1:1 ratchet's
	// "WhisperMessageKeys". Mirrors SenderMessageKey::new.
	senderMessageKeyInfo = "WhisperGroup"
)

// errChainTooLong is returned when a sender chain key would overflow its 32-bit
// iteration counter. Mirrors the InvalidState("sender_chain_key_next") error.
var errChainTooLong = errors.New("groups: sender chain is too long")

// SenderChainKey is one link in a sender chain: an iteration counter and the
// 32-byte chain key seed. It advances by HMAC and derives per-message keys.
// Mirrors SenderChainKey in sender_keys.rs.
type SenderChainKey struct {
	iteration uint32
	chainKey  []byte
}

// newSenderChainKey builds a SenderChainKey from an iteration and seed. The
// seed is copied so the caller's slice cannot mutate the chain key.
func newSenderChainKey(iteration uint32, chainKey []byte) SenderChainKey {
	return SenderChainKey{iteration: iteration, chainKey: append([]byte(nil), chainKey...)}
}

// Iteration returns the chain key's iteration counter.
func (c SenderChainKey) Iteration() uint32 { return c.iteration }

// Seed returns the 32-byte chain key material. The slice aliases internal
// state; callers must not mutate it.
func (c SenderChainKey) Seed() []byte { return c.chainKey }

// derivative computes HMAC-SHA256(chainKey, label), used to fork the chain key
// into the next chain key (0x02) or a message-key seed (0x01).
func (c SenderChainKey) derivative(label byte) []byte {
	return crypto.HMACSHA256(c.chainKey, []byte{label})
}

// next advances to the chain key for the following iteration. It errors if the
// iteration counter would overflow. Mirrors SenderChainKey::next.
func (c SenderChainKey) next() (SenderChainKey, error) {
	if c.iteration == ^uint32(0) {
		return SenderChainKey{}, errChainTooLong
	}
	return SenderChainKey{
		iteration: c.iteration + 1,
		chainKey:  c.derivative(chainKeySeed),
	}, nil
}

// senderMessageKey derives the per-message key for this chain key's iteration.
// Mirrors SenderChainKey::sender_message_key.
func (c SenderChainKey) senderMessageKey() (senderMessageKey, error) {
	return newSenderMessageKey(c.iteration, c.derivative(messageKeySeed))
}

// senderMessageKey is the symmetric material for a single sender-key message:
// an AES IV and cipher key derived from a seed, tagged with its iteration.
// Mirrors SenderMessageKey in sender_keys.rs. It is unexported because the
// per-message key derivation is consumed only by the (later) group cipher; the
// chain-key ratchet step itself is exercised via SenderChainKey.
type senderMessageKey struct {
	iteration uint32
	iv        []byte
	cipherKey []byte
}

// newSenderMessageKey expands seed via HKDF-SHA256(salt=nil, info="WhisperGroup")
// into 48 bytes: 16B IV || 32B cipher key. Mirrors SenderMessageKey::new.
func newSenderMessageKey(iteration uint32, seed []byte) (senderMessageKey, error) {
	derived, err := crypto.HKDFSHA256(seed, nil, []byte(senderMessageKeyInfo), ivLen+cipherKeyLen)
	if err != nil {
		return senderMessageKey{}, fmt.Errorf("groups: deriving sender message key: %w", err)
	}
	return senderMessageKey{
		iteration: iteration,
		iv:        derived[:ivLen],
		cipherKey: derived[ivLen : ivLen+cipherKeyLen],
	}, nil
}

// Iteration returns the message key's iteration.
func (m senderMessageKey) Iteration() uint32 { return m.iteration }

// IV returns the 16-byte AES IV. The slice aliases internal state.
func (m senderMessageKey) IV() []byte { return m.iv }

// CipherKey returns the 32-byte AES cipher key. The slice aliases internal state.
func (m senderMessageKey) CipherKey() []byte { return m.cipherKey }

// SenderKeyState wraps a single sender-key state proto: a chain key plus a
// signing key (public always, private only for the local sender). Mirrors
// SenderKeyState in sender_keys.rs.
//
// Like session.SessionState, it stores its secrets in the wrapped proto rather
// than in redacting wrapper types; the proto-backed state is the codebase's
// accepted exception to the chain/root-key redaction convention.
type SenderKeyState struct {
	state *proto.SenderKeyStateStructure
}

// newSenderKeyState builds a fresh state. signaturePrivate is optional: it is
// set on the sender that owns the chain and nil on receivers.
func newSenderKeyState(
	messageVersion uint8,
	chainID uint32,
	iteration uint32,
	chainKey []byte,
	signatureKey curve.PublicKey,
	signaturePrivate *curve.PrivateKey,
) *SenderKeyState {
	var private []byte
	if signaturePrivate != nil {
		private = signaturePrivate.Serialize()
	}
	return &SenderKeyState{
		state: &proto.SenderKeyStateStructure{
			MessageVersion: uint32(messageVersion),
			ChainId:        chainID,
			SenderChainKey: &proto.SenderKeyStateStructure_SenderChainKey{
				Iteration: iteration,
				Seed:      append([]byte(nil), chainKey...),
			},
			SenderSigningKey: &proto.SenderKeyStateStructure_SenderSigningKey{
				Public:  signatureKey.Serialize(),
				Private: private,
			},
		},
	}
}

// MessageVersion returns the state's SenderKey message version, mapping a
// stored 0 to 3 (the first SenderKey version), matching upstream.
func (s *SenderKeyState) MessageVersion() uint32 {
	if v := s.state.GetMessageVersion(); v != 0 {
		return v
	}
	return senderKeyMessageVersion
}

// ChainID returns the state's chain id.
func (s *SenderKeyState) ChainID() uint32 { return s.state.GetChainId() }

// ChainKey returns the current sender chain key, or ok=false if the state has
// none. Mirrors SenderKeyState::sender_chain_key.
func (s *SenderKeyState) ChainKey() (SenderChainKey, bool) {
	sck := s.state.GetSenderChainKey()
	if sck == nil {
		return SenderChainKey{}, false
	}
	return newSenderChainKey(sck.GetIteration(), sck.GetSeed()), true
}

// SigningKeyPublic returns the signing public key, or ok=false if it is missing
// or malformed.
func (s *SenderKeyState) SigningKeyPublic() (curve.PublicKey, bool) {
	sk := s.state.GetSenderSigningKey()
	if sk == nil {
		return curve.PublicKey{}, false
	}
	pub, err := curve.DeserializePublicKey(sk.GetPublic())
	if err != nil {
		return curve.PublicKey{}, false
	}
	return pub, true
}

// SigningKeyPrivate returns the signing private key, or ok=false if it is
// absent (receiver-side states carry no private key) or malformed.
func (s *SenderKeyState) SigningKeyPrivate() (curve.PrivateKey, bool) {
	sk := s.state.GetSenderSigningKey()
	if sk == nil || len(sk.GetPrivate()) == 0 {
		return curve.PrivateKey{}, false
	}
	priv, err := curve.DeserializePrivateKey(sk.GetPrivate())
	if err != nil {
		return curve.PrivateKey{}, false
	}
	return priv, true
}

// SenderKeyRecord is the persisted unit for a (sender, distribution) pair: an
// ordered list of SenderKeyStates, newest first, capped at MaxSenderKeyStates.
// It serializes to a SenderKeyRecordStructure proto. Mirrors SenderKeyRecord in
// sender_keys.rs.
type SenderKeyRecord struct {
	states []*SenderKeyState
}

// NewSenderKeyRecord returns an empty record.
func NewSenderKeyRecord() *SenderKeyRecord {
	return &SenderKeyRecord{}
}

// DeserializeSenderKeyRecord decodes a SenderKeyRecordStructure protobuf into a
// SenderKeyRecord. Malformed input returns an error and never panics.
func DeserializeSenderKeyRecord(b []byte) (*SenderKeyRecord, error) {
	var structure proto.SenderKeyRecordStructure
	if err := googleproto.Unmarshal(b, &structure); err != nil {
		return nil, fmt.Errorf("groups: decoding sender key record: %w", err)
	}
	states := make([]*SenderKeyState, 0, len(structure.GetSenderKeyStates()))
	for _, st := range structure.GetSenderKeyStates() {
		states = append(states, &SenderKeyState{state: st})
	}
	return &SenderKeyRecord{states: states}, nil
}

// StateCount returns the number of states in the record.
func (r *SenderKeyRecord) StateCount() int { return len(r.states) }

// SenderKeyState returns the head (most recent) state, or ok=false if the
// record is empty. Mirrors SenderKeyRecord::sender_key_state.
func (r *SenderKeyRecord) SenderKeyState() (*SenderKeyState, bool) {
	if len(r.states) == 0 {
		return nil, false
	}
	return r.states[0], true
}

// SenderKeyStateForChainID returns the state matching chainID, or nil if none.
// Mirrors SenderKeyRecord::sender_key_state_for_chain_id.
func (r *SenderKeyRecord) SenderKeyStateForChainID(chainID uint32) *SenderKeyState {
	for _, s := range r.states {
		if s.ChainID() == chainID {
			return s
		}
	}
	return nil
}

// AddSenderKeyState inserts a state for (chainID, signatureKey) at the front
// (most recent), capped at MaxSenderKeyStates. Mirrors
// SenderKeyRecord::add_sender_key_state:
//   - if a state with the same (chainID, signatureKey) already exists, it is
//     removed and reused unchanged (preserving its chain key), then moved to the
//     front — so re-processing an SKDM does not reset the chain;
//   - any other states sharing chainID (different signing key) are dropped;
//   - once at the cap, the oldest (tail) state is evicted before inserting.
func (r *SenderKeyRecord) AddSenderKeyState(
	messageVersion uint8,
	chainID uint32,
	iteration uint32,
	chainKey []byte,
	signatureKey curve.PublicKey,
	signaturePrivate *curve.PrivateKey,
) {
	existing := r.removeState(chainID, signatureKey)
	r.removeStatesWithChainID(chainID)

	state := existing
	if state == nil {
		state = newSenderKeyState(messageVersion, chainID, iteration, chainKey, signatureKey, signaturePrivate)
	}

	for len(r.states) >= MaxSenderKeyStates {
		r.states = r.states[:len(r.states)-1]
	}
	r.states = append([]*SenderKeyState{state}, r.states...)
}

// removeState removes and returns the state matching both chainID and
// signatureKey, or nil if none. Mirrors SenderKeyRecord::remove_state.
func (r *SenderKeyRecord) removeState(chainID uint32, signatureKey curve.PublicKey) *SenderKeyState {
	for i, s := range r.states {
		pub, ok := s.SigningKeyPublic()
		if s.ChainID() == chainID && ok && pub.Equal(signatureKey) {
			r.states = append(r.states[:i], r.states[i+1:]...)
			return s
		}
	}
	return nil
}

// removeStatesWithChainID drops every state matching chainID. Mirrors
// SenderKeyRecord::remove_states_with_chain_id.
func (r *SenderKeyRecord) removeStatesWithChainID(chainID uint32) {
	kept := r.states[:0]
	for _, s := range r.states {
		if s.ChainID() != chainID {
			kept = append(kept, s)
		}
	}
	r.states = kept
}

// Serialize encodes the record to its SenderKeyRecordStructure protobuf bytes.
// Mirrors SenderKeyRecord::serialize.
func (r *SenderKeyRecord) Serialize() ([]byte, error) {
	structure := &proto.SenderKeyRecordStructure{
		SenderKeyStates: make([]*proto.SenderKeyStateStructure, 0, len(r.states)),
	}
	for _, s := range r.states {
		structure.SenderKeyStates = append(structure.SenderKeyStates, s.state)
	}
	out, err := googleproto.Marshal(structure)
	if err != nil {
		return nil, fmt.Errorf("groups: encoding sender key record: %w", err)
	}
	return out, nil
}
