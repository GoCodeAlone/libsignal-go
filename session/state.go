// Package session models the Double Ratchet session state: SessionState (a thin
// wrapper over the generated proto.SessionStructure) and SessionRecord (the
// current state plus a bounded list of archived states). It is a pure-Go port
// of rust/protocol/src/state/session.rs and serializes to the same
// SessionStructure / RecordStructure protobufs as upstream libsignal v0.91.0.
package session

import (
	"fmt"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/proto"
	"github.com/GoCodeAlone/libsignal-go/ratchet"
)

// Bounds from rust/protocol/src/consts.rs. These cap unbounded growth of the
// receiver-chain list, the per-chain skipped-message-key cache, and the
// archived-states list, matching upstream eviction exactly.
const (
	// MaxMessageKeys bounds the skipped-message-key cache per receiver chain.
	MaxMessageKeys = 2000
	// MaxReceiverChains bounds how many receiver (DH ratchet) chains are kept.
	MaxReceiverChains = 5
	// ArchivedStatesMaxLength bounds the archived (previous) session list.
	ArchivedStatesMaxLength = 40
)

// SessionState wraps a *proto.SessionStructure. It does not re-model the
// session; every field lives in the proto so serialization is exactly the
// upstream wire form. A nil structure is never valid for an initialized state;
// constructors always allocate one.
type SessionState struct {
	structure *proto.SessionStructure
}

// NewSessionState wraps an existing SessionStructure. The structure is taken by
// reference (not copied); callers that need isolation should Clone first.
func NewSessionState(s *proto.SessionStructure) *SessionState {
	return &SessionState{structure: s}
}

// NewEmptySessionState returns a state backed by a freshly allocated, zero-value
// SessionStructure.
func NewEmptySessionState() *SessionState {
	return &SessionState{structure: &proto.SessionStructure{}}
}

// Structure returns the underlying proto. Mutating it mutates the state.
func (s *SessionState) Structure() *proto.SessionStructure { return s.structure }

// SessionVersion reports the session/ciphertext version.
func (s *SessionState) SessionVersion() uint32 { return s.structure.GetSessionVersion() }

// SetSessionVersion sets the session/ciphertext version.
func (s *SessionState) SetSessionVersion(v uint32) { s.structure.SessionVersion = v }

// RootKey returns the current root key bytes (may be nil on a fresh state).
func (s *SessionState) RootKey() []byte { return s.structure.GetRootKey() }

// SetRootKey stores the root key bytes.
func (s *SessionState) SetRootKey(rk ratchet.RootKey) { s.structure.RootKey = rk.Key() }

// PreviousCounter returns the previous sending-chain counter.
func (s *SessionState) PreviousCounter() uint32 { return s.structure.GetPreviousCounter() }

// SetPreviousCounter sets the previous sending-chain counter.
func (s *SessionState) SetPreviousCounter(c uint32) { s.structure.PreviousCounter = c }

// LocalIdentityPublic returns the bound local identity public key bytes.
func (s *SessionState) LocalIdentityPublic() []byte { return s.structure.GetLocalIdentityPublic() }

// RemoteIdentityPublic returns the bound remote identity public key bytes.
func (s *SessionState) RemoteIdentityPublic() []byte { return s.structure.GetRemoteIdentityPublic() }

// SetLocalIdentityPublic stores the bound local identity public key.
func (s *SessionState) SetLocalIdentityPublic(pk curve.PublicKey) {
	s.structure.LocalIdentityPublic = pk.Serialize()
}

// SetRemoteIdentityPublic stores the bound remote identity public key.
func (s *SessionState) SetRemoteIdentityPublic(pk curve.PublicKey) {
	s.structure.RemoteIdentityPublic = pk.Serialize()
}

// LocalRegistrationID returns the local registration id.
func (s *SessionState) LocalRegistrationID() uint32 { return s.structure.GetLocalRegistrationId() }

// RemoteRegistrationID returns the remote registration id.
func (s *SessionState) RemoteRegistrationID() uint32 { return s.structure.GetRemoteRegistrationId() }

// SetLocalRegistrationID sets the local registration id.
func (s *SessionState) SetLocalRegistrationID(id uint32) {
	s.structure.LocalRegistrationId = id
}

// SetRemoteRegistrationID sets the remote registration id.
func (s *SessionState) SetRemoteRegistrationID(id uint32) {
	s.structure.RemoteRegistrationId = id
}

// AliceBaseKey returns the recorded Alice base key (used to match sessions).
func (s *SessionState) AliceBaseKey() []byte { return s.structure.GetAliceBaseKey() }

// SetAliceBaseKey records the Alice base key used to match sessions.
func (s *SessionState) SetAliceBaseKey(key []byte) { s.structure.AliceBaseKey = cloneBytes(key) }

// PQRatchetState returns the opaque post-quantum ratchet (SPQR) state bytes.
// This package treats it as an opaque blob — it is preserved verbatim through
// serialize/deserialize and never interpreted here.
func (s *SessionState) PQRatchetState() []byte { return s.structure.GetPqRatchetState() }

// SetPQRatchetState stores the opaque SPQR state bytes.
func (s *SessionState) SetPQRatchetState(b []byte) { s.structure.PqRatchetState = cloneBytes(b) }

// SetSenderChain installs the sending chain from the local ratchet key pair and
// its chain key (SessionState::set_sender_chain). The public + private ratchet
// key are both stored (the local sender owns the private key).
func (s *SessionState) SetSenderChain(senderRatchet curve.KeyPair, chainKey ratchet.ChainKey) {
	s.structure.SenderChain = &proto.SessionStructure_Chain{
		SenderRatchetKey:        senderRatchet.PublicKey.Serialize(),
		SenderRatchetKeyPrivate: senderRatchet.PrivateKey.Serialize(),
		ChainKey:                chainKeyToProto(chainKey),
	}
}

// SenderChainKey returns the current sending chain key, or an error if no
// sender chain is set or its chain key is malformed.
func (s *SessionState) SenderChainKey() (ratchet.ChainKey, error) {
	sc := s.structure.GetSenderChain()
	if sc == nil || sc.GetChainKey() == nil {
		return ratchet.ChainKey{}, fmt.Errorf("session: no sender chain")
	}
	return chainKeyFromProto(sc.GetChainKey())
}

// SetSenderChainKey replaces the sending chain key, keeping the ratchet keys.
func (s *SessionState) SetSenderChainKey(chainKey ratchet.ChainKey) error {
	sc := s.structure.GetSenderChain()
	if sc == nil {
		return fmt.Errorf("session: no sender chain to update")
	}
	sc.ChainKey = chainKeyToProto(chainKey)
	return nil
}

// SenderRatchetKey returns the public sending ratchet key, or an error if unset.
func (s *SessionState) SenderRatchetKey() (curve.PublicKey, error) {
	sc := s.structure.GetSenderChain()
	if sc == nil {
		return curve.PublicKey{}, fmt.Errorf("session: no sender chain")
	}
	return curve.DeserializePublicKey(sc.GetSenderRatchetKey())
}

// AddReceiverChain appends a receiving chain for the given remote ratchet key,
// evicting the oldest chain when the count exceeds MaxReceiverChains
// (SessionState::add_receiver_chain: push then remove(0) over the cap).
func (s *SessionState) AddReceiverChain(senderRatchetKey curve.PublicKey, chainKey ratchet.ChainKey) {
	chain := &proto.SessionStructure_Chain{
		SenderRatchetKey:        senderRatchetKey.Serialize(),
		SenderRatchetKeyPrivate: nil,
		ChainKey:                chainKeyToProto(chainKey),
	}
	s.structure.ReceiverChains = append(s.structure.ReceiverChains, chain)
	if len(s.structure.ReceiverChains) > MaxReceiverChains {
		s.structure.ReceiverChains = s.structure.ReceiverChains[1:]
	}
}

// receiverChainIndex returns the index of the receiver chain whose ratchet key
// matches, or -1. Comparison is on the serialized public key bytes.
func (s *SessionState) receiverChainIndex(senderRatchetKey curve.PublicKey) int {
	want := senderRatchetKey.Serialize()
	for i, c := range s.structure.GetReceiverChains() {
		if bytesEqual(c.GetSenderRatchetKey(), want) {
			return i
		}
	}
	return -1
}

// ReceiverChainKey returns the chain key for the receiver chain matching the
// given ratchet key, and whether such a chain exists.
func (s *SessionState) ReceiverChainKey(senderRatchetKey curve.PublicKey) (ratchet.ChainKey, bool, error) {
	idx := s.receiverChainIndex(senderRatchetKey)
	if idx < 0 {
		return ratchet.ChainKey{}, false, nil
	}
	ck := s.structure.ReceiverChains[idx].GetChainKey()
	if ck == nil {
		return ratchet.ChainKey{}, false, fmt.Errorf("session: receiver chain has no chain key")
	}
	key, err := chainKeyFromProto(ck)
	if err != nil {
		return ratchet.ChainKey{}, false, err
	}
	return key, true, nil
}

// SetReceiverChainKey replaces the chain key on the matching receiver chain.
func (s *SessionState) SetReceiverChainKey(senderRatchetKey curve.PublicKey, chainKey ratchet.ChainKey) error {
	idx := s.receiverChainIndex(senderRatchetKey)
	if idx < 0 {
		return fmt.Errorf("session: no receiver chain for the given ratchet key")
	}
	s.structure.ReceiverChains[idx].ChainKey = chainKeyToProto(chainKey)
	return nil
}

// MessageKeyAt holds a cached (skipped) set of message keys with its index.
type MessageKeyAt struct {
	Index     uint32
	CipherKey []byte
	MacKey    []byte
	IV        []byte
}

// CacheMessageKeys inserts skipped message keys at the front of the matching
// receiver chain's cache, evicting the oldest (tail) when the count exceeds
// MaxMessageKeys (SessionState::set_message_keys: insert(0) then pop over cap).
func (s *SessionState) CacheMessageKeys(senderRatchetKey curve.PublicKey, mk MessageKeyAt) error {
	idx := s.receiverChainIndex(senderRatchetKey)
	if idx < 0 {
		return fmt.Errorf("session: no receiver chain to cache message keys for")
	}
	chain := s.structure.ReceiverChains[idx]
	entry := &proto.SessionStructure_Chain_MessageKey{
		Index:     mk.Index,
		CipherKey: cloneBytes(mk.CipherKey),
		MacKey:    cloneBytes(mk.MacKey),
		Iv:        cloneBytes(mk.IV),
	}
	chain.MessageKeys = append([]*proto.SessionStructure_Chain_MessageKey{entry}, chain.MessageKeys...)
	if len(chain.MessageKeys) > MaxMessageKeys {
		chain.MessageKeys = chain.MessageKeys[:MaxMessageKeys]
	}
	return nil
}

// TakeMessageKeys removes and returns the cached message keys at the given
// index on the matching receiver chain, if present. The second return is false
// when no matching cached entry exists.
func (s *SessionState) TakeMessageKeys(senderRatchetKey curve.PublicKey, index uint32) (MessageKeyAt, bool, error) {
	idx := s.receiverChainIndex(senderRatchetKey)
	if idx < 0 {
		return MessageKeyAt{}, false, fmt.Errorf("session: no receiver chain")
	}
	chain := s.structure.ReceiverChains[idx]
	for i, e := range chain.MessageKeys {
		if e.GetIndex() == index {
			out := MessageKeyAt{
				Index:     e.GetIndex(),
				CipherKey: cloneBytes(e.GetCipherKey()),
				MacKey:    cloneBytes(e.GetMacKey()),
				IV:        cloneBytes(e.GetIv()),
			}
			chain.MessageKeys = append(chain.MessageKeys[:i], chain.MessageKeys[i+1:]...)
			return out, true, nil
		}
	}
	return MessageKeyAt{}, false, nil
}

// Clone returns a deep copy of the state (independent proto).
func (s *SessionState) Clone() *SessionState {
	return &SessionState{structure: cloneStructure(s.structure)}
}

// chainKeyToProto / chainKeyFromProto convert between ratchet.ChainKey and the
// proto chain-key message.
func chainKeyToProto(ck ratchet.ChainKey) *proto.SessionStructure_Chain_ChainKey {
	return &proto.SessionStructure_Chain_ChainKey{
		Index: ck.Index(),
		Key:   ck.Key(),
	}
}

func chainKeyFromProto(p *proto.SessionStructure_Chain_ChainKey) (ratchet.ChainKey, error) {
	return ratchet.NewChainKey(p.GetKey(), p.GetIndex())
}

// cloneStructure deep-copies a SessionStructure via the protobuf runtime.
func cloneStructure(s *proto.SessionStructure) *proto.SessionStructure {
	if s == nil {
		return &proto.SessionStructure{}
	}
	return googleproto.Clone(s).(*proto.SessionStructure)
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
