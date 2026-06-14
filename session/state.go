// Package session models the Double Ratchet session state and the PQXDH
// establishment + message cipher: SessionState (a thin wrapper over the
// generated proto.SessionStructure), SessionRecord (the current state plus a
// bounded list of archived states), ProcessPreKeyBundle / InitializeBobSession
// (handshake), and Encrypt / Decrypt (the message cipher). It is a pure-Go port
// of rust/protocol/src/state/session.rs, session.rs, and ratchet.rs, and
// serializes to the same SessionStructure / RecordStructure protobufs as
// upstream libsignal v0.91.0.
//
// Compatibility staging: sessions negotiate at the v0.91.0 surface, which ships
// the Sparse Post-Quantum Ratchet (SPQR) as an optional layer. The session
// drives SPQR through PQRatchetSend / PQRatchetRecv (the pq_ratchet message
// field and pq_ratchet_state), mixing the SPQR key into the Double Ratchet
// message keys; min_version V0 means a peer that does not speak SPQR still
// interoperates (the key contribution is empty and the derivation is unchanged).
// See decisions/0001-spqr-staged-compat.md and the README scope matrix.
package session

import (
	"fmt"
	"io"
	"time"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/proto"
	"github.com/GoCodeAlone/libsignal-go/ratchet"
	"github.com/GoCodeAlone/libsignal-go/spqr"
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

// MaxUnacknowledgedSessionAge is how long an initiator session may sit with an
// unacknowledged pre-key message before encrypting to it fails as stale
// (MAX_UNACKNOWLEDGED_SESSION_AGE in consts.rs: 30 days).
const MaxUnacknowledgedSessionAge = 30 * 24 * time.Hour

// SessionState wraps a *proto.SessionStructure. It does not re-model the
// session; every field lives in the proto so serialization is exactly the
// upstream wire form. A nil structure is never valid for an initialized state;
// constructors always allocate one.
type SessionState struct {
	structure *proto.SessionStructure
}

// NewSessionState wraps an existing SessionStructure. The structure is taken by
// reference (not copied); callers that need isolation should Clone first.
//
// A nil structure is replaced with a freshly allocated zero-value one, so the
// returned state is always backed by a non-nil structure and every method stays
// panic-free (a setter on a nil structure would otherwise panic). Callers
// passing a real structure are unaffected.
func NewSessionState(s *proto.SessionStructure) *SessionState {
	if s == nil {
		s = &proto.SessionStructure{}
	}
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

// PQRatchetState returns the serialized Sparse Post-Quantum Ratchet (SPQR)
// state bytes. The session layer drives it through PQRatchetSend / PQRatchetRecv;
// it is also preserved verbatim through serialize/deserialize.
func (s *SessionState) PQRatchetState() []byte { return s.structure.GetPqRatchetState() }

// SetPQRatchetState stores the serialized SPQR state bytes.
func (s *SessionState) SetPQRatchetState(b []byte) { s.structure.PqRatchetState = cloneBytes(b) }

// PQRatchetSend advances the SPQR send ratchet one step: it produces the
// outbound SPQR message to attach to the ciphertext (the SignalMessage
// pq_ratchet field) and the SPQR message key to mix into the Double Ratchet
// message keys, updating the stored SPQR state in place. A nil/empty returned
// key means SPQR contributed no key this message (V0 / still negotiating), in
// which case the message-key derivation is unchanged. Mirrors
// SessionState::pq_ratchet_send (spqr::send). rng must be a CSPRNG.
func (s *SessionState) PQRatchetSend(rng io.Reader) (msg []byte, key []byte, err error) {
	res, err := spqr.Send(s.structure.GetPqRatchetState(), rng)
	if err != nil {
		return nil, nil, fmt.Errorf("session: SPQR send: %w", err)
	}
	s.structure.PqRatchetState = res.State
	return res.Msg, res.Key, nil
}

// PQRatchetRecv advances the SPQR receive ratchet one step from an inbound SPQR
// message (the SignalMessage pq_ratchet field), returning the SPQR message key
// to mix into the Double Ratchet message keys and updating the stored SPQR state
// in place. A nil/empty returned key means SPQR contributed no key. Mirrors
// SessionState::pq_ratchet_recv (spqr::recv).
func (s *SessionState) PQRatchetRecv(msg []byte) (key []byte, err error) {
	res, err := spqr.Recv(s.structure.GetPqRatchetState(), msg)
	if err != nil {
		return nil, fmt.Errorf("session: SPQR recv: %w", err)
	}
	s.structure.PqRatchetState = res.State
	return res.Key, nil
}

// PendingPreKey reports whether an unacknowledged pre-key message is pending
// (either the X25519 pending pre-key or the Kyber pending pre-key is set).
func (s *SessionState) PendingPreKey() bool {
	return s.structure.GetPendingPreKey() != nil || s.structure.GetPendingKyberPreKey() != nil
}

// PendingPreKeyMessage is the unacknowledged pre-key message state an initiator
// session carries until the recipient's first reply: the optional one-time
// pre-key id, the signed pre-key id, the Kyber pre-key id + ciphertext, the
// initiator's base public key, and the creation time in Unix seconds.
type PendingPreKeyMessage struct {
	PreKeyID        *uint32 // nil when no one-time pre-key was used
	SignedPreKeyID  uint32
	KyberPreKeyID   *uint32 // nil when no Kyber pre-key is pending (should not happen at v4)
	KyberCiphertext []byte
	BaseKey         []byte
	UnixSeconds     uint64
}

// PendingPreKeyMessage returns the unacknowledged pre-key message state and
// whether one is pending. The EC pending pre-key record is the sole gate: when
// it is absent there is no pending message (ok=false). The Kyber pending record
// is OPTIONAL and read opportunistically — its id and ciphertext fill in only
// when present. This mirrors upstream SessionState::
// unacknowledged_pre_key_message_items (rust/protocol/src/state/session.rs:536),
// which keys solely on `pending_pre_key` and passes `pending_kyber_pre_key` as
// an Option (so kyber_pre_key_id is Option<KyberPreKeyId>). At v4 the Kyber
// record is expected present (PreKeyID nil "should not happen at v4"), but its
// absence is not treated as "no pending message" here, matching upstream.
func (s *SessionState) PendingPreKeyMessage() (PendingPreKeyMessage, bool) {
	pp := s.structure.GetPendingPreKey()
	if pp == nil {
		return PendingPreKeyMessage{}, false
	}
	out := PendingPreKeyMessage{
		SignedPreKeyID: uint32(pp.GetSignedPreKeyId()),
		BaseKey:        pp.GetBaseKey(),
		UnixSeconds:    pp.GetTimestamp(),
	}
	if pp.PreKeyId != nil {
		id := pp.GetPreKeyId()
		out.PreKeyID = &id
	}
	if pk := s.structure.GetPendingKyberPreKey(); pk != nil {
		id := pk.GetPreKeyId()
		out.KyberPreKeyID = &id
		out.KyberCiphertext = pk.GetCiphertext()
	}
	return out, true
}

// ClearUnacknowledgedPreKeyMessage clears the pending pre-key and pending Kyber
// pre-key, mirroring SessionState::clear_unacknowledged_pre_key_message in
// rust/protocol/src/state/session.rs. Upstream calls this when archiving a
// session (archive_current_state_inner) so an archived state never retains an
// unacknowledged pre-key message; it carries an IMPORTANT banner reminding that
// any future pending field must be cleared here too.
func (s *SessionState) ClearUnacknowledgedPreKeyMessage() {
	s.structure.PendingPreKey = nil
	s.structure.PendingKyberPreKey = nil
}

// SetUnacknowledgedPreKeyMessage records the pending (unacknowledged) pre-key
// message on an initiator session: the optional one-time pre-key id, the
// signed pre-key id, the initiator's base (ephemeral) public key, and the
// creation time in whole seconds since the Unix epoch. Mirrors
// SessionState::set_unacknowledged_pre_key_message in session.rs.
func (s *SessionState) SetUnacknowledgedPreKeyMessage(preKeyID *uint32, signedPreKeyID uint32, baseKey curve.PublicKey, unixSeconds uint64) {
	pending := &proto.SessionStructure_PendingPreKey{
		SignedPreKeyId: int32(signedPreKeyID),
		BaseKey:        baseKey.Serialize(),
		Timestamp:      unixSeconds,
	}
	if preKeyID != nil {
		id := *preKeyID
		pending.PreKeyId = &id
	}
	s.structure.PendingPreKey = pending
}

// SetKyberCiphertext stores the initiator's Kyber ciphertext as a pending Kyber
// pre-key, with the pre-key id left at its sentinel until
// SetUnacknowledgedKyberPreKeyID sets the real id (mirrors
// SessionState::set_kyber_ciphertext, which uses u32::MAX as the placeholder).
func (s *SessionState) SetKyberCiphertext(ciphertext []byte) {
	s.structure.PendingKyberPreKey = &proto.SessionStructure_PendingKyberPreKey{
		PreKeyId:   ^uint32(0),
		Ciphertext: cloneBytes(ciphertext),
	}
}

// SetUnacknowledgedKyberPreKeyID sets the pending Kyber pre-key id, which must
// already have been created by SetKyberCiphertext. Mirrors
// SessionState::set_unacknowledged_kyber_pre_key_id.
func (s *SessionState) SetUnacknowledgedKyberPreKeyID(id uint32) error {
	if s.structure.PendingKyberPreKey == nil {
		return fmt.Errorf("session: no pending Kyber pre-key to set id on")
	}
	s.structure.PendingKyberPreKey.PreKeyId = id
	return nil
}

// UnacknowledgedKyberCiphertext returns the pending Kyber ciphertext (the
// initiator's KEM ciphertext, to be relayed in the PreKeySignalMessage), and
// whether one is pending.
func (s *SessionState) UnacknowledgedKyberCiphertext() ([]byte, bool) {
	pk := s.structure.GetPendingKyberPreKey()
	if pk == nil {
		return nil, false
	}
	return pk.GetCiphertext(), true
}

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

// SenderRatchetKeyPair returns the local sending ratchet key pair (public +
// private), needed to compute the next DH ratchet step on the receive path. It
// errors if no sender chain is set or its keys are malformed.
func (s *SessionState) SenderRatchetKeyPair() (curve.KeyPair, error) {
	sc := s.structure.GetSenderChain()
	if sc == nil {
		return curve.KeyPair{}, fmt.Errorf("session: no sender chain")
	}
	pub, err := curve.DeserializePublicKey(sc.GetSenderRatchetKey())
	if err != nil {
		return curve.KeyPair{}, fmt.Errorf("session: sender ratchet public key: %w", err)
	}
	priv, err := curve.DeserializePrivateKey(sc.GetSenderRatchetKeyPrivate())
	if err != nil {
		return curve.KeyPair{}, fmt.Errorf("session: sender ratchet private key: %w", err)
	}
	return curve.NewKeyPair(pub, priv), nil
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

// CacheMessageKeys inserts a skipped message's key generator at the front of the
// matching receiver chain's cache, evicting the oldest (tail) when the count
// exceeds MaxMessageKeys (SessionState::set_message_keys: insert(0) then pop over
// cap). The generator is stored in its proto form — the SEED for a deferred
// (Seed) generator (so the Sparse Post-Quantum Ratchet key for that specific
// skipped message can be mixed in when it later arrives) or the derived keys for
// a materialized (Keys) generator. Mirrors MessageKeyGenerator::into_pb.
func (s *SessionState) CacheMessageKeys(senderRatchetKey curve.PublicKey, gen ratchet.MessageKeyGenerator) error {
	idx := s.receiverChainIndex(senderRatchetKey)
	if idx < 0 {
		return fmt.Errorf("session: no receiver chain to cache message keys for")
	}
	chain := s.structure.ReceiverChains[idx]
	chain.MessageKeys = append([]*proto.SessionStructure_Chain_MessageKey{messageKeyGenToProto(gen)}, chain.MessageKeys...)
	if len(chain.MessageKeys) > MaxMessageKeys {
		chain.MessageKeys = chain.MessageKeys[:MaxMessageKeys]
	}
	return nil
}

// TakeMessageKeys removes and returns the cached message-key generator at the
// given index on the matching receiver chain, if present. The second return is
// false when no matching cached entry exists. Mirrors get_message_keys +
// MessageKeyGenerator::from_pb (the caller derives the final keys, mixing in the
// per-message SPQR key).
func (s *SessionState) TakeMessageKeys(senderRatchetKey curve.PublicKey, index uint32) (ratchet.MessageKeyGenerator, bool, error) {
	idx := s.receiverChainIndex(senderRatchetKey)
	if idx < 0 {
		return ratchet.MessageKeyGenerator{}, false, fmt.Errorf("session: no receiver chain")
	}
	chain := s.structure.ReceiverChains[idx]
	for i, e := range chain.MessageKeys {
		if e.GetIndex() == index {
			gen, err := messageKeyGenFromProto(e)
			if err != nil {
				return ratchet.MessageKeyGenerator{}, false, err
			}
			chain.MessageKeys = append(chain.MessageKeys[:i], chain.MessageKeys[i+1:]...)
			return gen, true, nil
		}
	}
	return ratchet.MessageKeyGenerator{}, false, nil
}

// messageKeyGenToProto serializes a MessageKeyGenerator to the proto cache entry.
// A Seed (deferred) generator stores its seed + index with empty key fields; a
// Keys (materialized) generator stores the derived cipher/mac/iv + index with an
// empty seed. Mirrors MessageKeyGenerator::into_pb.
func messageKeyGenToProto(gen ratchet.MessageKeyGenerator) *proto.SessionStructure_Chain_MessageKey {
	if seed, counter, ok := gen.Seed(); ok {
		return &proto.SessionStructure_Chain_MessageKey{Index: counter, Seed: seed}
	}
	// Keys variant: materialize (no PQR key — Keys-variant generators are
	// pre-SPQR cached keys) and store the derived components.
	mk, _ := gen.GenerateKeys(nil)
	return &proto.SessionStructure_Chain_MessageKey{
		Index:     mk.Index(),
		CipherKey: mk.CipherKey(),
		MacKey:    mk.MACKey(),
		Iv:        mk.IV(),
	}
}

// messageKeyGenFromProto reconstructs a MessageKeyGenerator from a proto cache
// entry: a non-empty seed yields a deferred Seed generator (the per-message SPQR
// key is mixed in at GenerateKeys time); otherwise the stored derived keys yield
// a Keys generator. Mirrors MessageKeyGenerator::from_pb.
func messageKeyGenFromProto(pb *proto.SessionStructure_Chain_MessageKey) (ratchet.MessageKeyGenerator, error) {
	if len(pb.GetSeed()) != 0 {
		return ratchet.NewMessageKeyGeneratorFromSeed(pb.GetSeed(), pb.GetIndex()), nil
	}
	mk, err := ratchet.NewMessageKeys(pb.GetCipherKey(), pb.GetMacKey(), pb.GetIv(), pb.GetIndex())
	if err != nil {
		return ratchet.MessageKeyGenerator{}, fmt.Errorf("session: decoding cached message key: %w", err)
	}
	return ratchet.NewMessageKeyGeneratorFromKeys(mk), nil
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
