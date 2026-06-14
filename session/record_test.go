// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"bytes"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/proto"
	"github.com/GoCodeAlone/libsignal-go/ratchet"
)

// fixedReader yields deterministic bytes for reproducible key generation.
type fixedReader struct{ b byte }

func (r *fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
		r.b++
	}
	return len(p), nil
}

func genKeyPair(t *testing.T, seed byte) curve.KeyPair {
	t.Helper()
	kp, err := curve.GenerateKeyPair(&fixedReader{b: seed})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

func chainKey(t *testing.T, b byte, index uint32) ratchet.ChainKey {
	t.Helper()
	ck, err := ratchet.NewChainKey(bytes.Repeat([]byte{b}, 32), index)
	if err != nil {
		t.Fatalf("NewChainKey: %v", err)
	}
	return ck
}

// TestSessionRecordRoundTrip exercises new -> populate -> serialize ->
// deserialize and confirms the decoded state matches.
func TestSessionRecordRoundTrip(t *testing.T) {
	st := NewEmptySessionState()
	st.SetSessionVersion(4)
	st.SetLocalRegistrationID(0x1111)
	st.SetRemoteRegistrationID(0x2222)
	rk, _ := ratchet.NewRootKey(bytes.Repeat([]byte{0x55}, 32))
	st.SetRootKey(rk)
	st.SetPreviousCounter(7)
	sender := genKeyPair(t, 1)
	st.SetSenderChain(sender, chainKey(t, 0xAA, 3))

	rec := NewSessionRecord(st)
	ser, err := rec.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	got, err := DeserializeSessionRecord(ser)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if !got.HasCurrentState() {
		t.Fatal("decoded record has no current state")
	}
	cs := got.CurrentState()
	if cs.SessionVersion() != 4 {
		t.Fatalf("version = %d, want 4", cs.SessionVersion())
	}
	if cs.LocalRegistrationID() != 0x1111 || cs.RemoteRegistrationID() != 0x2222 {
		t.Fatalf("registration ids = %d/%d", cs.LocalRegistrationID(), cs.RemoteRegistrationID())
	}
	if !bytes.Equal(cs.RootKey(), rk.Key()) {
		t.Fatal("root key mismatch")
	}
	if cs.PreviousCounter() != 7 {
		t.Fatalf("previous counter = %d, want 7", cs.PreviousCounter())
	}
	gotCK, err := cs.SenderChainKey()
	if err != nil {
		t.Fatalf("SenderChainKey: %v", err)
	}
	if gotCK.Index() != 3 || !bytes.Equal(gotCK.Key(), bytes.Repeat([]byte{0xAA}, 32)) {
		t.Fatal("sender chain key mismatch")
	}

	// Re-serializing the decoded record yields identical bytes.
	ser2, err := got.Serialize()
	if err != nil {
		t.Fatalf("re-Serialize: %v", err)
	}
	if !bytes.Equal(ser, ser2) {
		t.Fatal("serialize is not stable across round-trip")
	}
}

// TestSenderChainSetGet covers installing and reading back the sender chain.
func TestSenderChainSetGet(t *testing.T) {
	st := NewEmptySessionState()
	if _, err := st.SenderChainKey(); err == nil {
		t.Fatal("SenderChainKey on empty state = nil error")
	}
	sender := genKeyPair(t, 9)
	st.SetSenderChain(sender, chainKey(t, 0x11, 1))

	gotPub, err := st.SenderRatchetKey()
	if err != nil {
		t.Fatalf("SenderRatchetKey: %v", err)
	}
	if !gotPub.Equal(sender.PublicKey) {
		t.Fatal("sender ratchet public key mismatch")
	}
	// SetSenderChainKey replaces only the chain key.
	if err := st.SetSenderChainKey(chainKey(t, 0x22, 2)); err != nil {
		t.Fatalf("SetSenderChainKey: %v", err)
	}
	ck, err := st.SenderChainKey()
	if err != nil {
		t.Fatalf("SenderChainKey: %v", err)
	}
	if ck.Index() != 2 || !bytes.Equal(ck.Key(), bytes.Repeat([]byte{0x22}, 32)) {
		t.Fatal("updated sender chain key mismatch")
	}
}

// TestReceiverChainEviction adds more than MaxReceiverChains chains and confirms
// the oldest (first-added) is evicted, capping the list at MaxReceiverChains.
func TestReceiverChainEviction(t *testing.T) {
	st := NewEmptySessionState()
	keys := make([]curve.PublicKey, MaxReceiverChains+2)
	for i := range keys {
		keys[i] = genKeyPair(t, byte(10+i)).PublicKey
		st.AddReceiverChain(keys[i], chainKey(t, byte(0x40+i), uint32(i)))
	}
	if got := len(st.Structure().GetReceiverChains()); got != MaxReceiverChains {
		t.Fatalf("receiver chains = %d, want %d", got, MaxReceiverChains)
	}
	// The two oldest keys must have been evicted.
	for _, evicted := range keys[:2] {
		if _, ok, _ := st.ReceiverChainKey(evicted); ok {
			t.Fatal("expected oldest receiver chain to be evicted")
		}
	}
	// The most recent must still be present with the right chain key.
	last := keys[len(keys)-1]
	ck, ok, err := st.ReceiverChainKey(last)
	if err != nil || !ok {
		t.Fatalf("newest receiver chain missing: ok=%v err=%v", ok, err)
	}
	if ck.Index() != uint32(len(keys)-1) {
		t.Fatalf("newest chain index = %d, want %d", ck.Index(), len(keys)-1)
	}
}

// TestMessageKeyCacheInsertTake covers caching skipped message keys and taking
// them back out by index, including a miss.
func TestMessageKeyCacheInsertTake(t *testing.T) {
	st := NewEmptySessionState()
	rk := genKeyPair(t, 30).PublicKey
	st.AddReceiverChain(rk, chainKey(t, 0x50, 0))

	// Cache a materialized (Keys-variant) generator — the cipher/mac/iv must
	// survive the proto round-trip and come back identically.
	keys, err := ratchet.NewMessageKeys(
		bytes.Repeat([]byte{0xC1}, 32),
		bytes.Repeat([]byte{0xC2}, 32),
		bytes.Repeat([]byte{0xC3}, 16),
		42,
	)
	if err != nil {
		t.Fatalf("NewMessageKeys: %v", err)
	}
	if err := st.CacheMessageKeys(rk, ratchet.NewMessageKeyGeneratorFromKeys(keys)); err != nil {
		t.Fatalf("CacheMessageKeys: %v", err)
	}
	// Miss on a different index.
	if _, ok, err := st.TakeMessageKeys(rk, 7); err != nil || ok {
		t.Fatalf("expected miss for index 7: ok=%v err=%v", ok, err)
	}
	// Hit: the materialized keys come back unchanged (no PQR key for a
	// Keys-variant entry).
	gen, ok, err := st.TakeMessageKeys(rk, 42)
	if err != nil || !ok {
		t.Fatalf("TakeMessageKeys(42): ok=%v err=%v", ok, err)
	}
	got, err := gen.GenerateKeys(nil)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	if !bytes.Equal(got.CipherKey(), keys.CipherKey()) || !bytes.Equal(got.MACKey(), keys.MACKey()) || !bytes.Equal(got.IV(), keys.IV()) {
		t.Fatal("taken message keys mismatch")
	}
	// Taking again is a miss (entry consumed).
	if _, ok, _ := st.TakeMessageKeys(rk, 42); ok {
		t.Fatal("message key entry was not consumed on take")
	}
}

// TestMessageKeyCacheEviction inserts more than MaxMessageKeys and confirms the
// cache is capped and the oldest (highest, inserted earliest) entry is dropped.
func TestMessageKeyCacheEviction(t *testing.T) {
	st := NewEmptySessionState()
	rk := genKeyPair(t, 31).PublicKey
	st.AddReceiverChain(rk, chainKey(t, 0x60, 0))

	// Insert MaxMessageKeys+1 entries; index 0 is inserted first (so it ends up
	// at the tail and should be evicted).
	for i := 0; i <= MaxMessageKeys; i++ {
		gen := ratchet.NewMessageKeyGeneratorFromSeed(bytes.Repeat([]byte{byte(i)}, 32), uint32(i))
		if err := st.CacheMessageKeys(rk, gen); err != nil {
			t.Fatalf("CacheMessageKeys[%d]: %v", i, err)
		}
	}
	chain := st.Structure().GetReceiverChains()[0]
	if got := len(chain.GetMessageKeys()); got != MaxMessageKeys {
		t.Fatalf("cache size = %d, want %d", got, MaxMessageKeys)
	}
	// Index 0 (first inserted) must have been evicted from the tail.
	if _, ok, _ := st.TakeMessageKeys(rk, 0); ok {
		t.Fatal("oldest message key (index 0) should have been evicted")
	}
	// The most recently inserted (MaxMessageKeys) must still be present.
	if _, ok, _ := st.TakeMessageKeys(rk, uint32(MaxMessageKeys)); !ok {
		t.Fatal("newest message key should be present")
	}
}

// TestArchiveAndCap covers archive: promote a fresh state, current -> archived,
// and the archived list capped at ArchivedStatesMaxLength (oldest dropped).
func TestArchiveAndCap(t *testing.T) {
	mkState := func(v uint32) *SessionState {
		s := NewEmptySessionState()
		s.SetSessionVersion(v)
		// Distinct alice_base_key so each archived blob differs.
		s.SetAliceBaseKey([]byte{byte(v), byte(v >> 8)})
		return s
	}

	rec := NewSessionRecord(mkState(1))
	// Promote many fresh states; each promote archives the current one.
	for v := uint32(2); v <= uint32(ArchivedStatesMaxLength+5); v++ {
		if err := rec.PromoteState(mkState(v)); err != nil {
			t.Fatalf("PromoteState(%d): %v", v, err)
		}
	}
	if got := rec.PreviousSessionCount(); got != ArchivedStatesMaxLength {
		t.Fatalf("archived count = %d, want %d", got, ArchivedStatesMaxLength)
	}
	// Current is the last promoted.
	if rec.CurrentState().SessionVersion() != uint32(ArchivedStatesMaxLength+5) {
		t.Fatalf("current version = %d", rec.CurrentState().SessionVersion())
	}
	// Newest archived (index 0) is the previously-current one.
	prev, err := rec.PreviousStates()
	if err != nil {
		t.Fatalf("PreviousStates: %v", err)
	}
	if prev[0].SessionVersion() != uint32(ArchivedStatesMaxLength+4) {
		t.Fatalf("newest archived version = %d, want %d", prev[0].SessionVersion(), ArchivedStatesMaxLength+4)
	}
}

// TestArchiveFreshIsNoop confirms archiving with no current state is a no-op.
func TestArchiveFreshIsNoop(t *testing.T) {
	rec := NewFreshSessionRecord()
	if err := rec.ArchiveCurrentState(); err != nil {
		t.Fatalf("ArchiveCurrentState on fresh: %v", err)
	}
	if rec.PreviousSessionCount() != 0 || rec.HasCurrentState() {
		t.Fatal("archiving a fresh record changed it")
	}
}

// TestArchiveClearsPendingPreKey is the regression test for the T15 review
// behavioral fix: ArchiveCurrentState must clear the pending pre-key AND
// pending Kyber pre-key before snapshotting, matching upstream
// clear_unacknowledged_pre_key_message. A green build/test gate cannot catch
// this divergence — only an explicit assertion on the archived bytes can.
func TestArchiveClearsPendingPreKey(t *testing.T) {
	st := NewEmptySessionState()
	st.SetSessionVersion(4)
	preKeyID := uint32(77)
	st.Structure().PendingPreKey = &proto.SessionStructure_PendingPreKey{
		PreKeyId:       &preKeyID,
		SignedPreKeyId: 88,
		BaseKey:        bytes.Repeat([]byte{0x05}, 33),
		Timestamp:      1234,
	}
	st.Structure().PendingKyberPreKey = &proto.SessionStructure_PendingKyberPreKey{
		PreKeyId:   99,
		Ciphertext: bytes.Repeat([]byte{0x06}, 64),
	}
	// Sanity: both pending fields are set before archiving.
	if !st.PendingPreKey() {
		t.Fatal("precondition: pending pre-key should be set")
	}

	rec := NewSessionRecord(st)
	if err := rec.ArchiveCurrentState(); err != nil {
		t.Fatalf("ArchiveCurrentState: %v", err)
	}

	// The archived snapshot must have BOTH pending fields cleared.
	prev, err := rec.PreviousStates()
	if err != nil {
		t.Fatalf("PreviousStates: %v", err)
	}
	if len(prev) != 1 {
		t.Fatalf("archived count = %d, want 1", len(prev))
	}
	archived := prev[0]
	if archived.Structure().GetPendingPreKey() != nil {
		t.Fatal("archived state still has pending_pre_key set")
	}
	if archived.Structure().GetPendingKyberPreKey() != nil {
		t.Fatal("archived state still has pending_kyber_pre_key set")
	}
	if archived.PendingPreKey() {
		t.Fatal("archived state reports a pending pre-key after archive")
	}
	// The rest of the state must survive (only the pending fields are cleared).
	if archived.SessionVersion() != 4 {
		t.Fatalf("archived session version = %d, want 4", archived.SessionVersion())
	}
}

// TestPromoteStateClearsPendingPreKey confirms PromoteState routes through
// Archive, so promoting also clears the outgoing session's pending pre-key.
func TestPromoteStateClearsPendingPreKey(t *testing.T) {
	st := NewEmptySessionState()
	st.SetSessionVersion(4)
	pid := uint32(1)
	st.Structure().PendingPreKey = &proto.SessionStructure_PendingPreKey{PreKeyId: &pid, BaseKey: []byte{0x01}}
	st.Structure().PendingKyberPreKey = &proto.SessionStructure_PendingKyberPreKey{PreKeyId: 2, Ciphertext: []byte{0x02}}

	rec := NewSessionRecord(st)
	next := NewEmptySessionState()
	next.SetSessionVersion(5)
	if err := rec.PromoteState(next); err != nil {
		t.Fatalf("PromoteState: %v", err)
	}
	prev, err := rec.PreviousStates()
	if err != nil {
		t.Fatalf("PreviousStates: %v", err)
	}
	if len(prev) != 1 || prev[0].Structure().GetPendingPreKey() != nil || prev[0].Structure().GetPendingKyberPreKey() != nil {
		t.Fatal("PromoteState did not clear pending pre-key on the archived session")
	}
}

// TestPromoteOldSession promotes an archived session back to current.
func TestPromoteOldSession(t *testing.T) {
	s1 := NewEmptySessionState()
	s1.SetSessionVersion(100)
	s1.SetAliceBaseKey([]byte{0x01})
	rec := NewSessionRecord(s1)

	s2 := NewEmptySessionState()
	s2.SetSessionVersion(200)
	s2.SetAliceBaseKey([]byte{0x02})
	if err := rec.PromoteState(s2); err != nil { // archives s1
		t.Fatalf("PromoteState: %v", err)
	}
	// s1 is now archived at index 0; promote it back.
	if err := rec.PromoteOldSession(0); err != nil {
		t.Fatalf("PromoteOldSession: %v", err)
	}
	if rec.CurrentState().SessionVersion() != 100 {
		t.Fatalf("promoted current version = %d, want 100", rec.CurrentState().SessionVersion())
	}
	// s2 should now be archived (it was current when we promoted s1 back).
	prev, err := rec.PreviousStates()
	if err != nil {
		t.Fatalf("PreviousStates: %v", err)
	}
	if len(prev) != 1 || prev[0].SessionVersion() != 200 {
		t.Fatalf("archived after promote = %d entries; [0] version unexpected", len(prev))
	}
	// Out-of-range promote errors.
	if err := rec.PromoteOldSession(99); err == nil {
		t.Fatal("PromoteOldSession(99) = nil error")
	}
}

// TestPQRatchetStateOpaqueRoundTrip confirms pq_ratchet_state bytes are
// preserved verbatim through serialize/deserialize without interpretation.
func TestPQRatchetStateOpaqueRoundTrip(t *testing.T) {
	st := NewEmptySessionState()
	st.SetSessionVersion(4)
	// Arbitrary opaque bytes that are NOT a valid anything — must survive as-is.
	raw := []byte{0x00, 0xFF, 0x7F, 0x80, 0x01, 0x02, 0x03, 0xAB, 0xCD, 0xEF}
	st.SetPQRatchetState(raw)

	ser, err := NewSessionRecord(st).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	got, err := DeserializeSessionRecord(ser)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if !bytes.Equal(got.CurrentState().PQRatchetState(), raw) {
		t.Fatalf("pq_ratchet_state not preserved: got %x want %x", got.CurrentState().PQRatchetState(), raw)
	}
}

// FuzzDeserializeSessionRecord ensures malformed input never panics.
func FuzzDeserializeSessionRecord(f *testing.F) {
	// Seed with a valid record and some degenerate inputs.
	st := NewEmptySessionState()
	st.SetSessionVersion(4)
	st.SetPQRatchetState([]byte{0x01, 0x02})
	if ser, err := NewSessionRecord(st).Serialize(); err == nil {
		f.Add(ser)
	}
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Fuzz(func(_ *testing.T, b []byte) {
		rec, err := DeserializeSessionRecord(b)
		if err != nil {
			return
		}
		// If it decoded, serialize must not panic and previous-state decoding
		// must not panic (it may error on malformed archived blobs).
		if _, err := rec.Serialize(); err != nil {
			return
		}
		_, _ = rec.PreviousStates()
	})
}

// TestNewSessionStateNilStructure confirms NewSessionState(nil) yields a usable,
// panic-free state backed by a non-nil structure: getters return zero values and
// setters (which would panic on a nil structure) work.
func TestNewSessionStateNilStructure(t *testing.T) {
	st := NewSessionState(nil)
	if st == nil {
		t.Fatal("NewSessionState(nil) returned nil")
	}
	if st.Structure() == nil {
		t.Fatal("NewSessionState(nil) left a nil backing structure")
	}
	// A getter on the zero-value structure is safe and returns the zero value.
	if v := st.SessionVersion(); v != 0 {
		t.Fatalf("SessionVersion() = %d, want 0", v)
	}
	// A setter must not panic on the (formerly nil) structure.
	st.SetRemoteRegistrationID(7)
	if got := st.RemoteRegistrationID(); got != 7 {
		t.Fatalf("RemoteRegistrationID() = %d, want 7", got)
	}
}

// TestPendingPreKeyMessageContract pins the documented contract of
// PendingPreKeyMessage: the EC pending pre-key record is the SOLE gate (absent =>
// ok=false), the Kyber pending record is OPTIONAL and read opportunistically,
// and the one-time pre-key id round-trips iff it was set. This mirrors upstream
// SessionState::unacknowledged_pre_key_message_items, which keys only on
// pending_pre_key and treats pending_kyber_pre_key as an Option.
func TestPendingPreKeyMessageContract(t *testing.T) {
	base := genKeyPair(t, 60)

	// (a) No pending state at all -> ok=false.
	if _, ok := NewEmptySessionState().PendingPreKeyMessage(); ok {
		t.Fatal("empty state: PendingPreKeyMessage ok=true, want false")
	}

	// (b) EC pending present, NO Kyber record -> ok=true, Kyber fields absent.
	// (The EC record alone is sufficient; Kyber is optional per the contract.)
	stNoKyber := NewEmptySessionState()
	stNoKyber.SetUnacknowledgedPreKeyMessage(nil, 55, base.PublicKey, 1234)
	got, ok := stNoKyber.PendingPreKeyMessage()
	if !ok {
		t.Fatal("EC-only pending: ok=false, want true (Kyber is optional)")
	}
	if got.KyberPreKeyID != nil || len(got.KyberCiphertext) != 0 {
		t.Fatalf("EC-only pending: Kyber fields set (id=%v, ct len=%d), want absent", got.KyberPreKeyID, len(got.KyberCiphertext))
	}
	if got.PreKeyID != nil {
		t.Fatalf("EC-only pending without one-time prekey: PreKeyID=%v, want nil", *got.PreKeyID)
	}
	if got.SignedPreKeyID != 55 || got.UnixSeconds != 1234 || !bytes.Equal(got.BaseKey, base.PublicKey.Serialize()) {
		t.Fatalf("EC-only pending: fields mismatch: %+v", got)
	}

	// (c) EC + Kyber both present, WITH a one-time pre-key id -> all fields filled.
	stFull := NewEmptySessionState()
	oneTimeID := uint32(77)
	stFull.SetUnacknowledgedPreKeyMessage(&oneTimeID, 55, base.PublicKey, 1234)
	stFull.SetKyberCiphertext([]byte("kyber-ct"))
	if err := stFull.SetUnacknowledgedKyberPreKeyID(66); err != nil {
		t.Fatalf("SetUnacknowledgedKyberPreKeyID: %v", err)
	}
	gotFull, ok := stFull.PendingPreKeyMessage()
	if !ok {
		t.Fatal("full pending: ok=false, want true")
	}
	if gotFull.PreKeyID == nil || *gotFull.PreKeyID != oneTimeID {
		t.Fatalf("full pending: PreKeyID=%v, want %d", gotFull.PreKeyID, oneTimeID)
	}
	if gotFull.KyberPreKeyID == nil || *gotFull.KyberPreKeyID != 66 {
		t.Fatalf("full pending: KyberPreKeyID=%v, want 66", gotFull.KyberPreKeyID)
	}
	if !bytes.Equal(gotFull.KyberCiphertext, []byte("kyber-ct")) {
		t.Fatalf("full pending: KyberCiphertext=%q, want %q", gotFull.KyberCiphertext, "kyber-ct")
	}

	// (d) Clearing the EC record makes it absent again even if a Kyber record
	// lingers — the EC record is the gate.
	stFull.ClearUnacknowledgedPreKeyMessage()
	if _, ok := stFull.PendingPreKeyMessage(); ok {
		t.Fatal("after clear: ok=true, want false")
	}
}
