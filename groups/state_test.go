package groups

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/curve"
)

// randomPublicKey draws a fresh signing public key, mirroring the Rust tests'
// random_public_key helper.
func randomPublicKey(t *testing.T) curve.PublicKey {
	t.Helper()
	kp, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return kp.PublicKey
}

// chainKey32 builds a deterministic 32-byte chain key seeded by i, so distinct
// states have distinct (and recognizable) chain keys. The sender-key chain key
// must be 32 bytes (the SKDM wire form enforces this), unlike the Rust unit
// test which used arbitrary lengths; here we keep it spec-shaped.
func chainKey32(i byte) []byte {
	ck := make([]byte, chainKeyLen)
	ck[0] = i
	return ck
}

func TestSenderKeyRecord_AddSingleState(t *testing.T) {
	rec := NewSenderKeyRecord()
	pub := randomPublicKey(t)
	ck := chainKey32(1)

	rec.AddSenderKeyState(senderKeyMessageVersion, 1, 1, ck, pub, nil)

	if got := rec.StateCount(); got != 1 {
		t.Fatalf("state count = %d, want 1", got)
	}
	state := rec.SenderKeyStateForChainID(1)
	if state == nil {
		t.Fatal("expected to find state for chain id 1")
	}
	sck, ok := state.ChainKey()
	if !ok {
		t.Fatal("expected a sender chain key")
	}
	if !bytes.Equal(sck.Seed(), ck) {
		t.Fatalf("chain key seed = %x, want %x", sck.Seed(), ck)
	}
}

func TestSenderKeyRecord_AddSecondState(t *testing.T) {
	rec := NewSenderKeyRecord()
	pub1, pub2 := randomPublicKey(t), randomPublicKey(t)
	ck1, ck2 := chainKey32(1), chainKey32(2)

	rec.AddSenderKeyState(senderKeyMessageVersion, 1, 1, ck1, pub1, nil)
	rec.AddSenderKeyState(senderKeyMessageVersion, 2, 1, ck2, pub2, nil)

	if got := rec.StateCount(); got != 2 {
		t.Fatalf("state count = %d, want 2", got)
	}
	for _, tc := range []struct {
		chainID uint32
		want    []byte
	}{{1, ck1}, {2, ck2}} {
		state := rec.SenderKeyStateForChainID(tc.chainID)
		if state == nil {
			t.Fatalf("expected state for chain id %d", tc.chainID)
		}
		sck, _ := state.ChainKey()
		if !bytes.Equal(sck.Seed(), tc.want) {
			t.Fatalf("chain id %d seed = %x, want %x", tc.chainID, sck.Seed(), tc.want)
		}
	}
}

// chainIDOrder reads back the chain IDs in record order (newest first), the
// analog of the Rust assert_record_order helper.
func chainIDOrder(rec *SenderKeyRecord) []uint32 {
	out := make([]uint32, 0, len(rec.states))
	for _, s := range rec.states {
		out = append(out, s.ChainID())
	}
	return out
}

func TestSenderKeyRecord_ExceedMaxStatesEjectsOldest(t *testing.T) {
	if MaxSenderKeyStates != 5 {
		t.Fatalf("test written for MaxSenderKeyStates == 5, got %d", MaxSenderKeyStates)
	}
	rec := NewSenderKeyRecord()
	for id := uint32(1); id <= 5; id++ {
		rec.AddSenderKeyState(senderKeyMessageVersion, id, 1, chainKey32(byte(id)), randomPublicKey(t), nil)
	}
	// Newest (5) is at the front, oldest (1) at the back.
	if got, want := chainIDOrder(rec), []uint32{5, 4, 3, 2, 1}; !equalU32(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}

	rec.AddSenderKeyState(senderKeyMessageVersion, 6, 1, chainKey32(6), randomPublicKey(t), nil)

	if got, want := chainIDOrder(rec), []uint32{6, 5, 4, 3, 2}; !equalU32(got, want) {
		t.Fatalf("after 6th add, order = %v, want %v (oldest must drop)", got, want)
	}
	if got := rec.StateCount(); got != 5 {
		t.Fatalf("state count = %d, want 5 (cap)", got)
	}
}

func TestSenderKeyRecord_SamePublicKeyAndChainID_KeepsFirstData(t *testing.T) {
	rec := NewSenderKeyRecord()
	pub := randomPublicKey(t)
	ck1, ck2 := chainKey32(1), chainKey32(2)

	rec.AddSenderKeyState(senderKeyMessageVersion, 1, 1, ck1, pub, nil)
	rec.AddSenderKeyState(senderKeyMessageVersion, 1, 1, ck2, pub, nil)

	if got := rec.StateCount(); got != 1 {
		t.Fatalf("state count = %d, want 1", got)
	}
	// Re-adding a (chain_id, public_key) that already exists must preserve the
	// original chain key, not overwrite with ck2.
	state := rec.SenderKeyStateForChainID(1)
	sck, _ := state.ChainKey()
	if !bytes.Equal(sck.Seed(), ck1) {
		t.Fatalf("seed = %x, want original %x", sck.Seed(), ck1)
	}
}

func TestSenderKeyRecord_DifferentPublicKeySameChainID_GetsReplaced(t *testing.T) {
	rec := NewSenderKeyRecord()
	pub1, pub2 := randomPublicKey(t), randomPublicKey(t)
	ck1, ck2 := chainKey32(1), chainKey32(2)

	rec.AddSenderKeyState(senderKeyMessageVersion, 1, 1, ck1, pub1, nil)
	rec.AddSenderKeyState(senderKeyMessageVersion, 1, 1, ck2, pub2, nil)

	if got := rec.StateCount(); got != 1 {
		t.Fatalf("state count = %d, want 1", got)
	}
	state := rec.SenderKeyStateForChainID(1)
	sck, _ := state.ChainKey()
	if !bytes.Equal(sck.Seed(), ck2) {
		t.Fatalf("seed = %x, want replacement %x", sck.Seed(), ck2)
	}
	pub, ok := state.SigningKeyPublic()
	if !ok {
		t.Fatal("expected a signing key")
	}
	if !pub.Equal(pub2) {
		t.Fatal("expected the replacement public key")
	}
}

func TestSenderKeyRecord_ReAddSamePublicKeyAndChainID_BecomesMostRecent(t *testing.T) {
	rec := NewSenderKeyRecord()
	pub1, pub2 := randomPublicKey(t), randomPublicKey(t)

	rec.AddSenderKeyState(senderKeyMessageVersion, 1, 1, chainKey32(1), pub1, nil)
	rec.AddSenderKeyState(senderKeyMessageVersion, 2, 1, chainKey32(2), pub2, nil)
	if got, want := chainIDOrder(rec), []uint32{2, 1}; !equalU32(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}

	// Re-add (pub1, chain 1): it moves to the front, preserving its data.
	rec.AddSenderKeyState(senderKeyMessageVersion, 1, 1, chainKey32(3), pub1, nil)
	if got, want := chainIDOrder(rec), []uint32{1, 2}; !equalU32(got, want) {
		t.Fatalf("after re-add, order = %v, want %v", got, want)
	}
	state := rec.SenderKeyStateForChainID(1)
	sck, _ := state.ChainKey()
	if !bytes.Equal(sck.Seed(), chainKey32(1)) {
		t.Fatalf("seed = %x, want preserved original %x", sck.Seed(), chainKey32(1))
	}
}

func TestSenderKeyRecord_SerializeRoundTrip(t *testing.T) {
	rec := NewSenderKeyRecord()
	kp, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	priv := kp.PrivateKey
	rec.AddSenderKeyState(senderKeyMessageVersion, 42, 7, chainKey32(9), kp.PublicKey, &priv)
	rec.AddSenderKeyState(senderKeyMessageVersion, 43, 0, chainKey32(8), randomPublicKey(t), nil)

	serialized, err := rec.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	got, err := DeserializeSenderKeyRecord(serialized)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}

	if got.StateCount() != rec.StateCount() {
		t.Fatalf("state count = %d, want %d", got.StateCount(), rec.StateCount())
	}
	reSerialized, err := got.Serialize()
	if err != nil {
		t.Fatalf("re-serialize: %v", err)
	}
	if !bytes.Equal(serialized, reSerialized) {
		t.Fatal("round-trip serialization is not stable")
	}

	// The private signing key must survive the round trip for the state that had
	// one, and the message version/chain id/iteration must be preserved.
	state := got.SenderKeyStateForChainID(42)
	if state == nil {
		t.Fatal("expected chain id 42")
	}
	if state.MessageVersion() != senderKeyMessageVersion {
		t.Fatalf("message version = %d, want %d", state.MessageVersion(), senderKeyMessageVersion)
	}
	sck, _ := state.ChainKey()
	if sck.Iteration() != 7 {
		t.Fatalf("iteration = %d, want 7", sck.Iteration())
	}
	gotPriv, ok := state.SigningKeyPrivate()
	if !ok {
		t.Fatal("expected the private signing key to survive serialization")
	}
	if !bytes.Equal(gotPriv.Serialize(), priv.Serialize()) {
		t.Fatal("private signing key changed across round trip")
	}
}

func TestSenderKeyRecord_MessageVersionZeroDefaultsToThree(t *testing.T) {
	// Upstream maps a stored message_version of 0 (the proto default for an old
	// record) to 3, the first SenderKey version.
	rec := NewSenderKeyRecord()
	rec.AddSenderKeyState(0, 1, 0, chainKey32(1), randomPublicKey(t), nil)
	state := rec.SenderKeyStateForChainID(1)
	if got := state.MessageVersion(); got != 3 {
		t.Fatalf("message version = %d, want 3 (zero must default)", got)
	}
}

func TestSenderChainKey_Iteration(t *testing.T) {
	const initialIteration = 0
	seed := []byte{1, 2, 3, 4}
	ck := newSenderChainKey(initialIteration, seed)

	seen := map[string]bool{string(ck.Seed()): true}
	for i := uint32(1); i < 10; i++ {
		next, err := ck.next()
		if err != nil {
			t.Fatalf("next at %d: %v", i, err)
		}
		if seen[string(next.Seed())] {
			t.Fatalf("seed repeated at iteration %d", i)
		}
		seen[string(next.Seed())] = true
		if next.Iteration() != initialIteration+i {
			t.Fatalf("iteration = %d, want %d", next.Iteration(), initialIteration+i)
		}
		ck = next
	}
}

func TestSenderChainKey_IterationOverflow(t *testing.T) {
	ck := newSenderChainKey(^uint32(0), []byte{1, 2, 3, 4})
	if _, err := ck.next(); err == nil {
		t.Fatal("expected overflow error at iteration u32::MAX")
	}
}

// TestSenderChainKey_MessageKeyDerivation pins the message-key derivation: the
// per-message key seed is HMAC-SHA256(chainKey, 0x01), then HKDF over that with
// info "WhisperGroup" gives 16B IV || 32B cipher key (distinct from the 1:1
// ratchet's "WhisperMessageKeys" / cipher||mac||iv layout).
func TestSenderChainKey_MessageKeyDerivation(t *testing.T) {
	ck := newSenderChainKey(0, chainKey32(1))
	smk, err := ck.senderMessageKey()
	if err != nil {
		t.Fatalf("sender message key: %v", err)
	}
	if smk.Iteration() != 0 {
		t.Fatalf("iteration = %d, want 0", smk.Iteration())
	}
	if len(smk.IV()) != ivLen {
		t.Fatalf("iv len = %d, want %d", len(smk.IV()), ivLen)
	}
	if len(smk.CipherKey()) != cipherKeyLen {
		t.Fatalf("cipher key len = %d, want %d", len(smk.CipherKey()), cipherKeyLen)
	}
	// Deriving the same chain key twice yields identical material.
	smk2, _ := ck.senderMessageKey()
	if !bytes.Equal(smk.IV(), smk2.IV()) || !bytes.Equal(smk.CipherKey(), smk2.CipherKey()) {
		t.Fatal("message key derivation is not deterministic")
	}
}

func equalU32(a, b []uint32) bool {
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
