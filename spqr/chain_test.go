package spqr

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/proto"
)

// defaultParams returns a fresh ChainParams with proto-default (zero) fields, so
// ResolveMaxJump/resolveMaxOOO apply the 25000/2000 library defaults.
func defaultParams() *proto.ChainParams { return &proto.ChainParams{} }

// TestChainDirectionsMatch ports chain.rs directions_match: an A2B chain's
// send_key must equal the mirror B2A chain's recv_key at the same (epoch,index),
// across an epoch advance and a run of sends. This is the cross-direction
// agreement check — it fails if the KDF info strings, the zero salt, the 96-byte
// direction slicing, or the next-key derivation diverge from the reference.
func TestChainDirectionsMatch(t *testing.T) {
	a2b := newChain([]byte("1"), proto.Direction_A_2_B, defaultParams())
	b2a := newChain([]byte("1"), proto.Direction_B_2_A, defaultParams())

	idx, sk1, err := a2b.sendKey(0)
	if err != nil {
		t.Fatalf("a2b.sendKey(0): %v", err)
	}
	if idx != 1 {
		t.Fatalf("first send index = %d, want 1", idx)
	}
	rk1, err := b2a.recvKey(0, 1)
	if err != nil {
		t.Fatalf("b2a.recvKey(0,1): %v", err)
	}
	if !bytes.Equal(sk1, rk1) {
		t.Fatal("epoch 0 send key != mirror recv key")
	}

	if err := a2b.addEpoch(epochSecret{epoch: 1, secret: []byte{2}}); err != nil {
		t.Fatalf("a2b.addEpoch: %v", err)
	}
	if err := b2a.addEpoch(epochSecret{epoch: 1, secret: []byte{2}}); err != nil {
		t.Fatalf("b2a.addEpoch: %v", err)
	}

	idx, sk2, err := a2b.sendKey(1)
	if err != nil {
		t.Fatalf("a2b.sendKey(1): %v", err)
	}
	if idx != 1 {
		t.Fatalf("epoch-1 first index = %d, want 1", idx)
	}
	rk2, err := b2a.recvKey(1, 1)
	if err != nil {
		t.Fatalf("b2a.recvKey(1,1): %v", err)
	}
	if !bytes.Equal(sk2, rk2) {
		t.Fatal("epoch 1 send key != mirror recv key")
	}

	// Advance to index 10 on the send side, then the mirror recovers it.
	for i := 2; i < 10; i++ {
		if _, _, err := a2b.sendKey(1); err != nil {
			t.Fatalf("a2b.sendKey(1) iter %d: %v", i, err)
		}
	}
	idx, sk3, err := a2b.sendKey(1)
	if err != nil {
		t.Fatalf("a2b.sendKey(1) final: %v", err)
	}
	if idx != 10 {
		t.Fatalf("send index = %d, want 10", idx)
	}
	rk3, err := b2a.recvKey(1, 10)
	if err != nil {
		t.Fatalf("b2a.recvKey(1,10): %v", err)
	}
	if !bytes.Equal(sk3, rk3) {
		t.Fatal("epoch 1 index-10 send key != mirror recv key")
	}
}

// TestChainPreviouslyReturnedKey ports previously_returned_key: requesting the
// same recv index twice is KeyAlreadyRequested.
func TestChainPreviouslyReturnedKey(t *testing.T) {
	a2b := newChain([]byte("1"), proto.Direction_A_2_B, defaultParams())
	if _, err := a2b.recvKey(0, 2); err != nil {
		t.Fatalf("first recvKey(0,2): %v", err)
	}
	if _, err := a2b.recvKey(0, 2); !errors.Is(err, ErrKeyAlreadyRequested) {
		t.Fatalf("re-request err = %v, want ErrKeyAlreadyRequested", err)
	}
}

// TestChainVeryOldKeysTrimmed ports very_old_keys_are_trimmed: with a small OOO
// window, a recv index that fell behind the horizon is KeyTrimmed.
func TestChainVeryOldKeysTrimmed(t *testing.T) {
	params := &proto.ChainParams{MaxJump: 10, MaxOooKeys: 10}
	a2b := newChain([]byte("1"), proto.Direction_A_2_B, params)
	if _, err := a2b.recvKey(0, 10); err != nil {
		t.Fatalf("recvKey(0,10): %v", err)
	}
	if _, err := a2b.recvKey(0, 12); err != nil {
		t.Fatalf("recvKey(0,12): %v", err)
	}
	if _, err := a2b.recvKey(0, 1); !errors.Is(err, ErrKeyTrimmed) {
		t.Fatalf("recvKey(0,1) err = %v, want ErrKeyTrimmed", err)
	}
}

// TestChainOutOfOrder ports out_of_order_keys: a window of send keys is recovered
// by recv in shuffled order.
func TestChainOutOfOrder(t *testing.T) {
	const window = 2000 // defaultMaxOOOKeys
	a2b := newChain([]byte("1"), proto.Direction_A_2_B, defaultParams())
	b2a := newChain([]byte("1"), proto.Direction_B_2_A, defaultParams())

	type kv struct {
		idx uint32
		key []byte
	}
	keys := make([]kv, 0, window)
	for i := 0; i < window; i++ {
		idx, k, err := a2b.sendKey(0)
		if err != nil {
			t.Fatalf("sendKey iter %d: %v", i, err)
		}
		keys = append(keys, kv{idx, k})
	}
	rng := rand.New(rand.NewSource(1))
	rng.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
	for _, e := range keys {
		got, err := b2a.recvKey(0, e.idx)
		if err != nil {
			t.Fatalf("recvKey(0,%d): %v", e.idx, err)
		}
		if !bytes.Equal(got, e.key) {
			t.Fatalf("recvKey(0,%d) mismatch", e.idx)
		}
	}
}

// TestChainClearOldSendKeys ports clear_old_send_keys: after advancing the send
// epoch, asking for a key on an older send epoch is SendKeyEpochDecreased.
func TestChainClearOldSendKeys(t *testing.T) {
	a2b := newChain([]byte("1"), proto.Direction_A_2_B, defaultParams())
	if _, _, err := a2b.sendKey(0); err != nil {
		t.Fatalf("sendKey(0): %v", err)
	}
	if _, _, err := a2b.sendKey(0); err != nil {
		t.Fatalf("sendKey(0): %v", err)
	}
	if err := a2b.addEpoch(epochSecret{epoch: 1, secret: []byte{2}}); err != nil {
		t.Fatalf("addEpoch: %v", err)
	}
	if _, _, err := a2b.sendKey(1); err != nil {
		t.Fatalf("sendKey(1): %v", err)
	}
	if _, _, err := a2b.sendKey(0); !errors.Is(err, ErrSendKeyEpochDecreased) {
		t.Fatalf("sendKey(0) after advance err = %v, want ErrSendKeyEpochDecreased", err)
	}
}

// TestChainProtoRoundTrip checks a chain serializes and parses back, preserving
// the key schedule (the recovered chain produces the same next send key).
func TestChainProtoRoundTrip(t *testing.T) {
	a2b := newChain([]byte("seed"), proto.Direction_A_2_B, defaultParams())
	if _, _, err := a2b.sendKey(0); err != nil {
		t.Fatalf("sendKey: %v", err)
	}
	pb := a2b.toProto()
	got, err := chainFromProto(pb)
	if err != nil {
		t.Fatalf("chainFromProto: %v", err)
	}
	idxA, keyA, _ := a2b.sendKey(0)
	idxB, keyB, _ := got.sendKey(0)
	if idxA != idxB || !bytes.Equal(keyA, keyB) {
		t.Fatal("round-tripped chain diverges on next send key")
	}
}
