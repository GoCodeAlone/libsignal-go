package groups

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/stores/inmem"
)

func testAddress(t *testing.T, name string, device uint32) address.ProtocolAddress {
	t.Helper()
	dev, err := address.NewDeviceID(device)
	if err != nil {
		t.Fatalf("device id: %v", err)
	}
	return address.NewProtocolAddress(name, dev)
}

func distributionID() [16]byte {
	var id [16]byte
	id[0] = 0xab
	id[15] = 0xcd
	return id
}

// TestCreateThenProcessSenderKeyDistributionMessage is the core group-setup
// flow: a sender creates an SKDM (which provisions a fresh chain in its own
// store), a second participant processes it, and the resulting states must
// agree on chain id, iteration, chain key, and signing public key.
func TestCreateThenProcessSenderKeyDistributionMessage(t *testing.T) {
	ctx := context.Background()
	sender := testAddress(t, "+14155550100", 1)
	distID := distributionID()

	senderStore := inmem.NewSenderKeyStore()
	receiverStore := inmem.NewSenderKeyStore()

	skdm, err := CreateSenderKeyDistributionMessage(ctx, sender, distID, senderStore, rand.Reader)
	if err != nil {
		t.Fatalf("create SKDM: %v", err)
	}

	if err := ProcessSenderKeyDistributionMessage(ctx, sender, skdm, receiverStore); err != nil {
		t.Fatalf("process SKDM: %v", err)
	}

	// Load both records and compare the head states.
	senderRec := loadRecord(ctx, t, senderStore, sender, distID)
	receiverRec := loadRecord(ctx, t, receiverStore, sender, distID)

	senderState := senderRec.SenderKeyStateForChainID(skdm.ChainID())
	receiverState := receiverRec.SenderKeyStateForChainID(skdm.ChainID())
	if senderState == nil || receiverState == nil {
		t.Fatal("expected both stores to hold the chain id")
	}

	if senderState.ChainID() != receiverState.ChainID() {
		t.Fatalf("chain id mismatch: %d vs %d", senderState.ChainID(), receiverState.ChainID())
	}
	if senderState.MessageVersion() != receiverState.MessageVersion() {
		t.Fatalf("message version mismatch: %d vs %d", senderState.MessageVersion(), receiverState.MessageVersion())
	}
	sSck, _ := senderState.ChainKey()
	rSck, _ := receiverState.ChainKey()
	if sSck.Iteration() != rSck.Iteration() {
		t.Fatalf("iteration mismatch: %d vs %d", sSck.Iteration(), rSck.Iteration())
	}
	if !bytes.Equal(sSck.Seed(), rSck.Seed()) {
		t.Fatalf("chain key mismatch: %x vs %x", sSck.Seed(), rSck.Seed())
	}
	sPub, _ := senderState.SigningKeyPublic()
	rPub, ok := receiverState.SigningKeyPublic()
	if !ok || !sPub.Equal(rPub) {
		t.Fatal("signing public key mismatch")
	}

	// The receiver must NOT have the private signing key (process passes None).
	if _, ok := receiverState.SigningKeyPrivate(); ok {
		t.Fatal("receiver must not hold the private signing key")
	}
	// The sender (creator) must hold the private signing key.
	if _, ok := senderState.SigningKeyPrivate(); !ok {
		t.Fatal("sender must hold the private signing key")
	}
}

// TestCreateSenderKeyDistributionMessage_Idempotent verifies that creating an
// SKDM twice for the same (sender, distribution) reuses the existing chain (no
// new chain id, no re-randomized key) — upstream only provisions when absent.
func TestCreateSenderKeyDistributionMessage_Idempotent(t *testing.T) {
	ctx := context.Background()
	sender := testAddress(t, "+14155550100", 1)
	distID := distributionID()
	store := inmem.NewSenderKeyStore()

	first, err := CreateSenderKeyDistributionMessage(ctx, sender, distID, store, rand.Reader)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	second, err := CreateSenderKeyDistributionMessage(ctx, sender, distID, store, rand.Reader)
	if err != nil {
		t.Fatalf("second create: %v", err)
	}

	if first.ChainID() != second.ChainID() {
		t.Fatalf("chain id changed across creates: %d vs %d", first.ChainID(), second.ChainID())
	}
	if first.Iteration() != second.Iteration() {
		t.Fatalf("iteration changed: %d vs %d", first.Iteration(), second.Iteration())
	}
	if !bytes.Equal(first.ChainKey(), second.ChainKey()) {
		t.Fatal("chain key changed across creates")
	}
	if !first.SigningKey().Equal(second.SigningKey()) {
		t.Fatal("signing key changed across creates")
	}
}

// TestCreateSenderKeyDistributionMessage_ChainIDIs31Bit checks the chain id is
// drawn as a 31-bit integer (top bit clear), matching upstream's
// libsignal-protocol-java compatibility note.
func TestCreateSenderKeyDistributionMessage_ChainIDIs31Bit(t *testing.T) {
	ctx := context.Background()
	sender := testAddress(t, "+14155550100", 1)
	store := inmem.NewSenderKeyStore()
	for i := 0; i < 50; i++ {
		var distID [16]byte
		distID[0] = byte(i)
		skdm, err := CreateSenderKeyDistributionMessage(ctx, sender, distID, store, rand.Reader)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if skdm.ChainID()&0x8000_0000 != 0 {
			t.Fatalf("chain id %d has the high bit set (must be 31-bit)", skdm.ChainID())
		}
	}
}

// TestProcessSenderKeyDistributionMessage_MultipleSenders confirms a receiver
// can hold sender keys from distinct senders under the same distribution id
// (the store is keyed by (sender, distributionID)).
func TestProcessSenderKeyDistributionMessage_MultipleSenders(t *testing.T) {
	ctx := context.Background()
	distID := distributionID()
	alice := testAddress(t, "+14155550100", 1)
	bob := testAddress(t, "+14155550101", 1)

	aliceStore := inmem.NewSenderKeyStore()
	bobStore := inmem.NewSenderKeyStore()
	receiverStore := inmem.NewSenderKeyStore()

	aliceSKDM, err := CreateSenderKeyDistributionMessage(ctx, alice, distID, aliceStore, rand.Reader)
	if err != nil {
		t.Fatalf("alice create: %v", err)
	}
	bobSKDM, err := CreateSenderKeyDistributionMessage(ctx, bob, distID, bobStore, rand.Reader)
	if err != nil {
		t.Fatalf("bob create: %v", err)
	}
	if err := ProcessSenderKeyDistributionMessage(ctx, alice, aliceSKDM, receiverStore); err != nil {
		t.Fatalf("process alice: %v", err)
	}
	if err := ProcessSenderKeyDistributionMessage(ctx, bob, bobSKDM, receiverStore); err != nil {
		t.Fatalf("process bob: %v", err)
	}

	aliceRec := loadRecord(ctx, t, receiverStore, alice, distID)
	bobRec := loadRecord(ctx, t, receiverStore, bob, distID)
	if aliceRec.SenderKeyStateForChainID(aliceSKDM.ChainID()) == nil {
		t.Fatal("missing alice's chain")
	}
	if bobRec.SenderKeyStateForChainID(bobSKDM.ChainID()) == nil {
		t.Fatal("missing bob's chain")
	}
}

func loadRecord(ctx context.Context, t *testing.T, store *inmem.SenderKeyStore, sender address.ProtocolAddress, distID [16]byte) *SenderKeyRecord {
	t.Helper()
	raw, err := store.LoadSenderKey(ctx, sender, distID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if raw == nil {
		t.Fatal("expected a stored record")
	}
	rec, err := DeserializeSenderKeyRecord(raw)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	return rec
}
