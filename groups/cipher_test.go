package groups

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/stores/inmem"
)

// groupOf3 sets up a sender that has distributed its sender key to two
// receivers (each with its own store), returning the sender address, the
// distribution id, and the three stores. The sender's own store holds the chain
// with the private signing key; each receiver's store holds the public-only
// state after processing the SKDM.
func groupOf3(t *testing.T) (address.ProtocolAddress, [16]byte, *inmem.SenderKeyStore, *inmem.SenderKeyStore, *inmem.SenderKeyStore) {
	t.Helper()
	ctx := context.Background()
	sender := testAddress(t, "+14155550100", 1)
	distID := distributionID()

	senderStore := inmem.NewSenderKeyStore()
	rx1 := inmem.NewSenderKeyStore()
	rx2 := inmem.NewSenderKeyStore()

	skdm, err := CreateSenderKeyDistributionMessage(ctx, sender, distID, senderStore, rand.Reader)
	if err != nil {
		t.Fatalf("create SKDM: %v", err)
	}
	if err := ProcessSenderKeyDistributionMessage(ctx, sender, skdm, rx1); err != nil {
		t.Fatalf("process SKDM rx1: %v", err)
	}
	if err := ProcessSenderKeyDistributionMessage(ctx, sender, skdm, rx2); err != nil {
		t.Fatalf("process SKDM rx2: %v", err)
	}
	return sender, distID, senderStore, rx1, rx2
}

// TestGroupEncryptDecrypt_TwoReceivers is the core group flow: the sender
// encrypts once and both receivers decrypt to the byte-identical plaintext.
func TestGroupEncryptDecrypt_TwoReceivers(t *testing.T) {
	ctx := context.Background()
	sender, distID, senderStore, rx1, rx2 := groupOf3(t)
	plaintext := []byte("hello group, this is a sender-key message")

	skm, err := Encrypt(ctx, sender, distID, plaintext, senderStore, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	for name, store := range map[string]*inmem.SenderKeyStore{"rx1": rx1, "rx2": rx2} {
		got, err := Decrypt(ctx, sender, skm.Serialized(), store)
		if err != nil {
			t.Fatalf("%s decrypt: %v", name, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("%s plaintext = %q, want %q", name, got, plaintext)
		}
	}
}

// TestGroupEncryptDecrypt_InOrderSequence checks a run of messages decrypts in
// order, with the chain advancing one iteration per message on both sides.
func TestGroupEncryptDecrypt_InOrderSequence(t *testing.T) {
	ctx := context.Background()
	sender, distID, senderStore, rx1, _ := groupOf3(t)

	for i := 0; i < 20; i++ {
		pt := []byte{byte(i), 0xAA, byte(i * 7)}
		skm, err := Encrypt(ctx, sender, distID, pt, senderStore, rand.Reader)
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		if skm.Iteration() != uint32(i) {
			t.Fatalf("message %d has iteration %d, want %d", i, skm.Iteration(), i)
		}
		got, err := Decrypt(ctx, sender, skm.Serialized(), rx1)
		if err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("message %d plaintext = %x, want %x", i, got, pt)
		}
	}
}

// TestGroupDecrypt_OutOfOrderWithinCap checks the skipped-message-key cache:
// the sender produces several messages, the receiver decrypts a later one first
// (caching the skipped keys), then decrypts the earlier ones out of order.
func TestGroupDecrypt_OutOfOrderWithinCap(t *testing.T) {
	ctx := context.Background()
	sender, distID, senderStore, rx1, _ := groupOf3(t)

	const n = 6
	msgs := make([][]byte, n)  // serialized SKMs
	plain := make([][]byte, n) // matching plaintexts
	for i := 0; i < n; i++ {
		plain[i] = []byte{0x10 + byte(i), 0x20, 0x30 + byte(i)}
		skm, err := Encrypt(ctx, sender, distID, plain[i], senderStore, rand.Reader)
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		msgs[i] = skm.Serialized()
	}

	// Decrypt out of order: 3, then 0, 1, 2 (skipped keys cached at 3), then 5, 4.
	order := []int{3, 0, 1, 2, 5, 4}
	for _, i := range order {
		got, err := Decrypt(ctx, sender, msgs[i], rx1)
		if err != nil {
			t.Fatalf("decrypt msg %d (out of order): %v", i, err)
		}
		if !bytes.Equal(got, plain[i]) {
			t.Fatalf("msg %d plaintext = %x, want %x", i, got, plain[i])
		}
	}
}

// TestGroupDecrypt_Duplicate checks replay rejection: decrypting the same
// message twice fails the second time (its message key was consumed).
func TestGroupDecrypt_Duplicate(t *testing.T) {
	ctx := context.Background()
	sender, distID, senderStore, rx1, _ := groupOf3(t)

	skm, err := Encrypt(ctx, sender, distID, []byte("once"), senderStore, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := Decrypt(ctx, sender, skm.Serialized(), rx1); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}
	_, err = Decrypt(ctx, sender, skm.Serialized(), rx1)
	if err == nil {
		t.Fatal("second decrypt of the same message must fail (duplicate)")
	}
	if !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("duplicate decrypt error = %v, want ErrDuplicateMessage", err)
	}
}

// TestGroupDecrypt_DuplicateAfterSkip checks that decrypting a cached
// (previously skipped) key twice also fails as a duplicate.
func TestGroupDecrypt_DuplicateAfterSkip(t *testing.T) {
	ctx := context.Background()
	sender, distID, senderStore, rx1, _ := groupOf3(t)

	skm0, _ := Encrypt(ctx, sender, distID, []byte("m0"), senderStore, rand.Reader)
	skm1, _ := Encrypt(ctx, sender, distID, []byte("m1"), senderStore, rand.Reader)

	// Decrypt m1 first (caches m0's key), then m0, then m0 again.
	if _, err := Decrypt(ctx, sender, skm1.Serialized(), rx1); err != nil {
		t.Fatalf("decrypt m1: %v", err)
	}
	if _, err := Decrypt(ctx, sender, skm0.Serialized(), rx1); err != nil {
		t.Fatalf("decrypt m0 (from cache): %v", err)
	}
	_, err := Decrypt(ctx, sender, skm0.Serialized(), rx1)
	if !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("re-decrypt cached m0 error = %v, want ErrDuplicateMessage", err)
	}
}

// TestGroupDecrypt_TamperedSignature checks a message whose signature does not
// verify under the chain's signing key is rejected.
func TestGroupDecrypt_TamperedSignature(t *testing.T) {
	ctx := context.Background()
	sender, distID, senderStore, rx1, _ := groupOf3(t)

	skm, err := Encrypt(ctx, sender, distID, []byte("authentic"), senderStore, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Flip a byte in the trailing signature (last byte of the serialized form).
	tampered := append([]byte(nil), skm.Serialized()...)
	tampered[len(tampered)-1] ^= 0x01

	_, err = Decrypt(ctx, sender, tampered, rx1)
	if err == nil {
		t.Fatal("decrypt of a signature-tampered message must fail")
	}
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered-signature error = %v, want ErrSignatureInvalid", err)
	}
}

// TestGroupDecrypt_NoSession checks that a receiver with no record for the
// (sender, distribution) rejects the message.
func TestGroupDecrypt_NoSession(t *testing.T) {
	ctx := context.Background()
	sender, distID, senderStore, _, _ := groupOf3(t)

	skm, err := Encrypt(ctx, sender, distID, []byte("orphan"), senderStore, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	empty := inmem.NewSenderKeyStore()
	_, err = Decrypt(ctx, sender, skm.Serialized(), empty)
	if !errors.Is(err, ErrNoSenderKeyState) {
		t.Fatalf("decrypt with no record error = %v, want ErrNoSenderKeyState", err)
	}
}

// TestGroupDecrypt_WrongChainID checks that a message whose chain id is not in
// the receiver's record is rejected (no matching state).
func TestGroupDecrypt_WrongChainID(t *testing.T) {
	ctx := context.Background()
	sender, distID, senderStore, _, _ := groupOf3(t)

	skm, err := Encrypt(ctx, sender, distID, []byte("m"), senderStore, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Build a fresh receiver that only knows a *different* chain (a second
	// sender-key chain under the same distribution id, with a different chain id).
	other := inmem.NewSenderKeyStore()
	otherSenderStore := inmem.NewSenderKeyStore()
	otherSKDM, err := CreateSenderKeyDistributionMessage(ctx, sender, distID, otherSenderStore, rand.Reader)
	if err != nil {
		t.Fatalf("create other SKDM: %v", err)
	}
	if err := ProcessSenderKeyDistributionMessage(ctx, sender, otherSKDM, other); err != nil {
		t.Fatalf("process other SKDM: %v", err)
	}
	// `other` knows otherSKDM's chain id, not skm's (overwhelmingly different).
	if otherSKDM.ChainID() == skm.ChainID() {
		t.Skip("chain ids collided (1-in-2^31); rerun")
	}
	_, err = Decrypt(ctx, sender, skm.Serialized(), other)
	if !errors.Is(err, ErrNoSenderKeyState) {
		t.Fatalf("decrypt with wrong chain id error = %v, want ErrNoSenderKeyState", err)
	}
}

// TestGroupDecrypt_ForwardJumpCap checks the MAX_FORWARD_JUMPS bound: a message
// whose iteration is more than the cap beyond the receiver's current iteration
// is rejected rather than driving an unbounded ratchet.
func TestGroupDecrypt_ForwardJumpCap(t *testing.T) {
	ctx := context.Background()
	sender, distID, senderStore, rx1, _ := groupOf3(t)

	// Advance the SENDER's chain past the cap without producing decryptable
	// messages for the receiver, then encrypt: the receiver is still at
	// iteration 0, so the gap exceeds MAX_FORWARD_JUMPS.
	if err := advanceSenderChain(ctx, sender, distID, senderStore, MaxForwardJumps+2); err != nil {
		t.Fatalf("advance sender chain: %v", err)
	}
	skm, err := Encrypt(ctx, sender, distID, []byte("far future"), senderStore, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if skm.Iteration() <= MaxForwardJumps {
		t.Fatalf("setup: skm iteration %d not past the cap %d", skm.Iteration(), MaxForwardJumps)
	}
	_, err = Decrypt(ctx, sender, skm.Serialized(), rx1)
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("forward-jump-cap error = %v, want ErrInvalidMessage", err)
	}
}

// advanceSenderChain fast-forwards the sender's chain key by n iterations
// without emitting messages, by loading the record, stepping the head state's
// chain key, and storing it back. It exists only to set up the forward-jump
// test cheaply (vs. encrypting MaxForwardJumps real messages).
func advanceSenderChain(ctx context.Context, sender address.ProtocolAddress, distID [16]byte, store *inmem.SenderKeyStore, n int) error {
	raw, err := store.LoadSenderKey(ctx, sender, distID)
	if err != nil {
		return err
	}
	rec, err := DeserializeSenderKeyRecord(raw)
	if err != nil {
		return err
	}
	state, _ := rec.SenderKeyState()
	ck, _ := state.ChainKey()
	for i := 0; i < n; i++ {
		ck, err = ck.next()
		if err != nil {
			return err
		}
	}
	state.setSenderChainKey(ck)
	serialized, err := rec.Serialize()
	if err != nil {
		return err
	}
	return store.StoreSenderKey(ctx, sender, distID, serialized)
}
