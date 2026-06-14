// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/protocol"
)

// convo wires an established Alice<->Bob pair through the stores, ready to
// exchange messages. Alice is the initiator (ProcessPreKeyBundle); Bob's
// session is established via the InitializeBobSession seam from the same
// handshake material + Alice's base key + Kyber ciphertext.
type convo struct {
	aliceSess  *fakeSessionStore
	aliceID    *fakeIdentityStore
	bobSess    *fakeSessionStore
	bobIDStore *fakeIdentityStore
	bobAddr    address.ProtocolAddress
	aliceAddr  address.ProtocolAddress
}

func protoAddr(t *testing.T, name string) address.ProtocolAddress {
	t.Helper()
	dev, err := address.NewDeviceID(1)
	if err != nil {
		t.Fatalf("NewDeviceID: %v", err)
	}
	return address.NewProtocolAddress(name, dev)
}

func setupConvo(t *testing.T) *convo {
	t.Helper()
	ctx := context.Background()
	bob := makeBobBundle(t, true, tamperNone)

	aliceID := newFakeIdentityStore(t, 30, 1001)
	aliceSess := newFakeSessionStore()
	bobAddr := protoAddr(t, "+15550000bob")
	aliceAddr := protoAddr(t, "+15550000ali")

	// Alice processes Bob's bundle -> her session is stored.
	if err := ProcessPreKeyBundle(ctx, &fixedReaderB{b: 40}, bobAddr, bob.bundle, aliceSess, aliceID); err != nil {
		t.Fatalf("ProcessPreKeyBundle: %v", err)
	}

	// Recover Alice's base key + Kyber ciphertext from her session, then build
	// Bob's session from the same material via the recipient seam.
	aliceRec, _ := aliceSess.LoadSession(ctx, bobAddr)
	pending, ok := aliceRec.CurrentState().PendingPreKeyMessage()
	if !ok {
		t.Fatal("alice has no pending pre-key message")
	}
	aliceIdentityKP := aliceID.identity

	bobState, err := InitializeBobSession(BobParams{
		OurIdentity:   bob.identity,
		OurSignedPre:  bob.signedPre,
		OurOneTime:    bob.oneTime,
		OurKyber:      bob.kyber,
		TheirIdentity: aliceIdentityKP.PublicKey,
		TheirBaseKey:  mustPub(t, pending.BaseKey),
		KyberCipher:   pending.KyberCiphertext,
	})
	if err != nil {
		t.Fatalf("InitializeBobSession: %v", err)
	}
	bobSess := newFakeSessionStore()
	if err := bobSess.StoreSession(ctx, aliceAddr, NewSessionRecord(bobState)); err != nil {
		t.Fatalf("store bob session: %v", err)
	}

	return &convo{
		aliceSess: aliceSess,
		aliceID:   aliceID,
		bobSess:   bobSess,
		bobAddr:   bobAddr,
		aliceAddr: aliceAddr,
	}
}

func mustPub(t *testing.T, b []byte) curve.PublicKey {
	t.Helper()
	pk, err := curve.DeserializePublicKey(b)
	if err != nil {
		t.Fatalf("deserialize public key: %v", err)
	}
	return pk
}

// aliceEncrypt encrypts from Alice to Bob, returning the inner SignalMessage
// (Alice wraps in a PreKeySignalMessage until Bob replies; the inner message is
// what Bob's established session decrypts).
func (c *convo) aliceEncrypt(t *testing.T, msg []byte) *protocol.SignalMessage {
	t.Helper()
	signal, preKey, err := Encrypt(context.Background(), msg, c.bobAddr, c.aliceSess, c.aliceID, nil, cryptorand.Reader)
	if err != nil {
		t.Fatalf("alice Encrypt: %v", err)
	}
	if preKey != nil {
		return preKey.Message()
	}
	return signal
}

func (c *convo) bobDecrypt(t *testing.T, m *protocol.SignalMessage) []byte {
	t.Helper()
	pt, err := Decrypt(context.Background(), m, c.aliceAddr, c.bobSess, cryptorand.Reader)
	if err != nil {
		t.Fatalf("bob Decrypt: %v", err)
	}
	return pt
}

// tamperBody flips a byte inside the ciphertext body of a SignalMessage so the
// MAC will no longer verify, while keeping the framing parseable.
func tamperBody(t *testing.T, m *protocol.SignalMessage) *protocol.SignalMessage {
	t.Helper()
	raw := append([]byte(nil), m.Serialize()...)
	// Flip a byte near the middle (inside the protobuf body / ciphertext, well
	// clear of the 1-byte version prefix and the trailing 8-byte MAC).
	if len(raw) < 12 {
		t.Fatalf("serialized message too short to tamper: %d", len(raw))
	}
	raw[len(raw)/2] ^= 0x01
	tampered, err := protocol.DeserializeSignalMessage(raw)
	if err != nil {
		// If the flip broke framing, that's still a rejected message — but we
		// want a MAC failure specifically, so retry flipping a different byte.
		raw = append([]byte(nil), m.Serialize()...)
		raw[len(raw)-9] ^= 0x01 // last byte before the 8-byte MAC trailer
		tampered, err = protocol.DeserializeSignalMessage(raw)
		if err != nil {
			t.Fatalf("could not produce a parseable tampered message: %v", err)
		}
	}
	return tampered
}

// TestCipherConversation runs a 50-message conversation. Alice sends; Bob
// decrypts; each plaintext must round-trip byte-for-byte. (Alternating
// directions exercises the DH ratchet once Bob replies — covered by the
// dedicated ratchet-step test; here we drive a long single-direction run plus
// the first reply to keep the harness focused on chain stepping + wrapping.)
func TestCipherConversation(t *testing.T) {
	c := setupConvo(t)
	for i := 0; i < 50; i++ {
		msg := []byte(fmt.Sprintf("message number %d with some payload", i))
		ct := c.aliceEncrypt(t, msg)
		got := c.bobDecrypt(t, ct)
		if !bytes.Equal(got, msg) {
			t.Fatalf("msg %d: got %q want %q", i, got, msg)
		}
	}
}

// TestCipherPreKeyWrappingUntilReply asserts Alice wraps in a PreKeySignalMessage
// while unacknowledged. (Acknowledgement clearing happens on Alice's decrypt of
// Bob's reply, exercised in the ratchet test.)
func TestCipherPreKeyWrappingUntilReply(t *testing.T) {
	c := setupConvo(t)
	signal, preKey, err := Encrypt(context.Background(), []byte("hi"), c.bobAddr, c.aliceSess, c.aliceID, nil, cryptorand.Reader)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if preKey == nil || signal != nil {
		t.Fatal("expected a PreKeySignalMessage while unacknowledged, got a plain SignalMessage")
	}
}

// TestCipherOutOfOrder skips ahead then delivers the skipped message from the
// cached keys.
func TestCipherOutOfOrder(t *testing.T) {
	c := setupConvo(t)
	// Encrypt 5 messages; deliver #4 first (skips 0..3), then #0 from cache.
	msgs := make([]*protocol.SignalMessage, 5)
	plains := make([][]byte, 5)
	for i := range msgs {
		plains[i] = []byte(fmt.Sprintf("ooo-%d", i))
		msgs[i] = c.aliceEncrypt(t, plains[i])
	}
	// Deliver last first: Bob caches keys 0..3, decrypts 4.
	if got := c.bobDecrypt(t, msgs[4]); !bytes.Equal(got, plains[4]) {
		t.Fatalf("ooo #4: got %q", got)
	}
	// Now deliver #1 and #0 from the cache (any order).
	if got := c.bobDecrypt(t, msgs[1]); !bytes.Equal(got, plains[1]) {
		t.Fatalf("ooo #1 from cache: got %q", got)
	}
	if got := c.bobDecrypt(t, msgs[0]); !bytes.Equal(got, plains[0]) {
		t.Fatalf("ooo #0 from cache: got %q", got)
	}
}

// TestCipherDuplicate decrypts a message, then re-delivers it: the second must
// be ErrDuplicateMessage (its keys were consumed).
func TestCipherDuplicate(t *testing.T) {
	c := setupConvo(t)
	m := c.aliceEncrypt(t, []byte("once"))
	if got := c.bobDecrypt(t, m); !bytes.Equal(got, []byte("once")) {
		t.Fatalf("first decrypt: %q", got)
	}
	_, err := Decrypt(context.Background(), m, c.aliceAddr, c.bobSess, cryptorand.Reader)
	if !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("re-deliver err = %v, want ErrDuplicateMessage", err)
	}
}

// TestCipherFailedDecryptLeavesStoreUnchanged: a forged/corrupt message must
// not mutate Bob's stored session bytes.
func TestCipherFailedDecryptLeavesStoreUnchanged(t *testing.T) {
	c := setupConvo(t)
	m := c.aliceEncrypt(t, []byte("legit"))
	before := append([]byte(nil), c.bobSess.records[c.aliceAddr.String()]...)

	// Corrupt the ciphertext body so the MAC fails.
	tampered := tamperBody(t, m)
	_, err := Decrypt(context.Background(), tampered, c.aliceAddr, c.bobSess, cryptorand.Reader)
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("tampered decrypt err = %v, want ErrInvalidMessage", err)
	}
	if !bytes.Equal(before, c.bobSess.records[c.aliceAddr.String()]) {
		t.Fatal("stored session bytes changed after a failed decrypt")
	}
	// The legit message still decrypts afterward (state really was untouched).
	if got := c.bobDecrypt(t, m); !bytes.Equal(got, []byte("legit")) {
		t.Fatalf("legit decrypt after failure: %q", got)
	}
}

// TestCipherStaleSessionEncryptFails: with a clock advanced past
// MaxUnacknowledgedSessionAge, encrypting to an unacknowledged session fails as
// ErrSessionNotFound.
func TestCipherStaleSessionEncryptFails(t *testing.T) {
	c := setupConvo(t)
	future := func() time.Time { return time.Now().Add(MaxUnacknowledgedSessionAge + time.Hour) }
	_, _, err := Encrypt(context.Background(), []byte("late"), c.bobAddr, c.aliceSess, c.aliceID, future, cryptorand.Reader)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("stale encrypt err = %v, want ErrSessionNotFound", err)
	}
}

// TestCipherEncryptNoSession: encrypting with no stored session is
// ErrSessionNotFound.
func TestCipherEncryptNoSession(t *testing.T) {
	idStore := newFakeIdentityStore(t, 31, 1)
	sess := newFakeSessionStore()
	_, _, err := Encrypt(context.Background(), []byte("x"), protoAddr(t, "+1555nope"), sess, idStore, nil, cryptorand.Reader)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("no-session encrypt err = %v, want ErrSessionNotFound", err)
	}
}

// bobEncrypt encrypts from Bob back to Alice (plain SignalMessage; Bob's
// session has no pending pre-key). Returns the SignalMessage Alice decrypts.
func (c *convo) bobEncrypt(t *testing.T, msg []byte) *protocol.SignalMessage {
	t.Helper()
	signal, preKey, err := Encrypt(context.Background(), msg, c.aliceAddr, c.bobSess, c.bobID(t), nil, cryptorand.Reader)
	if err != nil {
		t.Fatalf("bob Encrypt: %v", err)
	}
	if preKey != nil {
		t.Fatal("bob unexpectedly produced a PreKeySignalMessage")
	}
	return signal
}

// bobID is a trust-all identity store for Bob (encrypt's trust check + save).
func (c *convo) bobID(t *testing.T) *fakeIdentityStore {
	t.Helper()
	if c.bobIDStore == nil {
		c.bobIDStore = newFakeIdentityStore(t, 32, 2002)
	}
	return c.bobIDStore
}

func (c *convo) aliceDecrypt(t *testing.T, m *protocol.SignalMessage) []byte {
	t.Helper()
	pt, err := Decrypt(context.Background(), m, c.bobAddr, c.aliceSess, cryptorand.Reader)
	if err != nil {
		t.Fatalf("alice Decrypt: %v", err)
	}
	return pt
}

// TestCipherRatchetStep drives a reply so the DH ratchet advances: Alice sends,
// Bob decrypts (establishing his receiver chain on Alice's ratchet key), Bob
// replies with HIS ratchet key, Alice decrypts (DH ratchet step on Bob's new
// key), then Alice sends again under the stepped chain.
func TestCipherRatchetStep(t *testing.T) {
	c := setupConvo(t)
	// Alice -> Bob
	if got := c.bobDecrypt(t, c.aliceEncrypt(t, []byte("a1"))); !bytes.Equal(got, []byte("a1")) {
		t.Fatalf("a1: %q", got)
	}
	// Bob -> Alice (introduces Bob's ratchet key; Alice DH-ratchets on decrypt)
	if got := c.aliceDecrypt(t, c.bobEncrypt(t, []byte("b1"))); !bytes.Equal(got, []byte("b1")) {
		t.Fatalf("b1: %q", got)
	}
	// Alice -> Bob again, now under the ratcheted sending chain.
	if got := c.bobDecrypt(t, c.aliceEncrypt(t, []byte("a2"))); !bytes.Equal(got, []byte("a2")) {
		t.Fatalf("a2: %q", got)
	}
	// Bob -> Alice again.
	if got := c.aliceDecrypt(t, c.bobEncrypt(t, []byte("b2"))); !bytes.Equal(got, []byte("b2")) {
		t.Fatalf("b2: %q", got)
	}
}

// TestCipherTripleRatchetOnWire confirms SPQR is actually engaged in the session
// cipher: an encrypted message carries a non-empty pq_ratchet field, and a
// full bidirectional conversation still decrypts correctly with the SPQR key
// mixed into every message key. If the SPQR mix were broken (keys diverging
// between sender and receiver), decryption would fail the MAC check.
func TestCipherTripleRatchetOnWire(t *testing.T) {
	c := setupConvo(t)

	m1 := c.aliceEncrypt(t, []byte("a1"))
	if len(m1.PQRatchet()) == 0 {
		t.Fatal("encrypted message carries no pq_ratchet field — SPQR not engaged")
	}
	if got := c.bobDecrypt(t, m1); !bytes.Equal(got, []byte("a1")) {
		t.Fatalf("a1 decrypt with SPQR mix: %q", got)
	}
	// Reply (DH ratchet step) — Bob's outbound also carries SPQR, and Alice
	// decrypts with the mixed key.
	b1 := c.bobEncrypt(t, []byte("b1"))
	if len(b1.PQRatchet()) == 0 {
		t.Fatal("bob's message carries no pq_ratchet field")
	}
	if got := c.aliceDecrypt(t, b1); !bytes.Equal(got, []byte("b1")) {
		t.Fatalf("b1 decrypt with SPQR mix: %q", got)
	}
	// A few more rounds to advance epochs and exercise the SPQR ratchet under
	// the Double Ratchet steps.
	for i := 0; i < 5; i++ {
		if got := c.bobDecrypt(t, c.aliceEncrypt(t, []byte("ping"))); !bytes.Equal(got, []byte("ping")) {
			t.Fatalf("round %d ping: %q", i, got)
		}
		if got := c.aliceDecrypt(t, c.bobEncrypt(t, []byte("pong"))); !bytes.Equal(got, []byte("pong")) {
			t.Fatalf("round %d pong: %q", i, got)
		}
	}
}

// TestCipherMixedVersionFallback simulates a peer that does not speak SPQR (an
// older client): its stored SPQR state is empty (V0). With min_version V0 on
// both sides, the conversation must still work — the V0 side sends no pq_ratchet
// field and contributes no key, and the V1 side negotiates down rather than
// failing. This is the staged-rollout fallback (min_version V0) the integration
// is designed around.
func TestCipherMixedVersionFallback(t *testing.T) {
	c := setupConvo(t)
	ctx := context.Background()

	// Make Bob a "V0" peer by clearing his SPQR state (as if he never
	// initialized one). Alice keeps her V1 (min V0) state.
	bobRec, err := c.bobSess.LoadSession(ctx, c.aliceAddr)
	if err != nil {
		t.Fatalf("load bob session: %v", err)
	}
	bobRec.CurrentState().SetPQRatchetState(nil)
	if err := c.bobSess.StoreSession(ctx, c.aliceAddr, bobRec); err != nil {
		t.Fatalf("store bob session: %v", err)
	}

	// Alice -> Bob: Alice's message carries a pq_ratchet field (she is V1), but
	// Bob (V0) ignores it and decrypts with no SPQR key mixed. The message must
	// still decrypt.
	if got := c.bobDecrypt(t, c.aliceEncrypt(t, []byte("a1"))); !bytes.Equal(got, []byte("a1")) {
		t.Fatalf("V0 bob failed to decrypt V1 alice's message: %q", got)
	}
	// Bob -> Alice: Bob (V0) sends no pq_ratchet field; Alice (V1, min V0)
	// negotiates down and decrypts.
	b1 := c.bobEncrypt(t, []byte("b1"))
	if len(b1.PQRatchet()) != 0 {
		t.Fatal("V0 bob unexpectedly produced a pq_ratchet field")
	}
	if got := c.aliceDecrypt(t, b1); !bytes.Equal(got, []byte("b1")) {
		t.Fatalf("V1 alice failed to decrypt V0 bob's message: %q", got)
	}
	// Continue the conversation to confirm the downgraded session is stable.
	for i := 0; i < 3; i++ {
		if got := c.bobDecrypt(t, c.aliceEncrypt(t, []byte("ping"))); !bytes.Equal(got, []byte("ping")) {
			t.Fatalf("round %d ping (mixed-version): %q", i, got)
		}
		if got := c.aliceDecrypt(t, c.bobEncrypt(t, []byte("pong"))); !bytes.Equal(got, []byte("pong")) {
			t.Fatalf("round %d pong (mixed-version): %q", i, got)
		}
	}
}

// TestCipherForwardJumpCap rejects a message whose counter is more than
// MaxForwardJumps beyond the current chain index. The jump check fires before
// MAC verification, so a crafted far-future counter is rejected as
// ErrInvalidMessage regardless of its MAC.
func TestCipherForwardJumpCap(t *testing.T) {
	c := setupConvo(t)
	// Bob first establishes a receiver chain on Alice's ratchet key.
	if got := c.bobDecrypt(t, c.aliceEncrypt(t, []byte("seed"))); !bytes.Equal(got, []byte("seed")) {
		t.Fatalf("seed decrypt: %q", got)
	}
	// Craft a SignalMessage on Alice's same ratchet key with a wildly future
	// counter. We don't have the right keys to MAC it, but the forward-jump
	// guard rejects it before the MAC check.
	aliceState := mustCurrentState(t, c.aliceSess, c.bobAddr)
	ratchetKey, err := aliceState.SenderRatchetKey()
	if err != nil {
		t.Fatalf("alice sender ratchet key: %v", err)
	}
	bobState := mustCurrentState(t, c.bobSess, c.aliceAddr)
	farCounter := uint32(MaxForwardJumps + 2)
	forged, err := protocol.NewSignalMessage(
		uint8(bobState.SessionVersion()),
		bytes.Repeat([]byte{0x00}, 32), // wrong MAC key — irrelevant, jump guard fires first
		ratchetKey,
		farCounter,
		0,
		[]byte("x"),
		mustPub(t, aliceState.LocalIdentityPublic()),  // alice = sender
		mustPub(t, aliceState.RemoteIdentityPublic()), // bob = receiver
		nil, nil,
	)
	if err != nil {
		t.Fatalf("forge SignalMessage: %v", err)
	}
	_, err = Decrypt(context.Background(), forged, c.aliceAddr, c.bobSess, cryptorand.Reader)
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("forward-jump err = %v, want ErrInvalidMessage", err)
	}
}

func mustCurrentState(t *testing.T, store *fakeSessionStore, a address.ProtocolAddress) *SessionState {
	t.Helper()
	rec, err := store.LoadSession(context.Background(), a)
	if err != nil || rec == nil || !rec.HasCurrentState() {
		t.Fatalf("load current state for %s: rec=%v err=%v", a.String(), rec, err)
	}
	return rec.CurrentState()
}

// FuzzDecrypt feeds arbitrary bytes as a SignalMessage body against an
// established session and asserts decryption never panics or corrupts the
// stored session (the stored bytes must be identical after any failed decrypt).
func FuzzDecrypt(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x33})
	f.Add(bytes.Repeat([]byte{0xAB}, 80))
	f.Fuzz(func(t *testing.T, raw []byte) {
		c := setupConvo(t)
		before := append([]byte(nil), c.bobSess.records[c.aliceAddr.String()]...)
		msg, err := protocol.DeserializeSignalMessage(raw)
		if err != nil {
			return // unparseable framing is fine; nothing to decrypt
		}
		// Must not panic. Random bytes won't carry a valid MAC, so this errors;
		// a failed decrypt must leave the stored session byte-identical
		// (clone-then-commit). A valid forge is cryptographically infeasible here.
		if _, derr := Decrypt(context.Background(), msg, c.aliceAddr, c.bobSess, cryptorand.Reader); derr != nil {
			if !bytes.Equal(before, c.bobSess.records[c.aliceAddr.String()]) {
				t.Fatal("failed Decrypt mutated the stored session")
			}
		}
	})
}
