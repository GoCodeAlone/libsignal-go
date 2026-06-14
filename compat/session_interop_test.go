// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build interop

// Session interop: drives a full PQXDH / Double Ratchet conversation between the
// pure-Go session layer and the genuine upstream session API (v0.91.0) exposed
// by the Rust harness over JSON-RPC. This is the protocol's core cross-impl
// proof — both impls must agree on the handshake and on every message key,
// including out-of-order and skipped-key delivery, in BOTH role assignments
// (Go=Alice/Rust=Bob and Rust=Alice/Go=Bob) and with AND without a one-time
// pre-key (the no-OPK case exercises the optional-DH4 PQXDH path).
//
// v0.91.0 sessions are PQXDH/v4 only — X3DH/v3 is removed upstream (the decrypt
// path returns "X3DH no longer supported"), and process_prekey_bundle takes no
// UsePQRatchet flag at this tag, so sessions negotiate WITHOUT the SPQR
// post-quantum ratchet (Stage 1): every SignalMessage carries pq_ratchet absent
// and pq_ratchet_state empty, and both roles interoperate on that basis. A v3
// decrypt-vector suite is therefore not achievable with the v0.91.0 public API
// (documented limitation — see compat/README.md); the v4 interop here is the
// full protocol surface the pinned upstream supports.
//
// Like the other interop tests this is gated behind the `interop` build tag and
// driven via COMPAT_HARNESS_BIN (see interop_test.go for the client).
package compat

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/kem"
	"github.com/GoCodeAlone/libsignal-go/protocol"
	"github.com/GoCodeAlone/libsignal-go/session"
	"github.com/GoCodeAlone/libsignal-go/stores"
	"github.com/GoCodeAlone/libsignal-go/stores/inmem"
)

// Ciphertext type tags, matching CiphertextMessageType (protocol.rs) and the
// harness's session.encrypt/`type` field: 2 = Whisper/SignalMessage,
// 3 = PreKey/PreKeySignalMessage.
const (
	typeWhisper = 2
	typePreKey  = 3
)

// bundleJSON is the wire shape of a PreKeyBundle exchanged with the harness. The
// one-time pre-key fields are pointers so they can be omitted (no OPK) — the
// harness emits them only when present, and accepts a bundle without them.
type bundleJSON struct {
	RegistrationID        uint32  `json:"registration_id"`
	DeviceID              uint32  `json:"device_id"`
	IdentityKey           string  `json:"identity_key"`
	SignedPreKeyID        uint32  `json:"signed_pre_key_id"`
	SignedPreKeyPublic    string  `json:"signed_pre_key_public"`
	SignedPreKeySignature string  `json:"signed_pre_key_signature"`
	KyberPreKeyID         uint32  `json:"kyber_pre_key_id"`
	KyberPreKeyPublic     string  `json:"kyber_pre_key_public"`
	KyberPreKeySignature  string  `json:"kyber_pre_key_signature"`
	PreKeyID              *uint32 `json:"pre_key_id,omitempty"`
	PreKeyPublic          *string `json:"pre_key_public,omitempty"`
}

// ctMsg is one ciphertext: the wire-type tag plus its serialized bytes (hex).
type ctMsg struct {
	Type       int    `json:"type"`
	Serialized string `json:"serialized"`
}

func interopAddr(t *testing.T, name string) address.ProtocolAddress {
	t.Helper()
	// The harness uses a fixed device id of 1; mirror it so addresses line up.
	dev, err := address.NewDeviceID(1)
	if err != nil {
		t.Fatalf("NewDeviceID: %v", err)
	}
	return address.NewProtocolAddress(name, dev)
}

// --- harness session-method wrappers -------------------------------------

// rustCreateBundle asks the harness to create a recipient (Bob) key set in a
// fresh store under `handle` and returns the resulting bundle. with_one_time
// controls whether a one-time pre-key is offered.
func rustCreateBundle(t *testing.T, h *harness, handle string, withOneTime bool) bundleJSON {
	t.Helper()
	var b bundleJSON
	h.ok("session.create-prekey-bundle", map[string]any{
		"handle":        handle,
		"with_one_time": withOneTime,
	}, &b)
	return b
}

// rustProcessBundleAsAlice has the harness build an Alice session under `handle`
// toward `remoteName` from a Go-produced bundle.
func rustProcessBundleAsAlice(t *testing.T, h *harness, handle, remoteName string, b bundleJSON) {
	t.Helper()
	params := map[string]any{
		"handle":                   handle,
		"remote_name":              remoteName,
		"registration_id":          b.RegistrationID,
		"device_id":                b.DeviceID,
		"identity_key":             b.IdentityKey,
		"signed_pre_key_id":        b.SignedPreKeyID,
		"signed_pre_key_public":    b.SignedPreKeyPublic,
		"signed_pre_key_signature": b.SignedPreKeySignature,
		"kyber_pre_key_id":         b.KyberPreKeyID,
		"kyber_pre_key_public":     b.KyberPreKeyPublic,
		"kyber_pre_key_signature":  b.KyberPreKeySignature,
	}
	if b.PreKeyID != nil && b.PreKeyPublic != nil {
		params["pre_key_id"] = *b.PreKeyID
		params["pre_key_public"] = *b.PreKeyPublic
	}
	h.ok("session.process-bundle-as-alice", params, nil)
}

// rustEncrypt encrypts plaintext from `handle` toward `remoteName` via the
// harness's message_encrypt; returns the ciphertext (type + bytes).
func rustEncrypt(t *testing.T, h *harness, handle, remoteName string, plaintext []byte) ctMsg {
	t.Helper()
	var m ctMsg
	h.ok("session.encrypt", map[string]any{
		"handle":      handle,
		"remote_name": remoteName,
		"plaintext":   hx(plaintext),
	}, &m)
	return m
}

// rustDecrypt decrypts a ciphertext into `handle`'s store from `remoteName` via
// the harness's message_decrypt; returns the recovered plaintext.
func rustDecrypt(t *testing.T, h *harness, handle, remoteName string, m ctMsg) []byte {
	t.Helper()
	var res struct {
		Plaintext string `json:"plaintext"`
	}
	h.ok("session.decrypt", map[string]any{
		"handle":      handle,
		"remote_name": remoteName,
		"type":        m.Type,
		"serialized":  m.Serialized,
	}, &res)
	return mustDecodeHex(t, res.Plaintext)
}

// --- Go-side bundle + recipient helpers ----------------------------------

// goBob holds the recipient key material the Go side keeps when it plays Bob, so
// it can both publish a bundle (for a Rust=Alice) and run InitializeBobSession
// once it receives a PreKeySignalMessage. v0.91.0 PreKeyBundle requires a Kyber
// pre-key; the one-time EC pre-key is optional.
type goBob struct {
	identity  curve.KeyPair
	signedPre curve.KeyPair
	kyber     kem.KeyPair
	oneTime   *curve.KeyPair // nil when no one-time pre-key is offered
	regID     uint32
}

// newGoBob generates a recipient's key material with real randomness.
func newGoBob(t *testing.T, withOneTime bool) *goBob {
	t.Helper()
	gen := func(label string) curve.KeyPair {
		kp, err := curve.GenerateKeyPair(cryptorand.Reader)
		if err != nil {
			t.Fatalf("generate %s: %v", label, err)
		}
		return kp
	}
	kyberKP, err := kem.GenerateKeyPair(kem.KeyTypeKyber1024, cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate kyber: %v", err)
	}
	b := &goBob{
		identity:  gen("identity"),
		signedPre: gen("signedPre"),
		kyber:     kyberKP,
		regID:     4242,
	}
	if withOneTime {
		ot := gen("oneTime")
		b.oneTime = &ot
	}
	return b
}

// bundle produces the bundleJSON a Rust=Alice consumes, signing the signed and
// Kyber pre-keys under Bob's identity exactly as a publisher would.
func (b *goBob) bundle(t *testing.T) bundleJSON {
	t.Helper()
	signedSig, err := b.identity.PrivateKey.CalculateSignature(cryptorand.Reader, b.signedPre.PublicKey.Serialize())
	if err != nil {
		t.Fatalf("sign signed-pre: %v", err)
	}
	kyberSig, err := b.identity.PrivateKey.CalculateSignature(cryptorand.Reader, b.kyber.PublicKey.Serialize())
	if err != nil {
		t.Fatalf("sign kyber: %v", err)
	}
	out := bundleJSON{
		RegistrationID:        b.regID,
		DeviceID:              1,
		IdentityKey:           hx(b.identity.PublicKey.Serialize()),
		SignedPreKeyID:        55,
		SignedPreKeyPublic:    hx(b.signedPre.PublicKey.Serialize()),
		SignedPreKeySignature: hx(signedSig),
		KyberPreKeyID:         66,
		KyberPreKeyPublic:     hx(b.kyber.PublicKey.Serialize()),
		KyberPreKeySignature:  hx(kyberSig),
	}
	if b.oneTime != nil {
		id := uint32(77)
		pub := hx(b.oneTime.PublicKey.Serialize())
		out.PreKeyID = &id
		out.PreKeyPublic = &pub
	}
	return out
}

// initBobSession establishes Go-Bob's session from a received PreKeySignalMessage
// and stores it under the remote (Alice) address. It mirrors what an upstream
// message_decrypt_prekey does before decrypting the inner SignalMessage: resolve
// the recipient pre-keys (here held directly), run InitializeBobSession from the
// initiator's base key + Kyber ciphertext, and persist the session.
//
// The Go session package has no single public message_decrypt_prekey entry; the
// recipient flow is composed here from its public building blocks
// (DeserializePreKeySignalMessage + InitializeBobSession + Decrypt), exactly as
// session/cipher_test.go's setupConvo does. No production code is added.
func (b *goBob) initBobSession(t *testing.T, sessStore session.Store, aliceAddr address.ProtocolAddress, pkMsg ctMsg, withOneTime bool) {
	t.Helper()
	if pkMsg.Type != typePreKey {
		t.Fatalf("Go=Bob expected a PreKey message (type %d), got type %d", typePreKey, pkMsg.Type)
	}
	raw := mustDecodeHex(t, pkMsg.Serialized)
	m, err := protocol.DeserializePreKeySignalMessage(raw)
	if err != nil {
		t.Fatalf("DeserializePreKeySignalMessage: %v", err)
	}

	// Assert the message's one-time-prekey use matches the bundle we published.
	// This is what proves the without_one_time case truly drives the DH4-ABSENT
	// path: the upstream initiator must have omitted the one-time prekey (no
	// PreKeyID on the wire), so InitializeBobSession runs with OurOneTime=nil and
	// computes the master secret without DH4. If upstream had included an OPK
	// here, PreKeyID would be set and this would fail loudly.
	usedOneTime := m.PreKeyID() != nil
	if usedOneTime != withOneTime {
		t.Fatalf("incoming PreKey message one-time-prekey use = %v, want %v (DH4-absent path requires no PreKeyID)", usedOneTime, withOneTime)
	}

	var oneTime *curve.KeyPair
	if usedOneTime {
		if b.oneTime == nil {
			t.Fatal("incoming message used a one-time pre-key but Go=Bob has none")
		}
		oneTime = b.oneTime
	}

	state, err := session.InitializeBobSession(session.BobParams{
		OurIdentity:   b.identity,
		OurSignedPre:  b.signedPre,
		OurOneTime:    oneTime,
		OurKyber:      b.kyber,
		TheirIdentity: m.IdentityKey(),
		TheirBaseKey:  m.BaseKey(),
		KyberCipher:   m.KyberCiphertext(),
	})
	if err != nil {
		t.Fatalf("InitializeBobSession: %v", err)
	}
	if err := sessStore.StoreSession(context.Background(), aliceAddr, session.NewSessionRecord(state)); err != nil {
		t.Fatalf("store Go=Bob session: %v", err)
	}
}

// --- the suite -----------------------------------------------------------

// TestSessionInteropGoAliceRustBob runs the handshake + a 20-message exchange
// (with out-of-order and skipped-key delivery) with Go as the initiator and the
// genuine upstream session as the recipient, for both with- and without-one-time
// -prekey bundles. The no-OPK case is the cross-impl proof of the optional-DH4
// fix: Go omits DH4 and upstream must derive the same keys.
func TestSessionInteropGoAliceRustBob(t *testing.T) {
	for _, withOneTime := range []bool{true, false} {
		name := "without_one_time"
		if withOneTime {
			name = "with_one_time"
		}
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()

			bobHandle := "bob_" + name
			aliceAddr := interopAddr(t, "alice_"+name)
			bobAddr := interopAddr(t, "bob_"+name)

			// Rust=Bob publishes a bundle; Go=Alice processes it.
			b := rustCreateBundle(t, h, bobHandle, withOneTime)
			if withOneTime && b.PreKeyID == nil {
				t.Fatal("with_one_time bundle missing pre_key_id")
			}
			if !withOneTime && b.PreKeyID != nil {
				t.Fatal("without_one_time bundle unexpectedly carries a pre_key_id")
			}

			goBundle := goBundleFromRust(t, b)
			aliceSess := inmem.NewSessionStore()
			aliceID := inmem.NewIdentityKeyStore(mustGenCurve(t), 1001)
			if err := session.ProcessPreKeyBundle(ctx, cryptorand.Reader, bobAddr, goBundle, aliceSess, aliceID); err != nil {
				t.Fatalf("Go ProcessPreKeyBundle: %v", err)
			}

			// First Go=Alice -> Rust=Bob message establishes the session on Bob's
			// side (it is a PreKey message). After Bob's first reply Alice stops
			// wrapping, but here Alice keeps sending until Bob replies below.
			first := goEncrypt(ctx, t, aliceSess, aliceID, bobAddr, []byte("alice msg 0"))
			if first.Type != typePreKey {
				t.Fatalf("first Go=Alice message type %d, want PreKey %d", first.Type, typePreKey)
			}
			// Prove the without_one_time case truly drives the DH4-ABSENT path: the
			// PreKeySignalMessage Go=Alice emits must carry no PreKeyID when no
			// one-time prekey was offered, which means initializeAliceSession ran
			// with an empty dh4. (With an OPK it must carry one.) Rust=Bob then
			// decrypting it is the cross-impl proof that both sides derived the same
			// keys without DH4.
			firstMsg, err := protocol.DeserializePreKeySignalMessage(mustDecodeHex(t, first.Serialized))
			if err != nil {
				t.Fatalf("DeserializePreKeySignalMessage (Go=Alice first): %v", err)
			}
			if usedOPK := firstMsg.PreKeyID() != nil; usedOPK != withOneTime {
				t.Fatalf("Go=Alice PreKey message one-time-prekey use = %v, want %v (DH4-absent path requires no PreKeyID)", usedOPK, withOneTime)
			}
			if got := rustDecrypt(t, h, bobHandle, aliceAddr.Name(), first); !bytes.Equal(got, []byte("alice msg 0")) {
				t.Fatalf("Rust=Bob decrypt msg 0: got %q", got)
			}

			// Bob replies so Alice's session becomes acknowledged (a Whisper).
			reply := rustEncrypt(t, h, bobHandle, aliceAddr.Name(), []byte("bob reply 0"))
			if got := goDecryptWhisper(ctx, t, aliceSess, bobAddr, reply); !bytes.Equal(got, []byte("bob reply 0")) {
				t.Fatalf("Go=Alice decrypt reply 0: got %q", got)
			}

			// Now run a 20-message Alice->Bob exchange with out-of-order delivery.
			runOutOfOrderExchange(t, 20,
				func(pt []byte) ctMsg { return goEncrypt(ctx, t, aliceSess, aliceID, bobAddr, pt) },
				func(m ctMsg) []byte { return rustDecrypt(t, h, bobHandle, aliceAddr.Name(), m) },
			)
		})
	}
}

// TestSessionInteropRustAliceGoBob is the mirror role assignment: the genuine
// upstream session is the initiator and Go is the recipient, for both with- and
// without-one-time-prekey bundles.
func TestSessionInteropRustAliceGoBob(t *testing.T) {
	for _, withOneTime := range []bool{true, false} {
		name := "without_one_time"
		if withOneTime {
			name = "with_one_time"
		}
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()

			aliceHandle := "alice_" + name
			aliceAddr := interopAddr(t, "alice_"+name)
			bobAddr := interopAddr(t, "bob_"+name)

			// Go=Bob publishes a bundle; Rust=Alice processes it.
			bob := newGoBob(t, withOneTime)
			rustProcessBundleAsAlice(t, h, aliceHandle, bobAddr.Name(), bob.bundle(t))

			bobSess := inmem.NewSessionStore()

			// Rust=Alice's first message is a PreKey message; Go=Bob establishes its
			// session from it, then decrypts the inner SignalMessage.
			first := rustEncrypt(t, h, aliceHandle, bobAddr.Name(), []byte("alice msg 0"))
			bob.initBobSession(t, bobSess, aliceAddr, first, withOneTime)
			if got := goDecryptPreKey(ctx, t, bobSess, aliceAddr, first); !bytes.Equal(got, []byte("alice msg 0")) {
				t.Fatalf("Go=Bob decrypt msg 0: got %q", got)
			}

			// Go=Bob replies so Rust=Alice's session is acknowledged.
			bobID := inmem.NewIdentityKeyStore(bob.identity, bob.regID)
			reply := goEncrypt(ctx, t, bobSess, bobID, aliceAddr, []byte("bob reply 0"))
			if got := rustDecrypt(t, h, aliceHandle, bobAddr.Name(), reply); !bytes.Equal(got, []byte("bob reply 0")) {
				t.Fatalf("Rust=Alice decrypt reply 0: got %q", got)
			}

			// 20-message Alice->Bob exchange with out-of-order delivery.
			runOutOfOrderExchange(t, 20,
				func(pt []byte) ctMsg { return rustEncrypt(t, h, aliceHandle, bobAddr.Name(), pt) },
				func(m ctMsg) []byte { return goDecryptWhisper(ctx, t, bobSess, aliceAddr, m) },
			)
		})
	}
}

// TestSessionInteropPersistence proves Go session state survives a serialize /
// reload mid-conversation (storage.proto structural compat): the in-memory store
// already round-trips every record through Serialize/Deserialize on each
// Store/Load, so this drives a Go=Alice <-> Rust=Bob conversation, then
// explicitly serializes the live SessionRecord, reloads it into a fresh store,
// and continues the ratchet from the reloaded state — the next messages must
// still decrypt on the Rust side.
func TestSessionInteropPersistence(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	bobHandle := "bob_persist"
	aliceAddr := interopAddr(t, "alice_persist")
	bobAddr := interopAddr(t, "bob_persist")

	b := rustCreateBundle(t, h, bobHandle, true)
	goBundle := goBundleFromRust(t, b)
	aliceSess := inmem.NewSessionStore()
	aliceID := inmem.NewIdentityKeyStore(mustGenCurve(t), 1001)
	if err := session.ProcessPreKeyBundle(ctx, cryptorand.Reader, bobAddr, goBundle, aliceSess, aliceID); err != nil {
		t.Fatalf("Go ProcessPreKeyBundle: %v", err)
	}

	// Exchange a few messages to advance the chain past its initial state.
	first := goEncrypt(ctx, t, aliceSess, aliceID, bobAddr, []byte("p0"))
	if got := rustDecrypt(t, h, bobHandle, aliceAddr.Name(), first); !bytes.Equal(got, []byte("p0")) {
		t.Fatalf("Rust=Bob decrypt p0: got %q", got)
	}
	reply := rustEncrypt(t, h, bobHandle, aliceAddr.Name(), []byte("pr0"))
	if got := goDecryptWhisper(ctx, t, aliceSess, bobAddr, reply); !bytes.Equal(got, []byte("pr0")) {
		t.Fatalf("Go=Alice decrypt pr0: got %q", got)
	}
	for i := 1; i <= 3; i++ {
		pt := []byte(fmt.Sprintf("p%d", i))
		m := goEncrypt(ctx, t, aliceSess, aliceID, bobAddr, pt)
		if got := rustDecrypt(t, h, bobHandle, aliceAddr.Name(), m); !bytes.Equal(got, pt) {
			t.Fatalf("Rust=Bob decrypt %s: got %q", pt, got)
		}
	}

	// Serialize the live Alice record, reload it into a brand-new store, and
	// continue. If the serialized form were lossy or structurally incompatible
	// the reloaded session would derive different keys and Rust would reject.
	rec, err := aliceSess.LoadSession(ctx, bobAddr)
	if err != nil || rec == nil {
		t.Fatalf("load Alice record: rec=%v err=%v", rec, err)
	}
	serialized, err := rec.Serialize()
	if err != nil {
		t.Fatalf("serialize record: %v", err)
	}
	reloaded, err := session.DeserializeSessionRecord(serialized)
	if err != nil {
		t.Fatalf("deserialize record: %v", err)
	}
	freshSess := inmem.NewSessionStore()
	if err := freshSess.StoreSession(ctx, bobAddr, reloaded); err != nil {
		t.Fatalf("store reloaded record: %v", err)
	}

	for i := 4; i <= 6; i++ {
		pt := []byte(fmt.Sprintf("p%d", i))
		m := goEncrypt(ctx, t, freshSess, aliceID, bobAddr, pt)
		if got := rustDecrypt(t, h, bobHandle, aliceAddr.Name(), m); !bytes.Equal(got, pt) {
			t.Fatalf("Rust=Bob decrypt %s after reload: got %q", pt, got)
		}
	}
}

// --- shared exchange driver + Go encrypt/decrypt wrappers ----------------

// runOutOfOrderExchange encrypts n messages with `enc`, then delivers them to
// `dec` in a deliberately scrambled order (skipping ahead, then filling the gap
// from cached keys) and asserts byte-level plaintext equality. This exercises
// the receiver's skipped-message-key handling across the impl boundary.
func runOutOfOrderExchange(t *testing.T, n int, enc func(pt []byte) ctMsg, dec func(m ctMsg) []byte) {
	t.Helper()
	plains := make([][]byte, n)
	cts := make([]ctMsg, n)
	for i := 0; i < n; i++ {
		plains[i] = []byte(fmt.Sprintf("ooo message %d / payload", i))
		cts[i] = enc(plains[i])
	}

	// Delivery order: jump to the last message first (forcing the receiver to
	// cache keys 0..n-2), then deliver the rest in a shuffled-but-deterministic
	// order so skipped + out-of-order keys are both exercised.
	order := deliveryOrder(n)
	for _, i := range order {
		got := dec(cts[i])
		if !bytes.Equal(got, plains[i]) {
			t.Fatalf("out-of-order msg %d: got %q want %q", i, got, plains[i])
		}
	}
}

// deliveryOrder returns a deterministic permutation of [0,n) that delivers the
// highest index first (maximizing skipped keys), then alternates the remaining
// indices from the ends inward, so neither pure-forward nor pure-reverse.
func deliveryOrder(n int) []int {
	if n == 0 {
		return nil
	}
	order := make([]int, 0, n)
	order = append(order, n-1) // deliver last first -> skip 0..n-2
	lo, hi := 0, n-2
	for lo <= hi {
		order = append(order, lo)
		if hi != lo {
			order = append(order, hi)
		}
		lo++
		hi--
	}
	return order
}

// goEncrypt encrypts via the Go session layer and adapts the (SignalMessage,
// PreKeySignalMessage) return into the harness ctMsg shape: a PreKeySignalMessage
// is type PreKey and serialized whole; otherwise a plain Whisper SignalMessage.
func goEncrypt(ctx context.Context, t *testing.T, sess session.Store, id stores.IdentityKeyStore, remote address.ProtocolAddress, pt []byte) ctMsg {
	t.Helper()
	signal, preKey, err := session.Encrypt(ctx, pt, remote, sess, id, nil, cryptorand.Reader)
	if err != nil {
		t.Fatalf("Go Encrypt: %v", err)
	}
	if preKey != nil {
		return ctMsg{Type: typePreKey, Serialized: hx(preKey.Serialize())}
	}
	return ctMsg{Type: typeWhisper, Serialized: hx(signal.Serialize())}
}

// goDecryptWhisper decrypts a Whisper SignalMessage via the Go session layer.
func goDecryptWhisper(ctx context.Context, t *testing.T, sess session.Store, remote address.ProtocolAddress, m ctMsg) []byte {
	t.Helper()
	if m.Type != typeWhisper {
		t.Fatalf("goDecryptWhisper: expected Whisper (%d), got type %d", typeWhisper, m.Type)
	}
	sm, err := protocol.DeserializeSignalMessage(mustDecodeHex(t, m.Serialized))
	if err != nil {
		t.Fatalf("DeserializeSignalMessage: %v", err)
	}
	pt, err := session.Decrypt(ctx, sm, remote, sess, cryptorand.Reader)
	if err != nil {
		t.Fatalf("Go Decrypt (Whisper): %v", err)
	}
	return pt
}

// goDecryptPreKey decrypts the inner SignalMessage of a received
// PreKeySignalMessage. The recipient session must already be established (via
// goBob.initBobSession); this then runs the ordinary Double Ratchet receive on
// the inner message, mirroring how upstream decrypts after process_prekey.
func goDecryptPreKey(ctx context.Context, t *testing.T, sess session.Store, remote address.ProtocolAddress, m ctMsg) []byte {
	t.Helper()
	if m.Type != typePreKey {
		t.Fatalf("goDecryptPreKey: expected PreKey (%d), got type %d", typePreKey, m.Type)
	}
	pk, err := protocol.DeserializePreKeySignalMessage(mustDecodeHex(t, m.Serialized))
	if err != nil {
		t.Fatalf("DeserializePreKeySignalMessage: %v", err)
	}
	pt, err := session.Decrypt(ctx, pk.Message(), remote, sess, cryptorand.Reader)
	if err != nil {
		t.Fatalf("Go Decrypt (inner SignalMessage): %v", err)
	}
	return pt
}

// --- small construction helpers ------------------------------------------

func mustGenCurve(t *testing.T) curve.KeyPair {
	t.Helper()
	kp, err := curve.GenerateKeyPair(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

// goBundleFromRust converts a harness-produced bundleJSON into a Go PreKeyBundle.
func goBundleFromRust(t *testing.T, b bundleJSON) *session.PreKeyBundle {
	t.Helper()
	signedPre, err := curve.DeserializePublicKey(mustDecodeHex(t, b.SignedPreKeyPublic))
	if err != nil {
		t.Fatalf("deserialize signed pre-key: %v", err)
	}
	kyberPub, err := kem.DeserializePublicKey(mustDecodeHex(t, b.KyberPreKeyPublic))
	if err != nil {
		t.Fatalf("deserialize kyber pre-key: %v", err)
	}
	identity, err := curve.DeserializePublicKey(mustDecodeHex(t, b.IdentityKey))
	if err != nil {
		t.Fatalf("deserialize identity key: %v", err)
	}
	params := session.PreKeyBundleParams{
		RegistrationID:  b.RegistrationID,
		DeviceID:        b.DeviceID,
		SignedPreKeyID:  b.SignedPreKeyID,
		SignedPreKey:    signedPre,
		SignedPreKeySig: mustDecodeHex(t, b.SignedPreKeySignature),
		KyberPreKeyID:   b.KyberPreKeyID,
		KyberPreKey:     kyberPub,
		KyberPreKeySig:  mustDecodeHex(t, b.KyberPreKeySignature),
		IdentityKey:     identity,
	}
	if b.PreKeyID != nil && b.PreKeyPublic != nil {
		preKey, err := curve.DeserializePublicKey(mustDecodeHex(t, *b.PreKeyPublic))
		if err != nil {
			t.Fatalf("deserialize one-time pre-key: %v", err)
		}
		id := *b.PreKeyID
		params.PreKeyID = &id
		params.PreKey = &preKey
	}
	bundle, err := session.NewPreKeyBundle(params)
	if err != nil {
		t.Fatalf("NewPreKeyBundle: %v", err)
	}
	return bundle
}
