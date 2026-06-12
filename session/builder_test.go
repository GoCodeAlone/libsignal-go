// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/kem"
	"github.com/GoCodeAlone/libsignal-go/stores"
)

// --- in-test store fakes implementing the session-local store interfaces ---
//
// These satisfy session.IdentityKeyStore / session.SessionStore directly. The
// real stores/inmem types use stores.Direction / stores.IdentityChange named
// types and so don't structurally match the session-local interfaces; bridging
// stores/inmem to the session layer is a separate integration seam (the
// session<->stores import cycle is documented in builder.go). For unit-testing
// the builder, in-test fakes are the right tool — no dependency on stores/.

type fakeIdentityStore struct {
	identity  curve.KeyPair
	regID     uint32
	trusted   map[string]curve.PublicKey // address.String() -> recorded identity
	trustAll  bool                       // when true, IsTrustedIdentity always true (TOFU)
	saveCalls int
}

func newFakeIdentityStore(t *testing.T, idSeed byte, regID uint32) *fakeIdentityStore {
	return &fakeIdentityStore{
		identity: genCurve(t, idSeed),
		regID:    regID,
		trusted:  map[string]curve.PublicKey{},
		trustAll: true,
	}
}

func (s *fakeIdentityStore) GetIdentityKeyPair(_ context.Context) (curve.KeyPair, error) {
	return s.identity, nil
}

func (s *fakeIdentityStore) GetLocalRegistrationID(_ context.Context) (uint32, error) {
	return s.regID, nil
}

func (s *fakeIdentityStore) SaveIdentity(_ context.Context, addr address.ProtocolAddress, identity curve.PublicKey) (stores.IdentityChange, error) {
	prev, existed := s.trusted[addr.String()]
	s.trusted[addr.String()] = identity
	s.saveCalls++
	return stores.IdentityChangeFromReplaced(existed && !prev.Equal(identity)), nil
}

func (s *fakeIdentityStore) IsTrustedIdentity(_ context.Context, addr address.ProtocolAddress, identity curve.PublicKey, _ stores.Direction) (bool, error) {
	if rec, ok := s.trusted[addr.String()]; ok {
		return rec.Equal(identity), nil
	}
	return s.trustAll, nil
}

// GetIdentity satisfies stores.IdentityKeyStore (unused by the builder path).
func (s *fakeIdentityStore) GetIdentity(_ context.Context, addr address.ProtocolAddress) (curve.PublicKey, bool, error) {
	pk, ok := s.trusted[addr.String()]
	return pk, ok, nil
}

// Compile-time checks that the fakes satisfy the real store interfaces.
var (
	_ stores.IdentityKeyStore = (*fakeIdentityStore)(nil)
	_ Store                   = (*fakeSessionStore)(nil)
)

type fakeSessionStore struct {
	records map[string][]byte // address.String() -> serialized SessionRecord
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{records: map[string][]byte{}}
}

func (s *fakeSessionStore) LoadSession(_ context.Context, addr address.ProtocolAddress) (*SessionRecord, error) {
	b, ok := s.records[addr.String()]
	if !ok {
		return nil, nil
	}
	return DeserializeSessionRecord(b)
}

func (s *fakeSessionStore) StoreSession(_ context.Context, addr address.ProtocolAddress, record *SessionRecord) error {
	b, err := record.Serialize()
	if err != nil {
		return err
	}
	s.records[addr.String()] = b
	return nil
}

// bobBundle builds a recipient (Bob) PreKeyBundle with its signed pre-key and
// Kyber pre-key correctly signed by Bob's identity key, plus the secret key
// material a test needs to drive the Bob side. tamper lets a test corrupt a
// signature to exercise the rejection paths.
type bobBundleKeys struct {
	identity  curve.KeyPair
	signedPre curve.KeyPair
	kyber     kem.KeyPair
	oneTime   *curve.KeyPair
	bundle    *PreKeyBundle
}

type bundleTamper int

const (
	tamperNone bundleTamper = iota
	tamperSignedPreSig
	tamperKyberSig
)

func makeBobBundle(t *testing.T, withOneTime bool, tamper bundleTamper) bobBundleKeys {
	t.Helper()
	identity := genCurve(t, 100)
	signedPre := genCurve(t, 101)
	kyberKP := genKyber(t, 102)

	signedSig, err := identity.PrivateKey.CalculateSignature(cryptorand.Reader, signedPre.PublicKey.Serialize())
	if err != nil {
		t.Fatalf("sign signed-pre: %v", err)
	}
	kyberSig, err := identity.PrivateKey.CalculateSignature(cryptorand.Reader, kyberKP.PublicKey.Serialize())
	if err != nil {
		t.Fatalf("sign kyber: %v", err)
	}
	switch tamper {
	case tamperSignedPreSig:
		signedSig[0] ^= 0x01
	case tamperKyberSig:
		kyberSig[0] ^= 0x01
	}

	params := PreKeyBundleParams{
		RegistrationID:  4242,
		DeviceID:        1,
		SignedPreKeyID:  55,
		SignedPreKey:    signedPre.PublicKey,
		SignedPreKeySig: signedSig,
		KyberPreKeyID:   66,
		KyberPreKey:     kyberKP.PublicKey,
		KyberPreKeySig:  kyberSig,
		IdentityKey:     identity.PublicKey,
	}
	keys := bobBundleKeys{identity: identity, signedPre: signedPre, kyber: kyberKP}
	if withOneTime {
		ot := genCurve(t, 103)
		keys.oneTime = &ot
		id := uint32(77)
		params.PreKeyID = &id
		params.PreKey = &ot.PublicKey
	}
	b, err := NewPreKeyBundle(params)
	if err != nil {
		t.Fatalf("NewPreKeyBundle: %v", err)
	}
	keys.bundle = b
	return keys
}

// fixedReaderB yields deterministic bytes for reproducible key generation in
// the builder tests (named to avoid clashing with record_test.go's fixedReader).
type fixedReaderB struct{ b byte }

func (r *fixedReaderB) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
		r.b++
	}
	return len(p), nil
}

func genCurve(t *testing.T, seed byte) curve.KeyPair {
	t.Helper()
	kp, err := curve.GenerateKeyPair(&fixedReaderB{b: seed})
	if err != nil {
		t.Fatalf("curve.GenerateKeyPair: %v", err)
	}
	return kp
}

func genKyber(t *testing.T, seed byte) kem.KeyPair {
	t.Helper()
	kp, err := kem.GenerateKeyPair(kem.KeyTypeKyber1024, &fixedReaderB{b: seed})
	if err != nil {
		t.Fatalf("kem.GenerateKeyPair: %v", err)
	}
	return kp
}

// TestBuilderAliceBobRoundTrip is the core correctness check: an Alice
// initiator and a Bob recipient run the PQXDH handshake over the same key
// material and must agree on the session secrets. Concretely, Alice's receiver
// chain (keyed by Bob's signed pre-key, carrying the PQXDH chain key) must equal
// Bob's sender chain (his own signed pre-key, same PQXDH chain key) — and both
// must share the same root key. This is decision-independent of the store wiring.
func TestBuilderAliceBobRoundTrip(t *testing.T) {
	for _, withOneTime := range []bool{true, false} {
		name := "without_one_time"
		if withOneTime {
			name = "with_one_time"
		}
		t.Run(name, func(t *testing.T) {
			bobIdentity := genCurve(t, 1)
			bobSignedPre := genCurve(t, 2)
			bobKyber := genKyber(t, 3)
			aliceIdentity := genCurve(t, 4)

			var bobOneTime *curve.KeyPair
			var aliceTheirOneTime *curve.PublicKey
			if withOneTime {
				ot := genCurve(t, 5)
				bobOneTime = &ot
				aliceTheirOneTime = &ot.PublicKey
			}

			// Alice side: fresh base key, then the initiator agreement.
			aliceBase := genCurve(t, 6)
			aliceState, err := initializeAliceSession(&fixedReaderB{b: 7}, aliceParams{
				ourIdentity:    aliceIdentity,
				ourBase:        aliceBase,
				theirIdentity:  bobIdentity.PublicKey,
				theirSignedPre: bobSignedPre.PublicKey,
				theirOneTime:   aliceTheirOneTime,
				theirKyber:     bobKyber.PublicKey,
			})
			if err != nil {
				t.Fatalf("initializeAliceSession: %v", err)
			}

			// The Kyber ciphertext Alice would relay in the PreKeySignalMessage.
			kyberCT, ok := aliceState.UnacknowledgedKyberCiphertext()
			if !ok || len(kyberCT) == 0 {
				t.Fatal("alice has no pending Kyber ciphertext")
			}

			// Bob side: same key material + Alice's base key + the Kyber ciphertext.
			bobState, err := InitializeBobSession(BobParams{
				OurIdentity:   bobIdentity,
				OurSignedPre:  bobSignedPre,
				OurOneTime:    bobOneTime,
				OurKyber:      bobKyber,
				TheirIdentity: aliceIdentity.PublicKey,
				TheirBaseKey:  aliceBase.PublicKey,
				KyberCipher:   kyberCT,
			})
			if err != nil {
				t.Fatalf("InitializeBobSession: %v", err)
			}

			// Both sides must agree on the PQXDH-derived chain key: Alice stored it
			// as the receiver chain keyed by Bob's signed pre-key; Bob stored it as
			// his sender chain.
			aliceRecv, present, err := aliceState.ReceiverChainKey(bobSignedPre.PublicKey)
			if err != nil || !present {
				t.Fatalf("alice receiver chain (bob signed pre): present=%v err=%v", present, err)
			}
			bobSend, err := bobState.SenderChainKey()
			if err != nil {
				t.Fatalf("bob sender chain key: %v", err)
			}
			if !bytes.Equal(aliceRecv.Key(), bobSend.Key()) {
				t.Fatalf("PQXDH chain key mismatch:\n alice recv %x\n bob send   %x", aliceRecv.Key(), bobSend.Key())
			}
			if aliceRecv.Index() != bobSend.Index() {
				t.Fatalf("chain index mismatch: alice %d bob %d", aliceRecv.Index(), bobSend.Index())
			}

			// Both must record the same alice_base_key (the matching key).
			if !bytes.Equal(aliceState.AliceBaseKey(), bobState.AliceBaseKey()) {
				t.Fatal("alice_base_key mismatch between the two sides")
			}
			// Identity bindings are mirror images.
			if !bytes.Equal(aliceState.RemoteIdentityPublic(), bobIdentity.PublicKey.Serialize()) {
				t.Fatal("alice remote identity != bob identity")
			}
			if !bytes.Equal(bobState.RemoteIdentityPublic(), aliceIdentity.PublicKey.Serialize()) {
				t.Fatal("bob remote identity != alice identity")
			}
			// Both sessions are v4.
			if aliceState.SessionVersion() != signalMessageCurrentVersion || bobState.SessionVersion() != signalMessageCurrentVersion {
				t.Fatalf("session versions: alice %d bob %d", aliceState.SessionVersion(), bobState.SessionVersion())
			}
		})
	}
}

// TestBuilderBobRequiresKyberCiphertext confirms the recipient side rejects a
// missing Kyber ciphertext (v4 requires it).
func TestBuilderBobRequiresKyberCiphertext(t *testing.T) {
	bobIdentity := genCurve(t, 10)
	bobSignedPre := genCurve(t, 11)
	bobKyber := genKyber(t, 12)
	aliceIdentity := genCurve(t, 13)
	aliceBase := genCurve(t, 14)

	_, err := InitializeBobSession(BobParams{
		OurIdentity:   bobIdentity,
		OurSignedPre:  bobSignedPre,
		OurKyber:      bobKyber,
		TheirIdentity: aliceIdentity.PublicKey,
		TheirBaseKey:  aliceBase.PublicKey,
		KyberCipher:   nil, // missing
	})
	if err == nil {
		t.Fatal("expected error for missing Kyber ciphertext")
	}
}

// addr is a fixed remote address for the bundle-processing tests.
func addr(t *testing.T) address.ProtocolAddress {
	t.Helper()
	dev, err := address.NewDeviceID(1)
	if err != nil {
		t.Fatalf("NewDeviceID: %v", err)
	}
	return address.NewProtocolAddress("+15550001234", dev)
}

// TestProcessPreKeyBundleStoresSession runs the full Alice initiator path
// through the stores and asserts a session was promoted+stored with the
// pending pre-key state recorded, and the identity saved.
func TestProcessPreKeyBundleStoresSession(t *testing.T) {
	for _, withOneTime := range []bool{true, false} {
		bob := makeBobBundle(t, withOneTime, tamperNone)
		idStore := newFakeIdentityStore(t, 200, 9001)
		sessStore := newFakeSessionStore()
		a := addr(t)

		if err := ProcessPreKeyBundle(context.Background(), &fixedReaderB{b: 210}, a, bob.bundle, sessStore, idStore); err != nil {
			t.Fatalf("ProcessPreKeyBundle: %v", err)
		}
		// Session stored + current state present.
		rec, err := sessStore.LoadSession(context.Background(), a)
		if err != nil || rec == nil || !rec.HasCurrentState() {
			t.Fatalf("session not stored: rec=%v err=%v", rec, err)
		}
		st := rec.CurrentState()
		if st.SessionVersion() != signalMessageCurrentVersion {
			t.Fatalf("session version = %d", st.SessionVersion())
		}
		if !st.PendingPreKey() {
			t.Fatal("expected pending pre-key message recorded")
		}
		if ct, ok := st.UnacknowledgedKyberCiphertext(); !ok || len(ct) == 0 {
			t.Fatal("expected pending Kyber ciphertext recorded")
		}
		if st.RemoteRegistrationID() != bob.bundle.RegistrationID() {
			t.Fatalf("remote reg id = %d, want %d", st.RemoteRegistrationID(), bob.bundle.RegistrationID())
		}
		if st.LocalRegistrationID() != 9001 {
			t.Fatalf("local reg id = %d, want 9001", st.LocalRegistrationID())
		}
		// Identity saved for the address.
		if idStore.saveCalls != 1 {
			t.Fatalf("SaveIdentity calls = %d, want 1", idStore.saveCalls)
		}
	}
}

// TestProcessPreKeyBundleUntrustedIdentity rejects a bundle whose identity is
// not trusted for the address.
func TestProcessPreKeyBundleUntrustedIdentity(t *testing.T) {
	bob := makeBobBundle(t, true, tamperNone)
	idStore := newFakeIdentityStore(t, 201, 9002)
	idStore.trustAll = false
	// Record a DIFFERENT identity for the address so the bundle's identity is untrusted.
	other := genCurve(t, 250)
	idStore.trusted[addr(t).String()] = other.PublicKey
	sessStore := newFakeSessionStore()

	err := ProcessPreKeyBundle(context.Background(), &fixedReaderB{b: 211}, addr(t), bob.bundle, sessStore, idStore)
	if !errors.Is(err, ErrUntrustedIdentity) {
		t.Fatalf("err = %v, want ErrUntrustedIdentity", err)
	}
	// No session stored, no identity saved on rejection.
	if rec, _ := sessStore.LoadSession(context.Background(), addr(t)); rec != nil {
		t.Fatal("session was stored despite untrusted identity")
	}
}

// TestProcessPreKeyBundleBadSignatures rejects bundles with an invalid signed
// pre-key or Kyber pre-key signature, and leaves the store untouched.
func TestProcessPreKeyBundleBadSignatures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tamper bundleTamper
	}{
		{"signed_pre_key", tamperSignedPreSig},
		{"kyber_pre_key", tamperKyberSig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bob := makeBobBundle(t, true, tc.tamper)
			idStore := newFakeIdentityStore(t, 202, 9003)
			sessStore := newFakeSessionStore()
			err := ProcessPreKeyBundle(context.Background(), &fixedReaderB{b: 212}, addr(t), bob.bundle, sessStore, idStore)
			if !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("err = %v, want ErrInvalidSignature", err)
			}
			if len(sessStore.records) != 0 {
				t.Fatal("session stored despite bad signature")
			}
			if idStore.saveCalls != 0 {
				t.Fatal("identity saved despite bad signature")
			}
		})
	}
}

// TestProcessPreKeyBundleFailureLeavesStoreUnchanged asserts that a rejected
// bundle does not mutate an existing stored session's bytes.
func TestProcessPreKeyBundleFailureLeavesStoreUnchanged(t *testing.T) {
	a := addr(t)
	// Seed an existing session in the store.
	existing := NewEmptySessionState()
	existing.SetSessionVersion(4)
	existing.SetAliceBaseKey([]byte{0xDE, 0xAD})
	sessStore := newFakeSessionStore()
	if err := sessStore.StoreSession(context.Background(), a, NewSessionRecord(existing)); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	before := append([]byte(nil), sessStore.records[a.String()]...)

	// Process a bundle with a bad signature -> must fail and not touch the store.
	bob := makeBobBundle(t, true, tamperKyberSig)
	idStore := newFakeIdentityStore(t, 203, 9004)
	if err := ProcessPreKeyBundle(context.Background(), &fixedReaderB{b: 213}, a, bob.bundle, sessStore, idStore); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
	if !bytes.Equal(before, sessStore.records[a.String()]) {
		t.Fatal("stored session bytes changed after a failed ProcessPreKeyBundle")
	}
}

// FuzzProcessPreKeyBundle feeds malformed signature/key bytes and confirms
// processing never panics (it must return an error, never crash or store).
func FuzzProcessPreKeyBundle(f *testing.F) {
	f.Add([]byte{0x05}, []byte{0x00})
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, signedSig, kyberSig []byte) {
		identity := genCurve(t, 220)
		signedPre := genCurve(t, 221)
		kyberKP := genKyber(t, 222)
		b, err := NewPreKeyBundle(PreKeyBundleParams{
			RegistrationID:  1,
			DeviceID:        1,
			SignedPreKeyID:  1,
			SignedPreKey:    signedPre.PublicKey,
			SignedPreKeySig: signedSig,
			KyberPreKeyID:   1,
			KyberPreKey:     kyberKP.PublicKey,
			KyberPreKeySig:  kyberSig,
			IdentityKey:     identity.PublicKey,
		})
		if err != nil {
			return
		}
		idStore := newFakeIdentityStore(t, 223, 1)
		sessStore := newFakeSessionStore()
		// Must not panic. An error is the expected outcome for garbage sigs.
		_ = ProcessPreKeyBundle(context.Background(), &fixedReaderB{b: 224}, addr(t), b, sessStore, idStore)
	})
}
