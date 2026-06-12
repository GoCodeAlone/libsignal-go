// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package inmem

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/session"
	"github.com/GoCodeAlone/libsignal-go/stores"
)

func testAddr(t *testing.T, name string, deviceID uint32) address.ProtocolAddress {
	t.Helper()
	dev, err := address.NewDeviceID(deviceID)
	if err != nil {
		t.Fatalf("NewDeviceID(%d): %v", deviceID, err)
	}
	return address.NewProtocolAddress(name, dev)
}

func testPubKey(t *testing.T) curve.PublicKey {
	t.Helper()
	kp, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp.PublicKey
}

// --- IdentityKeyStore: the trust decision table ---

func TestIdentityKeyStoreBasics(t *testing.T) {
	ctx := context.Background()
	kp, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	const regID = uint32(0x1234)
	s := NewIdentityKeyStore(kp, regID)

	gotKP, err := s.GetIdentityKeyPair(ctx)
	if err != nil {
		t.Fatalf("GetIdentityKeyPair: %v", err)
	}
	if !gotKP.PublicKey.Equal(kp.PublicKey) {
		t.Fatal("GetIdentityKeyPair returned a different public key")
	}
	gotReg, err := s.GetLocalRegistrationID(ctx)
	if err != nil {
		t.Fatalf("GetLocalRegistrationID: %v", err)
	}
	if gotReg != regID {
		t.Fatalf("registration id = %d, want %d", gotReg, regID)
	}

	// Unknown address: GetIdentity reports not-found.
	addr := testAddr(t, "alice", 1)
	if _, ok, err := s.GetIdentity(ctx, addr); err != nil || ok {
		t.Fatalf("GetIdentity(unknown) = ok %v, err %v; want ok false, nil", ok, err)
	}
}

func TestIdentityTrustDecisionTable(t *testing.T) {
	ctx := context.Background()
	selfKP, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair self: %v", err)
	}
	s := NewIdentityKeyStore(selfKP, 1)

	addr := testAddr(t, "bob", 2)
	idA := testPubKey(t)
	idB := testPubKey(t)
	if idA.Equal(idB) {
		t.Fatal("test setup: two generated keys collided")
	}

	// Unknown identity is trusted (first use), in both directions.
	for _, dir := range []stores.Direction{stores.Sending, stores.Receiving} {
		trusted, err := s.IsTrustedIdentity(ctx, addr, idA, dir)
		if err != nil {
			t.Fatalf("IsTrustedIdentity(unknown, dir=%d): %v", dir, err)
		}
		if !trusted {
			t.Fatalf("unknown identity not trusted (dir=%d); want trusted on first use", dir)
		}
	}

	// First save records the identity and reports NewOrUnchanged.
	change, err := s.SaveIdentity(ctx, addr, idA)
	if err != nil {
		t.Fatalf("SaveIdentity(first): %v", err)
	}
	if change != stores.NewOrUnchanged {
		t.Fatalf("first SaveIdentity = %v, want NewOrUnchanged", change)
	}

	// GetIdentity now returns the recorded key.
	got, ok, err := s.GetIdentity(ctx, addr)
	if err != nil || !ok {
		t.Fatalf("GetIdentity(known) = ok %v, err %v; want ok true", ok, err)
	}
	if !got.Equal(idA) {
		t.Fatal("GetIdentity returned the wrong key")
	}

	// Known + same identity: trusted, both directions.
	for _, dir := range []stores.Direction{stores.Sending, stores.Receiving} {
		trusted, err := s.IsTrustedIdentity(ctx, addr, idA, dir)
		if err != nil {
			t.Fatalf("IsTrustedIdentity(same, dir=%d): %v", dir, err)
		}
		if !trusted {
			t.Fatalf("same identity not trusted (dir=%d)", dir)
		}
	}

	// Known + different identity: untrusted, both directions.
	for _, dir := range []stores.Direction{stores.Sending, stores.Receiving} {
		trusted, err := s.IsTrustedIdentity(ctx, addr, idB, dir)
		if err != nil {
			t.Fatalf("IsTrustedIdentity(changed, dir=%d): %v", dir, err)
		}
		if trusted {
			t.Fatalf("changed identity trusted (dir=%d); want untrusted", dir)
		}
	}

	// Re-saving the same identity: NewOrUnchanged.
	change, err = s.SaveIdentity(ctx, addr, idA)
	if err != nil {
		t.Fatalf("SaveIdentity(same): %v", err)
	}
	if change != stores.NewOrUnchanged {
		t.Fatalf("re-save same = %v, want NewOrUnchanged", change)
	}

	// Saving a different identity: ReplacedExisting, and it becomes the trusted one.
	change, err = s.SaveIdentity(ctx, addr, idB)
	if err != nil {
		t.Fatalf("SaveIdentity(changed): %v", err)
	}
	if change != stores.ReplacedExisting {
		t.Fatalf("changed SaveIdentity = %v, want ReplacedExisting", change)
	}
	trusted, err := s.IsTrustedIdentity(ctx, addr, idB, stores.Sending)
	if err != nil {
		t.Fatalf("IsTrustedIdentity(after replace): %v", err)
	}
	if !trusted {
		t.Fatal("replaced identity not trusted after overwrite")
	}

	// Reset clears known keys: previously-known address is first-use again.
	s.Reset()
	if _, ok, err := s.GetIdentity(ctx, addr); err != nil || ok {
		t.Fatalf("after Reset GetIdentity = ok %v, err %v; want not found", ok, err)
	}
	trusted, err = s.IsTrustedIdentity(ctx, addr, idB, stores.Sending)
	if err != nil {
		t.Fatalf("IsTrustedIdentity(after reset): %v", err)
	}
	if !trusted {
		t.Fatal("after Reset, identity should be trusted on first use again")
	}
}

// --- PreKeyStore: CRUD + remove ---

func TestPreKeyStoreCRUD(t *testing.T) {
	ctx := context.Background()
	s := NewPreKeyStore()

	// Missing id is an error matchable with errors.Is.
	if _, err := s.GetPreKey(ctx, 7); !errors.Is(err, ErrInvalidPreKeyID) {
		t.Fatalf("GetPreKey(missing) err = %v, want ErrInvalidPreKeyID", err)
	}

	rec := []byte("prekey-record-7")
	if err := s.SavePreKey(ctx, 7, rec); err != nil {
		t.Fatalf("SavePreKey: %v", err)
	}
	got, err := s.GetPreKey(ctx, 7)
	if err != nil {
		t.Fatalf("GetPreKey: %v", err)
	}
	if !bytes.Equal(got, rec) {
		t.Fatalf("GetPreKey = %q, want %q", got, rec)
	}

	// Defensive copy: mutating the caller's input or the returned slice must not
	// change stored state.
	rec[0] = 'X'
	got[1] = 'Y'
	again, err := s.GetPreKey(ctx, 7)
	if err != nil {
		t.Fatalf("GetPreKey(again): %v", err)
	}
	if !bytes.Equal(again, []byte("prekey-record-7")) {
		t.Fatalf("stored record was mutated via aliasing: %q", again)
	}

	// Overwrite.
	if err := s.SavePreKey(ctx, 7, []byte("replacement")); err != nil {
		t.Fatalf("SavePreKey(overwrite): %v", err)
	}
	got, err = s.GetPreKey(ctx, 7)
	if err != nil {
		t.Fatalf("GetPreKey(after overwrite): %v", err)
	}
	if !bytes.Equal(got, []byte("replacement")) {
		t.Fatalf("overwrite failed: %q", got)
	}

	// Remove, then it's gone.
	if err := s.RemovePreKey(ctx, 7); err != nil {
		t.Fatalf("RemovePreKey: %v", err)
	}
	if _, err := s.GetPreKey(ctx, 7); !errors.Is(err, ErrInvalidPreKeyID) {
		t.Fatalf("GetPreKey(after remove) err = %v, want ErrInvalidPreKeyID", err)
	}
	// Removing a missing id is not an error.
	if err := s.RemovePreKey(ctx, 999); err != nil {
		t.Fatalf("RemovePreKey(missing) = %v, want nil", err)
	}
}

func TestPreKeyStoreAllIDs(t *testing.T) {
	ctx := context.Background()
	s := NewPreKeyStore()
	for _, id := range []uint32{3, 1, 2} {
		// The record body is an arbitrary per-id marker; the low byte suffices
		// and the mask makes the uint32->byte truncation explicit (gosec G115).
		if err := s.SavePreKey(ctx, id, []byte{byte(id & 0xFF)}); err != nil {
			t.Fatalf("SavePreKey(%d): %v", id, err)
		}
	}
	ids := s.AllPreKeyIDs()
	if len(ids) != 3 {
		t.Fatalf("AllPreKeyIDs len = %d, want 3", len(ids))
	}
	seen := map[uint32]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	for _, want := range []uint32{1, 2, 3} {
		if !seen[want] {
			t.Fatalf("AllPreKeyIDs missing %d", want)
		}
	}
}

// --- SignedPreKeyStore: CRUD (no remove) ---

func TestSignedPreKeyStoreCRUD(t *testing.T) {
	ctx := context.Background()
	s := NewSignedPreKeyStore()

	if _, err := s.GetSignedPreKey(ctx, 5); !errors.Is(err, ErrInvalidSignedPreKeyID) {
		t.Fatalf("GetSignedPreKey(missing) err = %v, want ErrInvalidSignedPreKeyID", err)
	}

	rec := []byte("signed-prekey-5")
	if err := s.SaveSignedPreKey(ctx, 5, rec); err != nil {
		t.Fatalf("SaveSignedPreKey: %v", err)
	}
	got, err := s.GetSignedPreKey(ctx, 5)
	if err != nil {
		t.Fatalf("GetSignedPreKey: %v", err)
	}
	if !bytes.Equal(got, rec) {
		t.Fatalf("GetSignedPreKey = %q, want %q", got, rec)
	}

	// Defensive copy on input.
	rec[0] = 'Z'
	again, err := s.GetSignedPreKey(ctx, 5)
	if err != nil {
		t.Fatalf("GetSignedPreKey(again): %v", err)
	}
	if !bytes.Equal(again, []byte("signed-prekey-5")) {
		t.Fatalf("stored signed pre-key mutated via aliasing: %q", again)
	}

	// Overwrite.
	if err := s.SaveSignedPreKey(ctx, 5, []byte("rotated")); err != nil {
		t.Fatalf("SaveSignedPreKey(overwrite): %v", err)
	}
	got, err = s.GetSignedPreKey(ctx, 5)
	if err != nil {
		t.Fatalf("GetSignedPreKey(after overwrite): %v", err)
	}
	if !bytes.Equal(got, []byte("rotated")) {
		t.Fatalf("overwrite failed: %q", got)
	}

	if ids := s.AllSignedPreKeyIDs(); len(ids) != 1 || ids[0] != 5 {
		t.Fatalf("AllSignedPreKeyIDs = %v, want [5]", ids)
	}
}

// --- KyberPreKeyStore: CRUD + mark-used reuse rejection ---

func TestKyberPreKeyStoreCRUD(t *testing.T) {
	ctx := context.Background()
	s := NewKyberPreKeyStore()

	if _, err := s.GetKyberPreKey(ctx, 9); !errors.Is(err, ErrInvalidKyberPreKeyID) {
		t.Fatalf("GetKyberPreKey(missing) err = %v, want ErrInvalidKyberPreKeyID", err)
	}

	rec := []byte("kyber-prekey-9")
	if err := s.SaveKyberPreKey(ctx, 9, rec); err != nil {
		t.Fatalf("SaveKyberPreKey: %v", err)
	}
	got, err := s.GetKyberPreKey(ctx, 9)
	if err != nil {
		t.Fatalf("GetKyberPreKey: %v", err)
	}
	if !bytes.Equal(got, rec) {
		t.Fatalf("GetKyberPreKey = %q, want %q", got, rec)
	}

	if ids := s.AllKyberPreKeyIDs(); len(ids) != 1 || ids[0] != 9 {
		t.Fatalf("AllKyberPreKeyIDs = %v, want [9]", ids)
	}
}

func TestKyberMarkUsedRejectsReuse(t *testing.T) {
	ctx := context.Background()
	s := NewKyberPreKeyStore()

	baseA := testPubKey(t)
	baseB := testPubKey(t)
	if baseA.Equal(baseB) {
		t.Fatal("test setup: base keys collided")
	}

	const kyberID, ecID = uint32(9), uint32(4)

	// First use of baseA under (9,4): ok.
	if err := s.MarkKyberPreKeyUsed(ctx, kyberID, ecID, baseA); err != nil {
		t.Fatalf("MarkKyberPreKeyUsed(first): %v", err)
	}
	// Reusing baseA under the same (9,4): rejected.
	if err := s.MarkKyberPreKeyUsed(ctx, kyberID, ecID, baseA); !errors.Is(err, ErrReusedBaseKey) {
		t.Fatalf("MarkKyberPreKeyUsed(reuse) err = %v, want ErrReusedBaseKey", err)
	}
	// A different base key under the same (9,4): ok.
	if err := s.MarkKyberPreKeyUsed(ctx, kyberID, ecID, baseB); err != nil {
		t.Fatalf("MarkKyberPreKeyUsed(different base): %v", err)
	}
	// The same base key under a different (kyber,ec) pair: ok (keyed by the pair).
	if err := s.MarkKyberPreKeyUsed(ctx, kyberID, ecID+1, baseA); err != nil {
		t.Fatalf("MarkKyberPreKeyUsed(different ec): %v", err)
	}
	if err := s.MarkKyberPreKeyUsed(ctx, kyberID+1, ecID, baseA); err != nil {
		t.Fatalf("MarkKyberPreKeyUsed(different kyber): %v", err)
	}
}

// --- SessionStore: round-trip, absent->nil, overwrite, by-value storage ---

// sessionWithRegID builds a session record whose remote registration id is regID,
// giving each record observably distinct serialized content.
func sessionWithRegID(regID uint32) *session.SessionRecord {
	state := session.NewEmptySessionState()
	state.SetRemoteRegistrationID(regID)
	return session.NewSessionRecord(state)
}

func TestSessionStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewSessionStore()
	addr := testAddr(t, "alice", 1)

	// Absent -> (nil, nil), not an error.
	got, err := s.LoadSession(ctx, addr)
	if err != nil {
		t.Fatalf("LoadSession(absent): %v", err)
	}
	if got != nil {
		t.Fatal("LoadSession(absent) returned non-nil record")
	}

	rec := sessionWithRegID(42)
	if err := s.StoreSession(ctx, addr, rec); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}
	got, err = s.LoadSession(ctx, addr)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if got == nil {
		t.Fatal("LoadSession returned nil after store")
	}
	if got.CurrentState().RemoteRegistrationID() != 42 {
		t.Fatalf("loaded remote reg id = %d, want 42", got.CurrentState().RemoteRegistrationID())
	}

	// Stored by value: mutating the caller's record after store does not change
	// stored state, and the loaded record is an independent copy.
	rec.CurrentState().SetRemoteRegistrationID(99)
	got2, err := s.LoadSession(ctx, addr)
	if err != nil {
		t.Fatalf("LoadSession(after caller mutation): %v", err)
	}
	if got2.CurrentState().RemoteRegistrationID() != 42 {
		t.Fatalf("stored session mutated via caller aliasing: reg id = %d, want 42", got2.CurrentState().RemoteRegistrationID())
	}
	// Mutating one loaded copy does not affect another load.
	got.CurrentState().SetRemoteRegistrationID(7)
	got3, err := s.LoadSession(ctx, addr)
	if err != nil {
		t.Fatalf("LoadSession(after loaded mutation): %v", err)
	}
	if got3.CurrentState().RemoteRegistrationID() != 42 {
		t.Fatalf("stored session mutated via returned record aliasing: reg id = %d, want 42", got3.CurrentState().RemoteRegistrationID())
	}

	// Overwrite.
	if err := s.StoreSession(ctx, addr, sessionWithRegID(100)); err != nil {
		t.Fatalf("StoreSession(overwrite): %v", err)
	}
	got, err = s.LoadSession(ctx, addr)
	if err != nil {
		t.Fatalf("LoadSession(after overwrite): %v", err)
	}
	if got.CurrentState().RemoteRegistrationID() != 100 {
		t.Fatalf("overwrite failed: reg id = %d, want 100", got.CurrentState().RemoteRegistrationID())
	}
}

func TestSessionStoreNilRecordRejected(t *testing.T) {
	ctx := context.Background()
	s := NewSessionStore()
	if err := s.StoreSession(ctx, testAddr(t, "bob", 2), nil); err == nil {
		t.Fatal("StoreSession(nil) accepted; want error")
	}
}

func TestSessionStoreKeyedByAddress(t *testing.T) {
	ctx := context.Background()
	s := NewSessionStore()
	addr1 := testAddr(t, "alice", 1)
	addr2 := testAddr(t, "alice", 2) // same name, different device
	addr3 := testAddr(t, "carol", 1) // different name, same device

	if err := s.StoreSession(ctx, addr1, sessionWithRegID(1)); err != nil {
		t.Fatalf("StoreSession(addr1): %v", err)
	}
	if err := s.StoreSession(ctx, addr2, sessionWithRegID(2)); err != nil {
		t.Fatalf("StoreSession(addr2): %v", err)
	}

	for _, tc := range []struct {
		addr  address.ProtocolAddress
		want  uint32
		found bool
	}{
		{addr1, 1, true},
		{addr2, 2, true},
		{addr3, 0, false},
	} {
		got, err := s.LoadSession(ctx, tc.addr)
		if err != nil {
			t.Fatalf("LoadSession(%s): %v", tc.addr, err)
		}
		if !tc.found {
			if got != nil {
				t.Fatalf("LoadSession(%s) = non-nil, want absent", tc.addr)
			}
			continue
		}
		if got.CurrentState().RemoteRegistrationID() != tc.want {
			t.Fatalf("LoadSession(%s) reg id = %d, want %d", tc.addr, got.CurrentState().RemoteRegistrationID(), tc.want)
		}
	}
}

// --- SenderKeyStore: round-trip, absent->nil, overwrite, (sender,dist) keying ---

func TestSenderKeyStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewSenderKeyStore()
	sender := testAddr(t, "alice", 1)
	var dist [16]byte
	if _, err := rand.Read(dist[:]); err != nil {
		t.Fatalf("rand dist: %v", err)
	}

	// Absent -> (nil, nil).
	got, err := s.LoadSenderKey(ctx, sender, dist)
	if err != nil {
		t.Fatalf("LoadSenderKey(absent): %v", err)
	}
	if got != nil {
		t.Fatal("LoadSenderKey(absent) returned non-nil")
	}

	rec := []byte("sender-key-record")
	if err := s.StoreSenderKey(ctx, sender, dist, rec); err != nil {
		t.Fatalf("StoreSenderKey: %v", err)
	}
	got, err = s.LoadSenderKey(ctx, sender, dist)
	if err != nil {
		t.Fatalf("LoadSenderKey: %v", err)
	}
	if !bytes.Equal(got, rec) {
		t.Fatalf("LoadSenderKey = %q, want %q", got, rec)
	}

	// Defensive copy on input and output.
	rec[0] = 'X'
	got[1] = 'Y'
	again, err := s.LoadSenderKey(ctx, sender, dist)
	if err != nil {
		t.Fatalf("LoadSenderKey(again): %v", err)
	}
	if !bytes.Equal(again, []byte("sender-key-record")) {
		t.Fatalf("stored sender key mutated via aliasing: %q", again)
	}

	// Overwrite.
	if err := s.StoreSenderKey(ctx, sender, dist, []byte("rotated")); err != nil {
		t.Fatalf("StoreSenderKey(overwrite): %v", err)
	}
	got, err = s.LoadSenderKey(ctx, sender, dist)
	if err != nil {
		t.Fatalf("LoadSenderKey(after overwrite): %v", err)
	}
	if !bytes.Equal(got, []byte("rotated")) {
		t.Fatalf("overwrite failed: %q", got)
	}
}

func TestSenderKeyStoreKeyingIsolation(t *testing.T) {
	ctx := context.Background()
	s := NewSenderKeyStore()

	addr1 := testAddr(t, "alice", 1)
	addr2 := testAddr(t, "bob", 1)
	distA := [16]byte{0xA0}
	distB := [16]byte{0xB0}

	// (addr1, distA), (addr1, distB), (addr2, distA) are three distinct keys.
	if err := s.StoreSenderKey(ctx, addr1, distA, []byte("a1-A")); err != nil {
		t.Fatalf("store (addr1,distA): %v", err)
	}
	if err := s.StoreSenderKey(ctx, addr1, distB, []byte("a1-B")); err != nil {
		t.Fatalf("store (addr1,distB): %v", err)
	}
	if err := s.StoreSenderKey(ctx, addr2, distA, []byte("a2-A")); err != nil {
		t.Fatalf("store (addr2,distA): %v", err)
	}

	for _, tc := range []struct {
		name string
		addr address.ProtocolAddress
		dist [16]byte
		want string
	}{
		{"addr1/distA", addr1, distA, "a1-A"},
		{"addr1/distB", addr1, distB, "a1-B"},
		{"addr2/distA", addr2, distA, "a2-A"},
	} {
		got, err := s.LoadSenderKey(ctx, tc.addr, tc.dist)
		if err != nil {
			t.Fatalf("LoadSenderKey(%s): %v", tc.name, err)
		}
		if !bytes.Equal(got, []byte(tc.want)) {
			t.Fatalf("LoadSenderKey(%s) = %q, want %q", tc.name, got, tc.want)
		}
	}

	// A pair never stored is absent.
	if got, err := s.LoadSenderKey(ctx, addr2, distB); err != nil || got != nil {
		t.Fatalf("LoadSenderKey(addr2,distB) = %q, err %v; want absent", got, err)
	}
}
