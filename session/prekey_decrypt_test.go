package session

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	pb "github.com/GoCodeAlone/libsignal-go/proto"
	"github.com/GoCodeAlone/libsignal-go/protocol"
	googleproto "google.golang.org/protobuf/proto"
)

type preKeyRecordStore struct {
	pre, signed, kyber map[uint32][]byte
	used               map[string]bool
	writeErr           error
}

func (s *preKeyRecordStore) GetPreKey(_ context.Context, id uint32) ([]byte, error) {
	return s.get(s.pre, id)
}
func (s *preKeyRecordStore) GetSignedPreKey(_ context.Context, id uint32) ([]byte, error) {
	return s.get(s.signed, id)
}
func (s *preKeyRecordStore) GetKyberPreKey(_ context.Context, id uint32) ([]byte, error) {
	return s.get(s.kyber, id)
}
func (s *preKeyRecordStore) get(records map[uint32][]byte, id uint32) ([]byte, error) {
	raw, ok := records[id]
	if !ok {
		return nil, errors.New("missing test pre-key")
	}
	return bytes.Clone(raw), nil
}
func (s *preKeyRecordStore) SavePreKey(_ context.Context, id uint32, raw []byte) error {
	s.pre[id] = bytes.Clone(raw)
	return nil
}
func (s *preKeyRecordStore) SaveSignedPreKey(_ context.Context, id uint32, raw []byte) error {
	s.signed[id] = bytes.Clone(raw)
	return nil
}
func (s *preKeyRecordStore) SaveKyberPreKey(_ context.Context, id uint32, raw []byte) error {
	s.kyber[id] = bytes.Clone(raw)
	return nil
}
func (s *preKeyRecordStore) RemovePreKey(_ context.Context, id uint32) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	delete(s.pre, id)
	return nil
}
func (s *preKeyRecordStore) MarkKyberPreKeyUsed(_ context.Context, kyber, signed uint32, base curve.PublicKey) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	id := fmt.Sprintf("%d/%d/%x", kyber, signed, base.Serialize())
	if s.used[id] {
		return errors.New("test Kyber pre-key reused")
	}
	s.used[id] = true
	return nil
}

func preKeyFixture(t *testing.T, oneTime bool) (*convo, PreKeyDecryptStores, *preKeyRecordStore) {
	t.Helper()
	ctx := t.Context()
	bob := makeBobBundle(t, oneTime, tamperNone)
	c := &convo{
		aliceID: newFakeIdentityStore(t, 30, 1001), aliceSess: newFakeSessionStore(),
		bobAddr: protoAddr(t, "recipient"), aliceAddr: protoAddr(t, "initiator"),
		bobSess:    newFakeSessionStore(),
		bobIDStore: &fakeIdentityStore{identity: bob.identity, regID: 4242, trusted: map[string]curve.PublicKey{}, trustAll: true},
	}
	if err := ProcessPreKeyBundle(ctx, cryptorand.Reader, c.bobAddr, bob.bundle, c.aliceSess, c.aliceID); err != nil {
		t.Fatal(err)
	}
	records := &preKeyRecordStore{pre: map[uint32][]byte{}, signed: map[uint32][]byte{}, kyber: map[uint32][]byte{}, used: map[string]bool{}}
	marshal := func(message googleproto.Message) []byte {
		raw, err := googleproto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	records.signed[55] = marshal(&pb.SignedPreKeyRecordStructure{Id: 55, PublicKey: bob.signedPre.PublicKey.Serialize(), PrivateKey: bob.signedPre.PrivateKey.Serialize()})
	records.kyber[66] = marshal(&pb.SignedPreKeyRecordStructure{Id: 66, PublicKey: bob.kyber.PublicKey.Serialize(), PrivateKey: bob.kyber.SecretKey.Serialize()})
	if oneTime {
		records.pre[77] = marshal(&pb.PreKeyRecordStructure{Id: 77, PublicKey: bob.oneTime.PublicKey.Serialize(), PrivateKey: bob.oneTime.PrivateKey.Serialize()})
	}
	return c, PreKeyDecryptStores{Sessions: c.bobSess, Identities: c.bobIDStore, PreKeys: records, SignedKeys: records, KyberPreKeys: records}, records
}

func outgoingPreKey(t *testing.T, c *convo, text string) *protocol.PreKeySignalMessage {
	t.Helper()
	_, message, err := Encrypt(t.Context(), []byte(text), c.bobAddr, c.aliceSess, c.aliceID, nil, cryptorand.Reader)
	if err != nil || message == nil {
		t.Fatalf("pre-key encryption failed: %v", err)
	}
	return message
}

func preKeySnapshot(c *convo, records *preKeyRecordStore) any {
	clone := func(source map[uint32][]byte) map[uint32][]byte {
		out := maps.Clone(source)
		for id, raw := range out {
			out[id] = bytes.Clone(raw)
		}
		return out
	}
	return struct {
		Session            []byte
		Identity           map[string]curve.PublicKey
		Pre, Signed, Kyber map[uint32][]byte
		Used               map[string]bool
		IdentityWrites     int
	}{bytes.Clone(c.bobSess.records[c.aliceAddr.String()]), maps.Clone(c.bobIDStore.trusted), clone(records.pre), clone(records.signed), clone(records.kyber), maps.Clone(records.used), c.bobIDStore.saveCalls}
}

func TestDecryptPreKeyEstablishesRecipientAndReusesSession(t *testing.T) {
	for _, oneTime := range []bool{false, true} {
		t.Run(fmt.Sprint(oneTime), func(t *testing.T) {
			c, stores, records := preKeyFixture(t, oneTime)
			message := outgoingPreKey(t, c, "first encrypted message")
			plaintext, err := DecryptPreKey(t.Context(), message, c.aliceAddr, stores, cryptorand.Reader)
			if err != nil || string(plaintext) != "first encrypted message" {
				t.Fatalf("recipient pre-key decryption failed: %v", err)
			}
			if len(records.pre) != 0 || len(records.used) != 1 || len(records.signed) != 1 || len(records.kyber) != 1 {
				t.Fatal("recipient did not consume the one-time key and mark Kyber use while retaining signed/Kyber records")
			}
			if !records.used[fmt.Sprintf("66/55/%x", message.BaseKey().Serialize())] {
				t.Fatal("Kyber use was not bound to the signed EC pre-key and base key")
			}
			record, err := c.bobSess.LoadSession(t.Context(), c.aliceAddr)
			if err != nil || record.CurrentState().LocalRegistrationID() != 4242 || record.CurrentState().RemoteRegistrationID() != 1001 {
				t.Fatalf("recipient registration IDs not persisted: %v", err)
			}
			if key, ok := c.bobIDStore.trusted[c.aliceAddr.String()]; !ok || !key.Equal(c.aliceID.identity.PublicKey) {
				t.Fatal("recipient identity was not saved after successful decryption")
			}
			plaintext, err = DecryptPreKey(t.Context(), outgoingPreKey(t, c, "second encrypted message"), c.aliceAddr, stores, cryptorand.Reader)
			if err != nil || string(plaintext) != "second encrypted message" || len(records.used) != 1 {
				t.Fatalf("matching session incorrectly reused consumed pre-keys: %v", err)
			}
			_, err = DecryptPreKey(t.Context(), message, c.aliceAddr, stores, cryptorand.Reader)
			if !errors.Is(err, ErrDuplicateMessage) {
				t.Fatalf("replayed inner message error = %v, want ErrDuplicateMessage", err)
			}
		})
	}
}

func TestDecryptPreKeyIdentityMismatchLeavesAllStoresUnchanged(t *testing.T) {
	for _, archived := range []bool{false, true} {
		t.Run(fmt.Sprint(archived), func(t *testing.T) {
			c, stores, records := preKeyFixture(t, true)
			if _, err := DecryptPreKey(t.Context(), outgoingPreKey(t, c, "establish"), c.aliceAddr, stores, cryptorand.Reader); err != nil {
				t.Fatal(err)
			}
			if archived {
				record, err := c.bobSess.LoadSession(t.Context(), c.aliceAddr)
				if err != nil {
					t.Fatal(err)
				}
				next := record.CurrentState().Clone()
				next.SetAliceBaseKey(genCurve(t, 222).PublicKey.Serialize())
				if err := record.PromoteState(next); err != nil {
					t.Fatal(err)
				}
				if err := c.bobSess.StoreSession(t.Context(), c.aliceAddr, record); err != nil {
					t.Fatal(err)
				}
			}
			message := outgoingPreKey(t, c, "must not be accepted under another identity")
			foreign := genCurve(t, 223).PublicKey
			// Model an independently trusted key, so the matching-session identity
			// check is reached instead of only testing the host trust policy.
			c.bobIDStore.trusted[c.aliceAddr.String()] = foreign
			forged, err := protocol.NewPreKeySignalMessage(message.MessageVersion(), message.RegistrationID(), message.PreKeyID(), message.SignedPreKeyID(), message.KyberPreKeyID(), message.KyberCiphertext(), message.BaseKey(), foreign, message.Message())
			if err != nil {
				t.Fatal(err)
			}
			before := preKeySnapshot(c, records)
			plaintext, err := DecryptPreKey(t.Context(), forged, c.aliceAddr, stores, cryptorand.Reader)
			if !errors.Is(err, ErrInvalidMessage) || len(plaintext) != 0 {
				t.Fatalf("matching-session identity mismatch returned plaintext or wrong error: %v", err)
			}
			if !reflect.DeepEqual(before, preKeySnapshot(c, records)) {
				t.Fatal("identity mismatch mutated identity, pre-key, signed-pre-key, Kyber-use or session state")
			}
		})
	}
}

func TestDecryptPreKeyMalformedOrUnauthenticatedLeavesStoresUnchanged(t *testing.T) {
	for _, mode := range []string{"nil", "bad MAC", "bad signed record", "missing Kyber", "untrusted", "nil stores", "nil random"} {
		t.Run(mode, func(t *testing.T) {
			c, stores, records := preKeyFixture(t, true)
			message := outgoingPreKey(t, c, "must not escape")
			switch mode {
			case "nil":
				message = nil
			case "bad MAC":
				var err error
				message, err = protocol.NewPreKeySignalMessage(message.MessageVersion(), message.RegistrationID(), message.PreKeyID(), message.SignedPreKeyID(), message.KyberPreKeyID(), message.KyberCiphertext(), message.BaseKey(), message.IdentityKey(), tamperBody(t, message.Message()))
				if err != nil {
					t.Fatal(err)
				}
			case "bad signed record":
				records.signed[55] = []byte{0xff}
			case "missing Kyber":
				delete(records.kyber, 66)
			case "untrusted":
				c.bobIDStore.trusted[c.aliceAddr.String()] = genCurve(t, 222).PublicKey
			case "nil stores":
				stores = PreKeyDecryptStores{}
			}
			before := preKeySnapshot(c, records)
			var rng = cryptorand.Reader
			if mode == "nil random" {
				rng = nil
			}
			plaintext, err := DecryptPreKey(t.Context(), message, c.aliceAddr, stores, rng)
			if err == nil || len(plaintext) != 0 || !reflect.DeepEqual(before, preKeySnapshot(c, records)) {
				t.Fatalf("rejected pre-key input escaped plaintext or mutated stores: %v", err)
			}
		})
	}
}

func TestNewSessionsRequireSPQRVersionOne(t *testing.T) {
	local, remote := genCurve(t, 230).PublicKey, genCurve(t, 231).PublicKey
	for _, direction := range []pb.Direction{pb.Direction_A_2_B, pb.Direction_B_2_A} {
		raw, err := pqrInitialState(direction, [32]byte{}, local, remote)
		if err != nil {
			t.Fatal(err)
		}
		var state pb.PqRatchetState
		if err := googleproto.Unmarshal(raw, &state); err != nil {
			t.Fatal(err)
		}
		if state.GetVersionNegotiation().GetMinVersion() != pb.Version_V_1 || state.GetV1() == nil {
			t.Fatal("fresh PQXDH session permits an SPQR downgrade below upstream's V1 floor")
		}
	}
}

func TestDecryptPreKeyArchivedSessionResumesWithoutPreKeyReload(t *testing.T) {
	c, storage, records := preKeyFixture(t, true)
	if _, err := DecryptPreKey(t.Context(), outgoingPreKey(t, c, "first"), c.aliceAddr, storage, cryptorand.Reader); err != nil {
		t.Fatal(err)
	}
	record, err := c.bobSess.LoadSession(t.Context(), c.aliceAddr)
	if err != nil {
		t.Fatal(err)
	}
	next := record.CurrentState().Clone()
	next.SetAliceBaseKey(genCurve(t, 224).PublicKey.Serialize())
	if err := record.PromoteState(next); err != nil {
		t.Fatal(err)
	}
	if err := c.bobSess.StoreSession(t.Context(), c.aliceAddr, record); err != nil {
		t.Fatal(err)
	}
	clear(records.signed)
	clear(records.kyber)
	plaintext, err := DecryptPreKey(t.Context(), outgoingPreKey(t, c, "resume archived session"), c.aliceAddr, storage, cryptorand.Reader)
	if err != nil || string(plaintext) != "resume archived session" || len(records.used) != 1 {
		t.Fatalf("archived session re-read or re-consumed pre-keys: %v", err)
	}
}

func TestDecryptPreKeyStoreWriteFailureDoesNotReturnPlaintext(t *testing.T) {
	c, storage, records := preKeyFixture(t, true)
	records.writeErr = errors.New("injected pre-key commit failure")
	plaintext, err := DecryptPreKey(t.Context(), outgoingPreKey(t, c, "plaintext must not escape failed commit"), c.aliceAddr, storage, cryptorand.Reader)
	if !errors.Is(err, records.writeErr) || len(plaintext) != 0 {
		t.Fatalf("write failure returned plaintext or lost the host error: %v", err)
	}
	if len(c.bobSess.records) != 0 || len(records.pre) != 1 || len(records.used) != 0 {
		t.Fatal("failed Kyber mark continued to consume pre-key or commit session")
	}
	// Upstream saves identity first. This failure is not an atomic store denial.
	if c.bobIDStore.saveCalls != 1 {
		t.Fatal("store commit did not follow upstream identity-first ordering")
	}
}

type aliasSessionStore struct{ record *SessionRecord }

func (s *aliasSessionStore) LoadSession(context.Context, address.ProtocolAddress) (*SessionRecord, error) {
	return s.record, nil
}
func (s *aliasSessionStore) StoreSession(_ context.Context, _ address.ProtocolAddress, record *SessionRecord) error {
	s.record = record
	return nil
}

func TestDecryptPreKeyRejectedArchiveDoesNotMutateAliasedRecord(t *testing.T) {
	c, storage, _ := preKeyFixture(t, true)
	if _, err := DecryptPreKey(t.Context(), outgoingPreKey(t, c, "first"), c.aliceAddr, storage, cryptorand.Reader); err != nil {
		t.Fatal(err)
	}
	record, err := c.bobSess.LoadSession(t.Context(), c.aliceAddr)
	if err != nil {
		t.Fatal(err)
	}
	next := record.CurrentState().Clone()
	next.SetAliceBaseKey(genCurve(t, 224).PublicKey.Serialize())
	if err := record.PromoteState(next); err != nil {
		t.Fatal(err)
	}
	storage.Sessions = &aliasSessionStore{record}
	message := outgoingPreKey(t, c, "authenticated archive must stay isolated")
	forged, err := protocol.NewPreKeySignalMessage(message.MessageVersion(), message.RegistrationID(), message.PreKeyID(), message.SignedPreKeyID(), message.KyberPreKeyID(), message.KyberCiphertext(), message.BaseKey(), message.IdentityKey(), tamperBody(t, message.Message()))
	if err != nil {
		t.Fatal(err)
	}
	before, err := record.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err := DecryptPreKey(t.Context(), forged, c.aliceAddr, storage, cryptorand.Reader); err == nil || len(plaintext) != 0 {
		t.Fatal("corrupt archived message was accepted")
	}
	after, err := record.Serialize()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("archive promotion mutated the record returned by an aliasing host store")
	}
}

func FuzzDecryptPreKeyCiphertext(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, changes []byte) {
		if len(changes) > 1024 {
			t.Skip()
		}
		c, storage, records := preKeyFixture(t, true)
		message := outgoingPreKey(t, c, "fuzz pre-key plaintext")
		raw := message.Serialize()
		for i, delta := range changes {
			raw[i%len(raw)] ^= delta
		}
		message, err := protocol.DeserializePreKeySignalMessage(raw)
		if err != nil {
			return
		}
		before := preKeySnapshot(c, records)
		plaintext, err := DecryptPreKey(t.Context(), message, c.aliceAddr, storage, cryptorand.Reader)
		if err != nil {
			if len(plaintext) != 0 || !reflect.DeepEqual(before, preKeySnapshot(c, records)) {
				t.Fatal("failed fuzz decryption returned plaintext or changed a store")
			}
		} else if string(plaintext) != "fuzz pre-key plaintext" {
			t.Fatal("fuzz decryption returned unauthenticated plaintext")
		}
	})
}
