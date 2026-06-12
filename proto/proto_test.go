package proto

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
)

// TestSignalMessageRoundTrip covers the wire.proto SignalMessage, including the
// pq_ratchet field (number 5) that must be preserved on the wire.
func TestSignalMessageRoundTrip(t *testing.T) {
	msg := &SignalMessage{
		RatchetKey:      []byte{1, 2, 3},
		Counter:         proto.Uint32(7),
		PreviousCounter: proto.Uint32(6),
		Ciphertext:      []byte("ct"),
		PqRatchet:       []byte("pqr"),
		Addresses:       []byte("addr"),
	}
	out := marshalUnmarshal(t, msg, &SignalMessage{})
	got := out.(*SignalMessage)
	if !bytes.Equal(got.GetRatchetKey(), msg.GetRatchetKey()) ||
		got.GetCounter() != msg.GetCounter() ||
		got.GetPreviousCounter() != msg.GetPreviousCounter() ||
		!bytes.Equal(got.GetCiphertext(), msg.GetCiphertext()) ||
		!bytes.Equal(got.GetPqRatchet(), msg.GetPqRatchet()) ||
		!bytes.Equal(got.GetAddresses(), msg.GetAddresses()) {
		t.Fatalf("SignalMessage round-trip mismatch: got %+v want %+v", got, msg)
	}
}

func TestPreKeySignalMessageRoundTrip(t *testing.T) {
	msg := &PreKeySignalMessage{
		RegistrationId:  proto.Uint32(42),
		PreKeyId:        proto.Uint32(1),
		SignedPreKeyId:  proto.Uint32(2),
		KyberPreKeyId:   proto.Uint32(3),
		KyberCiphertext: []byte("kct"),
		BaseKey:         []byte("base"),
		IdentityKey:     []byte("id"),
		Message:         []byte("inner"),
	}
	got := marshalUnmarshal(t, msg, &PreKeySignalMessage{}).(*PreKeySignalMessage)
	if !proto.Equal(got, msg) {
		t.Fatalf("PreKeySignalMessage round-trip mismatch")
	}
}

func TestSenderKeyMessagesRoundTrip(t *testing.T) {
	skm := &SenderKeyMessage{
		DistributionUuid: []byte("uuid"),
		ChainId:          proto.Uint32(9),
		Iteration:        proto.Uint32(3),
		Ciphertext:       []byte("c"),
	}
	if got := marshalUnmarshal(t, skm, &SenderKeyMessage{}).(*SenderKeyMessage); !proto.Equal(got, skm) {
		t.Fatal("SenderKeyMessage round-trip mismatch")
	}

	skdm := &SenderKeyDistributionMessage{
		DistributionUuid: []byte("uuid"),
		ChainId:          proto.Uint32(9),
		Iteration:        proto.Uint32(3),
		ChainKey:         []byte("ck"),
		SigningKey:       []byte("sk"),
	}
	if got := marshalUnmarshal(t, skdm, &SenderKeyDistributionMessage{}).(*SenderKeyDistributionMessage); !proto.Equal(got, skdm) {
		t.Fatal("SenderKeyDistributionMessage round-trip mismatch")
	}
}

func TestServiceMessagesRoundTrip(t *testing.T) {
	content := &Content{
		DataMessage:                  []byte("dm"),
		SenderKeyDistributionMessage: []byte("skdm"),
		DecryptionErrorMessage:       []byte("dem"),
	}
	if got := marshalUnmarshal(t, content, &Content{}).(*Content); !proto.Equal(got, content) {
		t.Fatal("Content round-trip mismatch")
	}

	dem := &DecryptionErrorMessage{
		RatchetKey: []byte("rk"),
		Timestamp:  proto.Uint64(1234567890),
		DeviceId:   proto.Uint32(2),
	}
	if got := marshalUnmarshal(t, dem, &DecryptionErrorMessage{}).(*DecryptionErrorMessage); !proto.Equal(got, dem) {
		t.Fatal("DecryptionErrorMessage round-trip mismatch")
	}
}

// TestSessionStructureRoundTrip covers the proto3 storage.SessionStructure with
// nested messages, repeated fields, and the pq_ratchet_state field (number 15).
func TestSessionStructureRoundTrip(t *testing.T) {
	sess := &SessionStructure{
		SessionVersion:       4,
		LocalIdentityPublic:  []byte("lip"),
		RemoteIdentityPublic: []byte("rip"),
		RootKey:              []byte("rk"),
		PreviousCounter:      5,
		SenderChain: &SessionStructure_Chain{
			SenderRatchetKey:        []byte("srk"),
			SenderRatchetKeyPrivate: []byte("srkp"),
			ChainKey: &SessionStructure_Chain_ChainKey{
				Index: 1,
				Key:   []byte("k"),
			},
			MessageKeys: []*SessionStructure_Chain_MessageKey{
				{Index: 0, CipherKey: []byte("ck"), MacKey: []byte("mk"), Iv: []byte("iv")},
				{Index: 1, Seed: []byte("seed")},
			},
		},
		ReceiverChains:       []*SessionStructure_Chain{{SenderRatchetKey: []byte("rc")}},
		PendingPreKey:        &SessionStructure_PendingPreKey{PreKeyId: proto.Uint32(1), SignedPreKeyId: 3, BaseKey: []byte("bk"), Timestamp: 99},
		PendingKyberPreKey:   &SessionStructure_PendingKyberPreKey{PreKeyId: 2, Ciphertext: []byte("kct")},
		RemoteRegistrationId: 10,
		LocalRegistrationId:  11,
		AliceBaseKey:         []byte("abk"),
		PqRatchetState:       []byte("pqstate"),
	}
	got := marshalUnmarshal(t, sess, &SessionStructure{}).(*SessionStructure)
	if !proto.Equal(got, sess) {
		t.Fatal("SessionStructure round-trip mismatch")
	}
	if !bytes.Equal(got.GetPqRatchetState(), []byte("pqstate")) {
		t.Fatal("pq_ratchet_state not preserved")
	}
}

func TestStorageRecordsRoundTrip(t *testing.T) {
	for _, m := range []proto.Message{
		&RecordStructure{CurrentSession: &SessionStructure{SessionVersion: 4}, PreviousSessions: [][]byte{{1}, {2}}},
		&PreKeyRecordStructure{Id: 1, PublicKey: []byte("pk"), PrivateKey: []byte("sk")},
		&SignedPreKeyRecordStructure{Id: 1, PublicKey: []byte("pk"), PrivateKey: []byte("sk"), Signature: []byte("sig"), Timestamp: 7},
		&IdentityKeyPairStructure{PublicKey: []byte("pk"), PrivateKey: []byte("sk")},
		&SenderKeyRecordStructure{SenderKeyStates: []*SenderKeyStateStructure{{ChainId: 1, MessageVersion: 3}}},
	} {
		clone := m.ProtoReflect().New().Interface()
		got := marshalUnmarshal(t, m, clone)
		if !proto.Equal(got, m) {
			t.Fatalf("%T round-trip mismatch", m)
		}
	}
}

// TestSealedSenderRoundTrip covers proto2 messages with oneofs and nested enums.
func TestSealedSenderRoundTrip(t *testing.T) {
	uuidOneof := &SenderCertificate_Certificate{
		SenderE164:   proto.String("+15555550123"),
		SenderUuid:   &SenderCertificate_Certificate_UuidString{UuidString: "8c78cd2a-16ff-427d-83dc-1a5e36ce713d"},
		SenderDevice: proto.Uint32(1),
		Expires:      proto.Uint64(123),
		IdentityKey:  []byte("ik"),
		Signer:       &SenderCertificate_Certificate_Id{Id: 5},
	}
	if got := marshalUnmarshal(t, uuidOneof, &SenderCertificate_Certificate{}).(*SenderCertificate_Certificate); !proto.Equal(got, uuidOneof) {
		t.Fatal("SenderCertificate.Certificate (oneof) round-trip mismatch")
	}

	usm := &UnidentifiedSenderMessage_Message{
		Type:              UnidentifiedSenderMessage_Message_SENDERKEY_MESSAGE.Enum(),
		SenderCertificate: []byte("cert"),
		Content:           []byte("body"),
		ContentHint:       UnidentifiedSenderMessage_Message_IMPLICIT.Enum(),
		GroupId:           []byte("gid"),
	}
	if got := marshalUnmarshal(t, usm, &UnidentifiedSenderMessage_Message{}).(*UnidentifiedSenderMessage_Message); !proto.Equal(got, usm) {
		t.Fatal("UnidentifiedSenderMessage.Message round-trip mismatch")
	}
}

func TestFingerprintRoundTrip(t *testing.T) {
	cf := &CombinedFingerprints{
		Version:           proto.Uint32(1),
		LocalFingerprint:  &LogicalFingerprint{Content: []byte("local")},
		RemoteFingerprint: &LogicalFingerprint{Content: []byte("remote")},
	}
	if got := marshalUnmarshal(t, cf, &CombinedFingerprints{}).(*CombinedFingerprints); !proto.Equal(got, cf) {
		t.Fatal("CombinedFingerprints round-trip mismatch")
	}
}

// TestUnknownFieldPreservation guards the pq_ratchet passthrough behavior
// required before P10: a message carrying a field number this build does not
// define must survive a decode/re-encode cycle with the unknown field intact.
//
// We append an extra field (number 99, a length-delimited payload) to a
// serialized SenderKeyMessage — which defines no field 99 — then unmarshal and
// re-marshal, and confirm the unknown field bytes are preserved verbatim.
func TestUnknownFieldPreservation(t *testing.T) {
	base := &SenderKeyMessage{
		DistributionUuid: []byte("uuid"),
		ChainId:          proto.Uint32(1),
		Iteration:        proto.Uint32(2),
		Ciphertext:       []byte("ct"),
	}
	baseBytes, err := proto.Marshal(base)
	if err != nil {
		t.Fatalf("marshal base: %v", err)
	}

	// Hand-encode an unknown field: tag = (field 99 << 3) | wireType 2
	// (length-delimited), then length, then payload.
	unknownPayload := []byte("future-extension")
	extra := appendUnknownLenField(99, unknownPayload)
	withUnknown := append(append([]byte(nil), baseBytes...), extra...)

	// Decode into the current type (which has no field 99); the runtime stores
	// it as an unknown field.
	var decoded SenderKeyMessage
	if err := proto.Unmarshal(withUnknown, &decoded); err != nil {
		t.Fatalf("unmarshal with unknown field: %v", err)
	}
	// Known fields still decode correctly. We compare field-by-field rather
	// than proto.Equal, since decoded now also carries the unknown field (which
	// proto.Equal includes in its comparison).
	if !bytes.Equal(decoded.GetDistributionUuid(), base.GetDistributionUuid()) ||
		decoded.GetChainId() != base.GetChainId() ||
		decoded.GetIteration() != base.GetIteration() ||
		!bytes.Equal(decoded.GetCiphertext(), base.GetCiphertext()) {
		t.Fatal("known fields changed when an unknown field was present")
	}

	// Re-marshal; the unknown field must be preserved.
	reMarshaled, err := proto.Marshal(&decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Contains(reMarshaled, extra) {
		t.Fatalf("unknown field was dropped on re-marshal:\n got %x\n want to contain %x", reMarshaled, extra)
	}
}

// marshalUnmarshal marshals src, unmarshals into dst, and returns dst. It fails
// the test on any marshal/unmarshal error.
func marshalUnmarshal(t *testing.T, src, dst proto.Message) proto.Message {
	t.Helper()
	b, err := proto.Marshal(src)
	if err != nil {
		t.Fatalf("marshal %T: %v", src, err)
	}
	if err := proto.Unmarshal(b, dst); err != nil {
		t.Fatalf("unmarshal %T: %v", dst, err)
	}
	return dst
}

// appendUnknownLenField encodes a single length-delimited protobuf field
// (wire type 2) with the given field number and payload.
func appendUnknownLenField(fieldNumber uint64, payload []byte) []byte {
	var out []byte
	out = appendVarint(out, fieldNumber<<3|2) // tag
	out = appendVarint(out, uint64(len(payload)))
	out = append(out, payload...)
	return out
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}
