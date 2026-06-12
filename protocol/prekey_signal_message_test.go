package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/GoCodeAlone/libsignal-go/proto"
)

func u32(v uint32) *uint32 { return &v }

// TestPreKeySignalMessageGoldenBytes pins the PreKeySignalMessage wire layout
// with fixed inputs (provisional anchor; replaced by upstream vectors in Task
// 12). A small fixed Kyber ciphertext keeps the golden tractable.
func TestPreKeySignalMessageGoldenBytes(t *testing.T) {
	base := fixedKeyPair(t, 101).PublicKey
	identity := fixedKeyPair(t, 102).PublicKey
	inner := innerSignalMessage(t)

	msg, err := NewPreKeySignalMessage(
		CurrentVersion, 4242, u32(11), 22, u32(33), []byte{0xAB, 0xCD}, base, identity, inner,
	)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessage: %v", err)
	}

	const wantGolden = "44080b1221055714769d116bf76436ae74bc793d2c30ad1903c59ac5273805c7e2698b410c361a2105ca0ff4a4b789fc3063bb068e648933f844a9d284c6bd7f6ba2cb0d44089c100b2237440a2105c15d2265459455c9ff156e6c1da6bfb7910bb8af50f2b2f9f853ea9325259d4d100118002205696e6e6572bc3aeb6e52d9eb3c289221301638214202abcd"
	got := hex.EncodeToString(msg.Serialize())
	if got != wantGolden {
		t.Fatalf("golden hex changed (wire format changed — investigate before updating):\n got  %s\n want %s", got, wantGolden)
	}
}

// innerSignalMessage builds a valid inner SignalMessage for embedding.
func innerSignalMessage(t *testing.T) *SignalMessage {
	t.Helper()
	ratchet := fixedKeyPair(t, 51).PublicKey
	id := fixedKeyPair(t, 52).PublicKey
	m, err := NewSignalMessage(CurrentVersion, newMACKey(0x51), ratchet, 1, 0, []byte("inner"), id, id, nil, nil)
	if err != nil {
		t.Fatalf("inner NewSignalMessage: %v", err)
	}
	return m
}

func TestPreKeySignalMessageRoundTripV4(t *testing.T) {
	base := fixedKeyPair(t, 61).PublicKey
	identity := fixedKeyPair(t, 62).PublicKey
	inner := innerSignalMessage(t)
	kyberCT := bytes.Repeat([]byte{0x09}, 1568) // Kyber1024 ct size; opaque here

	msg, err := NewPreKeySignalMessage(
		CurrentVersion, 1234, u32(77), 88, u32(99), kyberCT, base, identity, inner,
	)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessage: %v", err)
	}

	rt, err := DeserializePreKeySignalMessage(msg.Serialize())
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if !bytes.Equal(rt.Serialize(), msg.Serialize()) {
		t.Fatal("round-trip serialize mismatch")
	}
	if rt.RegistrationID() != 1234 {
		t.Fatalf("registrationID = %d, want 1234", rt.RegistrationID())
	}
	if rt.PreKeyID() == nil || *rt.PreKeyID() != 77 {
		t.Fatalf("preKeyID = %v, want 77", rt.PreKeyID())
	}
	if rt.SignedPreKeyID() != 88 {
		t.Fatalf("signedPreKeyID = %d, want 88", rt.SignedPreKeyID())
	}
	if rt.KyberPreKeyID() == nil || *rt.KyberPreKeyID() != 99 {
		t.Fatalf("kyberPreKeyID = %v, want 99", rt.KyberPreKeyID())
	}
	if !bytes.Equal(rt.KyberCiphertext(), kyberCT) {
		t.Fatal("kyber ciphertext mismatch")
	}
	if !rt.BaseKey().Equal(base) || !rt.IdentityKey().Equal(identity) {
		t.Fatal("base/identity key mismatch")
	}
	if !bytes.Equal(rt.Message().Serialize(), inner.Serialize()) {
		t.Fatal("inner message mismatch")
	}
}

func TestPreKeySignalMessageNoOneTimePreKey(t *testing.T) {
	base := fixedKeyPair(t, 71).PublicKey
	identity := fixedKeyPair(t, 72).PublicKey
	inner := innerSignalMessage(t)
	// nil preKeyID is allowed (no one-time prekey), Kyber still required at v4.
	msg, err := NewPreKeySignalMessage(CurrentVersion, 1, nil, 5, u32(6), []byte{0x01}, base, identity, inner)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessage: %v", err)
	}
	rt, err := DeserializePreKeySignalMessage(msg.Serialize())
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if rt.PreKeyID() != nil {
		t.Fatalf("preKeyID = %v, want nil", rt.PreKeyID())
	}
}

// TestPreKeySignalMessageV4RequiresKyber checks that a v4 message with no Kyber
// payload is rejected on deserialize (the kyber-must-be-present rule), while a
// v3 message without Kyber is accepted.
func TestPreKeySignalMessageV4RequiresKyber(t *testing.T) {
	base := fixedKeyPair(t, 81).PublicKey
	identity := fixedKeyPair(t, 82).PublicKey
	inner := innerSignalMessage(t)

	// Hand-build a v4 body with NO kyber fields by marshaling the proto directly.
	body := &pb.PreKeySignalMessage{
		RegistrationId: proto.Uint32(1),
		SignedPreKeyId: proto.Uint32(2),
		BaseKey:        base.Serialize(),
		IdentityKey:    identity.Serialize(),
		Message:        inner.Serialize(),
	}
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	v4 := append([]byte{encodeVersionByte(CurrentVersion, CurrentVersion)}, bodyBytes...)
	if _, err := DeserializePreKeySignalMessage(v4); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("v4-without-kyber err = %v, want ErrInvalidMessage", err)
	}

	// Same body framed as v3 must be accepted (Kyber optional pre-v4).
	v3 := append([]byte{encodeVersionByte(PreKyberVersion, CurrentVersion)}, bodyBytes...)
	if _, err := DeserializePreKeySignalMessage(v3); err != nil {
		t.Fatalf("v3-without-kyber should deserialize, got %v", err)
	}
}

// TestPreKeySignalMessageKyberBothOrNeither checks that exactly one of
// kyber_pre_key_id / kyber_ciphertext present is rejected.
func TestPreKeySignalMessageKyberBothOrNeither(t *testing.T) {
	base := fixedKeyPair(t, 91).PublicKey
	identity := fixedKeyPair(t, 92).PublicKey
	inner := innerSignalMessage(t)

	for _, tc := range []struct {
		name string
		id   *uint32
		ct   []byte
	}{
		{"id-only", proto.Uint32(3), nil},
		{"ct-only", nil, []byte{0x02}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &pb.PreKeySignalMessage{
				RegistrationId:  proto.Uint32(1),
				SignedPreKeyId:  proto.Uint32(2),
				KyberPreKeyId:   tc.id,
				KyberCiphertext: tc.ct,
				BaseKey:         base.Serialize(),
				IdentityKey:     identity.Serialize(),
				Message:         inner.Serialize(),
			}
			bodyBytes, _ := proto.Marshal(body)
			v4 := append([]byte{encodeVersionByte(CurrentVersion, CurrentVersion)}, bodyBytes...)
			if _, err := DeserializePreKeySignalMessage(v4); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("err = %v, want ErrInvalidMessage", err)
			}
		})
	}
}

func TestPreKeySignalMessageVersionAndEmpty(t *testing.T) {
	if _, err := DeserializePreKeySignalMessage(nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("empty err = %v, want ErrCiphertextTooShort", err)
	}
	// Bad version nibble.
	if _, err := DeserializePreKeySignalMessage([]byte{byte((2 << 4) | CurrentVersion), 0x00}); !errors.Is(err, ErrLegacyVersion) {
		t.Fatalf("v2 err = %v, want ErrLegacyVersion", err)
	}
}

func TestPreKeySignalMessageMissingRequiredFields(t *testing.T) {
	// Body missing base_key/identity_key/message -> ErrInvalidProtobuf.
	body := &pb.PreKeySignalMessage{
		RegistrationId: proto.Uint32(1),
		SignedPreKeyId: proto.Uint32(2),
	}
	bodyBytes, _ := proto.Marshal(body)
	v4 := append([]byte{encodeVersionByte(CurrentVersion, CurrentVersion)}, bodyBytes...)
	if _, err := DeserializePreKeySignalMessage(v4); !errors.Is(err, ErrInvalidProtobuf) {
		t.Fatalf("err = %v, want ErrInvalidProtobuf", err)
	}
}
