package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/curve"
)

// fixedReader yields deterministic bytes, for reproducible key generation and
// signature nonces in tests.
type fixedReader struct{ b byte }

func (r *fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
		r.b++
	}
	return len(p), nil
}

func testDistributionID() [uuidLen]byte {
	return [uuidLen]byte{
		0x8c, 0x78, 0xcd, 0x2a, 0x16, 0xff, 0x42, 0x7d,
		0x83, 0xdc, 0x1a, 0x5e, 0x36, 0xce, 0x71, 0x3d,
	}
}

func TestSenderKeyMessageRoundTrip(t *testing.T) {
	signKP, err := curve.GenerateKeyPair(&fixedReader{b: 1})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	msg, err := NewSenderKeyMessage(testDistributionID(), 9, 3, []byte("ciphertext"), &fixedReader{b: 0x42}, signKP.PrivateKey)
	if err != nil {
		t.Fatalf("NewSenderKeyMessage: %v", err)
	}

	got, err := DeserializeSenderKeyMessage(msg.Serialized())
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.MessageVersion() != SenderKeyMessageCurrentVersion {
		t.Fatalf("version = %d, want %d", got.MessageVersion(), SenderKeyMessageCurrentVersion)
	}
	if got.DistributionID() != testDistributionID() {
		t.Fatalf("distribution id = %x", got.DistributionID())
	}
	if got.ChainID() != 9 || got.Iteration() != 3 {
		t.Fatalf("chainID/iteration = %d/%d, want 9/3", got.ChainID(), got.Iteration())
	}
	if !bytes.Equal(got.Ciphertext(), []byte("ciphertext")) {
		t.Fatalf("ciphertext = %q", got.Ciphertext())
	}
	if !bytes.Equal(got.Serialized(), msg.Serialized()) {
		t.Fatal("serialized round-trip mismatch")
	}
}

func TestSenderKeyMessageSignatureVerify(t *testing.T) {
	signKP, err := curve.GenerateKeyPair(&fixedReader{b: 5})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	msg, err := NewSenderKeyMessage(testDistributionID(), 1, 2, []byte("body"), &fixedReader{b: 0x11}, signKP.PrivateKey)
	if err != nil {
		t.Fatalf("NewSenderKeyMessage: %v", err)
	}

	// Valid signature verifies.
	parsed, err := DeserializeSenderKeyMessage(msg.Serialized())
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if !parsed.VerifySignature(signKP.PublicKey) {
		t.Fatal("valid signature failed to verify")
	}

	// Wrong key does not verify.
	otherKP, err := curve.GenerateKeyPair(&fixedReader{b: 99})
	if err != nil {
		t.Fatalf("GenerateKeyPair(other): %v", err)
	}
	if parsed.VerifySignature(otherKP.PublicKey) {
		t.Fatal("signature verified under the wrong key")
	}

	// Every single-byte flip in the serialized message breaks verification.
	for i := range msg.Serialized() {
		tampered := append([]byte(nil), msg.Serialized()...)
		tampered[i] ^= 0x01
		parsedT, err := DeserializeSenderKeyMessage(tampered)
		if err != nil {
			// A flip that breaks framing (version/proto) is a valid rejection.
			continue
		}
		if parsedT.VerifySignature(signKP.PublicKey) {
			t.Fatalf("tampered message (byte %d) verified", i)
		}
	}
}

func TestSenderKeyMessageRejectsBadInput(t *testing.T) {
	// Too short (< 1 + 64).
	if _, err := DeserializeSenderKeyMessage(make([]byte, 10)); err == nil {
		t.Fatal("short message accepted")
	} else if _, ok := err.(CiphertextMessageTooShortError); !ok {
		t.Fatalf("short message error = %T, want CiphertextMessageTooShortError", err)
	}

	signKP, _ := curve.GenerateKeyPair(&fixedReader{b: 1})
	msg, _ := NewSenderKeyMessage(testDistributionID(), 1, 1, []byte("x"), &fixedReader{b: 2}, signKP.PrivateKey)

	// Legacy version (< current): set high nibble to 2.
	legacy := append([]byte(nil), msg.Serialized()...)
	legacy[0] = (2 << 4) | SenderKeyMessageCurrentVersion
	if _, err := DeserializeSenderKeyMessage(legacy); err == nil {
		t.Fatal("legacy version accepted")
	} else if _, ok := err.(LegacyCiphertextVersionError); !ok {
		t.Fatalf("legacy error = %T, want LegacyCiphertextVersionError", err)
	}

	// Unrecognized version (> current): set high nibble to 5.
	future := append([]byte(nil), msg.Serialized()...)
	future[0] = (5 << 4) | SenderKeyMessageCurrentVersion
	if _, err := DeserializeSenderKeyMessage(future); err == nil {
		t.Fatal("future version accepted")
	} else if _, ok := err.(UnrecognizedCiphertextVersionError); !ok {
		t.Fatalf("future error = %T, want UnrecognizedCiphertextVersionError", err)
	}

	// Corrupt protobuf body (keep length >= 1+64 but garble the body).
	corrupt := append([]byte(nil), msg.Serialized()...)
	for i := 1; i < len(corrupt)-senderKeySignatureLen; i++ {
		corrupt[i] = 0xFF
	}
	if _, err := DeserializeSenderKeyMessage(corrupt); err == nil {
		t.Fatal("corrupt protobuf accepted")
	}
}

// TestSenderKeyMessageGolden locks the wire layout against a fixed key and
// fixed signature nonce. The expected hex is self-generated (not an upstream
// vector); it is replaced by upstream test vectors in Task 12. It guards
// against accidental layout changes in the meantime.
func TestSenderKeyMessageGolden(t *testing.T) {
	signKP, err := curve.GenerateKeyPair(&fixedReader{b: 0x10})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	msg, err := NewSenderKeyMessage(testDistributionID(), 0x01020304, 0x05060708, []byte("golden"), &fixedReader{b: 0x77}, signKP.PrivateKey)
	if err != nil {
		t.Fatalf("NewSenderKeyMessage: %v", err)
	}
	got := hex.EncodeToString(msg.Serialized())

	// The leading version byte and protobuf prefix are deterministic; the
	// 64-byte XEdDSA signature is deterministic given the fixed nonce + key.
	want := goldenSenderKeyMessageHex
	if got != want {
		t.Fatalf("golden mismatch:\n got %s\nwant %s", got, want)
	}
}
