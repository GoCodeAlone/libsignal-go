package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/curve"
)

// fixedReader yields deterministic bytes so key generation and message
// construction are reproducible across runs (used for golden-byte tests).
type fixedReader struct{ b byte }

func (r *fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
		r.b++
	}
	return len(p), nil
}

// fixedKeyPair derives a deterministic curve key pair from a seed byte.
func fixedKeyPair(t *testing.T, seed byte) curve.KeyPair {
	t.Helper()
	kp, err := curve.GenerateKeyPair(&fixedReader{b: seed})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

func newMACKey(b byte) []byte {
	k := make([]byte, macKeyLength)
	for i := range k {
		k[i] = b
	}
	return k
}

// TestSignalMessageGoldenBytes locks the wire layout with fixed keys and inputs.
// This is a provisional self-consistency anchor; it is replaced by
// upstream-generated vectors in Task 12 (compat harness). If this hex changes,
// the wire format changed — investigate before updating.
func TestSignalMessageGoldenBytes(t *testing.T) {
	ratchet := fixedKeyPair(t, 1).PublicKey
	senderID := fixedKeyPair(t, 2).PublicKey
	receiverID := fixedKeyPair(t, 3).PublicKey
	macKey := newMACKey(0x40)
	ciphertext := []byte("ratchet-encrypted-body")

	msg, err := NewSignalMessage(
		CurrentVersion, macKey, ratchet,
		7, 3, ciphertext, senderID, receiverID, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewSignalMessage: %v", err)
	}

	// Committed golden value: the exact serialized bytes for the fixed inputs
	// above. This pins the wire layout (version byte, proto field order, MAC).
	const wantGolden = "440a210507a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c100718032216726174636865742d656e637279707465642d626f6479ea6d64dd00ba899d"
	got := hex.EncodeToString(msg.Serialize())
	if got != wantGolden {
		t.Fatalf("golden hex changed (wire format changed — investigate before updating):\n got  %s\n want %s", got, wantGolden)
	}

	// Structural invariants that must hold regardless of proto byte ordering:
	ser := msg.Serialize()
	if ser[0] != byte((CurrentVersion<<4)|CurrentVersion) {
		t.Fatalf("version byte = 0x%02x, want 0x%02x", ser[0], (CurrentVersion<<4)|CurrentVersion)
	}
	if len(ser) < macLength+1 {
		t.Fatalf("serialized too short: %d", len(ser))
	}

	// Round-trip must reproduce the same bytes and fields.
	rt, err := DeserializeSignalMessage(ser)
	if err != nil {
		t.Fatalf("DeserializeSignalMessage: %v", err)
	}
	if !bytes.Equal(rt.Serialize(), ser) {
		t.Fatal("round-trip serialize mismatch")
	}
	if rt.Counter() != 7 || rt.PreviousCounter() != 3 {
		t.Fatalf("counters = (%d,%d), want (7,3)", rt.Counter(), rt.PreviousCounter())
	}
	if !bytes.Equal(rt.Body(), ciphertext) {
		t.Fatalf("body = %q, want %q", rt.Body(), ciphertext)
	}
	if !rt.SenderRatchetKey().Equal(ratchet) {
		t.Fatal("ratchet key mismatch after round-trip")
	}
}

func TestSignalMessageMACVerify(t *testing.T) {
	ratchet := fixedKeyPair(t, 11).PublicKey
	senderID := fixedKeyPair(t, 12).PublicKey
	receiverID := fixedKeyPair(t, 13).PublicKey
	macKey := newMACKey(0x11)

	msg, err := NewSignalMessage(CurrentVersion, macKey, ratchet, 1, 0, []byte("hi"), senderID, receiverID, nil, nil)
	if err != nil {
		t.Fatalf("NewSignalMessage: %v", err)
	}
	parsed, err := DeserializeSignalMessage(msg.Serialize())
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}

	ok, err := parsed.VerifyMAC(senderID, receiverID, macKey)
	if err != nil {
		t.Fatalf("VerifyMAC: %v", err)
	}
	if !ok {
		t.Fatal("MAC failed to verify on an honest message")
	}

	// Wrong mac key -> false.
	ok, err = parsed.VerifyMAC(senderID, receiverID, newMACKey(0x22))
	if err != nil {
		t.Fatalf("VerifyMAC: %v", err)
	}
	if ok {
		t.Fatal("MAC verified under wrong key")
	}

	// Swapped identity keys -> false (MAC binds direction).
	ok, _ = parsed.VerifyMAC(receiverID, senderID, macKey)
	if ok {
		t.Fatal("MAC verified with swapped identity keys")
	}

	// Flipped ciphertext byte -> false.
	tampered := append([]byte(nil), msg.Serialize()...)
	tampered[len(tampered)-macLength-1] ^= 0x01
	tparsed, err := DeserializeSignalMessage(tampered)
	if err != nil {
		t.Fatalf("Deserialize(tampered): %v", err)
	}
	ok, _ = tparsed.VerifyMAC(senderID, receiverID, macKey)
	if ok {
		t.Fatal("MAC verified on tampered ciphertext")
	}
}

func TestSignalMessageBadMACKeyLength(t *testing.T) {
	ratchet := fixedKeyPair(t, 21).PublicKey
	id := fixedKeyPair(t, 22).PublicKey
	if _, err := NewSignalMessage(CurrentVersion, make([]byte, 16), ratchet, 0, 0, nil, id, id, nil, nil); !errors.Is(err, ErrInvalidMACKeyLength) {
		t.Fatalf("err = %v, want ErrInvalidMACKeyLength", err)
	}
}

func TestSignalMessageVersionFloorAndCeiling(t *testing.T) {
	ratchet := fixedKeyPair(t, 31).PublicKey
	id := fixedKeyPair(t, 32).PublicKey
	macKey := newMACKey(0x31)
	msg, err := NewSignalMessage(CurrentVersion, macKey, ratchet, 0, 0, []byte("x"), id, id, nil, nil)
	if err != nil {
		t.Fatalf("NewSignalMessage: %v", err)
	}
	ser := append([]byte(nil), msg.Serialize()...)

	// Force version nibble to 2 (< PreKyber 3) -> ErrLegacyVersion.
	ser[0] = byte((2 << 4) | CurrentVersion)
	if _, err := DeserializeSignalMessage(ser); !errors.Is(err, ErrLegacyVersion) {
		t.Fatalf("v2 err = %v, want ErrLegacyVersion", err)
	}
	// Force version nibble to 5 (> Current 4) -> ErrUnrecognizedVersion.
	ser[0] = byte((5 << 4) | CurrentVersion)
	if _, err := DeserializeSignalMessage(ser); !errors.Is(err, ErrUnrecognizedVersion) {
		t.Fatalf("v5 err = %v, want ErrUnrecognizedVersion", err)
	}
	// v3 is accepted (floor inclusive).
	ser[0] = byte((PreKyberVersion << 4) | CurrentVersion)
	if _, err := DeserializeSignalMessage(ser); err != nil {
		t.Fatalf("v3 should deserialize, got %v", err)
	}
}

func TestSignalMessageTruncatedInputs(t *testing.T) {
	for _, n := range []int{0, 1, 8, macLength} {
		if _, err := DeserializeSignalMessage(make([]byte, n)); !errors.Is(err, ErrCiphertextTooShort) {
			t.Fatalf("len %d err = %v, want ErrCiphertextTooShort", n, err)
		}
	}
	// Just over the minimum but with a garbage body -> protobuf error, not panic.
	buf := make([]byte, macLength+2)
	buf[0] = byte((CurrentVersion << 4) | CurrentVersion)
	buf[1] = 0xFF // invalid protobuf tag
	if _, err := DeserializeSignalMessage(buf); err == nil {
		t.Fatal("expected error for garbage body")
	}
}

func TestSignalMessagePQRatchetPassthrough(t *testing.T) {
	ratchet := fixedKeyPair(t, 41).PublicKey
	id := fixedKeyPair(t, 42).PublicKey
	macKey := newMACKey(0x41)
	pq := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	msg, err := NewSignalMessage(CurrentVersion, macKey, ratchet, 2, 1, []byte("body"), id, id, pq, nil)
	if err != nil {
		t.Fatalf("NewSignalMessage: %v", err)
	}
	rt, err := DeserializeSignalMessage(msg.Serialize())
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if !bytes.Equal(rt.PQRatchet(), pq) {
		t.Fatalf("pq_ratchet = %x, want %x", rt.PQRatchet(), pq)
	}
}
