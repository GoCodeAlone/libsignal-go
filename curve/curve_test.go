package curve

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// mustHex decodes a hex string in a test, failing on malformed input.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestGenerateKeyPairDeterministic verifies that an injected RNG yields a
// deterministic key pair and that the derived public key matches the one
// computed from the private key.
func TestGenerateKeyPairDeterministic(t *testing.T) {
	// A fixed 32-byte seed makes generation reproducible.
	seed := bytes.Repeat([]byte{0x42}, PrivateKeyLength)
	kp1, err := GenerateKeyPair(bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	kp2, err := GenerateKeyPair(bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("GenerateKeyPair (2): %v", err)
	}
	if !bytes.Equal(kp1.PrivateKey.Serialize(), kp2.PrivateKey.Serialize()) {
		t.Fatal("same seed produced different private keys")
	}
	if !kp1.PublicKey.Equal(kp2.PublicKey) {
		t.Fatal("same seed produced different public keys")
	}

	// The stored private key is clamped.
	priv := kp1.PrivateKey.Serialize()
	if priv[0]&0b0000_0111 != 0 || priv[31]&0b1000_0000 != 0 || priv[31]&0b0100_0000 == 0 {
		t.Fatalf("private key not clamped: %x", priv)
	}

	// Re-deriving the public key from the private key matches.
	rederived, err := kp1.PrivateKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !rederived.Equal(kp1.PublicKey) {
		t.Fatal("re-derived public key does not match generated public key")
	}
}

// TestGenerateKeyPairShortRNG verifies a truncated RNG surfaces an error rather
// than panicking.
func TestGenerateKeyPairShortRNG(t *testing.T) {
	if _, err := GenerateKeyPair(bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("expected error from short RNG, got nil")
	}
}

// TestPublicKeySerializeShape verifies the 33-byte wire form and the 0x05 type
// byte.
func TestPublicKeySerializeShape(t *testing.T) {
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ser := kp.PublicKey.Serialize()
	if len(ser) != SerializedPublicKeyLength {
		t.Fatalf("Serialize() len = %d, want %d", len(ser), SerializedPublicKeyLength)
	}
	if len(ser) != 33 {
		t.Fatalf("Serialize() len = %d, want 33", len(ser))
	}
	if ser[0] != 0x05 {
		t.Fatalf("Serialize()[0] = 0x%02x, want 0x05", ser[0])
	}
	if !bytes.Equal(ser[1:], kp.PublicKey.PublicKeyBytes()) {
		t.Fatal("serialized body does not match raw public key bytes")
	}
}

// TestDeserializePublicKeyRoundTrip checks serialize/deserialize identity.
func TestDeserializePublicKeyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ser := kp.PublicKey.Serialize()
	got, err := DeserializePublicKey(ser)
	if err != nil {
		t.Fatalf("DeserializePublicKey: %v", err)
	}
	if !got.Equal(kp.PublicKey) {
		t.Fatal("round-trip public key mismatch")
	}
	if !bytes.Equal(got.Serialize(), ser) {
		t.Fatal("re-serialized bytes differ")
	}
}

// TestDeserializePublicKeyErrors ports the rust test_decode_size rejection
// cases: empty input, body one byte short, and a bad type byte. None may panic.
func TestDeserializePublicKeyErrors(t *testing.T) {
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ser := kp.PublicKey.Serialize()

	// Empty input: no type identifier.
	if _, err := DeserializePublicKey(nil); err == nil {
		t.Fatal("DeserializePublicKey(nil) = nil error, want error")
	} else if _, ok := err.(ErrNoKeyTypeIdentifier); !ok {
		t.Fatalf("DeserializePublicKey(nil) error = %T, want ErrNoKeyTypeIdentifier", err)
	}

	// Dropping the type byte leaves a 32-byte body, which is one byte short of
	// a full type-tagged key (upstream rejects ser[1:]).
	if _, err := DeserializePublicKey(ser[1:]); err == nil {
		t.Fatal("DeserializePublicKey(ser[1:]) = nil error, want error")
	}

	// Bad type byte 0x01.
	badType := append([]byte(nil), ser...)
	badType[0] = 0x01
	if _, err := DeserializePublicKey(badType); err == nil {
		t.Fatal("DeserializePublicKey(bad type) = nil error, want error")
	} else if _, ok := err.(BadKeyTypeError); !ok {
		t.Fatalf("DeserializePublicKey(bad type) error = %T, want BadKeyTypeError", err)
	}
}

// TestDeserializePublicKeyAllowsTrailing ports the rust test_decode_size
// trailing-bytes case: a 34-byte buffer (one extra byte) decodes successfully
// and re-serializes to the canonical 33 bytes.
func TestDeserializePublicKeyAllowsTrailing(t *testing.T) {
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ser := kp.PublicKey.Serialize()
	extra := append(append([]byte(nil), ser...), 0x00)
	got, err := DeserializePublicKey(extra)
	if err != nil {
		t.Fatalf("DeserializePublicKey(extra) error = %v, want success", err)
	}
	if !bytes.Equal(got.Serialize(), ser) {
		t.Fatal("trailing-byte decode did not round-trip to canonical form")
	}
}

// TestDeserializePrivateKeyLength checks that only 32-byte private keys are
// accepted.
func TestDeserializePrivateKeyLength(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := DeserializePrivateKey(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Fatalf("DeserializePrivateKey(len %d) = nil error, want error", n)
		}
	}
	if _, err := DeserializePrivateKey(bytes.Repeat([]byte{1}, PrivateKeyLength)); err != nil {
		t.Fatalf("DeserializePrivateKey(len 32) error = %v, want success", err)
	}
}

// TestDeserializePrivateKeyClamps verifies clamping is applied on deserialize.
func TestDeserializePrivateKeyClamps(t *testing.T) {
	raw := bytes.Repeat([]byte{0xFF}, PrivateKeyLength)
	priv, err := DeserializePrivateKey(raw)
	if err != nil {
		t.Fatalf("DeserializePrivateKey: %v", err)
	}
	got := priv.Serialize()
	if got[0]&0b0000_0111 != 0 {
		t.Fatalf("low 3 bits of byte 0 not cleared: 0x%02x", got[0])
	}
	if got[31]&0b1000_0000 != 0 {
		t.Fatalf("high bit of byte 31 not cleared: 0x%02x", got[31])
	}
	if got[31]&0b0100_0000 == 0 {
		t.Fatalf("bit 6 of byte 31 not set: 0x%02x", got[31])
	}
}

// TestECDHAgreementRFC7748Vector exercises the X25519 Diffie-Hellman test
// vector from RFC 7748 section 6.1 (the canonical Alice/Bob example), asserting
// both parties derive the documented shared secret.
func TestECDHAgreementRFC7748Vector(t *testing.T) {
	t.Log("RFC 7748 section 6.1 X25519 Diffie-Hellman test vector")

	alicePriv := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePub := mustHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPriv := mustHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPub := mustHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	wantShared := mustHex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	aPriv, err := DeserializePrivateKey(alicePriv)
	if err != nil {
		t.Fatalf("DeserializePrivateKey(alice): %v", err)
	}
	bPriv, err := DeserializePrivateKey(bobPriv)
	if err != nil {
		t.Fatalf("DeserializePrivateKey(bob): %v", err)
	}

	// Public keys derived from the private keys must match the vector.
	aPub, err := aPriv.PublicKey()
	if err != nil {
		t.Fatalf("alice PublicKey: %v", err)
	}
	if !bytes.Equal(aPub.PublicKeyBytes(), alicePub) {
		t.Fatalf("alice derived public = %x, want %x", aPub.PublicKeyBytes(), alicePub)
	}
	bPub, err := bPriv.PublicKey()
	if err != nil {
		t.Fatalf("bob PublicKey: %v", err)
	}
	if !bytes.Equal(bPub.PublicKeyBytes(), bobPub) {
		t.Fatalf("bob derived public = %x, want %x", bPub.PublicKeyBytes(), bobPub)
	}

	aPubKey, err := NewPublicKey(alicePub)
	if err != nil {
		t.Fatalf("NewPublicKey(alice): %v", err)
	}
	bPubKey, err := NewPublicKey(bobPub)
	if err != nil {
		t.Fatalf("NewPublicKey(bob): %v", err)
	}

	sharedAB, err := aPriv.CalculateAgreement(bPubKey)
	if err != nil {
		t.Fatalf("alice->bob agreement: %v", err)
	}
	sharedBA, err := bPriv.CalculateAgreement(aPubKey)
	if err != nil {
		t.Fatalf("bob->alice agreement: %v", err)
	}
	if !bytes.Equal(sharedAB, wantShared) {
		t.Fatalf("alice->bob shared = %x, want %x", sharedAB, wantShared)
	}
	if !bytes.Equal(sharedBA, wantShared) {
		t.Fatalf("bob->alice shared = %x, want %x", sharedBA, wantShared)
	}
}

// TestAgreementSymmetry checks that two freshly generated key pairs agree on a
// shared secret in both directions.
func TestAgreementSymmetry(t *testing.T) {
	alice, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair(alice): %v", err)
	}
	bob, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair(bob): %v", err)
	}
	ab, err := alice.CalculateAgreement(bob.PublicKey)
	if err != nil {
		t.Fatalf("alice agreement: %v", err)
	}
	ba, err := bob.CalculateAgreement(alice.PublicKey)
	if err != nil {
		t.Fatalf("bob agreement: %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatalf("agreements differ: %x vs %x", ab, ba)
	}
}

// TestAgreementRejectsLowOrderPoint verifies that a low-order peer public key
// (which would yield the all-zero shared secret) is rejected.
func TestAgreementRejectsLowOrderPoint(t *testing.T) {
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	// The all-zero point is a low-order point on Curve25519.
	lowOrder, err := NewPublicKey(make([]byte, PublicKeyLength))
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	if _, err := kp.PrivateKey.CalculateAgreement(lowOrder); err == nil {
		t.Fatal("agreement with low-order point succeeded, want ErrInvalidKeyAgreement")
	} else if _, ok := err.(ErrInvalidKeyAgreement); !ok {
		t.Fatalf("agreement error = %T, want ErrInvalidKeyAgreement", err)
	}
}

// TestPrivateKeyRedaction verifies that neither String nor any fmt verb leaks
// the private scalar.
func TestPrivateKeyRedaction(t *testing.T) {
	raw := bytes.Repeat([]byte{0xAB}, PrivateKeyLength)
	priv, err := DeserializePrivateKey(raw)
	if err != nil {
		t.Fatalf("DeserializePrivateKey: %v", err)
	}
	secretHex := hex.EncodeToString(priv.Serialize())

	for _, s := range []string{
		priv.String(),
		fmt.Sprintf("%v", priv),
		fmt.Sprintf("%s", priv),
		fmt.Sprintf("%+v", priv),
		fmt.Sprintf("%#v", priv),
		fmt.Sprintf("%x", priv),
	} {
		if !strings.Contains(s, "REDACTED") {
			t.Fatalf("formatted private key %q lacks REDACTED marker", s)
		}
		if strings.Contains(strings.ToLower(s), secretHex) {
			t.Fatalf("formatted private key leaked secret material: %q", s)
		}
	}
}

// FuzzDeserializePublicKey asserts the public-key parser never panics and that
// successful parses re-serialize to the canonical 33-byte form.
func FuzzDeserializePublicKey(f *testing.F) {
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		f.Fatalf("GenerateKeyPair: %v", err)
	}
	f.Add(kp.PublicKey.Serialize())
	f.Add([]byte{})
	f.Add([]byte{0x05})
	f.Add(append([]byte{0x05}, bytes.Repeat([]byte{0}, 40)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		pk, err := DeserializePublicKey(b)
		if err != nil {
			return
		}
		ser := pk.Serialize()
		if len(ser) != SerializedPublicKeyLength {
			t.Fatalf("serialized length = %d, want %d", len(ser), SerializedPublicKeyLength)
		}
		// Re-deserializing the canonical form must reproduce the same key.
		again, err := DeserializePublicKey(ser)
		if err != nil {
			t.Fatalf("canonical form failed to reparse: %v", err)
		}
		if !again.Equal(pk) {
			t.Fatal("re-parse mismatch")
		}
	})
}

// FuzzDeserializePrivateKey asserts the private-key parser never panics.
func FuzzDeserializePrivateKey(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x42}, PrivateKeyLength))
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		priv, err := DeserializePrivateKey(b)
		if err != nil {
			return
		}
		// A successful parse always yields a clamped 32-byte scalar.
		got := priv.Serialize()
		if len(got) != PrivateKeyLength {
			t.Fatalf("serialized length = %d, want %d", len(got), PrivateKeyLength)
		}
		if got[0]&0b0000_0111 != 0 || got[31]&0b1000_0000 != 0 || got[31]&0b0100_0000 == 0 {
			t.Fatalf("parsed private key not clamped: %x", got)
		}
	})
}
