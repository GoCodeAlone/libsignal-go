package kem

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"strings"
	"testing"
)

// Upstream Kyber1024 key fixtures, copied verbatim from
// rust/protocol/src/kem/test-data into kem/testdata. Embedded so the KAT and
// fixture tests are self-contained and the file paths are compile-time constant.
//
//go:embed testdata/pk.dat
var upstreamPublicKeyBytes []byte

//go:embed testdata/sk.dat
var upstreamSecretKeyBytes []byte

// Expected Kyber1024 wire sizes, mirroring the assertions in
// rust/protocol/src/kem.rs (serialized pk/sk carry a 1-byte type prefix).
const (
	kyber1024PublicKeyLen   = 1568
	kyber1024SecretKeyLen   = 3168
	kyber1024CiphertextLen  = 1568
	kyber1024SharedKeyLen   = 32
	serializedPublicKeyLen  = kyber1024PublicKeyLen + 1
	serializedSecretKeyLen  = kyber1024SecretKeyLen + 1
	serializedCiphertextLen = kyber1024CiphertextLen + 1
)

// TestUpstreamKeyFixtures deserializes the Kyber1024 pk.dat/sk.dat fixtures
// copied verbatim from rust/protocol/src/kem/test-data, proving wire/format
// compatibility with upstream libsignal: the raw circl-decoded keys must accept
// the upstream bytes, and encapsulate/decapsulate must round-trip. This is the
// Go port of kem.rs test_serialize + test_kyber1024_kem.
func TestUpstreamKeyFixtures(t *testing.T) {
	pkRaw := upstreamPublicKeyBytes
	skRaw := upstreamSecretKeyBytes
	if len(pkRaw) != kyber1024PublicKeyLen {
		t.Fatalf("pk.dat len = %d, want %d", len(pkRaw), kyber1024PublicKeyLen)
	}
	if len(skRaw) != kyber1024SecretKeyLen {
		t.Fatalf("sk.dat len = %d, want %d", len(skRaw), kyber1024SecretKeyLen)
	}

	// Prepend the Kyber1024 type byte to form the serialized wire representation.
	serializedPK := append([]byte{byte(KeyTypeKyber1024)}, pkRaw...)
	serializedSK := append([]byte{byte(KeyTypeKyber1024)}, skRaw...)

	pk, err := DeserializePublicKey(serializedPK)
	if err != nil {
		t.Fatalf("DeserializePublicKey(upstream pk): %v", err)
	}
	sk, err := DeserializeSecretKey(serializedSK)
	if err != nil {
		t.Fatalf("DeserializeSecretKey(upstream sk): %v", err)
	}
	if pk.KeyType() != KeyTypeKyber1024 {
		t.Fatalf("pk key type = %v, want Kyber1024", pk.KeyType())
	}

	// Serialize round-trip: re-serialization reproduces the input bytes exactly.
	if !bytes.Equal(pk.Serialize(), serializedPK) {
		t.Fatal("public key did not round-trip through serialize")
	}
	if !bytes.Equal(sk.Serialize(), serializedSK) {
		t.Fatal("secret key did not round-trip through serialize")
	}

	// Encapsulate against the upstream public key and decapsulate with the
	// upstream secret key: the shared secrets must agree.
	ssSender, ct, err := pk.Encapsulate()
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(ct) != serializedCiphertextLen {
		t.Fatalf("ciphertext len = %d, want %d", len(ct), serializedCiphertextLen)
	}
	if len(ssSender) != kyber1024SharedKeyLen {
		t.Fatalf("shared secret len = %d, want %d", len(ssSender), kyber1024SharedKeyLen)
	}
	ssRecipient, err := sk.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ssSender, ssRecipient) {
		t.Fatal("sender and recipient shared secrets differ")
	}
}

// TestGenerateKeyPairAndRoundTrip covers keypair generation, wire sizes, and an
// encaps/decaps self-consistency check, mirroring kem.rs test_kyber1024_keypair.
func TestGenerateKeyPairAndRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair(KeyTypeKyber1024, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if got := len(kp.PublicKey.Serialize()); got != serializedPublicKeyLen {
		t.Fatalf("serialized public key len = %d, want %d", got, serializedPublicKeyLen)
	}
	if got := len(kp.SecretKey.Serialize()); got != serializedSecretKeyLen {
		t.Fatalf("serialized secret key len = %d, want %d", got, serializedSecretKeyLen)
	}

	ss1, ct, err := kp.PublicKey.Encapsulate()
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(ct) != serializedCiphertextLen {
		t.Fatalf("ciphertext len = %d, want %d", len(ct), serializedCiphertextLen)
	}
	if len(ss1) != kyber1024SharedKeyLen {
		t.Fatalf("shared secret len = %d, want %d", len(ss1), kyber1024SharedKeyLen)
	}
	ss2, err := kp.SecretKey.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("encaps/decaps shared secrets differ")
	}

	// Deserialize the generated keys back and confirm equality.
	pk2, err := DeserializePublicKey(kp.PublicKey.Serialize())
	if err != nil {
		t.Fatalf("re-deserialize public key: %v", err)
	}
	if !pk2.Equal(kp.PublicKey) {
		t.Fatal("re-deserialized public key not equal")
	}
}

// TestDeserializeErrors covers the rejection paths: empty input, unknown type
// byte, wrong key length, and the ML-KEM-1024 recognized-but-not-enabled tag.
func TestDeserializeErrors(t *testing.T) {
	// Empty input.
	if _, err := DeserializePublicKey(nil); err == nil {
		t.Fatal("DeserializePublicKey(nil) = nil error")
	} else if _, ok := err.(ErrNoKeyTypeIdentifier); !ok {
		t.Fatalf("empty input error = %T, want ErrNoKeyTypeIdentifier", err)
	}

	// Unknown type byte.
	if _, err := DeserializePublicKey([]byte{0xFF}); err == nil {
		t.Fatal("DeserializePublicKey(0xFF) = nil error")
	} else if _, ok := err.(BadKEMKeyTypeError); !ok {
		t.Fatalf("unknown type error = %T, want BadKEMKeyTypeError", err)
	}

	// Recognized but unsupported type (ML-KEM-1024, 0x0A).
	if _, err := DeserializePublicKey([]byte{byte(KeyTypeMLKEM1024)}); err == nil {
		t.Fatal("DeserializePublicKey(0x0A) = nil error")
	} else if _, ok := err.(UnsupportedKEMKeyTypeError); !ok {
		t.Fatalf("mlkem type error = %T, want UnsupportedKEMKeyTypeError", err)
	}

	// Correct type byte, wrong body length.
	short := append([]byte{byte(KeyTypeKyber1024)}, make([]byte, 10)...)
	if _, err := DeserializePublicKey(short); err == nil {
		t.Fatal("DeserializePublicKey(short body) = nil error")
	} else if _, ok := err.(BadKEMKeyLengthError); !ok {
		t.Fatalf("short body error = %T, want BadKEMKeyLengthError", err)
	}
}

// TestDecapsulateWrongType verifies a ciphertext whose key type differs from the
// secret key is rejected.
func TestDecapsulateWrongType(t *testing.T) {
	kp, err := GenerateKeyPair(KeyTypeKyber1024, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_, ct, err := kp.PublicKey.Encapsulate()
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	// Flip the ciphertext's type byte to the (recognized) ML-KEM tag.
	bad := append([]byte(nil), ct...)
	bad[0] = byte(KeyTypeMLKEM1024)
	// ML-KEM is not enabled, so this is rejected at parse with an unsupported
	// type error before any key-type mismatch check.
	if _, err := kp.SecretKey.Decapsulate(bad); err == nil {
		t.Fatal("Decapsulate(mlkem-tagged ct) = nil error")
	}
}

// TestSecretKeyRedaction verifies the secret key never leaks its body via
// String or any fmt verb.
func TestSecretKeyRedaction(t *testing.T) {
	kp, err := GenerateKeyPair(KeyTypeKyber1024, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	for _, s := range []string{
		kp.SecretKey.String(),
		formatVerb("%v", kp.SecretKey),
		formatVerb("%s", kp.SecretKey),
		formatVerb("%+v", kp.SecretKey),
		formatVerb("%x", kp.SecretKey),
	} {
		if !strings.Contains(s, "REDACTED") {
			t.Fatalf("formatted secret key %q lacks REDACTED", s)
		}
	}
}

// FuzzDeserializePublicKey asserts the public-key parser never panics and that
// successful parses re-serialize to a stable canonical form.
func FuzzDeserializePublicKey(f *testing.F) {
	kp, err := GenerateKeyPair(KeyTypeKyber1024, rand.Reader)
	if err != nil {
		f.Fatalf("GenerateKeyPair: %v", err)
	}
	f.Add(kp.PublicKey.Serialize())
	f.Add([]byte{})
	f.Add([]byte{byte(KeyTypeKyber1024)})
	f.Add([]byte{byte(KeyTypeMLKEM1024)})
	f.Add([]byte{0xFF, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		pk, err := DeserializePublicKey(b)
		if err != nil {
			return
		}
		ser := pk.Serialize()
		if len(ser) != serializedPublicKeyLen {
			t.Fatalf("serialized len = %d, want %d", len(ser), serializedPublicKeyLen)
		}
		again, err := DeserializePublicKey(ser)
		if err != nil {
			t.Fatalf("canonical form failed to reparse: %v", err)
		}
		if !again.Equal(pk) {
			t.Fatal("re-parse mismatch")
		}
	})
}

// FuzzDeserializeSecretKey asserts the secret-key parser never panics.
func FuzzDeserializeSecretKey(f *testing.F) {
	kp, err := GenerateKeyPair(KeyTypeKyber1024, rand.Reader)
	if err != nil {
		f.Fatalf("GenerateKeyPair: %v", err)
	}
	f.Add(kp.SecretKey.Serialize())
	f.Add([]byte{})
	f.Add([]byte{byte(KeyTypeKyber1024)})
	f.Fuzz(func(t *testing.T, b []byte) {
		sk, err := DeserializeSecretKey(b)
		if err != nil {
			return
		}
		if len(sk.Serialize()) != serializedSecretKeyLen {
			t.Fatalf("serialized secret key len = %d, want %d", len(sk.Serialize()), serializedSecretKeyLen)
		}
	})
}
