package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// mustHex decodes a hex string or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestCBCKnownAnswer ports the KAT from rust/crypto/src/aes_cbc.rs (aes_cbc_test).
func TestCBCKnownAnswer(t *testing.T) {
	key := mustHex(t, "4e22eb16d964779994222e82192ce9f747da72dc4abe49dfdeeb71d0ffe3796e")
	iv := mustHex(t, "6f8a557ddc0a140c878063a6d5f31d3d")
	ptext := mustHex(t, "30736294a124482a4159")
	wantCtext := "dd3f573ab4508b9ed0e45e0baf5608f3"

	ctext, err := EncryptCBC(ptext, key, iv)
	if err != nil {
		t.Fatalf("EncryptCBC: %v", err)
	}
	if got := hex.EncodeToString(ctext); got != wantCtext {
		t.Fatalf("ciphertext = %s, want %s", got, wantCtext)
	}

	recovered, err := DecryptCBC(ctext, key, iv)
	if err != nil {
		t.Fatalf("DecryptCBC: %v", err)
	}
	if !bytes.Equal(recovered, ptext) {
		t.Fatalf("recovered = %x, want %x", recovered, ptext)
	}
}

// TestCBCBadIVChangesFirstBlock ports the bitflipped-IV case: a flipped IV bit
// changes only the first plaintext block but still decrypts (valid padding).
func TestCBCBadIVChangesFirstBlock(t *testing.T) {
	key := mustHex(t, "4e22eb16d964779994222e82192ce9f747da72dc4abe49dfdeeb71d0ffe3796e")
	iv := mustHex(t, "6f8a557ddc0a140c878063a6d5f31d3d")
	ptext := mustHex(t, "30736294a124482a4159")
	ctext, err := EncryptCBC(ptext, key, iv)
	if err != nil {
		t.Fatalf("EncryptCBC: %v", err)
	}

	badIV := mustHex(t, "ef8a557ddc0a140c878063a6d5f31d3d")
	recovered, err := DecryptCBC(ctext, key, badIV)
	if err != nil {
		t.Fatalf("DecryptCBC with bad IV: %v", err)
	}
	if got := hex.EncodeToString(recovered); got != "b0736294a124482a4159" {
		t.Fatalf("recovered = %s, want b0736294a124482a4159", got)
	}
}

func TestCBCInvalidPadding(t *testing.T) {
	key := mustHex(t, "4e22eb16d964779994222e82192ce9f747da72dc4abe49dfdeeb71d0ffe3796e")
	iv := mustHex(t, "6f8a557ddc0a140c878063a6d5f31d3d")
	// The recovered plaintext (10 bytes) is not block-aligned ciphertext, and
	// decrypting it as ciphertext yields invalid padding.
	ptext := mustHex(t, "30736294a124482a4159")
	if _, err := DecryptCBC(ptext, key, iv); !errors.Is(err, ErrBadCiphertext) {
		t.Fatalf("DecryptCBC(non-block-multiple) err = %v, want ErrBadCiphertext", err)
	}
}

func TestCBCEmptyCiphertextRejected(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := DecryptCBC([]byte{}, key, iv); !errors.Is(err, ErrBadCiphertext) {
		t.Fatalf("DecryptCBC(empty) err = %v, want ErrBadCiphertext", err)
	}
}

func TestCBCBadKeySize(t *testing.T) {
	shortKey := make([]byte, 16) // AES-128, not allowed here (AES-256 only)
	iv := make([]byte, 16)
	if _, err := EncryptCBC([]byte("hello"), shortKey, iv); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("EncryptCBC(short key) err = %v, want ErrInvalidKeySize", err)
	}
}

func TestCBCBadIVSize(t *testing.T) {
	key := make([]byte, 32)
	shortIV := make([]byte, 8)
	if _, err := EncryptCBC([]byte("hello"), key, shortIV); !errors.Is(err, ErrInvalidNonceSize) {
		t.Fatalf("EncryptCBC(short iv) err = %v, want ErrInvalidNonceSize", err)
	}
}

func TestCBCRoundTripVariousLengths(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	for n := 0; n < 64; n++ {
		ptext := bytes.Repeat([]byte{byte(n)}, n)
		ctext, err := EncryptCBC(ptext, key, iv)
		if err != nil {
			t.Fatalf("EncryptCBC(len %d): %v", n, err)
		}
		// PKCS7 always pads to a positive multiple of 16.
		if len(ctext) == 0 || len(ctext)%16 != 0 {
			t.Fatalf("len(ctext)=%d for ptext len %d", len(ctext), n)
		}
		recovered, err := DecryptCBC(ctext, key, iv)
		if err != nil {
			t.Fatalf("DecryptCBC(len %d): %v", n, err)
		}
		if !bytes.Equal(recovered, ptext) {
			t.Fatalf("round-trip mismatch at len %d", n)
		}
	}
}
