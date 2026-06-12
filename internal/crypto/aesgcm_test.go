package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// TestGCMKnownAnswer uses an AES-256-GCM known-answer vector (NIST gcmEncrypt
// Count=0, Keylen=256, IVlen=96, PTlen=128, AADlen=128 from the CAVP
// gcmEncryptExtIV256 set). It exercises associated data, ciphertext, and tag.
func TestGCMKnownAnswer(t *testing.T) {
	key := mustHex(t, "92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b")
	nonce := mustHex(t, "ac93a1a6145299bde902f21a")
	plaintext := mustHex(t, "2d71bcfa914e4ac045b2aa60955fad24")
	aad := mustHex(t, "1e0889016f67601c8ebea4943bc23ad6")
	wantCT := "8995ae2e6df3dbf96fac7b7137bae67f"
	wantTag := "eca5aa77d51d4a0a14d9c51e1da474ab"

	ct, tag, err := SealGCM(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("SealGCM: %v", err)
	}
	if got := hex.EncodeToString(ct); got != wantCT {
		t.Fatalf("ciphertext = %s, want %s", got, wantCT)
	}
	if got := hex.EncodeToString(tag); got != wantTag {
		t.Fatalf("tag = %s, want %s", got, wantTag)
	}

	pt, err := OpenGCM(key, nonce, ct, tag, aad)
	if err != nil {
		t.Fatalf("OpenGCM: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("decrypted = %x, want %x", pt, plaintext)
	}
}

func TestGCMTagFailure(t *testing.T) {
	key := mustHex(t, "92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b")
	nonce := mustHex(t, "ac93a1a6145299bde902f21a")
	plaintext := mustHex(t, "2d71bcfa914e4ac045b2aa60955fad24")
	aad := mustHex(t, "1e0889016f67601c8ebea4943bc23ad6")

	ct, tag, err := SealGCM(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("SealGCM: %v", err)
	}

	// Flip a tag bit.
	badTag := append([]byte(nil), tag...)
	badTag[0] ^= 0x01
	if _, err := OpenGCM(key, nonce, ct, badTag, aad); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("OpenGCM(bad tag) err = %v, want ErrInvalidTag", err)
	}

	// Flip a ciphertext bit.
	badCT := append([]byte(nil), ct...)
	badCT[0] ^= 0x01
	if _, err := OpenGCM(key, nonce, badCT, tag, aad); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("OpenGCM(bad ct) err = %v, want ErrInvalidTag", err)
	}

	// Wrong associated data.
	badAAD := append([]byte(nil), aad...)
	badAAD[0] ^= 0x01
	if _, err := OpenGCM(key, nonce, ct, tag, badAAD); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("OpenGCM(bad aad) err = %v, want ErrInvalidTag", err)
	}
}

func TestGCMRoundTripNoAAD(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, NonceSizeGCM)
	msg := []byte("sealed sender payload")

	ct, tag, err := SealGCM(key, nonce, msg, nil)
	if err != nil {
		t.Fatalf("SealGCM: %v", err)
	}
	pt, err := OpenGCM(key, nonce, ct, tag, nil)
	if err != nil {
		t.Fatalf("OpenGCM: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("round-trip mismatch: got %q", pt)
	}
}

func TestGCMBadKeySize(t *testing.T) {
	if _, _, err := SealGCM(make([]byte, 16), make([]byte, NonceSizeGCM), nil, nil); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("err = %v, want ErrInvalidKeySize", err)
	}
}

func TestGCMBadNonceSize(t *testing.T) {
	if _, _, err := SealGCM(make([]byte, 32), make([]byte, 16), nil, nil); !errors.Is(err, ErrInvalidNonceSize) {
		t.Fatalf("err = %v, want ErrInvalidNonceSize", err)
	}
	if _, err := OpenGCM(make([]byte, 32), make([]byte, 16), nil, make([]byte, TagSizeGCM), nil); !errors.Is(err, ErrInvalidNonceSize) {
		t.Fatalf("OpenGCM err = %v, want ErrInvalidNonceSize", err)
	}
}

func TestGCMBadTagSize(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, NonceSizeGCM)
	if _, err := OpenGCM(key, nonce, []byte{}, make([]byte, 8), nil); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("err = %v, want ErrInvalidTag", err)
	}
}
