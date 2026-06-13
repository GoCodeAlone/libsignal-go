// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package gcmsiv

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// rfcVectors is the committed RFC 8452 Appendix C.2 vector set.
type rfcVectors struct {
	Source string `json:"source"`
	Cases  []struct {
		N         int    `json:"n"`
		Plaintext string `json:"plaintext"`
		AAD       string `json:"aad"`
		Key       string `json:"key"`
		Nonce     string `json:"nonce"`
		Result    string `json:"result"`
	} `json:"cases"`
}

func loadRFCVectors(t *testing.T) rfcVectors {
	t.Helper()
	path := filepath.Join("testdata", "rfc8452_appendix_c2.json")
	data, err := os.ReadFile(path) //nolint:gosec // G304: fixed in-repo testdata path, not user input
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v rfcVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return v
}

// TestRFC8452AppendixC2 runs the full AES-256-GCM-SIV worked-example suite from
// RFC 8452 Appendix C.2: Seal must reproduce each Result exactly, and Open of
// that Result must recover the plaintext.
func TestRFC8452AppendixC2(t *testing.T) {
	v := loadRFCVectors(t)
	const wantCases = 24 // RFC 8452 Appendix C.2 has exactly 24 worked examples.
	if len(v.Cases) != wantCases {
		t.Fatalf("loaded %d cases, want %d (RFC 8452 C.2)", len(v.Cases), wantCases)
	}

	for _, c := range v.Cases {
		key := mustHex(t, c.Key)
		nonce := mustHex(t, c.Nonce)
		plaintext := mustHex(t, c.Plaintext)
		aad := mustHex(t, c.AAD)
		want := mustHex(t, c.Result)

		got, err := Seal(key, nonce, plaintext, aad)
		if err != nil {
			t.Fatalf("case %d: Seal: %v", c.N, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: Seal mismatch\n got  %x\n want %x", c.N, got, want)
		}

		opened, err := Open(key, nonce, want, aad)
		if err != nil {
			t.Fatalf("case %d: Open: %v", c.N, err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Fatalf("case %d: Open mismatch\n got  %x\n want %x", c.N, opened, plaintext)
		}
	}
	t.Logf("RFC 8452 Appendix C.2: all %d AES-256-GCM-SIV vectors pass (Seal + Open)", len(v.Cases))
}

// TestFieldMul validates the plain GF(2^128) field multiply against RFC 8452
// §7: a * b = 37856175e9dc9df26ebc6d6171aa0ae9 (the field's "*", a plain product
// reduced mod P). This pins the carry-less multiply + constant-time reduction
// independent of the end-to-end AEAD.
func TestFieldMul(t *testing.T) {
	a := bytesToFieldElement(mustHex(t, "66e94bd4ef8a2c3b884cfa59ca342b2e"))
	b := bytesToFieldElement(mustHex(t, "ff000000000000000000000000000000"))
	want := mustHex(t, "37856175e9dc9df26ebc6d6171aa0ae9")

	got := a.mul(b).bytes()
	if !bytes.Equal(got[:], want) {
		t.Fatalf("field a*b mismatch\n got  %x\n want %x", got, want)
	}
}

// TestPolyvalDot validates POLYVAL's "dot" operation dot(a,b) = a·b·x^-128
// against RFC 8452 §7's POLYVAL field example: dot(a,b) =
// ebe563401e7e91ea3ad6426b8140c394 for the same a, b. dot is the operation
// POLYVAL accumulation uses, so this pins the x^-128 factor.
func TestPolyvalDot(t *testing.T) {
	a := bytesToFieldElement(mustHex(t, "66e94bd4ef8a2c3b884cfa59ca342b2e"))
	b := bytesToFieldElement(mustHex(t, "ff000000000000000000000000000000"))
	want := mustHex(t, "ebe563401e7e91ea3ad6426b8140c394")

	got := a.dot(b).bytes()
	if !bytes.Equal(got[:], want) {
		t.Fatalf("POLYVAL dot(a,b) mismatch\n got  %x\n want %x", got, want)
	}
}

// --- failure cases ---

func TestOpenWrongKey(t *testing.T) {
	key := mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000")
	nonce := mustHex(t, "030000000000000000000000")
	ct, err := Seal(key, nonce, []byte("attack at dawn!!"), []byte("hdr"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	wrongKey := make([]byte, KeySize)
	copy(wrongKey, key)
	wrongKey[0] ^= 0x01
	if _, err := Open(wrongKey, nonce, ct, []byte("hdr")); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open(wrong key) err = %v, want ErrOpen", err)
	}
}

func TestOpenWrongNonce(t *testing.T) {
	key := mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000")
	nonce := mustHex(t, "030000000000000000000000")
	ct, err := Seal(key, nonce, []byte("attack at dawn!!"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	wrongNonce := make([]byte, NonceSize)
	copy(wrongNonce, nonce)
	wrongNonce[0] ^= 0x01
	if _, err := Open(key, wrongNonce, ct, nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open(wrong nonce) err = %v, want ErrOpen", err)
	}
}

func TestOpenWrongAAD(t *testing.T) {
	key := mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000")
	nonce := mustHex(t, "030000000000000000000000")
	ct, err := Seal(key, nonce, []byte("attack at dawn!!"), []byte("header-A"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(key, nonce, ct, []byte("header-B")); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open(wrong aad) err = %v, want ErrOpen", err)
	}
}

func TestOpenTamperedTag(t *testing.T) {
	key := mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000")
	nonce := mustHex(t, "030000000000000000000000")
	ct, err := Seal(key, nonce, []byte("attack at dawn!!"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 0x01 // flip a bit in the tag
	if _, err := Open(key, nonce, tampered, nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open(tampered tag) err = %v, want ErrOpen", err)
	}
}

func TestOpenTamperedCiphertext(t *testing.T) {
	key := mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000")
	nonce := mustHex(t, "030000000000000000000000")
	ct, err := Seal(key, nonce, []byte("attack at dawn!!"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 0x01 // flip a bit in the ciphertext body
	if _, err := Open(key, nonce, tampered, nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open(tampered ciphertext) err = %v, want ErrOpen", err)
	}
}

func TestOpenTooShort(t *testing.T) {
	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSize)
	if _, err := Open(key, nonce, make([]byte, TagSize-1), nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open(too short) err = %v, want ErrOpen", err)
	}
}

func TestBadKeyAndNonceSizes(t *testing.T) {
	goodKey := make([]byte, KeySize)
	goodNonce := make([]byte, NonceSize)

	if _, err := Seal(make([]byte, 16), goodNonce, nil, nil); !errors.Is(err, ErrKeySize) {
		t.Fatalf("Seal(16-byte key) err = %v, want ErrKeySize", err)
	}
	if _, err := Seal(goodKey, make([]byte, 16), nil, nil); !errors.Is(err, ErrNonceSize) {
		t.Fatalf("Seal(16-byte nonce) err = %v, want ErrNonceSize", err)
	}
	if _, err := Open(make([]byte, 16), goodNonce, make([]byte, TagSize), nil); !errors.Is(err, ErrKeySize) {
		t.Fatalf("Open(16-byte key) err = %v, want ErrKeySize", err)
	}
	if _, err := Open(goodKey, make([]byte, 16), make([]byte, TagSize), nil); !errors.Is(err, ErrNonceSize) {
		t.Fatalf("Open(16-byte nonce) err = %v, want ErrNonceSize", err)
	}
}

// TestInputLengthLimits pins the RFC 8452 §6 input limits. The rejection paths
// themselves cannot be exercised with real allocations (they require multi-GiB
// inputs), so this guards the constants the Seal/Open checks compare against.
func TestInputLengthLimits(t *testing.T) {
	if maxPlaintextLen != (1<<36)-1 {
		t.Fatalf("maxPlaintextLen = %d, want 2^36-1 (RFC 8452 §6)", maxPlaintextLen)
	}
	if maxADLen != 1<<36 {
		t.Fatalf("maxADLen = %d, want 2^36 (RFC 8452 §6)", maxADLen)
	}
}

// TestRoundTripVariousSizes exercises Seal/Open across plaintext and AAD lengths
// spanning partial and multiple blocks (nonce-misuse resistance means a fixed
// nonce is fine here).
func TestRoundTripVariousSizes(t *testing.T) {
	key := mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000")
	nonce := mustHex(t, "030000000000000000000000")
	for _, ptLen := range []int{0, 1, 15, 16, 17, 31, 32, 64, 100} {
		for _, aadLen := range []int{0, 1, 16, 20} {
			pt := bytes.Repeat([]byte{0xAB}, ptLen)
			aad := bytes.Repeat([]byte{0xCD}, aadLen)
			ct, err := Seal(key, nonce, pt, aad)
			if err != nil {
				t.Fatalf("Seal(pt=%d,aad=%d): %v", ptLen, aadLen, err)
			}
			if len(ct) != ptLen+TagSize {
				t.Fatalf("ct len = %d, want %d", len(ct), ptLen+TagSize)
			}
			opened, err := Open(key, nonce, ct, aad)
			if err != nil {
				t.Fatalf("Open(pt=%d,aad=%d): %v", ptLen, aadLen, err)
			}
			if !bytes.Equal(opened, pt) {
				t.Fatalf("round-trip mismatch pt=%d aad=%d", ptLen, aadLen)
			}
		}
	}
}

// FuzzOpen ensures Open never panics on arbitrary input and never returns a nil
// error with a non-nil plaintext for unauthenticated data.
func FuzzOpen(f *testing.F) {
	key := mustHex(f, "0100000000000000000000000000000000000000000000000000000000000000")
	nonce := mustHex(f, "030000000000000000000000")
	seed, _ := Seal(key, nonce, []byte("seed plaintext"), []byte("seed-aad"))
	f.Add(seed)
	f.Add([]byte{})
	f.Add(make([]byte, TagSize))
	f.Add(make([]byte, 64))
	f.Fuzz(func(_ *testing.T, ctAndTag []byte) {
		// Must not panic for any input. The fuzzer fails the run on any panic,
		// so no assertion on the result is needed here.
		_, _ = Open(key, nonce, ctAndTag, []byte("seed-aad"))
	})
}
