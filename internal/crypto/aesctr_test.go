package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// ctrKeystreamReference produces n bytes of AES-CTR keystream using the stdlib
// generic 16-byte-IV CTR mode, as an independent cross-check of our 32-bit
// counter layout.
func ctrKeystreamReference(t *testing.T, key, iv []byte, n int) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	out := make([]byte, n)
	cipher.NewCTR(block, iv).XORKeyStream(out, out)
	return out
}

// TestCTRKnownAnswer ports the KAT from rust/protocol/src/crypto.rs (aes_ctr_test):
// AES-256-CTR with a zero 16-byte IV (== 12-byte zero nonce + 32-bit counter
// starting at 0) over 35 zero bytes.
func TestCTRKnownAnswer(t *testing.T) {
	key := mustHex(t, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4")
	nonce := make([]byte, NonceSizeCTR) // 12 zero bytes
	ptext := make([]byte, 35)
	want := "e568f68194cf76d6174d4cc04310a85491151e5d0b7a1f1bc0d7acd0ae3e51e4170e23"

	c, err := NewAES256CTR32(key, nonce, 0)
	if err != nil {
		t.Fatalf("NewAES256CTR32: %v", err)
	}
	buf := append([]byte(nil), ptext...)
	c.Process(buf)
	if got := hex.EncodeToString(buf); got != want {
		t.Fatalf("ctext = %s, want %s", got, want)
	}
}

// TestCTRInitialCounterSeeks verifies that an initial counter of N is equivalent
// to processing N leading 16-byte zero blocks at counter 0 (per aes_ctr.rs seek).
func TestCTRInitialCounterSeeks(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, NonceSizeCTR)

	// Counter 0 over 48 bytes, then take the keystream from block 2 onward.
	full, err := NewAES256CTR32(key, nonce, 0)
	if err != nil {
		t.Fatalf("NewAES256CTR32: %v", err)
	}
	ks := make([]byte, 48)
	full.Process(ks)

	// Counter 2 over 16 bytes should equal the third keystream block above.
	from2, err := NewAES256CTR32(key, nonce, 2)
	if err != nil {
		t.Fatalf("NewAES256CTR32(initCtr=2): %v", err)
	}
	block := make([]byte, 16)
	from2.Process(block)
	if !bytes.Equal(block, ks[32:48]) {
		t.Fatalf("init-counter seek mismatch:\n got %x\nwant %x", block, ks[32:48])
	}
}

// TestCTR32BitCounterBigEndian asserts the counter is the trailing 4 bytes of
// the IV block in big-endian order: initCtr must match a hand-built CTR IV.
func TestCTR32BitCounterBigEndian(t *testing.T) {
	key := make([]byte, 32)
	nonce := mustHex(t, "000102030405060708090a0b")
	const initCtr = 0x01020304

	c, err := NewAES256CTR32(key, nonce, initCtr)
	if err != nil {
		t.Fatalf("NewAES256CTR32: %v", err)
	}
	got := make([]byte, 16)
	c.Process(got) // == keystream block at IV (nonce || initCtr BE)

	// Build the same keystream via a generic 16-byte-IV CTR helper for cross-check.
	iv := make([]byte, 16)
	copy(iv[:NonceSizeCTR], nonce)
	binary.BigEndian.PutUint32(iv[NonceSizeCTR:], initCtr)
	want := ctrKeystreamReference(t, key, iv, 16)
	if !bytes.Equal(got, want) {
		t.Fatalf("counter layout mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestCTRRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	nonce := mustHex(t, "0102030405060708090a0b0c")
	msg := []byte("the quick brown fox jumps over the lazy signal")

	enc, err := NewAES256CTR32(key, nonce, 0)
	if err != nil {
		t.Fatalf("enc: %v", err)
	}
	buf := append([]byte(nil), msg...)
	enc.Process(buf)
	if bytes.Equal(buf, msg) {
		t.Fatal("ciphertext equals plaintext")
	}

	dec, err := NewAES256CTR32(key, nonce, 0)
	if err != nil {
		t.Fatalf("dec: %v", err)
	}
	dec.Process(buf)
	if !bytes.Equal(buf, msg) {
		t.Fatalf("round-trip mismatch: got %q", buf)
	}
}

func TestCTRBadKeySize(t *testing.T) {
	if _, err := NewAES256CTR32(make([]byte, 16), make([]byte, NonceSizeCTR), 0); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("err = %v, want ErrInvalidKeySize", err)
	}
}

func TestCTRBadNonceSize(t *testing.T) {
	if _, err := NewAES256CTR32(make([]byte, 32), make([]byte, 16), 0); !errors.Is(err, ErrInvalidNonceSize) {
		t.Fatalf("err = %v, want ErrInvalidNonceSize", err)
	}
}
