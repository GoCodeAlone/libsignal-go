package crypto

import (
	"bytes"
	"testing"
)

// FuzzCBCRoundTrip checks that encrypt-then-decrypt is the identity for
// arbitrary plaintext and that neither direction panics on odd inputs.
func FuzzCBCRoundTrip(f *testing.F) {
	f.Add([]byte(""), uint8(0))
	f.Add([]byte("hello"), uint8(7))
	f.Add(bytes.Repeat([]byte{0xAB}, 100), uint8(255))

	key := make([]byte, keySizeAES256)
	iv := make([]byte, blockSize)

	f.Fuzz(func(t *testing.T, plaintext []byte, keyByte uint8) {
		// Vary the key/iv contents with the fuzzed byte (lengths stay valid).
		for i := range key {
			key[i] = keyByte
		}
		for i := range iv {
			iv[i] = keyByte ^ 0x5A
		}

		ct, err := EncryptCBC(plaintext, key, iv)
		if err != nil {
			t.Fatalf("EncryptCBC unexpected error: %v", err)
		}
		got, err := DecryptCBC(ct, key, iv)
		if err != nil {
			t.Fatalf("DecryptCBC unexpected error: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round-trip mismatch: got %x want %x", got, plaintext)
		}
	})
}

// FuzzGCMOpen feeds arbitrary key/nonce/ciphertext/tag/aad into OpenGCM; the
// contract is only that it never panics. Almost all inputs fail authentication.
func FuzzGCMOpen(f *testing.F) {
	f.Add([]byte("k"), []byte("n"), []byte("c"), []byte("t"), []byte("a"))
	f.Add(make([]byte, 32), make([]byte, 12), []byte{}, make([]byte, 16), []byte{})

	f.Fuzz(func(_ *testing.T, key, nonce, ciphertext, tag, aad []byte) {
		// Must not panic regardless of input shape.
		_, _ = OpenGCM(key, nonce, ciphertext, tag, aad)
	})
}

// FuzzCTRProcess checks that CTR processing never panics for arbitrary buffer
// lengths and chunking, and that splitting a stream matches processing it whole.
func FuzzCTRProcess(f *testing.F) {
	f.Add([]byte("streaming data of some length"), 7)
	f.Add([]byte{}, 1)

	key := make([]byte, keySizeAES256)
	nonce := make([]byte, NonceSizeCTR)

	f.Fuzz(func(t *testing.T, data []byte, split int) {
		whole := append([]byte(nil), data...)
		c1, err := NewAES256CTR32(key, nonce, 0)
		if err != nil {
			t.Fatalf("NewAES256CTR32: %v", err)
		}
		c1.Process(whole)

		chunked := append([]byte(nil), data...)
		c2, err := NewAES256CTR32(key, nonce, 0)
		if err != nil {
			t.Fatalf("NewAES256CTR32: %v", err)
		}
		if split <= 0 {
			split = 1
		}
		for off := 0; off < len(chunked); off += split {
			end := off + split
			if end > len(chunked) {
				end = len(chunked)
			}
			c2.Process(chunked[off:end])
		}
		if !bytes.Equal(whole, chunked) {
			t.Fatalf("chunked CTR != whole CTR (split=%d)", split)
		}
	})
}
