// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package gcmsiv implements AES-256-GCM-SIV, the nonce-misuse-resistant AEAD of
// RFC 8452. It is a self-contained pure-Go implementation (no cgo): AES is the
// standard library's constant-time/hardware AES, and the POLYVAL universal hash
// is implemented here with a constant-time, limb-based carry-less multiply (see
// polyval.go and design note D4 — this is the project's riskiest self-written
// crypto surface).
//
// Only the 256-bit key variant is provided, the only one the Signal protocol's
// sealed-sender v2 uses. Every step cites the relevant RFC 8452 section.
//
// # Reuse evaluation (recorded per design requirement)
//
// Before writing this, vetted pure-Go reuse was evaluated: the Go standard
// library and golang.org/x/crypto ship no public AES-GCM-SIV; the only
// third-party pure-Go ports found (secure-io/siv-go, ericlagergren/siv) are tiny
// (<10 stars), unreleased, unaudited, and one is self-described as an
// experimental proof-of-concept "not optimized for ... (side channel)
// security" — none meet the vetted/maintained/constant-time bar (D4). Outcome:
// implement in-repo, as the plan anticipated.
package gcmsiv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// KeySize is the AES-256-GCM-SIV key length in bytes (the key-generating
	// key, RFC 8452 §4).
	KeySize = 32
	// NonceSize is the GCM-SIV nonce length: 96 bits (RFC 8452 §4).
	NonceSize = 12
	// TagSize is the GCM-SIV authentication tag length: 128 bits (RFC 8452 §4).
	TagSize = 16
	// maxPlaintextLen and maxADLen are the input limits from RFC 8452 §6:
	// plaintext is at most 2^36 - 1 bytes and additional data at most 2^36
	// bytes. Enforcing them keeps the bit-length encodings in the POLYVAL length
	// block (and their *8 multiplications) within range.
	maxPlaintextLen = (1 << 36) - 1
	maxADLen        = 1 << 36
)

// Sentinel errors. ErrOpen is intentionally singular for every authentication
// failure (wrong key/nonce/AAD/tag or tampered ciphertext) so the cases are not
// distinguishable to an attacker, matching GCM-SIV's all-or-nothing decryption.
var (
	// ErrKeySize is returned when the key is not KeySize bytes.
	ErrKeySize = errors.New("gcmsiv: invalid key size")
	// ErrNonceSize is returned when the nonce is not NonceSize bytes.
	ErrNonceSize = errors.New("gcmsiv: invalid nonce size")
	// ErrOpen is returned when authentication fails or the ciphertext is too
	// short to contain a tag.
	ErrOpen = errors.New("gcmsiv: message authentication failed")
	// ErrInputTooLong is returned when plaintext or additional data exceeds the
	// RFC 8452 §6 limits.
	ErrInputTooLong = errors.New("gcmsiv: input exceeds RFC 8452 length limit")
)

// deriveKeys derives the per-nonce message-authentication key and
// message-encryption key from the key-generating key and nonce, per RFC 8452 §4
// ("Encryption", key-derivation step). The 16-byte AES blocks are formed by a
// 32-bit little-endian counter (0,1,2,...) in the first 4 bytes followed by the
// 12-byte nonce; each block is encrypted with the key-generating key under
// AES-256, and the low 8 bytes of each output are concatenated. The first two
// blocks give the 16-byte authentication key; the next four give the 32-byte
// encryption key.
func deriveKeys(kgkBlock cipher.Block, nonce []byte) (authKey [16]byte, encKey [32]byte) {
	var in [aes.BlockSize]byte
	copy(in[4:], nonce) // bytes 4..15 hold the nonce; bytes 0..3 the counter
	var out [aes.BlockSize]byte

	// Message-authentication key: blocks 0 and 1, low 8 bytes each.
	for ctr := uint32(0); ctr < 2; ctr++ {
		binary.LittleEndian.PutUint32(in[0:4], ctr)
		kgkBlock.Encrypt(out[:], in[:])
		copy(authKey[ctr*8:], out[:8])
	}
	// Message-encryption key: blocks 2..5, low 8 bytes each.
	for ctr := uint32(2); ctr < 6; ctr++ {
		binary.LittleEndian.PutUint32(in[0:4], ctr)
		kgkBlock.Encrypt(out[:], in[:])
		copy(encKey[(ctr-2)*8:], out[:8])
	}
	return authKey, encKey
}

// lengthBlock builds the POLYVAL length block: the 64-bit little-endian
// encodings of the bit-lengths of the additional data and the plaintext,
// concatenated (RFC 8452 §4).
func lengthBlock(aadLen, plaintextLen int) [16]byte {
	var b [16]byte
	// Seal/Open bound aadLen and plaintextLen to the RFC 8452 §6 limits (<= 2^36)
	// before reaching here, and len() is non-negative, so these conversions and
	// the *8 cannot overflow uint64.
	binary.LittleEndian.PutUint64(b[0:8], uint64(aadLen)*8)        //nolint:gosec // G115: bounded by maxADLen (RFC 8452 §6)
	binary.LittleEndian.PutUint64(b[8:16], uint64(plaintextLen)*8) //nolint:gosec // G115: bounded by maxPlaintextLen (RFC 8452 §6)
	return b
}

// computeTag computes the GCM-SIV tag for the given plaintext and additional
// data under the derived keys (RFC 8452 §4): POLYVAL over the padded AAD, padded
// plaintext, and length block; XOR the first 12 bytes with the nonce; clear the
// top bit of the last byte; then AES-encrypt the result with the
// message-encryption key.
func computeTag(authKey [16]byte, encBlock cipher.Block, nonce, plaintext, aad []byte) [16]byte {
	h := bytesToFieldElement(authKey[:])

	// POLYVAL input: padded AAD || padded plaintext || length block. Each of AAD
	// and plaintext is zero-padded up to a 16-byte multiple (RFC 8452 §4).
	var buf []byte
	buf = appendPadded(buf, aad)
	buf = appendPadded(buf, plaintext)
	lb := lengthBlock(len(aad), len(plaintext))
	buf = append(buf, lb[:]...)

	s := polyval(h, buf).bytes()

	// XOR the first 12 bytes of S with the nonce (RFC 8452 §4).
	for i := 0; i < NonceSize; i++ {
		s[i] ^= nonce[i]
	}
	// Clear the most significant bit of the last byte.
	s[15] &= 0x7f

	var tag [16]byte
	encBlock.Encrypt(tag[:], s[:])
	return tag
}

// appendPadded appends data to dst, then zero-pads to the next 16-byte boundary.
func appendPadded(dst, data []byte) []byte {
	dst = append(dst, data...)
	if rem := len(data) % 16; rem != 0 {
		var pad [16]byte
		dst = append(dst, pad[:16-rem]...)
	}
	return dst
}

// ctrCounterBlock builds the initial AES-CTR counter block from the tag: the tag
// with the most significant bit of its last byte set to 1 (RFC 8452 §4).
func ctrCounterBlock(tag [16]byte) [16]byte {
	ctr := tag
	ctr[15] |= 0x80
	return ctr
}

// ctrCrypt applies AES-256-CTR-SIV keystream to src, writing to dst (which may
// alias src), per RFC 8452 §4. The 32-bit little-endian counter occupies the
// first 4 bytes of the block and is incremented per block; the remaining 12
// bytes are held fixed from the initial counter block.
func ctrCrypt(encBlock cipher.Block, initialCtr [16]byte, dst, src []byte) {
	var block [aes.BlockSize]byte
	var ks [aes.BlockSize]byte
	copy(block[:], initialCtr[:])
	counter := binary.LittleEndian.Uint32(initialCtr[0:4])
	for i := 0; i < len(src); i += aes.BlockSize {
		binary.LittleEndian.PutUint32(block[0:4], counter)
		encBlock.Encrypt(ks[:], block[:])
		n := len(src) - i
		if n > aes.BlockSize {
			n = aes.BlockSize
		}
		for j := 0; j < n; j++ {
			dst[i+j] = src[i+j] ^ ks[j]
		}
		counter++
	}
}

// Seal encrypts and authenticates plaintext with the given 32-byte key, 12-byte
// nonce, and additional data, returning ciphertext || tag (RFC 8452 §4). It does
// not mutate any input slice.
func Seal(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: want %d bytes, got %d", ErrKeySize, KeySize, len(key))
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("%w: want %d bytes, got %d", ErrNonceSize, NonceSize, len(nonce))
	}
	if len(plaintext) > maxPlaintextLen || len(additionalData) > maxADLen {
		return nil, ErrInputTooLong
	}

	kgkBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("gcmsiv: AES init: %w", err)
	}
	authKey, encKey := deriveKeys(kgkBlock, nonce)
	encBlock, err := aes.NewCipher(encKey[:])
	if err != nil {
		return nil, fmt.Errorf("gcmsiv: AES init (enc key): %w", err)
	}

	tag := computeTag(authKey, encBlock, nonce, plaintext, additionalData)

	out := make([]byte, len(plaintext)+TagSize)
	ctrCrypt(encBlock, ctrCounterBlock(tag), out[:len(plaintext)], plaintext)
	copy(out[len(plaintext):], tag[:])
	return out, nil
}

// Open verifies and decrypts ciphertextAndTag (ciphertext || 16-byte tag) with
// the given key, nonce, and additional data, returning the plaintext (RFC 8452
// §4). On any authentication failure it returns ErrOpen and no plaintext. It
// does not mutate any input slice.
func Open(key, nonce, ciphertextAndTag, additionalData []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: want %d bytes, got %d", ErrKeySize, KeySize, len(key))
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("%w: want %d bytes, got %d", ErrNonceSize, NonceSize, len(nonce))
	}
	if len(ciphertextAndTag) < TagSize {
		return nil, fmt.Errorf("%w: ciphertext shorter than tag", ErrOpen)
	}
	if len(ciphertextAndTag)-TagSize > maxPlaintextLen || len(additionalData) > maxADLen {
		return nil, ErrInputTooLong
	}

	ctLen := len(ciphertextAndTag) - TagSize
	ciphertext := ciphertextAndTag[:ctLen]
	var receivedTag [16]byte
	copy(receivedTag[:], ciphertextAndTag[ctLen:])

	kgkBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("gcmsiv: AES init: %w", err)
	}
	authKey, encKey := deriveKeys(kgkBlock, nonce)
	encBlock, err := aes.NewCipher(encKey[:])
	if err != nil {
		return nil, fmt.Errorf("gcmsiv: AES init (enc key): %w", err)
	}

	// Decrypt first (CTR keystream derived from the received tag), then
	// recompute the tag over the recovered plaintext and compare in constant
	// time (RFC 8452 §4 "Decryption").
	plaintext := make([]byte, ctLen)
	ctrCrypt(encBlock, ctrCounterBlock(receivedTag), plaintext, ciphertext)

	expectedTag := computeTag(authKey, encBlock, nonce, plaintext, additionalData)
	if subtle.ConstantTimeCompare(expectedTag[:], receivedTag[:]) != 1 {
		// Do not leak the recovered plaintext on authentication failure.
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, ErrOpen
	}
	return plaintext, nil
}
