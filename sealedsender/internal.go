// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package sealedsender

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/GoCodeAlone/libsignal-go/internal/crypto"
)

// ctrHmacMACLen is the truncated HMAC-SHA256 tag length appended by the
// AES-256-CTR + HMAC-SHA256 construction used by sealed sender v1 (upstream
// crypto.rs aes256_ctr_hmacsha256_*: the 32-byte HMAC is truncated to 10 bytes).
const ctrHmacMACLen = 10

// aes256CtrHmacSha256Encrypt encrypts msg with AES-256-CTR (zero IV, 32-bit BE
// counter from 0) under cipherKey, then appends the first 10 bytes of
// HMAC-SHA256(macKey, ciphertext). Mirrors crypto::aes256_ctr_hmacsha256_encrypt.
func aes256CtrHmacSha256Encrypt(msg, cipherKey, macKey []byte) ([]byte, error) {
	ctext, err := aes256CTRZero(msg, cipherKey)
	if err != nil {
		return nil, err
	}
	mac := crypto.HMACSHA256(macKey, ctext)
	return append(ctext, mac[:ctrHmacMACLen]...), nil
}

// aes256CtrHmacSha256Decrypt verifies the trailing 10-byte truncated HMAC in
// constant time, then AES-256-CTR-decrypts the remaining bytes. Mirrors
// crypto::aes256_ctr_hmacsha256_decrypt. Returns ErrBadCiphertext on a truncated
// input or a MAC mismatch.
func aes256CtrHmacSha256Decrypt(ctextAndMAC, cipherKey, macKey []byte) ([]byte, error) {
	if len(ctextAndMAC) < ctrHmacMACLen {
		return nil, fmt.Errorf("%w: truncated ciphertext", ErrBadCiphertext)
	}
	split := len(ctextAndMAC) - ctrHmacMACLen
	ctext, theirMAC := ctextAndMAC[:split], ctextAndMAC[split:]
	ourMAC := crypto.HMACSHA256(macKey, ctext)
	if subtle.ConstantTimeCompare(ourMAC[:ctrHmacMACLen], theirMAC) != 1 {
		return nil, fmt.Errorf("%w: MAC verification failed", ErrBadCiphertext)
	}
	return aes256CTRZero(ctext, cipherKey)
}

// aes256CTRZero applies AES-256-CTR with a zero 12-byte nonce and a 32-bit
// big-endian counter starting at 0 (Ctr32BE with an all-zero IV), the transform
// used by both directions of aes256_ctr_hmacsha256. The input is copied so the
// caller retains its buffer.
func aes256CTRZero(in, cipherKey []byte) ([]byte, error) {
	ctr, err := crypto.NewAES256CTR32(cipherKey, make([]byte, crypto.NonceSizeCTR), 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCiphertext, err)
	}
	out := make([]byte, len(in))
	copy(out, in)
	ctr.Process(out)
	return out, nil
}

// cloneBytes returns a defensive copy of b (nil-preserving), so getters and
// constructors never alias caller-owned or proto-owned backing arrays.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// uuidStringFromBytes renders a 16-byte UUID in the canonical lowercase
// 8-4-4-4-12 hyphenated form, matching how upstream maps a sender certificate's
// uuidBytes field to a string (uuid::Uuid::from_slice(..).to_string()). It does
// not interpret version/variant bits — any 16 bytes are formatted verbatim.
func uuidStringFromBytes(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("uuid must be 16 bytes, got %d", len(b))
	}
	h := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]), nil
}
