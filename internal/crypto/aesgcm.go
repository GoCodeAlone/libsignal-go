package crypto

import (
	"crypto/cipher"
	"fmt"
)

// AES-256-GCM parameters, matching rust/crypto/src/aes_gcm.rs.
const (
	// NonceSizeGCM is the standard 96-bit GCM nonce length.
	NonceSizeGCM = 12
	// TagSizeGCM is the GCM authentication tag length in bytes.
	TagSizeGCM = 16
)

// SealGCM encrypts plaintext with AES-256-GCM and returns the ciphertext and
// authentication tag separately (the Rust API computes the tag separately, so
// callers control framing). The key must be 32 bytes and the nonce 12 bytes.
func SealGCM(key, nonce, plaintext, associatedData []byte) (ciphertext, tag []byte, err error) {
	aead, err := newGCM(key, nonce)
	if err != nil {
		return nil, nil, err
	}
	// Seal appends ciphertext||tag to dst; split them apart for the caller.
	sealed := aead.Seal(nil, nonce, plaintext, associatedData)
	ctLen := len(sealed) - TagSizeGCM
	return sealed[:ctLen], sealed[ctLen:], nil
}

// OpenGCM verifies the tag and decrypts AES-256-GCM ciphertext. A wrong key,
// nonce, tag, ciphertext, or associated data yields ErrInvalidTag (GCM does not
// distinguish these). The key must be 32 bytes, the nonce 12 bytes, and the tag
// 16 bytes.
func OpenGCM(key, nonce, ciphertext, tag, associatedData []byte) (plaintext []byte, err error) {
	if len(tag) != TagSizeGCM {
		return nil, fmt.Errorf("%w: GCM tag must be %d bytes, got %d", ErrInvalidTag, TagSizeGCM, len(tag))
	}
	aead, err := newGCM(key, nonce)
	if err != nil {
		return nil, err
	}
	// Reconstruct the sealed form (ciphertext||tag) the stdlib expects. Avoid
	// mutating the caller's slices.
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)

	pt, err := aead.Open(nil, nonce, sealed, associatedData)
	if err != nil {
		// crypto/cipher returns a single opaque error on authentication
		// failure; normalize it to our sentinel.
		return nil, fmt.Errorf("%w: %v", ErrInvalidTag, err)
	}
	return pt, nil
}

// newGCM builds an AES-256-GCM AEAD with explicit key- and nonce-size checks so
// the error taxonomy is reported before any cryptographic work.
func newGCM(key, nonce []byte) (cipher.AEAD, error) {
	block, err := newAES256(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSizeGCM {
		return nil, fmt.Errorf("%w: GCM nonce must be %d bytes, got %d", ErrInvalidNonceSize, NonceSizeGCM, len(nonce))
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		// Should not happen for a valid AES block with the standard tag size.
		return nil, fmt.Errorf("crypto: GCM init failed: %w", err)
	}
	return aead, nil
}
