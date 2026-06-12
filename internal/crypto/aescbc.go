package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// keySizeAES256 is the only AES key size used by the Signal protocol.
const keySizeAES256 = 32

// blockSize is the AES block size in bytes.
const blockSize = aes.BlockSize // 16

// EncryptCBC encrypts plaintext with AES-256-CBC and PKCS#7 padding, mirroring
// rust/crypto/src/aes_cbc.rs aes_256_cbc_encrypt. The key must be 32 bytes and
// the IV 16 bytes; otherwise ErrInvalidKeySize / ErrInvalidNonceSize is returned.
func EncryptCBC(plaintext, key, iv []byte) ([]byte, error) {
	block, err := newAES256(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != blockSize {
		return nil, fmt.Errorf("%w: CBC IV must be %d bytes, got %d", ErrInvalidNonceSize, blockSize, len(iv))
	}

	padded := pkcs7Pad(plaintext)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

// DecryptCBC decrypts AES-256-CBC + PKCS#7 ciphertext, mirroring
// rust/crypto/src/aes_cbc.rs aes_256_cbc_decrypt. The ciphertext length must be
// a non-zero multiple of the block size. Padding failures are reported as
// ErrBadCiphertext and are intentionally indistinguishable from other
// corruption (see errors.go).
func DecryptCBC(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := newAES256(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != blockSize {
		return nil, fmt.Errorf("%w: CBC IV must be %d bytes, got %d", ErrInvalidNonceSize, blockSize, len(iv))
	}
	if len(ciphertext) == 0 || len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("%w: ciphertext length must be a non-zero multiple of %d", ErrBadCiphertext, blockSize)
	}

	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)

	unpadded, ok := pkcs7Unpad(out)
	if !ok {
		return nil, fmt.Errorf("%w: invalid PKCS#7 padding", ErrBadCiphertext)
	}
	return unpadded, nil
}

// newAES256 constructs an AES cipher.Block, enforcing the 32-byte key size.
func newAES256(key []byte) (cipher.Block, error) {
	if len(key) != keySizeAES256 {
		return nil, fmt.Errorf("%w: AES-256 key must be %d bytes, got %d", ErrInvalidKeySize, keySizeAES256, len(key))
	}
	// aes.NewCipher only fails on bad key length, already checked above.
	return aes.NewCipher(key)
}

// pkcs7Pad appends PKCS#7 padding to a multiple of the block size. An input
// whose length is already a multiple of the block size gets a full block of
// padding, so the output is always a non-empty multiple of the block size.
func pkcs7Pad(data []byte) []byte {
	pad := blockSize - (len(data) % blockSize)
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// pkcs7Unpad removes PKCS#7 padding. It validates the padding in constant time
// with respect to the padding byte value to avoid a padding-oracle side channel,
// and returns ok=false on any malformed padding.
func pkcs7Unpad(data []byte) ([]byte, bool) {
	n := len(data)
	if n == 0 || n%blockSize != 0 {
		return nil, false
	}
	pad := int(data[n-1])
	if pad == 0 || pad > blockSize {
		return nil, false
	}
	// Constant-time check that the last `pad` bytes all equal `pad`. We always
	// scan a full block so the work is independent of the (secret) pad value.
	good := 1
	for i := 0; i < blockSize; i++ {
		b := data[n-blockSize+i]
		// This position is part of the padding when i >= blockSize-pad.
		inPad := subtle.ConstantTimeLessOrEq(blockSize-pad, i)
		isPadByte := subtle.ConstantTimeByteEq(b, byte(pad))
		// Outside the padding region, contribute 1 (no constraint).
		good &= subtle.ConstantTimeSelect(inPad, isPadByte, 1)
	}
	if good != 1 {
		return nil, false
	}
	return data[:n-pad], true
}
