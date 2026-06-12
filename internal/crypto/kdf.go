package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
)

// HMACSHA256 computes HMAC-SHA256 over input with the given key, mirroring
// rust/protocol/src/crypto.rs hmac_sha256. HMAC accepts a key of any length, so
// this never fails; the result is always 32 bytes.
func HMACSHA256(key, input []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(input)
	return mac.Sum(nil)
}

// HKDFExtractSHA256 performs the HKDF-Extract step (RFC 5869 §2.2) with
// SHA-256, returning the 32-byte pseudorandom key. A nil/empty salt is treated
// as a string of HashLen zero bytes, per the RFC.
//
// crypto/hkdf.Extract reports an error only when the supplied hash constructor
// is unusable; SHA-256 always is, so this never fails and returns no error.
func HKDFExtractSHA256(salt, ikm []byte) []byte {
	// The error is structurally unreachable for SHA-256 (see above); compute
	// the PRK directly via HMAC, which is exactly what HKDF-Extract is:
	// PRK = HMAC-Hash(salt, IKM), with an empty salt meaning HashLen zero bytes.
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	return HMACSHA256(salt, ikm)
}

// HKDFExpandSHA256 performs the HKDF-Expand step (RFC 5869 §2.3) with SHA-256,
// deriving length bytes of output keying material from a pseudorandom key and
// info string. It returns an error if length exceeds 255*HashLen (8160 bytes).
func HKDFExpandSHA256(prk, info []byte, length int) ([]byte, error) {
	return hkdf.Expand(sha256.New, prk, string(info), length)
}

// HKDFSHA256 is the one-shot HKDF (Extract then Expand) with SHA-256, deriving
// length bytes from input keying material, salt, and info. It returns an error
// if length exceeds 255*HashLen (8160 bytes).
func HKDFSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	return hkdf.Key(sha256.New, ikm, salt, string(info), length)
}
