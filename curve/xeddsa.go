package curve

import (
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// SignatureLength is the length of an XEdDSA signature in bytes.
const SignatureLength = 64

// xeddsaHashPrefix is the 32-byte domain-separation prefix prepended to the
// nonce hash input: 0xFE followed by 31 bytes of 0xFF. It is dom1 from the
// XEdDSA spec for Curve25519 (-2 - 0 encoded as 2^256 - 1 - 2*0 in
// little-endian, i.e. 0xFE 0xFF*31). Extracted verbatim from
// rust/core/src/curve/curve25519.rs calculate_signature.
var xeddsaHashPrefix = [32]byte{
	0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// CalculateSignature produces an XEdDSA signature over message using this
// private key, drawing 64 bytes of randomness from rng (use crypto/rand.Reader
// in production; a deterministic reader yields a deterministic signature for
// tests). message may be supplied in multiple pieces, which are concatenated;
// passing no pieces signs the empty message.
//
// The construction follows the XEdDSA spec
// (https://signal.org/docs/specifications/xeddsa/#curve25519) exactly as
// implemented in rust/core/src/curve/curve25519.rs: the Ed25519 public key's
// sign bit is carried in the otherwise-zero most significant bit of the
// signature (for compatibility with libsignal-protocol-java) rather than forced
// to 0 as in the original paper.
func (p PrivateKey) CalculateSignature(rng io.Reader, message ...[]byte) ([]byte, error) {
	var random [64]byte
	if _, err := io.ReadFull(rng, random[:]); err != nil {
		return nil, fmt.Errorf("curve: reading signature nonce: %w", err)
	}

	keyData := p.data // the clamped 32-byte scalar bytes

	// a = scalar reduced from the private key bytes (little-endian, mod l).
	a, err := scalarFromBytesModOrder(keyData[:])
	if err != nil {
		return nil, fmt.Errorf("curve: deriving signing scalar: %w", err)
	}

	// A = a*B, and the sign bit of its compressed Edwards encoding.
	edPub := new(edwards25519.Point).ScalarBaseMult(a)
	edPubBytes := edPub.Bytes()
	signBit := edPubBytes[31] & 0x80

	// r = SHA-512(prefix || keyData || message... || random) reduced mod l.
	h1 := sha512.New()
	h1.Write(xeddsaHashPrefix[:])
	h1.Write(keyData[:])
	for _, piece := range message {
		h1.Write(piece)
	}
	h1.Write(random[:])
	r, err := scalarFromHash(h1.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("curve: deriving nonce scalar: %w", err)
	}

	// R = r*B.
	capR := new(edwards25519.Point).ScalarBaseMult(r)
	capRBytes := capR.Bytes()

	// h = SHA-512(R || A || message...) reduced mod l.
	h2 := sha512.New()
	h2.Write(capRBytes)
	h2.Write(edPubBytes)
	for _, piece := range message {
		h2.Write(piece)
	}
	hScalar, err := scalarFromHash(h2.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("curve: deriving challenge scalar: %w", err)
	}

	// s = h*a + r.
	s := new(edwards25519.Scalar).MultiplyAdd(hScalar, a, r)
	sBytes := s.Bytes()

	sig := make([]byte, SignatureLength)
	copy(sig[:32], capRBytes)
	copy(sig[32:], sBytes)
	// Carry the public key sign bit in the top bit of s (which is always 0 for
	// a canonical scalar), matching upstream.
	sig[SignatureLength-1] &= 0x7F
	sig[SignatureLength-1] |= signBit
	return sig, nil
}

// VerifySignature reports whether signature is a valid XEdDSA signature by this
// public key over message (supplied in one or more pieces, concatenated). It
// never panics and returns false for any malformed input.
//
// Mirrors rust/core/src/curve/curve25519.rs verify_signature.
func (p PublicKey) VerifySignature(signature []byte, message ...[]byte) bool {
	if len(signature) != SignatureLength {
		return false
	}

	// Recover the Edwards public key from the Montgomery u-coordinate, using
	// the sign bit carried in the top bit of the signature. Returns false if
	// the point does not exist on the curve.
	edPub, ok := montgomeryToEdwards(p.data, (signature[SignatureLength-1]&0x80)>>7)
	if !ok {
		return false
	}
	capAbytes := edPub.Bytes()

	var capR [32]byte
	copy(capR[:], signature[:32])

	var sBytes [32]byte
	copy(sBytes[:], signature[32:])
	sBytes[31] &= 0x7F
	// Reject non-canonical s: upstream requires the top three bits of s[31] to
	// be clear (s < 2^253 < l would otherwise not be guaranteed canonical).
	if sBytes[31]&0xE0 != 0 {
		return false
	}

	s, err := scalarFromBytesModOrder(sBytes[:])
	if err != nil {
		return false
	}

	minusA := new(edwards25519.Point).Negate(edPub)

	// h = SHA-512(R || A || message...) reduced mod l.
	h := sha512.New()
	h.Write(capR[:])
	h.Write(capAbytes)
	for _, piece := range message {
		h.Write(piece)
	}
	hScalar, err := scalarFromHash(h.Sum(nil))
	if err != nil {
		return false
	}

	// Rcheck = h*(-A) + s*B; valid iff its compression equals R.
	rCheck := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(hScalar, minusA, s)
	return subtle.ConstantTimeCompare(rCheck.Bytes(), capR[:]) == 1
}

// IsTorsionFree reports whether the public key, interpreted as a Montgomery
// point mapped to Edwards, lies in the prime-order subgroup (i.e. has no
// small-order torsion component). Mirrors PublicKey::is_torsion_free in
// rust/core/src/curve.rs. A point that does not map to a valid Edwards point is
// treated as not torsion-free.
func (p PublicKey) IsTorsionFree() bool {
	ed, ok := montgomeryToEdwards(p.data, 0)
	if !ok {
		return false
	}
	// A point P is in the prime-order subgroup iff [l]P == identity. The group
	// order l is not a representable Scalar (it reduces to 0), but l-1 is, so we
	// test [l-1]P + P == identity, exactly as curve25519_dalek's
	// EdwardsPoint::is_torsion_free does. l-1 == -1 mod l = 0 - 1.
	lMinus1 := new(edwards25519.Scalar).Subtract(edwards25519.NewScalar(), scalarOne)
	lP := new(edwards25519.Point).ScalarMult(lMinus1, ed) // [l-1]P
	lP.Add(lP, ed)                                        // [l-1]P + P == [l]P
	return lP.Equal(edwards25519.NewIdentityPoint()) == 1
}

// ScalarIsInRange reports whether the public key's 32-byte little-endian value
// is below 2^255 - 19. It rejects keys with the high bit set, and keys whose
// value lies in [2^255-19, 2^255-1] (the non-canonical "above the prime modulus"
// range). Mirrors PublicKey::scalar_is_in_range in rust/core/src/curve.rs,
// byte-for-byte.
func (p PublicKey) ScalarIsInRange() bool {
	k := p.data
	highBitSet := k[31]&0x80 != 0
	// The top 247 bits all 1 and the low byte > 2^8 - 19, i.e. value in
	// [2^255-19, 2^255-1]: k[0] >= 256-19, k[1..31] all 0xFF, k[31] == 0x7F.
	allHighOnes := k[31] == 0x7F
	if allHighOnes {
		for i := 1; i < 31; i++ {
			if k[i] != 0xFF {
				allHighOnes = false
				break
			}
		}
	}
	// 0u8.wrapping_sub(19) == 237; k[0] >= 237 is the low-byte condition from
	// rust/core/src/curve.rs scalar_is_in_range.
	const lowByteThreshold = byte(256 - 19) // 237
	aboveModulus := k[0] >= lowByteThreshold && allHighOnes
	// In range iff neither the high bit is set nor the value is in the
	// above-modulus band. (Upstream writes this as !(highBitSet || aboveModulus).)
	return !highBitSet && !aboveModulus
}

// IsCanonical reports whether the public key is both torsion-free and in range,
// i.e. a well-formed prime-order Curve25519 point. Mirrors
// PublicKey::is_canonical in rust/core/src/curve.rs.
func (p PublicKey) IsCanonical() bool {
	return p.IsTorsionFree() && p.ScalarIsInRange()
}

// scalarFromBytesModOrder reduces a 32-byte little-endian integer modulo the
// group order l, matching curve25519_dalek Scalar::from_bytes_mod_order. It does
// so by zero-extending to 64 bytes and using the wide (uniform) reduction, which
// is exact for a 256-bit input.
func scalarFromBytesModOrder(b []byte) (*edwards25519.Scalar, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("curve: scalar input must be 32 bytes, got %d", len(b))
	}
	var wide [64]byte
	copy(wide[:32], b)
	return new(edwards25519.Scalar).SetUniformBytes(wide[:])
}

// scalarFromHash reduces a 64-byte hash output modulo l, matching
// Scalar::from_hash over SHA-512.
func scalarFromHash(h []byte) (*edwards25519.Scalar, error) {
	if len(h) != 64 {
		return nil, fmt.Errorf("curve: hash must be 64 bytes, got %d", len(h))
	}
	return new(edwards25519.Scalar).SetUniformBytes(h)
}

// scalarOne is the scalar 1, used to derive l-1 (= 0 - 1) for the torsion-free
// test. Built once from its canonical little-endian encoding.
var scalarOne = func() *edwards25519.Scalar {
	var b [32]byte
	b[0] = 1
	s, _ := new(edwards25519.Scalar).SetCanonicalBytes(b[:]) // 1 is always canonical
	return s
}()

// montgomeryToEdwards maps a 32-byte Montgomery u-coordinate to an Edwards
// point, choosing the x-coordinate whose sign equals signBit (0 or 1). It
// mirrors curve25519_dalek MontgomeryPoint::to_edwards: y = (u-1)/(u+1), then
// the Edwards point is recovered from the compressed (y, sign) encoding. It
// returns ok=false when no valid point exists (e.g. u == -1, or a non-canonical
// encoding).
func montgomeryToEdwards(u [32]byte, signBit byte) (*edwards25519.Point, bool) {
	uElem, err := new(field.Element).SetBytes(u[:])
	if err != nil {
		return nil, false
	}
	one := new(field.Element).One()
	// y = (u - 1) / (u + 1).
	uMinus1 := new(field.Element).Subtract(uElem, one)
	uPlus1 := new(field.Element).Add(uElem, one)
	// u + 1 == 0 has no inverse: reject (matches dalek returning None).
	if uPlus1.Equal(new(field.Element).Zero()) == 1 {
		return nil, false
	}
	invUPlus1 := new(field.Element).Invert(uPlus1)
	y := new(field.Element).Multiply(uMinus1, invUPlus1)

	// Build the compressed Edwards encoding: 32-byte little-endian y with the
	// desired x sign in the top bit, then let edwards25519 recover x (handling
	// the square-root and on-curve check, returning an error if invalid).
	comp := y.Bytes()
	comp[31] |= signBit << 7
	pt, err := new(edwards25519.Point).SetBytes(comp)
	if err != nil {
		return nil, false
	}
	return pt, true
}
