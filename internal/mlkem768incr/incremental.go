// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// Incremental ML-KEM-768 — the chunked KEM split that SPQR (the Stage-2 sparse
// post-quantum ratchet) builds on. This layer is ported from libcrux-ml-kem
// 0.0.8 (src/ind_cca/incremental.rs + incremental/types.rs) and SPQR v1.5.1
// (src/incremental_mlkem768.rs), layered on top of the FIPS-203 PKE core in
// mlkem.go. It is byte-exact against that reference (see the libcrux oracle in
// incremental_oracle_test.go).
//
// The split: a standard ML-KEM-768 public key is (ByteEncode₁₂(t̂) ‖ ρ). The
// incremental form carries it as two parts —
//
//	pk1 (header, 64B) = ρ ‖ H(ek)
//	pk2 (encaps key, 1152B) = ByteEncode₁₂(t̂)
//
// — so the bulky t̂ can be transported in chunks (a later SPQR slice). The
// encapsulation is correspondingly two-phase:
//
//	Encapsulate1(pk1, m) computes everything that depends only on the header —
//	  the randomized vector r̂, the errors e₁/e₂, and u = NTT⁻¹(Âᵀ◦r̂)+e₁ — emits
//	  ct1 = Compress₁₀(u), the shared secret K = G(m‖H(ek))[:32], and saves
//	  (r̂, e₂, m) in an EncapsState blob.
//	Encapsulate2(state, pk2) finishes with t̂: v = NTT⁻¹(t̂ᵀ◦r̂)+e₂+Decompress₁(m),
//	  emits ct2 = Compress₄(v).
//
// Decapsulation is NOT split: decapsulate_compressed_key just concatenates
// ct1 ‖ ct2 into the standard 1088-byte ciphertext and runs the ordinary
// FIPS-203 ML-KEM decaps (with implicit rejection) against the standard
// 2400-byte decapsulation key. So decaps reuses mlkem.go's Decapsulate verbatim.

package mlkem768incr

import (
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// Incremental ML-KEM-768 wire sizes (libcrux 0.0.8, K=3).
const (
	// PublicKey1Size is the header: ρ (32) ‖ H(ek) (32).
	PublicKey1Size = 64
	// PublicKey2Size is the chunked encapsulation key: ByteEncode₁₂(t̂).
	PublicKey2Size = k * encodingSize12 // 1152
	// DecapsulationKeySize is the standard expanded dk: ByteEncode₁₂(ŝ) ‖ ek ‖
	// H(ek) ‖ z.
	DecapsulationKeySize = k*encodingSize12 + EncapsulationKeySize768 + 32 + 32 // 2400
	// Ciphertext1Size is Compress₁₀(u).
	Ciphertext1Size = k * encodingSize10 // 960
	// Ciphertext2Size is Compress₄(v).
	Ciphertext2Size = encodingSize4 // 128
	// rawPolyI16Size is one polynomial as 256 raw little-endian int16
	// coefficients — libcrux's EncapsState poly encoding, distinct from the
	// 12-bit ByteEncode₁₂ used for t̂/ŝ.
	rawPolyI16Size = n * 2 // 512
	// EncapsStateSize is the saved phase-1 state: r̂ (k polys) ‖ e₂ (1 poly) ‖
	// m (32). = 3*512 + 512 + 32 = 2080.
	EncapsStateSize = k*rawPolyI16Size + rawPolyI16Size + messageSize
)

// IncrementalKey is a freshly generated incremental ML-KEM-768 key, split into
// its header, chunked encapsulation key, and (standard, expanded) decapsulation
// key. Mirrors SPQR's generate() output (incremental_mlkem768.rs).
type IncrementalKey struct {
	PK1 []byte // header (PublicKey1Size)
	PK2 []byte // chunked encaps key (PublicKey2Size)
	DK  []byte // expanded decapsulation key (DecapsulationKeySize)
}

// GenerateIncrementalKey expands an incremental ML-KEM-768 key from a 64-byte
// seed (d‖z), per FIPS 203 KeyGen, and serializes it into the incremental split.
// This is libcrux's KeyPairCompressedBytes::from_seed.
func GenerateIncrementalKey(seed []byte) (*IncrementalKey, error) {
	dk, err := NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	ek := dk.EncapsulationKey()
	return &IncrementalKey{
		PK1: encodePublicKey1(ek),
		PK2: ek.encodePublicKey2(),
		DK:  dk.encodeExpanded(),
	}, nil
}

// encodePublicKey1 returns the 64-byte header ρ ‖ H(ek). libcrux's pk1_bytes:
// seed_for_A ‖ public_key_hash.
func encodePublicKey1(ek *EncapsulationKey768) []byte {
	out := make([]byte, 0, PublicKey1Size)
	out = append(out, ek.rho[:]...)
	out = append(out, ek.h[:]...)
	return out
}

// encodePublicKey2 returns ByteEncode₁₂(t̂) — the 1152-byte chunked encaps key.
// This is exactly the 1152-byte prefix of the standard encapsulation key
// (ek = ByteEncode₁₂(t̂) ‖ ρ); libcrux's pk2_bytes = serialize_vector(t_as_ntt).
func (ek *EncapsulationKey768) encodePublicKey2() []byte {
	b := make([]byte, 0, PublicKey2Size)
	for i := range ek.t {
		b = polyByteEncode(b, ek.t[i])
	}
	return b
}

// encodeExpanded serializes the standard 2400-byte ML-KEM-768 decapsulation key:
// ByteEncode₁₂(ŝ) ‖ ek ‖ H(ek) ‖ z. This is the form libcrux's
// decapsulate_compressed_key consumes.
func (dk *DecapsulationKey768) encodeExpanded() []byte {
	b := make([]byte, 0, DecapsulationKeySize)
	for i := range dk.s {
		b = polyByteEncode(b, dk.s[i])
	}
	b = dk.EncapsulationKey().bytes(b)
	b = append(b, dk.h[:]...)
	b = append(b, dk.z[:]...)
	return b
}

// ValidatePublicKeyParts checks that a header (pk1) and chunked encaps key (pk2)
// are consistent: it reconstructs the standard public key (t̂ ‖ ρ), verifies
// H(ek) matches the header's hash, and checks t̂ is in the valid domain (the
// ByteDecode₁₂ modulus check). libcrux validate_pk_bytes.
func ValidatePublicKeyParts(pk1, pk2 []byte) error {
	if len(pk1) != PublicKey1Size {
		return errors.New("mlkem768incr: invalid pk1 length")
	}
	if len(pk2) != PublicKey2Size {
		return errors.New("mlkem768incr: invalid pk2 length")
	}
	// Reconstruct ek = pk2 (t̂) ‖ ρ (= pk1[0:32]), then re-hash and re-parse.
	rho := pk1[:32]
	hash := pk1[32:64]

	ek := make([]byte, 0, EncapsulationKeySize768)
	ek = append(ek, pk2...)
	ek = append(ek, rho...)

	h := sha3.New256()
	h.Write(ek)
	var got [32]byte
	h.Sum(got[:0])
	if subtle.ConstantTimeCompare(got[:], hash) != 1 {
		return errors.New("mlkem768incr: pk1/pk2 hash mismatch")
	}
	// NewEncapsulationKey768 performs the ByteDecode₁₂ domain (modulus) check.
	if _, err := NewEncapsulationKey768(ek); err != nil {
		return err
	}
	return nil
}

// EncapsulationResult holds the phase-1 encapsulation outputs.
type EncapsulationResult struct {
	Ciphertext1  []byte // Compress₁₀(u) (Ciphertext1Size)
	EncapsState  []byte // saved (r̂ ‖ e₂ ‖ m) (EncapsStateSize)
	SharedSecret []byte // K = G(m‖H(ek))[:32]
}

// Encapsulate1Internal is the derandomized phase-1 encapsulation with the
// 32-byte message m supplied (for KATs); production callers draw m from a
// CSPRNG. pk1 is the 64-byte header.
//
// K = G(m‖H(ek))[:32]; the rest is K-PKE.Encrypt's r/e-sampling and the u half:
//
//	r̂[i]  = NTT(CBD_η1(PRF(r, i))),    i∈[0,k)
//	e₁[i] = CBD_η2(PRF(r, k+i)),       i∈[0,k)
//	e₂    = CBD_η2(PRF(r, 2k))
//	u     = NTT⁻¹(Âᵀ◦r̂) + e₁;  ct1 = Compress₁₀(u)
//
// (r̂, e₂, m) are stashed in the EncapsState for phase 2.
func Encapsulate1Internal(pk1 []byte, m *[messageBytes]byte) (*EncapsulationResult, error) {
	if len(pk1) != PublicKey1Size {
		return nil, errors.New("mlkem768incr: invalid pk1 length")
	}
	rho := pk1[:32]
	hash := pk1[32:64]

	// K ‖ r = G(m ‖ H(ek)).
	g := sha3.New512()
	g.Write(m[:])
	g.Write(hash)
	G := g.Sum(nil)
	K, rnd := G[:SharedKeySize], G[SharedKeySize:]

	// Â from ρ (transposed access below).
	var a [k * k]nttElement
	for i := byte(0); i < k; i++ {
		for j := byte(0); j < k; j++ {
			a[i*k+j] = sampleNTT(rho, j, i)
		}
	}

	var N byte
	r := make([]nttElement, k)
	for i := range r {
		r[i] = ntt(samplePolyCBD(rnd, N))
		N++
	}
	e1 := make([]ringElement, k)
	for i := range e1 {
		e1[i] = samplePolyCBD(rnd, N)
		N++
	}
	e2 := samplePolyCBD(rnd, N)

	u := make([]ringElement, k)
	for i := range u {
		var uHat nttElement
		for j := range r {
			uHat = polyAdd(uHat, nttMul(a[j*k+i], r[j])) // transposed Â
		}
		u[i] = polyAdd(e1[i], inverseNTT(uHat))
	}

	ct1 := make([]byte, 0, Ciphertext1Size)
	for _, f := range u {
		ct1 = ringCompressAndEncode10(ct1, f)
	}

	state := encodeEncapsState(r, e2, m)

	return &EncapsulationResult{
		Ciphertext1:  ct1,
		EncapsState:  state,
		SharedSecret: append([]byte(nil), K...),
	}, nil
}

// Encapsulate2 finishes encapsulation: it parses the EncapsState (applying the
// libcrux issue-1275 endianness fix if needed), decodes t̂ from pk2, computes
// v = NTT⁻¹(t̂ᵀ◦r̂) + e₂ + Decompress₁(m), and returns ct2 = Compress₄(v).
func Encapsulate2(state, pk2 []byte) ([]byte, error) {
	if len(pk2) != PublicKey2Size {
		return nil, errors.New("mlkem768incr: invalid pk2 length")
	}
	fixed, err := FixEncapsStateEndianness(state)
	if err != nil {
		return nil, err
	}
	r, e2, m, err := decodeEncapsState(fixed)
	if err != nil {
		return nil, err
	}

	// t̂ from pk2 (ByteEncode₁₂).
	t := make([]nttElement, k)
	rest := pk2
	for i := range t {
		t[i], err = polyByteDecode[nttElement](rest[:encodingSize12])
		if err != nil {
			return nil, err
		}
		rest = rest[encodingSize12:]
	}

	var vNTT nttElement
	for i := range t {
		vNTT = polyAdd(vNTT, nttMul(t[i], r[i]))
	}
	mu := ringDecodeAndDecompress1(&m)
	v := polyAdd(polyAdd(inverseNTT(vNTT), e2), mu)

	return ringCompressAndEncode4(make([]byte, 0, Ciphertext2Size), v), nil
}

// DecapsulateCompressedKey reconstructs the standard ciphertext ct1 ‖ ct2 and
// runs the ordinary FIPS-203 ML-KEM decaps (with constant-time implicit
// rejection) against the 2400-byte expanded decapsulation key. libcrux
// decapsulate_compressed_key.
func DecapsulateCompressedKey(dk, ct1, ct2 []byte) ([]byte, error) {
	if len(dk) != DecapsulationKeySize {
		return nil, errors.New("mlkem768incr: invalid decapsulation key length")
	}
	if len(ct1) != Ciphertext1Size {
		return nil, errors.New("mlkem768incr: invalid ct1 length")
	}
	if len(ct2) != Ciphertext2Size {
		return nil, errors.New("mlkem768incr: invalid ct2 length")
	}
	d, err := decodeExpandedDecapsulationKey(dk)
	if err != nil {
		return nil, err
	}
	ct := make([]byte, 0, CiphertextSize768)
	ct = append(ct, ct1...)
	ct = append(ct, ct2...)
	return d.Decapsulate(ct)
}

// decodeExpandedDecapsulationKey parses the 2400-byte expanded dk
// (ByteEncode₁₂(ŝ) ‖ ek ‖ H(ek) ‖ z) back into a DecapsulationKey768. It checks
// the embedded H(ek) against the recomputed hash (matching FIPS-203 §7.3 and the
// libcrux key-pair reconstruction).
func decodeExpandedDecapsulationKey(b []byte) (*DecapsulationKey768, error) {
	if len(b) != DecapsulationKeySize {
		return nil, errors.New("mlkem768incr: invalid decapsulation key length")
	}
	d := &DecapsulationKey768{}
	rest := b
	for i := range d.s {
		s, err := polyByteDecode[nttElement](rest[:encodingSize12])
		if err != nil {
			return nil, err
		}
		d.s[i] = s
		rest = rest[encodingSize12:]
	}
	ek, err := NewEncapsulationKey768(rest[:EncapsulationKeySize768])
	if err != nil {
		return nil, err
	}
	d.rho = ek.rho
	d.h = ek.h
	d.encryptionKey = ek.encryptionKey
	rest = rest[EncapsulationKeySize768:]
	if subtle.ConstantTimeCompare(d.h[:], rest[:32]) != 1 {
		return nil, errors.New("mlkem768incr: expanded dk H(ek) mismatch")
	}
	rest = rest[32:]
	copy(d.z[:], rest)
	return d, nil
}

// --- EncapsState raw-int16 codec (libcrux EncapsState::to_bytes/from_bytes) ---
//
// Unlike t̂/ŝ (12-bit ByteEncode₁₂), the EncapsState polynomials r̂ and e₂ are
// serialized as 256 raw signed little-endian int16 coefficients (512 B/poly).
// libcrux's portable backend writes bytes[2i]=low, bytes[2i+1]=high; the SIMD
// backends swap these (cryspen/libcrux#1275). Our writer is always correct LE;
// FixEncapsStateEndianness repairs a swapped state on read.
//
// Our field coefficients are canonical [0,q); libcrux carries small signed
// values for e₂ (CBD η2 ∈ [-2,2]) and reduced (often negative) values for r̂.
// The portable to_bytes is just the i16 two's-complement of whatever the vector
// holds, and from_bytes reads it back; round-tripping the same canonical reduced
// representative is byte-stable because r̂/e₂ here are always reduced mod q the
// same way the FIPS-203 core reduces them. (The oracle test pins this exactly.)

// encodeEncapsState serializes (r̂ ‖ e₂ ‖ m) into the 2080-byte state.
func encodeEncapsState(r []nttElement, e2 ringElement, m *[messageBytes]byte) []byte {
	out := make([]byte, EncapsStateSize)
	off := 0
	for i := range r {
		polyToRawI16LE(out[off:off+rawPolyI16Size], r[i])
		off += rawPolyI16Size
	}
	polyToRawI16LE(out[off:off+rawPolyI16Size], e2)
	off += rawPolyI16Size
	copy(out[off:off+messageSize], m[:])
	return out
}

// decodeEncapsState parses a (correct-endian) 2080-byte state into (r̂, e₂, m).
func decodeEncapsState(b []byte) (r []nttElement, e2 ringElement, m [messageBytes]byte, err error) {
	if len(b) != EncapsStateSize {
		return nil, e2, m, errors.New("mlkem768incr: invalid encaps state length")
	}
	r = make([]nttElement, k)
	off := 0
	for i := range r {
		r[i] = nttElement(polyFromRawI16LE(b[off : off+rawPolyI16Size]))
		off += rawPolyI16Size
	}
	e2 = polyFromRawI16LE(b[off : off+rawPolyI16Size])
	off += rawPolyI16Size
	copy(m[:], b[off:off+messageSize])
	return r, e2, m, nil
}

// polyToRawI16LE writes a polynomial's 256 coefficients as raw little-endian
// int16 (two bytes each), in the BALANCED (centered) representative libcrux
// carries: each canonical coefficient c ∈ [0,q) is mapped to c-q when c > (q-1)/2,
// giving a value in [-(q-1)/2, (q-1)/2]. (Verified against the libcrux fixture:
// e₂ ∈ [-2,2], r̂ ∈ ≈[-1664,1664].) This is NOT the 12-bit ByteEncode₁₂ used for
// t̂/ŝ — it is the per-coefficient signed-int16 form of EncapsState.
func polyToRawI16LE[T ~[n]fieldElement](out []byte, f T) {
	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint16(out[2*i:2*i+2], uint16(toBalanced(f[i])))
	}
}

// polyFromRawI16LE reads 256 raw little-endian int16 coefficients (the balanced
// representative) into a polynomial, reducing each back into canonical [0,q).
func polyFromRawI16LE(b []byte) ringElement {
	var f ringElement
	for i := 0; i < n; i++ {
		v := int16(binary.LittleEndian.Uint16(b[2*i : 2*i+2]))
		f[i] = fromBalanced(v)
	}
	return f
}

// toBalanced maps a canonical field element in [0,q) to libcrux's balanced
// int16 representative in [-(q-1)/2, (q-1)/2].
func toBalanced(c fieldElement) int16 {
	v := int16(c)
	if int(c) > (q-1)/2 {
		v -= q
	}
	return v
}

// fromBalanced reduces a signed int16 (the libcrux on-wire representative) into
// the canonical field element in [0,q).
func fromBalanced(v int16) fieldElement {
	r := int32(v) % q
	if r < 0 {
		r += q
	}
	return fieldElement(r)
}

// --- libcrux issue-1275 endianness fix (SPQR
//     potentially_fix_state_incorrectly_encoded_by_libcrux_issue_1275) ---

// FixEncapsStateEndianness detects and repairs an EncapsState whose polynomial
// int16s were serialized with swapped endianness by a libcrux SIMD backend
// (cryspen/libcrux#1275). It inspects the e₂ region (state[1536:2048]), whose
// coefficients are CBD η2 samples — all in [-2,2]. Read as little-endian int16,
// a correct encoding shows only {0, 1, 2, -1, -2}; a byte-swapped one shows the
// swapped images {0x0100, 0x0200, 0xFEFF}. On the first decisive coefficient we
// either keep the state (correct) or swap every int16 pair in state[0:len-32]
// (the trailing 32 random bytes have no endianness and are never swapped). A
// state of all-ambiguous {0,-1} values, or any unexpected value, is left as-is
// (matching SPQR's keep-and-warn fallback).
func FixEncapsStateEndianness(state []byte) ([]byte, error) {
	if len(state) != EncapsStateSize {
		return nil, errors.New("mlkem768incr: invalid encaps state length")
	}
	const (
		// Correct little-endian images of the η2-range values {0,1,2,-1,-2}.
		// 0 (0x0000) and -1 (0xFFFF) are byte-palindromes, so they don't decide.
		goodPos1 = int16(1)  // 0x0001
		goodPos2 = int16(2)  // 0x0002
		goodNeg2 = int16(-2) // 0xFFFE
		// Their byte-swapped images, as produced by a buggy SIMD backend.
		badPos1 = int16(0x0100)  // swapped 0x0001 → 256
		badPos2 = int16(0x0200)  // swapped 0x0002 → 512
		badNeg2 = int16(-0x0101) // swapped 0xFFFE → 0xFEFF → -257
	)
	e2Start := k * rawPolyI16Size // 1536
	e2End := EncapsStateSize - messageSize
	flip := false
	for i := e2Start; i+1 < e2End; i += 2 {
		v := int16(binary.LittleEndian.Uint16(state[i : i+2]))
		switch v {
		case 0, int16(-1):
			continue // palindrome byte pair; undecided, look at the next
		case goodPos1, goodPos2, goodNeg2:
			flip = false
		case badPos1, badPos2, badNeg2:
			flip = true
		default:
			flip = false // unexpected value — keep as-is (SPQR warns + keeps)
		}
		break
	}
	if !flip {
		return state, nil
	}
	out := make([]byte, EncapsStateSize)
	copy(out, state)
	for i := 0; i+1 < EncapsStateSize-messageSize; i += 2 {
		out[i], out[i+1] = out[i+1], out[i]
	}
	return out, nil
}
