// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// The FIPS-203 ML-KEM-768 KeyGen / Encaps / Decaps and K-PKE Encrypt / Decrypt
// in this file are re-derived from the Go standard library's
// crypto/internal/fips140/mlkem/mlkem768.go, which carries:
//
//	Copyright 2024 The Go Authors. All rights reserved.
//	Use of this source code is governed by a BSD-style license.
//
// We substitute the public crypto/sha3 for the toolchain-internal fips140
// SHA-3, and omit the FIPS self-test / DRBG / PCT plumbing (not needed here —
// randomness is caller-supplied). The byte encodings are FIPS-203, verified
// against the stdlib crypto/mlkem package and the NIST/ACVP ML-KEM-768 KATs
// (ADR 0003). This is the standard (monolithic) ML-KEM-768 core; the libcrux
// incremental split is layered on top in incremental.go.

package mlkem768incr

import (
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"fmt"
)

// Standard ML-KEM-768 byte sizes (FIPS 203).
const (
	SharedKeySize           = 32
	SeedSize                = 64                               // d ‖ z
	CiphertextSize768       = k*encodingSize10 + encodingSize4 // 1088
	EncapsulationKeySize768 = k*encodingSize12 + 32            // 1184
	messageBytes            = messageSize                      // 32 (m)
)

// encryptionKey is the parsed/expanded K-PKE encryption key: the public vector
// t̂ and the matrix Â (Â[i*k+j] = sampleNTT(ρ, j, i)).
type encryptionKey struct {
	t [k]nttElement
	a [k * k]nttElement
}

// decryptionKey is the parsed K-PKE decryption key: the secret vector ŝ.
type decryptionKey struct {
	s [k]nttElement
}

// DecapsulationKey768 is an expanded FIPS-203 ML-KEM-768 decapsulation key.
// It holds the seed (d‖z), ρ, H(ek), and the expanded encryption/decryption
// keys. The key material is secret; see String for redaction.
type DecapsulationKey768 struct {
	d   [32]byte // keygen seed half
	z   [32]byte // implicit-rejection seed half
	rho [32]byte
	h   [32]byte // H(ek)
	encryptionKey
	decryptionKey
}

// EncapsulationKey768 is an expanded FIPS-203 ML-KEM-768 encapsulation key.
type EncapsulationKey768 struct {
	rho [32]byte
	h   [32]byte // H(ek)
	encryptionKey
}

// NewDecapsulationKey768 expands a decapsulation key from a 64-byte seed (d‖z),
// per FIPS 203. The seed must be uniformly random and kept secret.
func NewDecapsulationKey768(seed []byte) (*DecapsulationKey768, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("mlkem768incr: invalid seed length")
	}
	dk := &DecapsulationKey768{}
	kemKeyGen(dk, (*[32]byte)(seed[:32]), (*[32]byte)(seed[32:]))
	return dk, nil
}

// kemKeyGen implements ML-KEM.KeyGen_internal + K-PKE.KeyGen (FIPS 203,
// Algorithms 16 + 13, merged): G = SHA3-512(d ‖ k) → (ρ, σ); Â from ρ; ŝ, ê from
// CBD(σ); t̂ = Â ◦ ŝ + ê; h = SHA3-256(ek).
func kemKeyGen(dk *DecapsulationKey768, d, z *[32]byte) {
	dk.d = *d
	dk.z = *z

	g := sha3.New512()
	g.Write(d[:])
	g.Write([]byte{k}) // module dimension as domain separator
	G := g.Sum(make([]byte, 0, 64))
	rho, sigma := G[:32], G[32:]
	dk.rho = [32]byte(rho)

	A := &dk.a
	for i := byte(0); i < k; i++ {
		for j := byte(0); j < k; j++ {
			A[i*k+j] = sampleNTT(rho, j, i)
		}
	}

	var N byte
	s := &dk.s
	for i := range s {
		s[i] = ntt(samplePolyCBD(sigma, N))
		N++
	}
	e := make([]nttElement, k)
	for i := range e {
		e[i] = ntt(samplePolyCBD(sigma, N))
		N++
	}

	t := &dk.t
	for i := range t { // t = A ◦ s + e
		t[i] = e[i]
		for j := range s {
			t[i] = polyAdd(t[i], nttMul(A[i*k+j], s[j]))
		}
	}

	H := sha3.New256()
	H.Write(dk.EncapsulationKey().Bytes())
	H.Sum(dk.h[:0])
}

// EncapsulationKey returns the public encapsulation key.
func (dk *DecapsulationKey768) EncapsulationKey() *EncapsulationKey768 {
	return &EncapsulationKey768{rho: dk.rho, h: dk.h, encryptionKey: dk.encryptionKey}
}

// Bytes returns the 64-byte seed form (d‖z) of the decapsulation key (secret).
func (dk *DecapsulationKey768) Bytes() []byte {
	b := make([]byte, 0, SeedSize)
	b = append(b, dk.d[:]...)
	b = append(b, dk.z[:]...)
	return b
}

// Bytes returns the encoded encapsulation key: ByteEncode₁₂(t̂) ‖ ρ (1184 bytes).
func (ek *EncapsulationKey768) bytes(b []byte) []byte {
	for i := range ek.t {
		b = polyByteEncode(b, ek.t[i])
	}
	return append(b, ek.rho[:]...)
}

// Bytes returns the standard 1184-byte ML-KEM-768 encapsulation key encoding.
func (ek *EncapsulationKey768) Bytes() []byte {
	return ek.bytes(make([]byte, 0, EncapsulationKeySize768))
}

// NewEncapsulationKey768 parses the standard 1184-byte encapsulation key,
// checking the modulus (FIPS 203 §7.2 step 2 via polyByteDecode).
func NewEncapsulationKey768(b []byte) (*EncapsulationKey768, error) {
	if len(b) != EncapsulationKeySize768 {
		return nil, errors.New("mlkem768incr: invalid encapsulation key length")
	}
	ek := &EncapsulationKey768{}
	h := sha3.New256()
	h.Write(b)
	h.Sum(ek.h[:0])

	rest := b
	for i := range ek.t {
		var err error
		ek.t[i], err = polyByteDecode[nttElement](rest[:encodingSize12])
		if err != nil {
			return nil, err
		}
		rest = rest[encodingSize12:]
	}
	copy(ek.rho[:], rest)
	for i := byte(0); i < k; i++ {
		for j := byte(0); j < k; j++ {
			ek.a[i*k+j] = sampleNTT(ek.rho[:], j, i)
		}
	}
	return ek, nil
}

// EncapsulateInternal is the derandomized ML-KEM.Encaps (FIPS 203, Algorithm 17)
// with the 32-byte message m supplied (for KATs). Encapsulate (production) draws
// m from a CSPRNG.
func (ek *EncapsulationKey768) EncapsulateInternal(m *[messageBytes]byte) (sharedKey, ciphertext []byte) {
	g := sha3.New512()
	g.Write(m[:])
	g.Write(ek.h[:])
	G := g.Sum(nil)
	K, r := G[:SharedKeySize], G[SharedKeySize:]
	c := pkeEncrypt(&ek.encryptionKey, m, r)
	return K, c
}

// pkeEncrypt implements K-PKE.Encrypt (FIPS 203, Algorithm 14): u = NTT⁻¹(Âᵀ ◦ r)
// + e₁; v = NTT⁻¹(t̂ᵀ ◦ r) + e₂ + Decompress₁(m); ciphertext = Compress₁₀(u) ‖
// Compress₄(v).
func pkeEncrypt(ex *encryptionKey, m *[messageBytes]byte, rnd []byte) []byte {
	var N byte
	r, e1 := make([]nttElement, k), make([]ringElement, k)
	for i := range r {
		r[i] = ntt(samplePolyCBD(rnd, N))
		N++
	}
	for i := range e1 {
		e1[i] = samplePolyCBD(rnd, N)
		N++
	}
	e2 := samplePolyCBD(rnd, N)

	u := make([]ringElement, k)
	for i := range u {
		var uHat nttElement
		for j := range r {
			uHat = polyAdd(uHat, nttMul(ex.a[j*k+i], r[j])) // transposed A
		}
		u[i] = polyAdd(e1[i], inverseNTT(uHat))
	}

	mu := ringDecodeAndDecompress1(m)

	var vNTT nttElement
	for i := range ex.t {
		vNTT = polyAdd(vNTT, nttMul(ex.t[i], r[i]))
	}
	v := polyAdd(polyAdd(inverseNTT(vNTT), e2), mu)

	c := make([]byte, 0, CiphertextSize768)
	for _, f := range u {
		c = ringCompressAndEncode10(c, f)
	}
	return ringCompressAndEncode4(c, v)
}

// Decapsulate implements ML-KEM.Decaps (FIPS 203, Algorithm 18) with implicit
// rejection, constant-time. ciphertext must be CiphertextSize768 bytes.
func (dk *DecapsulationKey768) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != CiphertextSize768 {
		return nil, errors.New("mlkem768incr: invalid ciphertext length")
	}
	c := (*[CiphertextSize768]byte)(ciphertext)
	m := pkeDecrypt(&dk.decryptionKey, c)
	g := sha3.New512()
	g.Write(m[:])
	g.Write(dk.h[:])
	G := g.Sum(make([]byte, 0, 64))
	Kprime, r := G[:SharedKeySize], G[SharedKeySize:]
	J := sha3.NewSHAKE256()
	J.Write(dk.z[:])
	J.Write(c[:])
	Kout := make([]byte, SharedKeySize)
	J.Read(Kout)
	c1 := pkeEncrypt(&dk.encryptionKey, (*[messageBytes]byte)(m), r)
	subtle.ConstantTimeCopy(subtle.ConstantTimeCompare(c[:], c1), Kout, Kprime)
	return Kout, nil
}

// pkeDecrypt implements K-PKE.Decrypt (FIPS 203, Algorithm 15): w = v - NTT⁻¹(ŝᵀ
// ◦ NTT(u)); m = Compress₁(w).
func pkeDecrypt(dx *decryptionKey, c *[CiphertextSize768]byte) []byte {
	u := make([]ringElement, k)
	for i := range u {
		b := (*[encodingSize10]byte)(c[encodingSize10*i : encodingSize10*(i+1)])
		u[i] = ringDecodeAndDecompress10(b)
	}
	b := (*[encodingSize4]byte)(c[encodingSize10*k:])
	v := ringDecodeAndDecompress4(b)

	var mask nttElement
	for i := range dx.s {
		mask = polyAdd(mask, nttMul(dx.s[i], ntt(u[i])))
	}
	w := polySub(v, inverseNTT(mask))
	return ringCompressAndEncode1(nil, w)
}

// String redacts the secret key material so a decapsulation key never leaks
// into logs. Value receiver (matching curve.PrivateKey) so a value copy — not
// just a pointer — also redacts under %v/%s.
func (dk DecapsulationKey768) String() string {
	return "mlkem768incr.DecapsulationKey768{[redacted]}"
}

// Format implements fmt.Formatter, redacting the secret key material under every
// verb. Without this, %#v dumps the seed (d), implicit-rejection secret (z), and
// secret vector ŝ as a raw struct, and %x dumps their bytes. Value receiver so a
// value copy redacts too. The embedded encryptionKey is public (t̂/Â) but is
// redacted along with the rest for a single uniform secret-key rendering; use
// EncapsulationKey() to print the public key. (FIPS-203 secret-leak convention;
// see curve.PrivateKey.Format.)
func (dk DecapsulationKey768) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "mlkem768incr.DecapsulationKey768{[redacted]}")
}
