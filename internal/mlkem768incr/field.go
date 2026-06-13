// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// The FIPS-203 field arithmetic, NTT, sampling, and byte (de)coding in this
// file are re-derived from the Go standard library's
// crypto/internal/fips140/mlkem/field.go, which carries:
//
//	Copyright 2024 The Go Authors. All rights reserved.
//	Use of this source code is governed by a BSD-style license.
//
// We substitute the public crypto/sha3 and encoding/binary for the
// toolchain-internal fips140 SHA-3/byteorder dependencies the stdlib version
// uses (which are import-locked to std). The algorithms are byte-for-byte
// FIPS-203, verified against the stdlib crypto/mlkem package and the NIST/ACVP
// ML-KEM-768 known-answer tests (ADR 0003).

package mlkem768incr

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
)

// FIPS-203 ML-KEM-768 parameters.
const (
	n = 256
	q = 3329
	k = 3 // ML-KEM-768

	// encodingSizeX is the byte length of a ring/NTT element with X bits per
	// coefficient (n*X/8).
	encodingSize12 = n * 12 / 8 // 384
	encodingSize10 = n * 10 / 8 // 320
	encodingSize4  = n * 4 / 8  // 128
	encodingSize1  = n * 1 / 8  // 32

	messageSize = encodingSize1 // 32

	// ML-KEM-768 ciphertext compression widths (FIPS 203 Table 2): u at du=10
	// (ringCompressAndEncode10), v at dv=4 (ringCompressAndEncode4). Encoded by
	// the width-specific helpers below rather than referenced as constants here.
)

// fieldElement is an integer modulo q (an element of ℤ_q), always reduced.
type fieldElement uint16

// fieldCheckReduced checks that a value a is < q.
func fieldCheckReduced(a uint16) (fieldElement, error) {
	if a >= q {
		return 0, errors.New("mlkem768incr: unreduced field element")
	}
	return fieldElement(a), nil
}

// fieldReduceOnce reduces a value a < 2q.
func fieldReduceOnce(a uint16) fieldElement {
	x := a - q
	// If x underflowed, x >= 2¹⁶ - q > 2¹⁵, so the top bit is set.
	x += (x >> 15) * q
	return fieldElement(x)
}

func fieldAdd(a, b fieldElement) fieldElement {
	return fieldReduceOnce(uint16(a + b))
}

func fieldSub(a, b fieldElement) fieldElement {
	return fieldReduceOnce(uint16(a - b + q))
}

const (
	barrettMultiplier = 5039 // ⌊2²⁴ / q⌋
	barrettShift      = 24
)

// fieldReduce reduces a value a < 2q² via Barrett reduction (constant time).
func fieldReduce(a uint32) fieldElement {
	quotient := uint32((uint64(a) * barrettMultiplier) >> barrettShift)
	return fieldReduceOnce(uint16(a - quotient*q))
}

func fieldMul(a, b fieldElement) fieldElement {
	return fieldReduce(uint32(a) * uint32(b))
}

// fieldMulSub returns a * (b - c), fused to save a reduction.
func fieldMulSub(a, b, c fieldElement) fieldElement {
	return fieldReduce(uint32(a) * uint32(b-c+q))
}

// fieldAddMul returns a * b + c * d, fused.
func fieldAddMul(a, b, c, d fieldElement) fieldElement {
	x := uint32(a) * uint32(b)
	x += uint32(c) * uint32(d)
	return fieldReduce(x)
}

// compress maps a field element to 0..2ᵈ-1 (FIPS 203, Definition 4.7).
func compress(x fieldElement, d uint8) uint16 {
	dividend := uint32(x) << d
	quotient := uint32(uint64(dividend) * barrettMultiplier >> barrettShift)
	remainder := dividend - quotient*q
	quotient += (q/2 - remainder) >> 31 & 1
	quotient += (q + q/2 - remainder) >> 31 & 1
	var mask uint32 = (1 << d) - 1
	return uint16(quotient & mask)
}

// decompress maps 0..2ᵈ-1 to the full field range (FIPS 203, Definition 4.8).
func decompress(y uint16, d uint8) fieldElement {
	dividend := uint32(y) * q
	quotient := dividend >> d
	quotient += dividend >> (d - 1) & 1
	return fieldElement(quotient)
}

// ringElement is a polynomial in R_q (FIPS 203, §2.4.4).
type ringElement [n]fieldElement

// nttElement is an NTT representation, an element of T_q.
type nttElement [n]fieldElement

func polyAdd[T ~[n]fieldElement](a, b T) (s T) {
	for i := range s {
		s[i] = fieldAdd(a[i], b[i])
	}
	return s
}

func polySub[T ~[n]fieldElement](a, b T) (s T) {
	for i := range s {
		s[i] = fieldSub(a[i], b[i])
	}
	return s
}

// polyByteEncode appends the 384-byte ByteEncode₁₂ of f (FIPS 203, Algorithm 5).
func polyByteEncode[T ~[n]fieldElement](b []byte, f T) []byte {
	out, B := sliceForAppend(b, encodingSize12)
	for i := 0; i < n; i += 2 {
		x := uint32(f[i]) | uint32(f[i+1])<<12
		B[0] = uint8(x)
		B[1] = uint8(x >> 8)
		B[2] = uint8(x >> 16)
		B = B[3:]
	}
	return out
}

// polyByteDecode decodes a 384-byte ByteDecode₁₂, checking reduction (FIPS 203,
// Algorithm 6 — the "modulus check" of ML-KEM encapsulation).
func polyByteDecode[T ~[n]fieldElement](b []byte) (T, error) {
	if len(b) != encodingSize12 {
		return T{}, errors.New("mlkem768incr: invalid encoding length")
	}
	var f T
	for i := 0; i < n; i += 2 {
		d := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
		const mask12 = 0b1111_1111_1111
		var err error
		if f[i], err = fieldCheckReduced(uint16(d & mask12)); err != nil {
			return T{}, errors.New("mlkem768incr: invalid polynomial encoding")
		}
		if f[i+1], err = fieldCheckReduced(uint16(d >> 12)); err != nil {
			return T{}, errors.New("mlkem768incr: invalid polynomial encoding")
		}
		b = b[3:]
	}
	return f, nil
}

// sliceForAppend extends in by n bytes, returning the whole slice and the tail.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// ringCompressAndEncode1 appends Compress₁ then ByteEncode₁ (32 bytes).
func ringCompressAndEncode1(s []byte, f ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize1)
	clear(b)
	for i := range f {
		b[i/8] |= uint8(compress(f[i], 1) << (i % 8))
	}
	return s
}

// ringDecodeAndDecompress1 decodes ByteDecode₁ then Decompress₁ (32 bytes).
func ringDecodeAndDecompress1(b *[encodingSize1]byte) ringElement {
	var f ringElement
	for i := range f {
		bi := b[i/8] >> (i % 8) & 1
		const halfQ = (q + 1) / 2 // ⌈q/2⌋
		f[i] = fieldElement(bi) * halfQ
	}
	return f
}

// ringCompressAndEncode4 appends Compress₄ then ByteEncode₄ (128 bytes).
func ringCompressAndEncode4(s []byte, f ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize4)
	for i := 0; i < n; i += 2 {
		b[i/2] = uint8(compress(f[i], 4) | compress(f[i+1], 4)<<4)
	}
	return s
}

// ringDecodeAndDecompress4 decodes ByteDecode₄ then Decompress₄ (128 bytes).
func ringDecodeAndDecompress4(b *[encodingSize4]byte) ringElement {
	var f ringElement
	for i := 0; i < n; i += 2 {
		f[i] = decompress(uint16(b[i/2]&0b1111), 4)
		f[i+1] = decompress(uint16(b[i/2]>>4), 4)
	}
	return f
}

// ringCompressAndEncode10 appends Compress₁₀ then ByteEncode₁₀ (320 bytes).
func ringCompressAndEncode10(s []byte, f ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize10)
	for i := 0; i < n; i += 4 {
		var x uint64
		x |= uint64(compress(f[i], 10))
		x |= uint64(compress(f[i+1], 10)) << 10
		x |= uint64(compress(f[i+2], 10)) << 20
		x |= uint64(compress(f[i+3], 10)) << 30
		b[0] = uint8(x)
		b[1] = uint8(x >> 8)
		b[2] = uint8(x >> 16)
		b[3] = uint8(x >> 24)
		b[4] = uint8(x >> 32)
		b = b[5:]
	}
	return s
}

// ringDecodeAndDecompress10 decodes ByteDecode₁₀ then Decompress₁₀ (320 bytes).
func ringDecodeAndDecompress10(bb *[encodingSize10]byte) ringElement {
	b := bb[:]
	var f ringElement
	for i := 0; i < n; i += 4 {
		x := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32
		b = b[5:]
		f[i] = decompress(uint16(x>>0&0b11_1111_1111), 10)
		f[i+1] = decompress(uint16(x>>10&0b11_1111_1111), 10)
		f[i+2] = decompress(uint16(x>>20&0b11_1111_1111), 10)
		f[i+3] = decompress(uint16(x>>30&0b11_1111_1111), 10)
	}
	return f
}

// gammas are ζ^(2·BitRev7(i)+1) mod q (FIPS 203, Appendix A).
var gammas = [128]fieldElement{17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175}

// nttMul multiplies two nttElements (FIPS 203, Algorithm 11).
func nttMul(f, g nttElement) nttElement {
	var h nttElement
	for i := 0; i < 256; i += 2 {
		a0, a1 := f[i], f[i+1]
		b0, b1 := g[i], g[i+1]
		h[i] = fieldAddMul(a0, b0, fieldMul(a1, b1), gammas[i/2])
		h[i+1] = fieldAddMul(a0, b1, a1, b0)
	}
	return h
}

// zetas are ζ^BitRev7(k) mod q (FIPS 203, Appendix A).
var zetas = [128]fieldElement{1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154}

// ntt maps a ringElement to its nttElement (FIPS 203, Algorithm 9).
func ntt(f ringElement) nttElement {
	kk := 1
	for length := 128; length >= 2; length /= 2 {
		for start := 0; start < 256; start += 2 * length {
			zeta := zetas[kk]
			kk++
			flo, fhi := f[start:start+length], f[start+length:start+length+length]
			for j := 0; j < length; j++ {
				t := fieldMul(zeta, fhi[j])
				fhi[j] = fieldSub(flo[j], t)
				flo[j] = fieldAdd(flo[j], t)
			}
		}
	}
	return nttElement(f)
}

// inverseNTT maps an nttElement back to its ringElement (FIPS 203, Algorithm 10).
func inverseNTT(f nttElement) ringElement {
	kk := 127
	for length := 2; length <= 128; length *= 2 {
		for start := 0; start < 256; start += 2 * length {
			zeta := zetas[kk]
			kk--
			flo, fhi := f[start:start+length], f[start+length:start+length+length]
			for j := 0; j < length; j++ {
				t := flo[j]
				flo[j] = fieldAdd(t, fhi[j])
				fhi[j] = fieldMulSub(zeta, fhi[j], t)
			}
		}
	}
	for i := range f {
		f[i] = fieldMul(f[i], 3303) // 128⁻¹ mod q
	}
	return ringElement(f)
}

// sampleNTT draws a uniform nttElement from XOF(rho‖i‖j) (FIPS 203, Algorithm 7).
func sampleNTT(rho []byte, ii, jj byte) nttElement {
	B := sha3.NewSHAKE128()
	B.Write(rho)
	B.Write([]byte{ii, jj})

	var a nttElement
	var j int
	var buf [24]byte
	off := len(buf)
	for {
		if off >= len(buf) {
			B.Read(buf[:])
			off = 0
		}
		d1 := binary.LittleEndian.Uint16(buf[off:]) & 0b1111_1111_1111
		d2 := binary.LittleEndian.Uint16(buf[off+1:]) >> 4
		off += 3
		if d1 < q {
			a[j] = fieldElement(d1)
			j++
		}
		if j >= len(a) {
			break
		}
		if d2 < q {
			a[j] = fieldElement(d2)
			j++
		}
		if j >= len(a) {
			break
		}
	}
	return a
}

// samplePolyCBD draws a ringElement from the CBD η=2 distribution given a PRF
// stream (FIPS 203, Algorithm 8 / Definition 4.3).
func samplePolyCBD(s []byte, b byte) ringElement {
	prf := sha3.NewSHAKE256()
	prf.Write(s)
	prf.Write([]byte{b})
	B := make([]byte, 64*2) // η = 2
	prf.Read(B)

	var f ringElement
	for i := 0; i < n; i += 2 {
		b := B[i/2]
		b7, b6, b5, b4 := b>>7, b>>6&1, b>>5&1, b>>4&1
		b3, b2, b1, b0 := b>>3&1, b>>2&1, b>>1&1, b&1
		f[i] = fieldSub(fieldElement(b0+b1), fieldElement(b2+b3))
		f[i+1] = fieldSub(fieldElement(b4+b5), fieldElement(b6+b7))
	}
	return f
}
