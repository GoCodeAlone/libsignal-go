// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// GF(2^16) field arithmetic for the SPQR chunked-transport erasure code, ported
// from SparsePostQuantumRatchet v1.5.1 src/encoding/gf.rs. The field is GF(2^16)
// with reducing polynomial POLY = 0x1100b (x^16 + x^12 + x^3 + x + 1). Addition
// and subtraction are XOR; multiplication is a carryless (polynomial) multiply
// reduced modulo POLY; division is multiplication by the Fermat inverse
// a^(2^16-2).
//
// The upstream crate multiplexes multiplication over a carryless-multiply SIMD
// path (pclmulqdq / pmull) and a portable long-multiplication path; both compute
// the SAME field product (unlike the KEM's EncapsState i16 serialization, there
// is no backend-dependent byte difference here — carryless multiply is exact).
// We port the portable math; the GF16 mul/div KAT in gf_test.go pins it against
// the upstream reference.

// Package chunked implements the SPQR chunked-transport erasure code: a
// GF(2^16) Reed-Solomon-style fountain code (gf.go + polynomial.go) that ships a
// message as a stream of fixed 32-byte chunks reconstructible from any
// sufficient subset. It is a byte-exact pure-Go port of
// SparsePostQuantumRatchet v1.5.1 src/encoding/.
package chunked

// gfPoly is the reducing polynomial for GF(2^16): x^16 + x^12 + x^3 + x + 1.
// (https://web.eecs.utk.edu/~jplank/plank/papers/CS-07-593/primitive-polynomial-table.txt)
const gfPoly uint32 = 0x1100b

// GF16 is an element of GF(2^16). Addition is XOR; multiplication is carryless
// multiply reduced mod gfPoly.
type GF16 struct {
	Value uint16
}

// gfZero and gfOne are the additive and multiplicative identities.
var (
	gfZero = GF16{Value: 0}
	gfOne  = GF16{Value: 1}
)

// NewGF16 wraps a raw 16-bit value as a field element.
func NewGF16(v uint16) GF16 { return GF16{Value: v} }

// Add returns a + b in GF(2^16), which is bitwise XOR.
func (a GF16) Add(b GF16) GF16 { return GF16{Value: a.Value ^ b.Value} }

// Sub returns a - b in GF(2^16); in characteristic 2 subtraction equals
// addition (XOR).
func (a GF16) Sub(b GF16) GF16 { return GF16{Value: a.Value ^ b.Value} }

// Mul returns a * b in GF(2^16): the carryless product reduced mod gfPoly.
func (a GF16) Mul(b GF16) GF16 { return GF16{Value: gfMul(a.Value, b.Value)} }

// Div returns a / b in GF(2^16) = a * b^(2^16-2) (Fermat inverse). Dividing by
// zero yields zero (matching the upstream square-and-multiply, which maps 0→0).
func (a GF16) Div(b GF16) GF16 { return GF16{Value: gfDiv(a.Value, b.Value)} }

// gfMul is the carryless (polynomial) multiply of a and b over GF(2), reduced
// mod gfPoly. Mirrors gf.rs unaccelerated::mul = poly_reduce(poly_mul(a, b)).
func gfMul(a, b uint16) uint16 {
	return gfReduce(polyMul(a, b))
}

// polyMul is carryless long multiplication: for each set bit i of b, XOR a<<i
// into the accumulator. The result is up to 31 bits wide. Mirrors gf.rs
// unaccelerated::poly_mul.
func polyMul(a, b uint16) uint32 {
	var acc uint32
	av := uint32(a)
	for shift := uint(0); shift < 16; shift++ {
		if b&(1<<shift) != 0 {
			acc ^= av << shift
		}
	}
	return acc
}

// gfReduce reduces a carryless product (up to 31 bits) modulo gfPoly into a
// 16-bit field element. Walking from the highest set bit down to bit 16, each
// set bit i (i >= 16) is cleared by XOR-ing gfPoly << (i-16) (gfPoly's top bit
// is 1<<16). Mirrors gf.rs reduce::poly_reduce (we use the straightforward
// bit-by-bit form; the upstream byte-table is a speed optimization with
// identical output, pinned by the KAT).
func gfReduce(v uint32) uint16 {
	for bit := 31; bit >= 16; bit-- {
		if v&(1<<uint(bit)) != 0 {
			v ^= gfPoly << uint(bit-16)
		}
	}
	return uint16(v)
}

// gfDiv computes a / b = a * b^(2^16-2). In GF(2^16) the multiplicative group
// has order 2^16-1, so b^(2^16-2) = b^-1. Implemented as the upstream
// square-and-multiply: 15 iterations accumulating b^(2^16-2) into out while
// squaring. Mirrors gf.rs GF16::div_impl.
func gfDiv(a, b uint16) uint16 {
	square := gfMul(b, b) // b^2
	out := a              // out starts at a (= a * b^1 of the running product)
	for i := 1; i < 16; i++ {
		// out *= square; square *= square
		out = gfMul(square, out)
		square = gfMul(square, square)
	}
	return out
}
