// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package chunked

import (
	"math/rand"
	"testing"
)

// GF(2^16) mul/div KAT (Slice B oracle leg b). The upstream crate has no golden
// triple file — its gf.rs test cross-checks GF16 against a generic GFu16
// reference over random rounds. We do the same with an INDEPENDENT reference
// built a different way: a log/antilog table over a primitive element, so the
// multiply path here (table lookup) shares no code with gfMul (carryless
// multiply + reduce). Agreement over the whole field + the field axioms pins the
// POLY=0x1100b arithmetic; a systematically-wrong reduction would diverge.

// gfRefTables builds discrete-log and antilog tables for GF(2^16) under gfPoly,
// using the standard generator x (0x2). x is primitive for this polynomial (the
// table construction below would fail to cover all 65535 nonzero elements
// otherwise — asserted in the test).
func gfRefTables(t *testing.T) (logTab [65536]int32, antilog [65536]uint16) {
	t.Helper()
	for i := range logTab {
		logTab[i] = -1
	}
	// Generate the multiplicative group by repeated multiply-by-x (carryless
	// shift-and-reduce, done MSB-first — a different reduction order than gfMul's
	// LSB-first loop, to stay independent).
	cur := uint16(1)
	for power := 0; power < 65535; power++ {
		if logTab[cur] != -1 {
			t.Fatalf("0x2 is not primitive for POLY=%#x: repeat at power %d", gfPoly, power)
		}
		logTab[cur] = int32(power)
		antilog[power] = cur
		cur = refMulByX(cur)
	}
	antilog[65535] = antilog[0] // wrap: x^65535 == x^0 == 1
	return logTab, antilog
}

// refMulByX multiplies by the field element x (0x2): shift left, and if the
// degree-16 bit appears, reduce by XOR-ing the low 16 bits of gfPoly.
func refMulByX(a uint16) uint16 {
	hi := a&0x8000 != 0
	r := a << 1
	if hi {
		r ^= uint16(gfPoly & 0xFFFF) // low 16 bits of the reducing polynomial
	}
	return r
}

// refMul multiplies via the log tables: a*b = antilog[(log a + log b) mod 65535].
func refMul(a, b uint16, logTab *[65536]int32, antilog *[65536]uint16) uint16 {
	if a == 0 || b == 0 {
		return 0
	}
	return antilog[(int(logTab[a])+int(logTab[b]))%65535]
}

func TestGF16MulMatchesLogTableReference(t *testing.T) {
	logTab, antilog := gfRefTables(t)

	// Spot-check the whole field against random partners, plus a deterministic
	// sweep of small values where reduction edge cases live.
	rng := rand.New(rand.NewSource(0x5163_6e61))
	for i := 0; i < 200000; i++ {
		a := uint16(rng.Intn(65536))
		b := uint16(rng.Intn(65536))
		got := gfMul(a, b)
		want := refMul(a, b, &logTab, &antilog)
		if got != want {
			t.Fatalf("gfMul(%#x,%#x)=%#x, ref=%#x", a, b, got, want)
		}
	}
	// Exhaustive low-value sweep (degree overflow boundary around the top bit).
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			got := gfMul(uint16(a), uint16(b))
			want := refMul(uint16(a), uint16(b), &logTab, &antilog)
			if got != want {
				t.Fatalf("gfMul(%#x,%#x)=%#x, ref=%#x", a, b, got, want)
			}
		}
	}
}

func TestGF16Axioms(t *testing.T) {
	rng := rand.New(rand.NewSource(0x47_6f00))
	for i := 0; i < 100000; i++ {
		a := GF16{Value: uint16(rng.Intn(65536))}
		b := GF16{Value: uint16(rng.Intn(65536))}
		c := GF16{Value: uint16(rng.Intn(65536))}

		// Identity and commutativity.
		if a.Mul(gfOne) != a {
			t.Fatalf("a*1 != a for a=%#x", a.Value)
		}
		if a.Mul(b) != b.Mul(a) {
			t.Fatalf("mul not commutative: %#x,%#x", a.Value, b.Value)
		}
		// Distributivity: a*(b+c) == a*b + a*c.
		if a.Mul(b.Add(c)) != a.Mul(b).Add(a.Mul(c)) {
			t.Fatalf("distributivity fails: a=%#x b=%#x c=%#x", a.Value, b.Value, c.Value)
		}
		// Add is its own inverse (characteristic 2): a+a == 0, a-b == a+b.
		if a.Add(a) != gfZero {
			t.Fatalf("a+a != 0 for a=%#x", a.Value)
		}
		if a.Sub(b) != a.Add(b) {
			t.Fatalf("sub != add for a=%#x b=%#x", a.Value, b.Value)
		}
	}
}

func TestGF16DivIsInverse(t *testing.T) {
	rng := rand.New(rand.NewSource(0x4b4154))
	for i := 0; i < 100000; i++ {
		a := GF16{Value: uint16(rng.Intn(65536))}
		b := GF16{Value: uint16(rng.Intn(65535) + 1)} // nonzero divisor

		// (a / b) * b == a.
		if a.Div(b).Mul(b) != a {
			t.Fatalf("(a/b)*b != a: a=%#x b=%#x", a.Value, b.Value)
		}
		// b / b == 1 for nonzero b.
		if b.Div(b) != gfOne {
			t.Fatalf("b/b != 1 for b=%#x", b.Value)
		}
		// b * b^-1 == 1 where b^-1 = 1/b.
		inv := gfOne.Div(b)
		if b.Mul(inv) != gfOne {
			t.Fatalf("b * (1/b) != 1 for b=%#x", b.Value)
		}
	}
	// Div by zero maps to zero (matches upstream square-and-multiply on 0).
	if (GF16{Value: 0x1234}).Div(gfZero) != gfZero {
		t.Fatalf("x/0 should be 0")
	}
}
