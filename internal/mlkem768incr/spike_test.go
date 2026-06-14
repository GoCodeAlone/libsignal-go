// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package mlkem768incr

import (
	"bytes"
	stdmlkem "crypto/mlkem"
	"testing"
)

// TestSpike1MatchesStdlibEncapsulationKey is the cheap PKE-correctness gate
// (ADR 0003 oracle 1): from a fixed 64-byte seed, this package's expanded
// encapsulation-key bytes must equal Go stdlib crypto/mlkem's FIPS-203
// ML-KEM-768 output. A mismatch means the field/NTT/sample/keygen port diverges
// from FIPS-203 and the incremental layer must not be built on it yet.
func TestSpike1MatchesStdlibEncapsulationKey(t *testing.T) {
	var seed [SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	mine, err := NewDecapsulationKey768(seed[:])
	if err != nil {
		t.Fatalf("NewDecapsulationKey768: %v", err)
	}
	std, err := stdmlkem.NewDecapsulationKey768(seed[:])
	if err != nil {
		t.Fatalf("stdlib NewDecapsulationKey768: %v", err)
	}

	mineEK := mine.EncapsulationKey().Bytes()
	stdEK := std.EncapsulationKey().Bytes()
	if len(mineEK) != EncapsulationKeySize768 {
		t.Fatalf("ek length = %d, want %d", len(mineEK), EncapsulationKeySize768)
	}
	if !bytes.Equal(mineEK, stdEK) {
		// Locate the first divergence to aid debugging the PKE port.
		for i := range mineEK {
			if mineEK[i] != stdEK[i] {
				t.Fatalf("encapsulation key diverges from stdlib at byte %d: mine=0x%02x std=0x%02x", i, mineEK[i], stdEK[i])
			}
		}
		t.Fatal("encapsulation key length/content mismatch vs stdlib")
	}
}

// TestSpike1EncapsDecapsVsStdlib checks the full FIPS-203 path cross-impl: my
// derandomized encaps against stdlib's parsed key must yield a ciphertext stdlib
// decapsulates to the same shared secret, and my Decapsulate must recover it
// too. (Derandomized so the m is fixed; production Encapsulate draws m randomly.)
func TestSpike1EncapsDecapsVsStdlib(t *testing.T) {
	var seed [SeedSize]byte
	for i := range seed {
		seed[i] = byte(0x40 + i)
	}
	mine, err := NewDecapsulationKey768(seed[:])
	if err != nil {
		t.Fatalf("NewDecapsulationKey768: %v", err)
	}
	std, err := stdmlkem.NewDecapsulationKey768(seed[:])
	if err != nil {
		t.Fatalf("stdlib NewDecapsulationKey768: %v", err)
	}

	var m [messageBytes]byte
	for i := range m {
		m[i] = byte(0x80 + i)
	}
	ss, ct := mine.EncapsulationKey().EncapsulateInternal(&m)
	if len(ss) != SharedKeySize || len(ct) != CiphertextSize768 {
		t.Fatalf("encaps sizes ss=%d ct=%d", len(ss), len(ct))
	}

	// stdlib decapsulates my ciphertext to the same shared secret.
	stdSS, err := std.Decapsulate(ct)
	if err != nil {
		t.Fatalf("stdlib Decapsulate: %v", err)
	}
	if !bytes.Equal(ss, stdSS) {
		t.Fatalf("stdlib decaps ss != my encaps ss\n mine %x\n std  %x", ss, stdSS)
	}

	// My Decapsulate recovers it too (self-consistency).
	mineSS, err := mine.Decapsulate(ct)
	if err != nil {
		t.Fatalf("my Decapsulate: %v", err)
	}
	if !bytes.Equal(ss, mineSS) {
		t.Fatalf("my decaps ss != my encaps ss\n encaps %x\n decaps %x", ss, mineSS)
	}
}
