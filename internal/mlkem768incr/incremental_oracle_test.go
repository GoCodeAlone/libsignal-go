// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package mlkem768incr

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Oracle 3: byte-exact incremental ML-KEM-768 KATs generated from libcrux 0.0.8
// (the KEM SPQR uses), via the Rust compat harness:
//
//	compat/rust-harness $ cargo build --release
//	./target/release/rust-harness gen-vectors mlkem-incremental \
//	    > internal/mlkem768incr/testdata/libcrux_incremental_mlkem768.json
//
// Each case pins the full incremental flow — keygen split (pk1/pk2/dk), two-phase
// encapsulation (ct1, EncapsState, ct2, shared secret), and decapsulation — to
// libcrux's exact bytes. `encaps_state` is the raw state from the harness host's
// libcrux backend; `encaps_state_fixed` is the issue-1275-normalized state (equal
// to `encaps_state` on a portable-backend host, which is what the harness uses).

type incrCase struct {
	Seed              string `json:"seed"`
	Message           string `json:"message"`
	PK1               string `json:"pk1"`
	PK2               string `json:"pk2"`
	DK                string `json:"dk"`
	CT1               string `json:"ct1"`
	CT2               string `json:"ct2"`
	EncapsState       string `json:"encaps_state"`
	EncapsStateFixed  string `json:"encaps_state_fixed"`
	SharedSecret      string `json:"shared_secret"`
	DecapsulatedMatch bool   `json:"decapsulated_matches"`
}

type incrVectors struct {
	Domain string     `json:"domain"`
	Seed   string     `json:"seed"`
	Cases  []incrCase `json:"cases"`
}

func loadIncrVectors(t *testing.T) *incrVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/libcrux_incremental_mlkem768.json")
	if err != nil {
		t.Fatalf("read libcrux incremental vectors: %v", err)
	}
	var v incrVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode libcrux incremental vectors: %v", err)
	}
	if v.Domain != "mlkem-incremental" {
		t.Fatalf("unexpected domain %q", v.Domain)
	}
	if len(v.Cases) == 0 {
		t.Fatal("no incremental vectors")
	}
	return &v
}

func unhexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// TestIncrementalOracleKeyGen pins the keygen split: GenerateIncrementalKey must
// reproduce libcrux's pk1 (ρ‖H), pk2 (ByteEncode₁₂ t̂), and 2400-byte expanded dk
// byte-for-byte, and the two parts must validate together.
func TestIncrementalOracleKeyGen(t *testing.T) {
	v := loadIncrVectors(t)
	for i, c := range v.Cases {
		key, err := GenerateIncrementalKey(unhexT(t, c.Seed))
		if err != nil {
			t.Fatalf("case %d: GenerateIncrementalKey: %v", i, err)
		}
		if !bytes.Equal(key.PK1, unhexT(t, c.PK1)) {
			t.Fatalf("case %d: pk1 mismatch vs libcrux", i)
		}
		if !bytes.Equal(key.PK2, unhexT(t, c.PK2)) {
			t.Fatalf("case %d: pk2 mismatch vs libcrux", i)
		}
		if !bytes.Equal(key.DK, unhexT(t, c.DK)) {
			t.Fatalf("case %d: dk mismatch vs libcrux", i)
		}
		if err := ValidatePublicKeyParts(key.PK1, key.PK2); err != nil {
			t.Fatalf("case %d: ValidatePublicKeyParts: %v", i, err)
		}
	}
	t.Logf("incremental keygen: %d cases match libcrux byte-for-byte", len(v.Cases))
}

// TestIncrementalOracleEncaps pins the two-phase encapsulation: phase 1 must
// reproduce ct1, the shared secret, and the EncapsState (compared against the
// 1275-normalized state); phase 2 must reproduce ct2.
func TestIncrementalOracleEncaps(t *testing.T) {
	v := loadIncrVectors(t)
	for i, c := range v.Cases {
		pk1 := unhexT(t, c.PK1)
		pk2 := unhexT(t, c.PK2)
		m := (*[messageBytes]byte)(unhexT(t, c.Message))

		res, err := Encapsulate1Internal(pk1, m)
		if err != nil {
			t.Fatalf("case %d: Encapsulate1Internal: %v", i, err)
		}
		if !bytes.Equal(res.Ciphertext1, unhexT(t, c.CT1)) {
			t.Fatalf("case %d: ct1 mismatch vs libcrux", i)
		}
		if !bytes.Equal(res.SharedSecret, unhexT(t, c.SharedSecret)) {
			t.Fatalf("case %d: shared secret mismatch vs libcrux", i)
		}
		if !bytes.Equal(res.EncapsState, unhexT(t, c.EncapsStateFixed)) {
			t.Fatalf("case %d: encaps state mismatch vs libcrux (1275-normalized)", i)
		}

		// The 1275 detector applied to the raw libcrux state must yield the
		// normalized state. On the portable-backend fixture raw == fixed, so this
		// is the idempotent (no-flip) case; the actual byte-swap repair is
		// exercised by TestFixEncapsStateEndianness's hand-crafted vector.
		fixedRaw, err := FixEncapsStateEndianness(unhexT(t, c.EncapsState))
		if err != nil {
			t.Fatalf("case %d: FixEncapsStateEndianness(raw): %v", i, err)
		}
		if !bytes.Equal(fixedRaw, unhexT(t, c.EncapsStateFixed)) {
			t.Fatalf("case %d: fix(raw) != fixed", i)
		}

		ct2, err := Encapsulate2(unhexT(t, c.EncapsStateFixed), pk2)
		if err != nil {
			t.Fatalf("case %d: Encapsulate2: %v", i, err)
		}
		if !bytes.Equal(ct2, unhexT(t, c.CT2)) {
			t.Fatalf("case %d: ct2 mismatch vs libcrux", i)
		}
	}
	t.Logf("incremental encaps: %d cases match libcrux byte-for-byte", len(v.Cases))
}

// TestIncrementalOracleDecaps pins decapsulation: the standard FIPS-203 decaps
// over the reassembled ct1‖ct2 against the 2400-byte dk must recover the same
// shared secret libcrux's encapsulation produced.
func TestIncrementalOracleDecaps(t *testing.T) {
	v := loadIncrVectors(t)
	for i, c := range v.Cases {
		if !c.DecapsulatedMatch {
			t.Fatalf("case %d: libcrux reported a decapsulation mismatch", i)
		}
		ss, err := DecapsulateCompressedKey(
			unhexT(t, c.DK), unhexT(t, c.CT1), unhexT(t, c.CT2),
		)
		if err != nil {
			t.Fatalf("case %d: DecapsulateCompressedKey: %v", i, err)
		}
		if !bytes.Equal(ss, unhexT(t, c.SharedSecret)) {
			t.Fatalf("case %d: decapsulated shared secret mismatch vs libcrux", i)
		}
	}
	t.Logf("incremental decaps: %d cases recover the encaps shared secret", len(v.Cases))
}

// TestIncrementalEndToEnd exercises the full pure-Go incremental round-trip with
// no fixture: keygen → encaps1 → encaps2 → decaps must agree on the shared
// secret, independent of the byte-exactness oracle.
func TestIncrementalEndToEnd(t *testing.T) {
	v := loadIncrVectors(t)
	for i, c := range v.Cases {
		key, err := GenerateIncrementalKey(unhexT(t, c.Seed))
		if err != nil {
			t.Fatalf("case %d: keygen: %v", i, err)
		}
		m := (*[messageBytes]byte)(unhexT(t, c.Message))
		res, err := Encapsulate1Internal(key.PK1, m)
		if err != nil {
			t.Fatalf("case %d: encaps1: %v", i, err)
		}
		ct2, err := Encapsulate2(res.EncapsState, key.PK2)
		if err != nil {
			t.Fatalf("case %d: encaps2: %v", i, err)
		}
		ss, err := DecapsulateCompressedKey(key.DK, res.Ciphertext1, ct2)
		if err != nil {
			t.Fatalf("case %d: decaps: %v", i, err)
		}
		if !bytes.Equal(ss, res.SharedSecret) {
			t.Fatalf("case %d: round-trip shared secret disagreement", i)
		}
	}
}

// TestFixEncapsStateEndianness covers the issue-1275 detect-and-flip directly.
//
// LOAD-BEARING — do not delete thinking the oracle fixture covers this. The
// committed fixture is generated on libcrux's PORTABLE backend (the harness
// disables simd128/simd256), so its raw `encaps_state` is already correct
// little-endian and equals `encaps_state_fixed`. The detect+fix(raw)==fixed
// assertion in TestIncrementalOracleEncaps is therefore the host-PORTABLE case:
// fix() is an idempotent no-op there and never runs the flip branch. The ONLY
// thing that exercises the actual byte-swap repair on a portable host is the
// hand-crafted swapped state below. (On a SIMD-backend host the fixture's raw
// field would be swapped and the oracle would also exercise the flip — but CI
// must not depend on that.)
//
// A hand-crafted byte-swapped state must be repaired back to the correct one; a
// correct state must pass through unchanged and still drive a working
// Encapsulate2.
func TestFixEncapsStateEndianness(t *testing.T) {
	v := loadIncrVectors(t)
	c := v.Cases[0]
	good := unhexT(t, c.EncapsStateFixed)

	// A correct state is returned unchanged and decapsulation still round-trips.
	fixedGood, err := FixEncapsStateEndianness(good)
	if err != nil {
		t.Fatalf("fix(good): %v", err)
	}
	if !bytes.Equal(fixedGood, good) {
		t.Fatal("fix(good) altered a correct state")
	}

	// Build the swapped (buggy-SIMD) image: swap every int16 byte pair in the
	// polynomial region [0:len-32], leaving the trailing 32 random bytes intact.
	swapped := make([]byte, len(good))
	copy(swapped, good)
	for i := 0; i+1 < EncapsStateSize-messageSize; i += 2 {
		swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
	}
	if bytes.Equal(swapped, good) {
		// Only possible if every polynomial int16 were a byte-palindrome; with
		// 1024 coefficients that is astronomically unlikely for a real state.
		t.Fatal("swapped state identical to good — cannot exercise the flip")
	}

	repaired, err := FixEncapsStateEndianness(swapped)
	if err != nil {
		t.Fatalf("fix(swapped): %v", err)
	}
	if !bytes.Equal(repaired, good) {
		t.Fatal("fix(swapped) did not recover the correct state")
	}

	// The repaired state must drive the same ct2 as the good state.
	pk2 := unhexT(t, c.PK2)
	ct2Good, err := Encapsulate2(good, pk2)
	if err != nil {
		t.Fatalf("encaps2(good): %v", err)
	}
	ct2Swapped, err := Encapsulate2(swapped, pk2)
	if err != nil {
		t.Fatalf("encaps2(swapped): %v", err)
	}
	if !bytes.Equal(ct2Good, ct2Swapped) {
		t.Fatal("Encapsulate2 did not repair a swapped state before use")
	}
	if !bytes.Equal(ct2Good, unhexT(t, c.CT2)) {
		t.Fatal("ct2 from good state mismatch vs libcrux")
	}
}

// TestEncapsStateLayout is a guard on the EncapsState byte boundaries: the e₂
// region the 1275 detector inspects must start at exactly k*512 and the trailing
// 32 bytes must be the message (never flipped).
func TestEncapsStateLayout(t *testing.T) {
	if EncapsStateSize != 2080 {
		t.Fatalf("EncapsStateSize = %d, want 2080", EncapsStateSize)
	}
	v := loadIncrVectors(t)
	c := v.Cases[0]
	state := unhexT(t, c.EncapsStateFixed)
	// The trailing 32 bytes of the state equal the message m.
	if !bytes.Equal(state[EncapsStateSize-messageSize:], unhexT(t, c.Message)) {
		t.Fatal("EncapsState trailing 32 bytes are not the message m")
	}
	// e₂ region: all coefficients in [-2,2] (CBD η2), as the 1275 detector relies on.
	for i := k * rawPolyI16Size; i+1 < EncapsStateSize-messageSize; i += 2 {
		val := int16(binary.LittleEndian.Uint16(state[i : i+2]))
		if val < -2 || val > 2 {
			t.Fatalf("e₂ coefficient %d out of CBD range: %d", (i-k*rawPolyI16Size)/2, val)
		}
	}
}
