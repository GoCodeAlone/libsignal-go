// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package mlkem768incr

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// acvpVectors mirrors testdata/acvp_mlkem768.json — the NIST ACVP-Server
// FIPS-203 ML-KEM-768 known-answer vectors (oracle 2 per ADR 0003). This is the
// independent intermediate-byte oracle: unlike the stdlib end-to-end check
// (which compares only the final shared secret and could mask a compensating
// pair of byte-level PKE bugs), these vectors pin the encapsulation-key bytes,
// the ciphertext compression bytes, and the shared secret against a spec-blessed
// reference that is independent of both stdlib and this implementation.
type acvpVectors struct {
	Note   string `json:"note"`
	KeyGen []struct {
		TcID int    `json:"tcId"`
		D    string `json:"d"`
		Z    string `json:"z"`
		EK   string `json:"ek"`
		DK   string `json:"dk"`
	} `json:"keyGen"`
	Encaps []struct {
		TcID int    `json:"tcId"`
		EK   string `json:"ek"`
		M    string `json:"m"`
		C    string `json:"c"`
		K    string `json:"k"`
	} `json:"encaps"`
	Decaps struct {
		DK    string `json:"dk"`
		Tests []struct {
			TcID int    `json:"tcId"`
			C    string `json:"c"`
			K    string `json:"k"`
		} `json:"tests"`
	} `json:"decaps"`
}

func loadACVP(t *testing.T) *acvpVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/acvp_mlkem768.json")
	if err != nil {
		t.Fatalf("read ACVP fixture: %v", err)
	}
	var v acvpVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode ACVP fixture: %v", err)
	}
	return &v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// decapsulationKeySize768 is the NIST expanded decapsulation-key encoding:
// ByteEncode₁₂(ŝ) ‖ ek(1184) ‖ H(ek)(32) ‖ z(32).
const decapsulationKeySize768 = k*encodingSize12 + EncapsulationKeySize768 + 32 + 32 // 2400

// parseExpandedNISTDecapsulationKey parses the NIST ACVP expanded dk format.
// Test-only: production keys use the 64-byte seed (NewDecapsulationKey768); this
// exists solely to drive the ACVP decapsulation-VAL vectors, which ship the
// expanded key. Mirrors stdlib's TestingOnlyNewDecapsulationKey768.
func parseExpandedNISTDecapsulationKey(t *testing.T, b []byte) *DecapsulationKey768 {
	t.Helper()
	if len(b) != decapsulationKeySize768 {
		t.Fatalf("expanded dk length = %d, want %d", len(b), decapsulationKeySize768)
	}
	dk := &DecapsulationKey768{}
	rest := b
	for i := range dk.s {
		s, err := polyByteDecode[nttElement](rest[:encodingSize12])
		if err != nil {
			t.Fatalf("decode ŝ[%d]: %v", i, err)
		}
		dk.s[i] = s
		rest = rest[encodingSize12:]
	}
	ek, err := NewEncapsulationKey768(rest[:EncapsulationKeySize768])
	if err != nil {
		t.Fatalf("parse embedded ek: %v", err)
	}
	dk.rho = ek.rho
	dk.h = ek.h
	dk.encryptionKey = ek.encryptionKey
	rest = rest[EncapsulationKeySize768:]
	if !bytes.Equal(dk.h[:], rest[:32]) {
		t.Fatal("expanded dk: H(ek) does not match recomputed hash")
	}
	rest = rest[32:]
	copy(dk.z[:], rest)
	return dk
}

// TestACVPKeyGen checks that keygen from the NIST (d, z) seed reproduces the
// expected encapsulation-key bytes (and that the expanded dk's embedded ek +
// H(ek) are consistent). This pins the ByteEncode₁₂(t̂)‖ρ encoding and the
// H(ek) computation against the NIST reference.
func TestACVPKeyGen(t *testing.T) {
	v := loadACVP(t)
	if len(v.KeyGen) == 0 {
		t.Fatal("no keyGen vectors")
	}
	for _, tc := range v.KeyGen {
		seed := append(append([]byte{}, unhex(t, tc.D)...), unhex(t, tc.Z)...)
		dk, err := NewDecapsulationKey768(seed)
		if err != nil {
			t.Fatalf("tc %d: NewDecapsulationKey768: %v", tc.TcID, err)
		}
		gotEK := dk.EncapsulationKey().Bytes()
		if !bytes.Equal(gotEK, unhex(t, tc.EK)) {
			t.Fatalf("tc %d: ek bytes mismatch vs NIST ACVP", tc.TcID)
		}
		// The expanded NIST dk must parse and round-trip its embedded ek/H(ek).
		parseExpandedNISTDecapsulationKey(t, unhex(t, tc.DK))
	}
	t.Logf("ACVP keyGen: %d ML-KEM-768 cases match NIST byte-for-byte", len(v.KeyGen))
}

// TestACVPEncaps checks deterministic encapsulation: (ek, m) → (c, k) must match
// the NIST reference byte-for-byte. This pins the ciphertext compression
// (Compress₁₀(u) ‖ Compress₄(v)) and the shared-secret derivation.
func TestACVPEncaps(t *testing.T) {
	v := loadACVP(t)
	if len(v.Encaps) == 0 {
		t.Fatal("no encaps vectors")
	}
	for _, tc := range v.Encaps {
		ek, err := NewEncapsulationKey768(unhex(t, tc.EK))
		if err != nil {
			t.Fatalf("tc %d: NewEncapsulationKey768: %v", tc.TcID, err)
		}
		m := (*[messageBytes]byte)(unhex(t, tc.M))
		ss, ct := ek.EncapsulateInternal(m)
		if !bytes.Equal(ct, unhex(t, tc.C)) {
			t.Fatalf("tc %d: ciphertext mismatch vs NIST ACVP", tc.TcID)
		}
		if !bytes.Equal(ss, unhex(t, tc.K)) {
			t.Fatalf("tc %d: shared secret mismatch vs NIST ACVP", tc.TcID)
		}
	}
	t.Logf("ACVP encaps: %d ML-KEM-768 cases match NIST byte-for-byte", len(v.Encaps))
}

// TestACVPDecaps checks decapsulation (incl. implicit rejection): (dk, c) → k
// must match the NIST reference. The dk is the NIST expanded form; some VAL
// vectors carry deliberately malformed ciphertexts whose expected k is the
// implicit-rejection value, exercising the constant-time reject path.
func TestACVPDecaps(t *testing.T) {
	v := loadACVP(t)
	if len(v.Decaps.Tests) == 0 {
		t.Fatal("no decaps vectors")
	}
	dk := parseExpandedNISTDecapsulationKey(t, unhex(t, v.Decaps.DK))
	for _, tc := range v.Decaps.Tests {
		k, err := dk.Decapsulate(unhex(t, tc.C))
		if err != nil {
			t.Fatalf("tc %d: Decapsulate: %v", tc.TcID, err)
		}
		if !bytes.Equal(k, unhex(t, tc.K)) {
			t.Fatalf("tc %d: shared secret mismatch vs NIST ACVP (implicit-reject path?)", tc.TcID)
		}
	}
	t.Logf("ACVP decaps: %d ML-KEM-768 cases match NIST byte-for-byte", len(v.Decaps.Tests))
}
