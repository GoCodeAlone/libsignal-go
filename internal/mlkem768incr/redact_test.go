// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package mlkem768incr

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// TestDecapsulationKeyRedaction is the secret-leak gate for the decapsulation
// key (the project's String()+Format() convention; cf. curve.PrivateKey,
// kem.SecretKey, ratchet.{ChainKey,RootKey,MessageKeys}). The key holds the
// keygen seed d (which regenerates the WHOLE key), the implicit-rejection
// secret z, and the secret vector ŝ — none of these may ever reach a log under
// any fmt verb. Both the value and the pointer must redact.
func TestDecapsulationKeyRedaction(t *testing.T) {
	// A seed whose bytes are easy to spot in any leak (d = 0x11.. , z = 0x22..).
	var seed [SeedSize]byte
	for i := 0; i < 32; i++ {
		seed[i] = 0x11
		seed[32+i] = 0x22
	}
	dk, err := NewDecapsulationKey768(seed[:])
	if err != nil {
		t.Fatalf("NewDecapsulationKey768: %v", err)
	}

	// The secret material that must NOT appear in any formatted output.
	dHex := hex.EncodeToString(dk.d[:])
	zHex := hex.EncodeToString(dk.z[:])
	var sBytes []byte
	for i := range dk.s {
		sBytes = polyByteEncode(sBytes, dk.s[i])
	}
	sHex := hex.EncodeToString(sBytes)
	secrets := map[string]string{"d (seed)": dHex, "z (reject)": zHex, "ŝ (secret vec)": sHex}

	verbs := []string{"%v", "%+v", "%#v", "%s", "%x", "%X"}
	for _, verb := range verbs {
		for _, target := range []struct {
			name string
			val  any
		}{
			{"value", dk0(t, seed)}, // value, not pointer
			{"pointer", dk},
		} {
			out := fmt.Sprintf(verb, target.val)
			lower := strings.ToLower(out)
			for name, secret := range secrets {
				if strings.Contains(lower, secret) {
					t.Errorf("%s on %s leaked %s: %q", verb, target.name, name, out)
				}
			}
			if !strings.Contains(out, "[redacted]") {
				t.Errorf("%s on %s did not redact: %q", verb, target.name, out)
			}
		}
	}
}

// dk0 builds a fresh DecapsulationKey768 *value* (not a pointer) from a seed, so
// the test exercises value-copy redaction (a pointer-receiver String() would
// leave a value copy leaking under %v/%#v).
func dk0(t *testing.T, seed [SeedSize]byte) DecapsulationKey768 {
	t.Helper()
	dk, err := NewDecapsulationKey768(seed[:])
	if err != nil {
		t.Fatalf("NewDecapsulationKey768: %v", err)
	}
	return *dk
}

// TestEncapsulationKeyNotRedacted guards the converse: the encapsulation key is
// PUBLIC and must NOT be redacted (so it remains printable/debuggable). It has
// no String/Format override, so %v renders the struct normally.
func TestEncapsulationKeyNotRedacted(t *testing.T) {
	var seed [SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	dk, err := NewDecapsulationKey768(seed[:])
	if err != nil {
		t.Fatalf("NewDecapsulationKey768: %v", err)
	}
	out := fmt.Sprintf("%v", dk.EncapsulationKey())
	if strings.Contains(out, "[redacted]") {
		t.Errorf("public EncapsulationKey768 should not be redacted: %q", out)
	}
}
