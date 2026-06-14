// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package ratchet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/curve"
)

// hkdfVectors mirrors compat/vectors/hkdf.json, the committed upstream-generated
// key-derivation vectors (4 sub-domains x 24 cases). These tests are the real
// home of the derivations the compat package previously checked with an inline
// oracle; ratchet/ now owns them and compat consumes ratchet/ exports.
type hkdfVectors struct {
	Subdomains struct {
		ChainKey []struct {
			ChainKey     string `json:"chain_key"`
			NextChainKey string `json:"next_chain_key"`
		} `json:"chain-key"`
		MessageKeys []struct {
			ChainKey  string `json:"chain_key"`
			CipherKey string `json:"cipher_key"`
			MacKey    string `json:"mac_key"`
			IV        string `json:"iv"`
		} `json:"message-keys"`
		RootKey []struct {
			RootKey     string `json:"root_key"`
			OurPrivate  string `json:"our_private"`
			TheirPublic string `json:"their_public"`
			DHOutput    string `json:"dh_output"`
			NextRootKey string `json:"next_root_key"`
			ChainKey    string `json:"chain_key"`
		} `json:"root-key"`
		PqxdhSecret []struct {
			SecretInput       string `json:"secret_input"`
			DH1               string `json:"dh1"`
			DH2               string `json:"dh2"`
			DH3               string `json:"dh3"`
			DH4               string `json:"dh4"`
			KyberSharedSecret string `json:"kyber_shared_secret"`
			RootKey           string `json:"root_key"`
			ChainKey          string `json:"chain_key"`
			PqrKey            string `json:"pqr_key"`
		} `json:"pqxdh-secret"`
	} `json:"subdomains"`
}

const minHKDFCases = 20

func loadHKDFVectors(t *testing.T) hkdfVectors {
	t.Helper()
	path := filepath.Join("..", "compat", "vectors", "hkdf.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v hkdfVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestChainKeyNext checks ChainKey.Next() against the chain-key sub-domain:
// next chain key = HMAC-SHA256(chain_key, 0x02).
func TestChainKeyNext(t *testing.T) {
	v := loadHKDFVectors(t)
	if len(v.Subdomains.ChainKey) < minHKDFCases {
		t.Fatalf("chain-key: %d cases, want >= %d", len(v.Subdomains.ChainKey), minHKDFCases)
	}
	for i, c := range v.Subdomains.ChainKey {
		ck, err := NewChainKey(mustHex(t, c.ChainKey), 0)
		if err != nil {
			t.Fatalf("case %d: NewChainKey: %v", i, err)
		}
		next := ck.Next()
		if !bytes.Equal(next.Key(), mustHex(t, c.NextChainKey)) {
			t.Fatalf("case %d: next chain key mismatch\n go   %x\n want %s", i, next.Key(), c.NextChainKey)
		}
		if next.Index() != 1 {
			t.Fatalf("case %d: next index = %d, want 1", i, next.Index())
		}
	}
	t.Logf("chain-key: %d cases == upstream", len(v.Subdomains.ChainKey))
}

// TestChainKeyMessageKeys checks ChainKey.MessageKeys() against the
// message-keys sub-domain: seed = HMAC-SHA256(chain_key, 0x01), then
// HKDF "WhisperMessageKeys" -> 32B cipher || 32B mac || 16B iv.
func TestChainKeyMessageKeys(t *testing.T) {
	v := loadHKDFVectors(t)
	if len(v.Subdomains.MessageKeys) < minHKDFCases {
		t.Fatalf("message-keys: %d cases, want >= %d", len(v.Subdomains.MessageKeys), minHKDFCases)
	}
	for i, c := range v.Subdomains.MessageKeys {
		ck, err := NewChainKey(mustHex(t, c.ChainKey), 7)
		if err != nil {
			t.Fatalf("case %d: NewChainKey: %v", i, err)
		}
		mk, err := ck.MessageKeys().GenerateKeys(nil)
		if err != nil {
			t.Fatalf("case %d: MessageKeys: %v", i, err)
		}
		if !bytes.Equal(mk.CipherKey(), mustHex(t, c.CipherKey)) {
			t.Fatalf("case %d: cipher_key mismatch", i)
		}
		if !bytes.Equal(mk.MACKey(), mustHex(t, c.MacKey)) {
			t.Fatalf("case %d: mac_key mismatch", i)
		}
		if !bytes.Equal(mk.IV(), mustHex(t, c.IV)) {
			t.Fatalf("case %d: iv mismatch", i)
		}
		// MessageKeys carries the chain index it was derived at.
		if mk.Index() != 7 {
			t.Fatalf("case %d: message-keys index = %d, want 7", i, mk.Index())
		}
	}
	t.Logf("message-keys: %d cases == upstream", len(v.Subdomains.MessageKeys))
}

// TestRootKeyCreateChain checks RootKey.CreateChain() against the root-key
// sub-domain: ECDH(our_private, their_public) then HKDF salt=root_key
// "WhisperRatchet" -> 32B next root || 32B chain. The Go ECDH is recomputed
// independently and must match the recorded dh_output.
func TestRootKeyCreateChain(t *testing.T) {
	v := loadHKDFVectors(t)
	if len(v.Subdomains.RootKey) < minHKDFCases {
		t.Fatalf("root-key: %d cases, want >= %d", len(v.Subdomains.RootKey), minHKDFCases)
	}
	for i, c := range v.Subdomains.RootKey {
		ourPriv, err := curve.DeserializePrivateKey(mustHex(t, c.OurPrivate))
		if err != nil {
			t.Fatalf("case %d: our_private: %v", i, err)
		}
		theirPub, err := curve.DeserializePublicKey(mustHex(t, c.TheirPublic))
		if err != nil {
			t.Fatalf("case %d: their_public: %v", i, err)
		}
		// Independent Go ECDH must reproduce the recorded DH output.
		shared, err := ourPriv.CalculateAgreement(theirPub)
		if err != nil {
			t.Fatalf("case %d: agreement: %v", i, err)
		}
		if !bytes.Equal(shared, mustHex(t, c.DHOutput)) {
			t.Fatalf("case %d: DH output mismatch", i)
		}

		rk, err := NewRootKey(mustHex(t, c.RootKey))
		if err != nil {
			t.Fatalf("case %d: NewRootKey: %v", i, err)
		}
		nextRoot, chain, err := rk.CreateChain(theirPub, ourPriv)
		if err != nil {
			t.Fatalf("case %d: CreateChain: %v", i, err)
		}
		if !bytes.Equal(nextRoot.Key(), mustHex(t, c.NextRootKey)) {
			t.Fatalf("case %d: next root key mismatch", i)
		}
		if !bytes.Equal(chain.Key(), mustHex(t, c.ChainKey)) {
			t.Fatalf("case %d: chain key mismatch", i)
		}
		if chain.Index() != 0 {
			t.Fatalf("case %d: new chain index = %d, want 0", i, chain.Index())
		}
	}
	t.Logf("root-key: %d cases == upstream (incl. independent Go ECDH)", len(v.Subdomains.RootKey))
}

// TestDeriveInitialKeys checks the PQXDH master-secret derivation against the
// pqxdh-secret sub-domain. Per the T12 code-review carry-forward, the secret
// is RE-DERIVED in Go from the recorded dh1..dh4 + kyber_shared_secret via
// PQXDHSecret (asserted byte-equal to the recorded secret_input), not consumed
// pre-assembled; then DeriveInitialKeys must reproduce root/chain/pqr.
func TestDeriveInitialKeys(t *testing.T) {
	v := loadHKDFVectors(t)
	if len(v.Subdomains.PqxdhSecret) < minHKDFCases {
		t.Fatalf("pqxdh-secret: %d cases, want >= %d", len(v.Subdomains.PqxdhSecret), minHKDFCases)
	}
	for i, c := range v.Subdomains.PqxdhSecret {
		dh1, dh2, dh3, dh4 := mustHex(t, c.DH1), mustHex(t, c.DH2), mustHex(t, c.DH3), mustHex(t, c.DH4)
		kyberSS := mustHex(t, c.KyberSharedSecret)

		// Re-derive the master secret from the components and confirm it equals
		// the recorded pre-assembled blob (carry-forward from T12 review).
		secret := PQXDHSecret(dh1, dh2, dh3, dh4, kyberSS)
		if !bytes.Equal(secret, mustHex(t, c.SecretInput)) {
			t.Fatalf("case %d: re-derived secret_input mismatch\n go   %x\n want %s", i, secret, c.SecretInput)
		}

		ik, err := DeriveInitialKeys(dh1, dh2, dh3, dh4, kyberSS)
		if err != nil {
			t.Fatalf("case %d: DeriveInitialKeys: %v", i, err)
		}
		if !bytes.Equal(ik.RootKey.Key(), mustHex(t, c.RootKey)) {
			t.Fatalf("case %d: root key mismatch", i)
		}
		if !bytes.Equal(ik.ChainKey.Key(), mustHex(t, c.ChainKey)) {
			t.Fatalf("case %d: chain key mismatch", i)
		}
		if !bytes.Equal(ik.PQRSeed[:], mustHex(t, c.PqrKey)) {
			t.Fatalf("case %d: pqr seed mismatch", i)
		}
		if ik.ChainKey.Index() != 0 {
			t.Fatalf("case %d: initial chain index = %d, want 0", i, ik.ChainKey.Index())
		}
	}
	t.Logf("pqxdh-secret: %d cases == upstream (secret_input re-derived from dh1..dh4+kyber_ss)", len(v.Subdomains.PqxdhSecret))
}

// TestDeriveInitialKeysRejectsBadDHLength confirms the DH-agreement length
// contract: DH1..DH3 are mandatory and must each be exactly agreementLen bytes;
// DH4 is optional, so absent (empty/nil) is accepted but any non-zero,
// non-agreementLen length is rejected. A wrong-length DH must error rather than
// silently producing a wrong master secret. DH4 optionality mirrors upstream's
// conditional fourth agreement (rust/protocol/src/pqxdh.rs:220 / :360).
func TestDeriveInitialKeysRejectsBadDHLength(t *testing.T) {
	good := bytes.Repeat([]byte{0x01}, agreementLen)
	kyberSS := bytes.Repeat([]byte{0x02}, 32)

	// A baseline of four good DHs derives without error.
	if _, err := DeriveInitialKeys(good, good, good, good, kyberSS); err != nil {
		t.Fatalf("baseline DeriveInitialKeys: %v", err)
	}

	short := bytes.Repeat([]byte{0x01}, agreementLen-1)
	long := bytes.Repeat([]byte{0x01}, agreementLen+1)

	// DH1..DH3 are mandatory: short, long, AND absent are all rejected.
	for pos := 0; pos < 3; pos++ {
		for _, bad := range [][]byte{short, long, nil} {
			dhs := [4][]byte{good, good, good, good}
			dhs[pos] = bad
			if _, err := DeriveInitialKeys(dhs[0], dhs[1], dhs[2], dhs[3], kyberSS); err == nil {
				t.Fatalf("DH%d len %d accepted; want error", pos+1, len(bad))
			}
		}
	}

	// DH4 is optional: short/long are rejected, but empty and nil are accepted
	// (no one-time prekey present).
	for _, bad := range [][]byte{short, long} {
		if _, err := DeriveInitialKeys(good, good, good, bad, kyberSS); err == nil {
			t.Fatalf("DH4 len %d accepted; want error", len(bad))
		}
	}
	for _, absent := range [][]byte{nil, {}} {
		if _, err := DeriveInitialKeys(good, good, good, absent, kyberSS); err != nil {
			t.Fatalf("DH4 absent (len %d) rejected; want accepted: %v", len(absent), err)
		}
	}
}

// TestDeriveInitialKeysOmitsAbsentDH4 is a ratchet-level KAT for the
// no-one-time-prekey path: when DH4 is absent the master secret must be exactly
// 0xFF*32 || DH1 || DH2 || DH3 || kyber_ss (no DH4), i.e. agreementLen bytes
// shorter than the with-DH4 secret, and derivation must still succeed. This
// mirrors upstream omitting the fourth agreement when there is no one-time
// prekey (rust/protocol/src/pqxdh.rs:220 initiator, :360 recipient).
//
// NOTE: the committed hkdf.json vectors only cover the with-DH4 case, so this
// asserts byte layout directly. A cross-impl no-one-time-prekey compat vector is
// tracked as a Task 19 follow-up (gen-vectors `sessions` domain).
func TestDeriveInitialKeysOmitsAbsentDH4(t *testing.T) {
	dh1 := bytes.Repeat([]byte{0x11}, agreementLen)
	dh2 := bytes.Repeat([]byte{0x22}, agreementLen)
	dh3 := bytes.Repeat([]byte{0x33}, agreementLen)
	dh4 := bytes.Repeat([]byte{0x44}, agreementLen)
	kyberSS := bytes.Repeat([]byte{0x55}, 32)

	withDH4 := PQXDHSecret(dh1, dh2, dh3, dh4, kyberSS)
	noDH4 := PQXDHSecret(dh1, dh2, dh3, nil, kyberSS)

	// The no-DH4 secret is exactly agreementLen bytes shorter.
	if len(withDH4)-len(noDH4) != agreementLen {
		t.Fatalf("with-DH4 secret %d B, no-DH4 secret %d B; want diff %d",
			len(withDH4), len(noDH4), agreementLen)
	}

	// Assert the exact expected byte layout: 0xFF*32 || DH1 || DH2 || DH3 || kyber_ss.
	want := make([]byte, 0, discontinuityLen+3*agreementLen+len(kyberSS))
	want = append(want, bytes.Repeat([]byte{0xFF}, discontinuityLen)...)
	want = append(want, dh1...)
	want = append(want, dh2...)
	want = append(want, dh3...)
	want = append(want, kyberSS...)
	if !bytes.Equal(noDH4, want) {
		t.Fatalf("no-DH4 secret layout mismatch\n go   %x\n want %x", noDH4, want)
	}

	// Derivation must succeed and stay distinct from the with-DH4 keys.
	noDH4Keys, err := DeriveInitialKeys(dh1, dh2, dh3, nil, kyberSS)
	if err != nil {
		t.Fatalf("DeriveInitialKeys (no DH4): %v", err)
	}
	withDH4Keys, err := DeriveInitialKeys(dh1, dh2, dh3, dh4, kyberSS)
	if err != nil {
		t.Fatalf("DeriveInitialKeys (with DH4): %v", err)
	}
	if bytes.Equal(noDH4Keys.RootKey.Key(), withDH4Keys.RootKey.Key()) {
		t.Fatal("no-DH4 and with-DH4 root keys are equal; DH4 was not actually omitted")
	}
	if noDH4Keys.ChainKey.Index() != 0 {
		t.Fatalf("no-DH4 initial chain index = %d, want 0", noDH4Keys.ChainKey.Index())
	}
}

// TestChainKeyAdvances confirms Next() advances the index and changes the key,
// and that successive message keys differ (chain ratchet sanity, beyond KATs).
func TestChainKeyAdvances(t *testing.T) {
	ck, err := NewChainKey(bytes.Repeat([]byte{0xAB}, chainKeyLen), 0)
	if err != nil {
		t.Fatalf("NewChainKey: %v", err)
	}
	mk0, err := ck.MessageKeys().GenerateKeys(nil)
	if err != nil {
		t.Fatalf("MessageKeys: %v", err)
	}
	next := ck.Next()
	if next.Index() != 1 {
		t.Fatalf("index after Next = %d, want 1", next.Index())
	}
	if bytes.Equal(next.Key(), ck.Key()) {
		t.Fatal("Next() did not change the chain key")
	}
	mk1, err := next.MessageKeys().GenerateKeys(nil)
	if err != nil {
		t.Fatalf("MessageKeys after Next: %v", err)
	}
	if bytes.Equal(mk0.CipherKey(), mk1.CipherKey()) {
		t.Fatal("message keys did not change across chain step")
	}
	if mk1.Index() != 1 {
		t.Fatalf("mk1 index = %d, want 1", mk1.Index())
	}
}

// TestMessageKeyGeneratorPQRMix verifies the SPQR triple-ratchet mix at the
// key-derivation layer: a nil/empty PQR key must reproduce the exact pre-SPQR
// derivation (HKDF salt=nil), while a non-empty PQR key must fold in as the
// HKDF salt and change every derived key. This is the backward-compat + actual-
// mix guarantee for the session integration (T28).
func TestMessageKeyGeneratorPQRMix(t *testing.T) {
	ck, err := NewChainKey(bytes.Repeat([]byte{0x42}, chainKeyLen), 5)
	if err != nil {
		t.Fatal(err)
	}

	// nil PQR key == empty PQR key == the original derivation.
	base, err := ck.MessageKeys().GenerateKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := ck.MessageKeys().GenerateKeys([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(base.CipherKey(), empty.CipherKey()) ||
		!bytes.Equal(base.MACKey(), empty.MACKey()) ||
		!bytes.Equal(base.IV(), empty.IV()) {
		t.Fatal("empty PQR key must derive identically to nil (no salt)")
	}
	if base.Index() != 5 {
		t.Fatalf("counter not preserved: got %d want 5", base.Index())
	}

	// A non-empty PQR key folds in as the HKDF salt and changes the keys.
	pqr := bytes.Repeat([]byte{0x99}, 32)
	mixed, err := ck.MessageKeys().GenerateKeys(pqr)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base.CipherKey(), mixed.CipherKey()) ||
		bytes.Equal(base.MACKey(), mixed.MACKey()) ||
		bytes.Equal(base.IV(), mixed.IV()) {
		t.Fatal("PQR key did not change the derived message keys")
	}
	// Different PQR keys produce different message keys (the salt actually matters).
	mixed2, err := ck.MessageKeys().GenerateKeys(bytes.Repeat([]byte{0x88}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(mixed.CipherKey(), mixed2.CipherKey()) {
		t.Fatal("distinct PQR keys produced identical message keys")
	}
}

// TestMessageKeyGeneratorVariants covers the Seed and Keys variants: a Seed
// generator exposes its seed/counter and derives; a Keys generator returns the
// wrapped keys and rejects a supplied PQR key (pre-SPQR cached keys never mix).
func TestMessageKeyGeneratorVariants(t *testing.T) {
	ck, _ := NewChainKey(bytes.Repeat([]byte{0x42}, chainKeyLen), 5)

	g := ck.MessageKeys()
	if !g.FromSeed() {
		t.Fatal("ChainKey.MessageKeys() must yield a Seed-variant generator")
	}
	seed, counter, ok := g.Seed()
	if !ok || counter != 5 || len(seed) != 32 {
		t.Fatalf("Seed() = (%d bytes, counter %d, ok %v)", len(seed), counter, ok)
	}

	// Round-trip a Seed generator rebuilt from the exposed seed/counter.
	rebuilt := NewMessageKeyGeneratorFromSeed(seed, counter)
	a, _ := g.GenerateKeys(nil)
	b, _ := rebuilt.GenerateKeys(nil)
	if !bytes.Equal(a.CipherKey(), b.CipherKey()) || a.Index() != b.Index() {
		t.Fatal("Seed round-trip changed the derived keys")
	}

	// Keys variant: returns the wrapped keys; rejects a PQR key.
	mk, _ := g.GenerateKeys(nil)
	kg := NewMessageKeyGeneratorFromKeys(mk)
	if kg.FromSeed() {
		t.Fatal("Keys-variant generator must report FromSeed()==false")
	}
	if got, _ := kg.GenerateKeys(nil); !bytes.Equal(got.CipherKey(), mk.CipherKey()) {
		t.Fatal("Keys variant did not return the wrapped keys")
	}
	if _, err := kg.GenerateKeys(bytes.Repeat([]byte{0x01}, 32)); err == nil {
		t.Fatal("Keys variant must reject a supplied PQR key")
	}
}

// TestNewMessageKeysValidation confirms NewMessageKeys rejects wrong-length
// component slices.
func TestNewMessageKeysValidation(t *testing.T) {
	good := func(n int) []byte { return make([]byte, n) }
	if _, err := NewMessageKeys(good(cipherKeyLen), good(macKeyLen), good(ivLen), 0); err != nil {
		t.Fatalf("valid lengths rejected: %v", err)
	}
	if _, err := NewMessageKeys(good(31), good(macKeyLen), good(ivLen), 0); err == nil {
		t.Fatal("short cipher key accepted")
	}
	if _, err := NewMessageKeys(good(cipherKeyLen), good(33), good(ivLen), 0); err == nil {
		t.Fatal("wrong-length MAC key accepted")
	}
	if _, err := NewMessageKeys(good(cipherKeyLen), good(macKeyLen), good(15), 0); err == nil {
		t.Fatal("short IV accepted")
	}
}

// TestConstructorLengthValidation confirms the constructors reject wrong-length
// inputs rather than silently truncating.
func TestConstructorLengthValidation(t *testing.T) {
	if _, err := NewChainKey(make([]byte, 31), 0); err == nil {
		t.Fatal("NewChainKey(31 bytes) = nil error")
	}
	if _, err := NewRootKey(make([]byte, 33)); err == nil {
		t.Fatal("NewRootKey(33 bytes) = nil error")
	}
}

// TestStringRedaction confirms key material never appears in String() output.
func TestStringRedaction(t *testing.T) {
	ck, _ := NewChainKey(bytes.Repeat([]byte{0x11}, chainKeyLen), 3)
	if got := ck.String(); !bytes.Contains([]byte(got), []byte("redacted")) || bytes.Contains([]byte(got), []byte("1111")) {
		t.Fatalf("ChainKey.String() leaks material or missing redaction: %q", got)
	}
	rk, _ := NewRootKey(bytes.Repeat([]byte{0x22}, rootKeyLen))
	if got := rk.String(); !bytes.Contains([]byte(got), []byte("redacted")) || bytes.Contains([]byte(got), []byte("2222")) {
		t.Fatalf("RootKey.String() leaks material or missing redaction: %q", got)
	}
	mk, _ := ck.MessageKeys().GenerateKeys(nil)
	if got := mk.String(); !bytes.Contains([]byte(got), []byte("redacted")) {
		t.Fatalf("MessageKeys.String() missing redaction: %q", got)
	}
}

// TestFormatRedaction confirms key material never leaks through ANY fmt verb,
// including the Go-syntax %#v and the hex %x that String() does not intercept.
// Each secret-bearing type must implement Format() (not just String()) — this
// is the code-review fix: a String()-only type dumps its raw byte fields under
// %#v. The key bytes are distinctive so any leak is detectable as hex.
func TestFormatRedaction(t *testing.T) {
	// Distinctive byte patterns; their hex must never appear in any formatting.
	ck, _ := NewChainKey(bytes.Repeat([]byte{0xAB}, chainKeyLen), 9)
	rk, _ := NewRootKey(bytes.Repeat([]byte{0xCD}, rootKeyLen))
	mk, _ := ck.MessageKeys().GenerateKeys(nil) // derives distinct cipher/mac/iv from the chain key
	// InitialKeys with a distinctive PQR seed (0xEE) so a leak is detectable;
	// the embedded keys also carry distinctive bytes.
	ik := InitialKeys{RootKey: rk, ChainKey: ck, PQRSeed: [32]byte(bytes.Repeat([]byte{0xEE}, 32))}

	verbs := []string{"%v", "%s", "%+v", "%#v", "%x"}
	// Hex fragments that would appear if a [N]byte field were dumped.
	leakMarkers := []string{"abab", "cdcd", "eeee"}

	check := func(name string, val any) {
		for _, verb := range verbs {
			out := fmt.Sprintf(verb, val)
			for _, marker := range leakMarkers {
				if strings.Contains(strings.ToLower(out), marker) {
					t.Fatalf("%s under %s leaks key material (found %q): %s", name, verb, marker, out)
				}
			}
			// Also ensure raw [N]uint8{ Go-syntax field dumps don't slip through.
			if strings.Contains(out, "uint8{") || strings.Contains(out, "[]byte{") {
				t.Fatalf("%s under %s exposes raw byte fields: %s", name, verb, out)
			}
			if !strings.Contains(strings.ToUpper(out), "REDACTED") {
				t.Fatalf("%s under %s missing REDACTED marker: %s", name, verb, out)
			}
		}
	}

	// Test both value and pointer forms (fmt dispatches Format on either when the
	// method has a value receiver).
	check("ChainKey", ck)
	check("ChainKey ptr", &ck)
	check("RootKey", rk)
	check("RootKey ptr", &rk)
	check("MessageKeys", mk)
	check("MessageKeys ptr", &mk)
	check("InitialKeys", ik)
	check("InitialKeys ptr", &ik)

	// Belt-and-suspenders: the MAC key bytes (derived, not 0xAB/0xCD) must also
	// be absent from %#v of MessageKeys. Compare against the actual derived hex.
	mkLeak := fmt.Sprintf("%#v", mk)
	if strings.Contains(strings.ToLower(mkLeak), strings.ToLower(hex.EncodeToString(mk.MACKey()))) {
		t.Fatalf("MessageKeys %%#v leaks derived MAC key: %s", mkLeak)
	}
}
