// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package ratchet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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
		mk, err := ck.MessageKeys()
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

// TestChainKeyAdvances confirms Next() advances the index and changes the key,
// and that successive message keys differ (chain ratchet sanity, beyond KATs).
func TestChainKeyAdvances(t *testing.T) {
	ck, err := NewChainKey(bytes.Repeat([]byte{0xAB}, chainKeyLen), 0)
	if err != nil {
		t.Fatalf("NewChainKey: %v", err)
	}
	mk0, err := ck.MessageKeys()
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
	mk1, err := next.MessageKeys()
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
	mk, _ := ck.MessageKeys()
	if got := mk.String(); !bytes.Contains([]byte(got), []byte("redacted")) {
		t.Fatalf("MessageKeys.String() missing redaction: %q", got)
	}
}
