// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package compat consumes the committed Rust-generated test vectors
// (compat/vectors/*.json) and asserts the pure-Go implementation agrees with
// upstream libsignal v0.91.0 byte-for-byte. The vectors are committed files, so
// these run under a plain `go test ./compat/` with no Rust toolchain present;
// regenerate them with the T11 harness (see compat/README.md).
package compat

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/kem"
	"github.com/GoCodeAlone/libsignal-go/protocol"
)

// loadVectors reads and JSON-decodes compat/vectors/<domain>.json into dst.
func loadVectors(t *testing.T, domain string, dst any) {
	t.Helper()
	path := filepath.Join("vectors", domain+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// mustHex decodes a hex string from a vector field, failing the test on error.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// --- curve ---

func TestCurveVectors(t *testing.T) {
	var batch struct {
		Seed  string `json:"seed"`
		Cases []struct {
			Op         string `json:"op"`
			PrivateKey string `json:"private_key"`
			PublicKey  string `json:"public_key"`
			Message    string `json:"message"`
			Nonce      string `json:"nonce"`
			Signature  string `json:"signature"`
			// ecdh fields
			APrivate string `json:"a_private"`
			APublic  string `json:"a_public"`
			BPrivate string `json:"b_private"`
			BPublic  string `json:"b_public"`
			Shared   string `json:"shared"`
		} `json:"cases"`
	}
	loadVectors(t, "curve", &batch)
	if len(batch.Cases) == 0 {
		t.Fatal("no curve cases")
	}

	var nSign, nECDH int
	for i, c := range batch.Cases {
		switch c.Op {
		case "xeddsa":
			pub, err := curve.DeserializePublicKey(mustHex(t, c.PublicKey))
			if err != nil {
				t.Fatalf("case %d: DeserializePublicKey: %v", i, err)
			}
			priv, err := curve.DeserializePrivateKey(mustHex(t, c.PrivateKey))
			if err != nil {
				t.Fatalf("case %d: DeserializePrivateKey: %v", i, err)
			}
			msg := mustHex(t, c.Message)
			upstreamSig := mustHex(t, c.Signature)

			// 1. Go verifies the upstream signature.
			if !pub.VerifySignature(upstreamSig, msg) {
				t.Fatalf("case %d: Go failed to verify upstream signature", i)
			}
			// 2. Go signing with the same 64-byte nonce reproduces the upstream
			// signature byte-for-byte.
			nonce := mustHex(t, c.Nonce)
			if len(nonce) != 64 {
				t.Fatalf("case %d: nonce length %d, want 64", i, len(nonce))
			}
			goSig, err := priv.CalculateSignature(bytes.NewReader(nonce), msg)
			if err != nil {
				t.Fatalf("case %d: CalculateSignature: %v", i, err)
			}
			if !bytes.Equal(goSig, upstreamSig) {
				t.Fatalf("case %d: Go signature != upstream\n go   %x\n want %x", i, goSig, upstreamSig)
			}
			nSign++
		case "ecdh":
			aPriv, err := curve.DeserializePrivateKey(mustHex(t, c.APrivate))
			if err != nil {
				t.Fatalf("case %d: a_private: %v", i, err)
			}
			bPub, err := curve.DeserializePublicKey(mustHex(t, c.BPublic))
			if err != nil {
				t.Fatalf("case %d: b_public: %v", i, err)
			}
			bPriv, err := curve.DeserializePrivateKey(mustHex(t, c.BPrivate))
			if err != nil {
				t.Fatalf("case %d: b_private: %v", i, err)
			}
			aPub, err := curve.DeserializePublicKey(mustHex(t, c.APublic))
			if err != nil {
				t.Fatalf("case %d: a_public: %v", i, err)
			}
			ab, err := aPriv.CalculateAgreement(bPub)
			if err != nil {
				t.Fatalf("case %d: agree ab: %v", i, err)
			}
			ba, err := bPriv.CalculateAgreement(aPub)
			if err != nil {
				t.Fatalf("case %d: agree ba: %v", i, err)
			}
			want := mustHex(t, c.Shared)
			if !bytes.Equal(ab, want) {
				t.Fatalf("case %d: Go ECDH != upstream\n go   %x\n want %x", i, ab, want)
			}
			if !bytes.Equal(ab, ba) {
				t.Fatalf("case %d: ECDH not symmetric", i)
			}
			nECDH++
		default:
			t.Fatalf("case %d: unknown op %q", i, c.Op)
		}
	}
	t.Logf("curve: %d xeddsa + %d ecdh cases", nSign, nECDH)
}

// --- kem-decaps (closes design assumption A1: circl Kyber == upstream libcrux kyber) ---

func TestKEMDecapsVectors(t *testing.T) {
	var batch struct {
		Cases []struct {
			SecretKey    string `json:"secret_key"`
			Ciphertext   string `json:"ciphertext"`
			SharedSecret string `json:"shared_secret"`
		} `json:"cases"`
	}
	loadVectors(t, "kem-decaps", &batch)
	if len(batch.Cases) < 100 {
		t.Fatalf("kem-decaps: %d cases, want >= 100", len(batch.Cases))
	}
	for i, c := range batch.Cases {
		sk, err := kem.DeserializeSecretKey(mustHex(t, c.SecretKey))
		if err != nil {
			t.Fatalf("case %d: DeserializeSecretKey: %v", i, err)
		}
		ss, err := sk.Decapsulate(mustHex(t, c.Ciphertext))
		if err != nil {
			t.Fatalf("case %d: Decapsulate: %v", i, err)
		}
		want := mustHex(t, c.SharedSecret)
		if !bytes.Equal(ss, want) {
			t.Fatalf("case %d: Go decaps != upstream ss\n go   %x\n want %x", i, ss, want)
		}
	}
	t.Logf("kem-decaps: %d Kyber1024 triples decapsulated == upstream (A1 closed)", len(batch.Cases))
}

// --- hkdf ---
//
// The Double Ratchet key derivations are pub(crate) upstream; T14 (PR 5) will
// add a Go ratchet/ package. Until then these derivations are reproduced here
// against Go's stdlib crypto/{hkdf,hmac,sha256}, with formulas from
// rust/protocol/src/ratchet/keys.rs. When T14 lands, move them into ratchet/
// and these committed vectors become its contract.

// chainKeyHMAC is ChainKey::calculate_base_material: HMAC-SHA256(chainKey, seed).
func chainKeyHMAC(chainKey []byte, seed byte) []byte {
	m := hmac.New(sha256.New, chainKey)
	m.Write([]byte{seed})
	return m.Sum(nil)
}

func TestHKDFVectors(t *testing.T) {
	var batch struct {
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
				SecretInput string `json:"secret_input"`
				RootKey     string `json:"root_key"`
				ChainKey    string `json:"chain_key"`
				PqrKey      string `json:"pqr_key"`
			} `json:"pqxdh-secret"`
		} `json:"subdomains"`
	}
	loadVectors(t, "hkdf", &batch)

	const minCases = 20

	// chain-key: next = HMAC-SHA256(chain_key, 0x02).
	if len(batch.Subdomains.ChainKey) < minCases {
		t.Fatalf("chain-key: %d cases, want >= %d", len(batch.Subdomains.ChainKey), minCases)
	}
	for i, c := range batch.Subdomains.ChainKey {
		got := chainKeyHMAC(mustHex(t, c.ChainKey), 0x02)
		if !bytes.Equal(got, mustHex(t, c.NextChainKey)) {
			t.Fatalf("chain-key case %d: mismatch\n go   %x\n want %s", i, got, c.NextChainKey)
		}
	}

	// message-keys: HKDF-SHA256(ikm=HMAC-SHA256(chain_key,0x01), salt=nil,
	// info="WhisperMessageKeys") -> 32B cipher || 32B mac || 16B iv.
	if len(batch.Subdomains.MessageKeys) < minCases {
		t.Fatalf("message-keys: %d cases, want >= %d", len(batch.Subdomains.MessageKeys), minCases)
	}
	for i, c := range batch.Subdomains.MessageKeys {
		ikm := chainKeyHMAC(mustHex(t, c.ChainKey), 0x01)
		okm, err := hkdf.Key(sha256.New, ikm, nil, "WhisperMessageKeys", 80)
		if err != nil {
			t.Fatalf("message-keys case %d: hkdf: %v", i, err)
		}
		if !bytes.Equal(okm[0:32], mustHex(t, c.CipherKey)) {
			t.Fatalf("message-keys case %d: cipher_key mismatch", i)
		}
		if !bytes.Equal(okm[32:64], mustHex(t, c.MacKey)) {
			t.Fatalf("message-keys case %d: mac_key mismatch", i)
		}
		if !bytes.Equal(okm[64:80], mustHex(t, c.IV)) {
			t.Fatalf("message-keys case %d: iv mismatch", i)
		}
	}

	// root-key: shared=ECDH(our_private, their_public); HKDF-SHA256(ikm=shared,
	// salt=root_key, info="WhisperRatchet") -> 32B next_root || 32B chain.
	if len(batch.Subdomains.RootKey) < minCases {
		t.Fatalf("root-key: %d cases, want >= %d", len(batch.Subdomains.RootKey), minCases)
	}
	for i, c := range batch.Subdomains.RootKey {
		ourPriv, err := curve.DeserializePrivateKey(mustHex(t, c.OurPrivate))
		if err != nil {
			t.Fatalf("root-key case %d: our_private: %v", i, err)
		}
		theirPub, err := curve.DeserializePublicKey(mustHex(t, c.TheirPublic))
		if err != nil {
			t.Fatalf("root-key case %d: their_public: %v", i, err)
		}
		shared, err := ourPriv.CalculateAgreement(theirPub)
		if err != nil {
			t.Fatalf("root-key case %d: agree: %v", i, err)
		}
		if !bytes.Equal(shared, mustHex(t, c.DHOutput)) {
			t.Fatalf("root-key case %d: DH output mismatch", i)
		}
		okm, err := hkdf.Key(sha256.New, shared, mustHex(t, c.RootKey), "WhisperRatchet", 64)
		if err != nil {
			t.Fatalf("root-key case %d: hkdf: %v", i, err)
		}
		if !bytes.Equal(okm[0:32], mustHex(t, c.NextRootKey)) {
			t.Fatalf("root-key case %d: next_root_key mismatch", i)
		}
		if !bytes.Equal(okm[32:64], mustHex(t, c.ChainKey)) {
			t.Fatalf("root-key case %d: chain_key mismatch", i)
		}
	}

	// pqxdh-secret: the secret_input (0xFF*32 || DH1..4 || kyber_ss) is assembled
	// by the harness; here we confirm the KDF over it. HKDF-SHA256(ikm=secret,
	// salt=nil, info=<X25519/Kyber label>) -> 32B root || 32B chain || 32B pqr.
	if len(batch.Subdomains.PqxdhSecret) < minCases {
		t.Fatalf("pqxdh-secret: %d cases, want >= %d", len(batch.Subdomains.PqxdhSecret), minCases)
	}
	const pqxdhLabel = "WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024"
	for i, c := range batch.Subdomains.PqxdhSecret {
		secret := mustHex(t, c.SecretInput)
		okm, err := hkdf.Key(sha256.New, secret, nil, pqxdhLabel, 96)
		if err != nil {
			t.Fatalf("pqxdh-secret case %d: hkdf: %v", i, err)
		}
		if !bytes.Equal(okm[0:32], mustHex(t, c.RootKey)) {
			t.Fatalf("pqxdh-secret case %d: root_key mismatch", i)
		}
		if !bytes.Equal(okm[32:64], mustHex(t, c.ChainKey)) {
			t.Fatalf("pqxdh-secret case %d: chain_key mismatch", i)
		}
		if !bytes.Equal(okm[64:96], mustHex(t, c.PqrKey)) {
			t.Fatalf("pqxdh-secret case %d: pqr_key mismatch", i)
		}
	}

	t.Logf("hkdf: chain-key %d, message-keys %d, root-key %d, pqxdh-secret %d cases == upstream",
		len(batch.Subdomains.ChainKey), len(batch.Subdomains.MessageKeys),
		len(batch.Subdomains.RootKey), len(batch.Subdomains.PqxdhSecret))
}

// --- messages ---
//
// All four wire message types are consumed both directions: deserialize the
// upstream golden bytes and check field equality, then re-serialize (re-signing
// where applicable, replaying the recorded nonce) and check byte equality with
// upstream.

type messageCase struct {
	Type string `json:"type"`
	// sender-key shared fields
	DistributionID string `json:"distribution_id"`
	ChainID        uint32 `json:"chain_id"`
	Iteration      uint32 `json:"iteration"`
	Ciphertext     string `json:"ciphertext"`
	SigningPrivate string `json:"signing_private"`
	SigningPublic  string `json:"signing_public"`
	Nonce          string `json:"nonce"`
	ChainKey       string `json:"chain_key"`
	// signal_message fields
	MacKey           string `json:"mac_key"`
	RatchetKey       string `json:"ratchet_key"`
	Counter          uint32 `json:"counter"`
	PreviousCounter  uint32 `json:"previous_counter"`
	SenderIdentity   string `json:"sender_identity"`
	ReceiverIdentity string `json:"receiver_identity"`
	// prekey_signal_message fields
	RegistrationID  uint32 `json:"registration_id"`
	PreKeyID        uint32 `json:"pre_key_id"`
	SignedPreKeyID  uint32 `json:"signed_pre_key_id"`
	KyberPreKeyID   uint32 `json:"kyber_pre_key_id"`
	KyberCiphertext string `json:"kyber_ciphertext"`
	BaseKey         string `json:"base_key"`

	Serialized string `json:"serialized"`
}

func TestMessagesVectors(t *testing.T) {
	var batch struct {
		Cases []messageCase `json:"cases"`
	}
	loadVectors(t, "messages", &batch)
	if len(batch.Cases) == 0 {
		t.Fatal("no messages cases")
	}

	counts := map[string]int{}
	for i, c := range batch.Cases {
		counts[c.Type]++
		switch c.Type {
		case "signal_message":
			testSignalMessageCase(t, i, c)
		case "prekey_signal_message":
			testPreKeySignalMessageCase(t, i, c)
		case "sender_key_message":
			testSenderKeyMessageCase(t, i, c)
		case "sender_key_distribution_message":
			testSenderKeyDistributionMessageCase(t, i, c)
		default:
			t.Fatalf("case %d: unknown message type %q", i, c.Type)
		}
	}

	t.Logf("messages: all four types consumed both directions — %d signal_message, "+
		"%d prekey_signal_message, %d sender_key_message, %d sender_key_distribution_message",
		counts["signal_message"], counts["prekey_signal_message"],
		counts["sender_key_message"], counts["sender_key_distribution_message"])
}

func testSignalMessageCase(t *testing.T, i int, c messageCase) {
	t.Helper()
	want := mustHex(t, c.Serialized)

	ratchet, err := curve.DeserializePublicKey(mustHex(t, c.RatchetKey))
	if err != nil {
		t.Fatalf("case %d: ratchet_key: %v", i, err)
	}
	senderID, err := curve.DeserializePublicKey(mustHex(t, c.SenderIdentity))
	if err != nil {
		t.Fatalf("case %d: sender_identity: %v", i, err)
	}
	receiverID, err := curve.DeserializePublicKey(mustHex(t, c.ReceiverIdentity))
	if err != nil {
		t.Fatalf("case %d: receiver_identity: %v", i, err)
	}

	// Deserialize upstream bytes -> field equality.
	msg, err := protocol.DeserializeSignalMessage(want)
	if err != nil {
		t.Fatalf("case %d: DeserializeSignalMessage: %v", i, err)
	}
	if msg.Counter() != c.Counter || msg.PreviousCounter() != c.PreviousCounter {
		t.Fatalf("case %d: counter/previous = %d/%d, want %d/%d", i, msg.Counter(), msg.PreviousCounter(), c.Counter, c.PreviousCounter)
	}
	if !bytes.Equal(msg.Body(), mustHex(t, c.Ciphertext)) {
		t.Fatalf("case %d: body mismatch", i)
	}
	if !msg.SenderRatchetKey().Equal(ratchet) {
		t.Fatalf("case %d: ratchet key mismatch", i)
	}
	// The MAC verifies under the recorded identity keys + mac key.
	ok, err := msg.VerifyMAC(senderID, receiverID, mustHex(t, c.MacKey))
	if err != nil {
		t.Fatalf("case %d: VerifyMAC: %v", i, err)
	}
	if !ok {
		t.Fatalf("case %d: MAC failed to verify", i)
	}

	// Re-serialize from the same inputs (the MAC is keyed, so it can only be
	// recomputed from the mac key + identities, not recovered from the message)
	// -> byte equality with upstream.
	rebuilt, err := protocol.NewSignalMessage(
		msg.MessageVersion(),
		mustHex(t, c.MacKey),
		ratchet,
		c.Counter,
		c.PreviousCounter,
		mustHex(t, c.Ciphertext),
		senderID,
		receiverID,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("case %d: NewSignalMessage: %v", i, err)
	}
	if !bytes.Equal(rebuilt.Serialize(), want) {
		t.Fatalf("case %d: re-serialized != upstream\n go   %x\n want %x", i, rebuilt.Serialize(), want)
	}
}

func testPreKeySignalMessageCase(t *testing.T, i int, c messageCase) {
	t.Helper()
	want := mustHex(t, c.Serialized)

	baseKey, err := curve.DeserializePublicKey(mustHex(t, c.BaseKey))
	if err != nil {
		t.Fatalf("case %d: base_key: %v", i, err)
	}

	// Deserialize upstream bytes -> field equality.
	msg, err := protocol.DeserializePreKeySignalMessage(want)
	if err != nil {
		t.Fatalf("case %d: DeserializePreKeySignalMessage: %v", i, err)
	}
	if msg.RegistrationID() != c.RegistrationID {
		t.Fatalf("case %d: registration_id = %d, want %d", i, msg.RegistrationID(), c.RegistrationID)
	}
	if msg.PreKeyID() == nil || *msg.PreKeyID() != c.PreKeyID {
		t.Fatalf("case %d: pre_key_id = %v, want %d", i, msg.PreKeyID(), c.PreKeyID)
	}
	if msg.SignedPreKeyID() != c.SignedPreKeyID {
		t.Fatalf("case %d: signed_pre_key_id = %d, want %d", i, msg.SignedPreKeyID(), c.SignedPreKeyID)
	}
	if msg.KyberPreKeyID() == nil || *msg.KyberPreKeyID() != c.KyberPreKeyID {
		t.Fatalf("case %d: kyber_pre_key_id = %v, want %d", i, msg.KyberPreKeyID(), c.KyberPreKeyID)
	}
	if !bytes.Equal(msg.KyberCiphertext(), mustHex(t, c.KyberCiphertext)) {
		t.Fatalf("case %d: kyber_ciphertext mismatch", i)
	}
	if !msg.BaseKey().Equal(baseKey) {
		t.Fatalf("case %d: base key mismatch", i)
	}
	if msg.Message() == nil {
		t.Fatalf("case %d: nil inner SignalMessage", i)
	}

	// Re-serialize from the parsed fields (the wrapped SignalMessage carries its
	// own already-computed MAC, so re-wrapping the deserialized inner message
	// reproduces the bytes) -> byte equality with upstream.
	rebuilt, err := protocol.NewPreKeySignalMessage(
		msg.MessageVersion(),
		msg.RegistrationID(),
		msg.PreKeyID(),
		msg.SignedPreKeyID(),
		msg.KyberPreKeyID(),
		msg.KyberCiphertext(),
		msg.BaseKey(),
		msg.IdentityKey(),
		msg.Message(),
	)
	if err != nil {
		t.Fatalf("case %d: NewPreKeySignalMessage: %v", i, err)
	}
	if !bytes.Equal(rebuilt.Serialize(), want) {
		t.Fatalf("case %d: re-serialized != upstream\n go   %x\n want %x", i, rebuilt.Serialize(), want)
	}
}

// parseUUID16 decodes a canonical UUID string into a 16-byte array.
func parseUUID16(t *testing.T, s string) [16]byte {
	t.Helper()
	clean := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			clean = append(clean, s[i])
		}
	}
	raw, err := hex.DecodeString(string(clean))
	if err != nil || len(raw) != 16 {
		t.Fatalf("bad uuid %q: %v", s, err)
	}
	var out [16]byte
	copy(out[:], raw)
	return out
}

func testSenderKeyMessageCase(t *testing.T, i int, c messageCase) {
	t.Helper()
	want := mustHex(t, c.Serialized)

	// Deserialize upstream bytes -> field equality.
	msg, err := protocol.DeserializeSenderKeyMessage(want)
	if err != nil {
		t.Fatalf("case %d: DeserializeSenderKeyMessage: %v", i, err)
	}
	distID := parseUUID16(t, c.DistributionID)
	if msg.DistributionID() != distID {
		t.Fatalf("case %d: distribution id = %x, want %x", i, msg.DistributionID(), distID)
	}
	if msg.ChainID() != c.ChainID || msg.Iteration() != c.Iteration {
		t.Fatalf("case %d: chainID/iteration = %d/%d, want %d/%d", i, msg.ChainID(), msg.Iteration(), c.ChainID, c.Iteration)
	}
	if !bytes.Equal(msg.Ciphertext(), mustHex(t, c.Ciphertext)) {
		t.Fatalf("case %d: ciphertext mismatch", i)
	}

	// Re-serialize from the same inputs (replaying the recorded signing nonce) ->
	// byte equality with upstream.
	signPriv, err := curve.DeserializePrivateKey(mustHex(t, c.SigningPrivate))
	if err != nil {
		t.Fatalf("case %d: signing_private: %v", i, err)
	}
	nonce := mustHex(t, c.Nonce)
	rebuilt, err := protocol.NewSenderKeyMessage(distID, c.ChainID, c.Iteration, mustHex(t, c.Ciphertext), bytes.NewReader(nonce), signPriv)
	if err != nil {
		t.Fatalf("case %d: NewSenderKeyMessage: %v", i, err)
	}
	if !bytes.Equal(rebuilt.Serialized(), want) {
		t.Fatalf("case %d: re-serialized != upstream\n go   %x\n want %x", i, rebuilt.Serialized(), want)
	}
}

func testSenderKeyDistributionMessageCase(t *testing.T, i int, c messageCase) {
	t.Helper()
	want := mustHex(t, c.Serialized)

	msg, err := protocol.DeserializeSenderKeyDistributionMessage(want)
	if err != nil {
		t.Fatalf("case %d: DeserializeSenderKeyDistributionMessage: %v", i, err)
	}
	distID := parseUUID16(t, c.DistributionID)
	if msg.DistributionID() != distID {
		t.Fatalf("case %d: distribution id mismatch", i)
	}
	if msg.ChainID() != c.ChainID || msg.Iteration() != c.Iteration {
		t.Fatalf("case %d: chainID/iteration mismatch", i)
	}
	if !bytes.Equal(msg.ChainKey(), mustHex(t, c.ChainKey)) {
		t.Fatalf("case %d: chain_key mismatch", i)
	}

	signPub, err := curve.DeserializePublicKey(mustHex(t, c.SigningPublic))
	if err != nil {
		t.Fatalf("case %d: signing_public: %v", i, err)
	}
	rebuilt, err := protocol.NewSenderKeyDistributionMessage(distID, c.ChainID, c.Iteration, mustHex(t, c.ChainKey), signPub)
	if err != nil {
		t.Fatalf("case %d: NewSenderKeyDistributionMessage: %v", i, err)
	}
	if !bytes.Equal(rebuilt.Serialized(), want) {
		t.Fatalf("case %d: re-serialized != upstream\n go   %x\n want %x", i, rebuilt.Serialized(), want)
	}
}

// --- fingerprint ---
//
// The Go fingerprint package does not exist yet (T25). Per the task, assert the
// vector file parses with cases present, and leave a TODO(T25) consuming test.

func TestFingerprintVectors(t *testing.T) {
	var batch struct {
		Cases []struct {
			Version   uint32 `json:"version"`
			Display   string `json:"display"`
			Scannable string `json:"scannable"`
		} `json:"cases"`
	}
	loadVectors(t, "fingerprint", &batch)
	if len(batch.Cases) == 0 {
		t.Fatal("fingerprint: no cases")
	}
	// TODO(T25): once a Go fingerprint package exists, recompute display +
	// scannable from local/remote keys and assert equality with these vectors.
	for i, c := range batch.Cases {
		if c.Display == "" || len(mustHex(t, c.Scannable)) == 0 {
			t.Fatalf("fingerprint case %d: empty display or scannable", i)
		}
	}
	t.Logf("fingerprint: %d cases parsed (TODO(T25) consuming test once Go fingerprint pkg exists)", len(batch.Cases))
}
