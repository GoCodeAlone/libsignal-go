// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build interop

// Sealed sender interop: drives the genuine upstream sealed-sender API (v0.91.0)
// in the Rust harness against the pure-Go sealedsender package, proving both
// impls agree on the v1 ciphertext format (both directions) and that Go's v2
// received-message form decrypts under upstream. Go builds the certificate chain
// and USMC (T23) and seals/decrypts (T24); the harness seals/unseals via
// sealed_sender_encrypt_from_usmc / sealed_sender_decrypt_to_usmc.
//
// Gated behind the `interop` build tag and driven via COMPAT_HARNESS_BIN (see
// interop_test.go for the client).
package compat

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/protocol"
	"github.com/GoCodeAlone/libsignal-go/sealedsender"
)

// sealedParties holds the sender + recipient identities and a valid USMC (sender
// cert signed by a server cert under a trust root) for the sealed-sender interop.
type sealedParties struct {
	sender    curve.KeyPair
	recipient curve.KeyPair
	trustRoot curve.PublicKey
	usmc      *sealedsender.UnidentifiedSenderMessageContent
	contents  []byte
}

func newSealedParties(t *testing.T) *sealedParties {
	t.Helper()
	gen := func() curve.KeyPair {
		kp, err := curve.GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		return kp
	}
	trustRoot := gen()
	serverKey := gen()
	sender := gen()
	recipient := gen()

	server, err := sealedsender.NewServerCertificate(1, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("NewServerCertificate: %v", err)
	}
	senderCert, err := sealedsender.NewSenderCertificate(
		"de305d54-75b4-431b-adb2-eb6b9e546014", nil, sender.PublicKey, 1,
		time.UnixMilli(2_000_000_000_000).UTC(), server, serverKey.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("NewSenderCertificate: %v", err)
	}
	contents := []byte("sealed sender interop payload")
	usmc, err := sealedsender.NewUnidentifiedSenderMessageContent(
		protocol.MessageTypeWhisper, senderCert, contents, sealedsender.ContentHintResendable, []byte("group-x"))
	if err != nil {
		t.Fatalf("New USMC: %v", err)
	}
	return &sealedParties{
		sender:    sender,
		recipient: recipient,
		trustRoot: trustRoot.PublicKey,
		usmc:      usmc,
		contents:  contents,
	}
}

// assertRecoveredUSMC checks a recovered USMC carries the expected contents and a
// sender certificate that validates against the trust root.
func (p *sealedParties) assertRecoveredUSMC(t *testing.T, got *sealedsender.UnidentifiedSenderMessageContent) {
	t.Helper()
	if !bytes.Equal(got.Contents(), p.contents) {
		t.Fatalf("contents = %q, want %q", got.Contents(), p.contents)
	}
	valid, err := got.Sender().Validate(p.trustRoot, sealedsender.WithClock(time.UnixMilli(1_500_000_000_000).UTC()))
	if err != nil || !valid {
		t.Fatalf("recovered sender cert validate = (%v, %v), want (true, nil)", valid, err)
	}
}

// TestSealedInteropGoSealV1RustUnseal: Go seals a v1 message; the genuine
// upstream sealed_sender_decrypt_to_usmc recovers the USMC.
func TestSealedInteropGoSealV1RustUnseal(t *testing.T) {
	h := newHarness(t)
	p := newSealedParties(t)

	sealed, err := sealedsender.SealV1(p.usmc, p.sender, p.recipient.PublicKey, rand.Reader)
	if err != nil {
		t.Fatalf("Go SealV1: %v", err)
	}

	var res struct {
		USMC string `json:"usmc"`
	}
	h.ok("sealed.unseal", map[string]any{
		"sealed":                     hx(sealed),
		"recipient_identity_private": hx(p.recipient.PrivateKey.Serialize()),
	}, &res)

	// Rust returns the recovered USMC bytes; Go re-parses + validates them.
	got, err := sealedsender.DeserializeUnidentifiedSenderMessageContent(mustDecodeHex(t, res.USMC))
	if err != nil {
		t.Fatalf("re-parse recovered USMC: %v", err)
	}
	p.assertRecoveredUSMC(t, got)
}

// TestSealedInteropRustSealV1GoUnseal: the genuine upstream seals a v1 message
// (sealed_sender_encrypt_from_usmc); Go decrypts and validates it.
func TestSealedInteropRustSealV1GoUnseal(t *testing.T) {
	h := newHarness(t)
	p := newSealedParties(t)

	var res struct {
		Sealed string `json:"sealed"`
	}
	h.ok("sealed.seal-v1", map[string]any{
		"usmc":                      hx(p.usmc.Serialized()),
		"sender_identity_private":   hx(p.sender.PrivateKey.Serialize()),
		"recipient_identity_public": hx(p.recipient.PublicKey.Serialize()),
	}, &res)

	sealed := mustDecodeHex(t, res.Sealed)
	got, err := sealedsender.DecryptToUSMCAndValidate(sealed, p.recipient, p.trustRoot, time.UnixMilli(1_500_000_000_000).UTC())
	if err != nil {
		t.Fatalf("Go DecryptToUSMCAndValidate: %v", err)
	}
	p.assertRecoveredUSMC(t, got)
}

// TestSealedInteropGoSealV2RustUnseal: Go seals a v2 message to a single
// recipient and produces that recipient's received form; the genuine upstream
// decrypts it. Exercises the v2 KEM + AES-256-GCM-SIV path cross-impl.
func TestSealedInteropGoSealV2RustUnseal(t *testing.T) {
	h := newHarness(t)
	p := newSealedParties(t)

	var uuid [16]byte
	copy(uuid[:], bytes.Repeat([]byte{0x42}, len(uuid)))
	sent, err := sealedsender.SealV2(p.usmc, []sealedsender.SealV2Recipient{{
		ServiceID:      address.NewACI(uuid),
		IdentityKey:    p.recipient.PublicKey,
		DeviceID:       1,
		RegistrationID: 1,
	}}, p.sender, rand.Reader)
	if err != nil {
		t.Fatalf("Go SealV2: %v", err)
	}
	received, err := sent.ReceivedMessageForRecipient(0)
	if err != nil {
		t.Fatalf("ReceivedMessageForRecipient: %v", err)
	}

	var res struct {
		USMC string `json:"usmc"`
	}
	h.ok("sealed.unseal", map[string]any{
		"sealed":                     hx(received),
		"recipient_identity_private": hx(p.recipient.PrivateKey.Serialize()),
	}, &res)

	got, err := sealedsender.DeserializeUnidentifiedSenderMessageContent(mustDecodeHex(t, res.USMC))
	if err != nil {
		t.Fatalf("re-parse recovered USMC: %v", err)
	}
	p.assertRecoveredUSMC(t, got)
}

// TestSealedInteropRustSealV2GoUnseal: the genuine upstream multi-recipient
// encoder (sealed_sender_multi_recipient_encrypt) seals to N recipients; the
// harness fans out each recipient's received message; Go decrypts and validates
// every one. This closes the v2 reverse direction (upstream ENCODER -> Go decode,
// incl. the multi-recipient fan-out), the leg not covered by GoSealV2RustUnseal.
func TestSealedInteropRustSealV2GoUnseal(t *testing.T) {
	h := newHarness(t)
	p := newSealedParties(t)

	const numRecipients = 3
	var res struct {
		Recipients []struct {
			IdentityPrivate string `json:"identity_private"`
			Received        string `json:"received"`
		} `json:"recipients"`
	}
	h.ok("sealed.seal-v2", map[string]any{
		"usmc":                    hx(p.usmc.Serialized()),
		"sender_identity_private": hx(p.sender.PrivateKey.Serialize()),
		"num_recipients":          numRecipients,
	}, &res)

	if len(res.Recipients) != numRecipients {
		t.Fatalf("got %d recipients, want %d", len(res.Recipients), numRecipients)
	}
	for i, r := range res.Recipients {
		priv, err := curve.DeserializePrivateKey(mustDecodeHex(t, r.IdentityPrivate))
		if err != nil {
			t.Fatalf("recipient %d: private key: %v", i, err)
		}
		recipient, err := curve.KeyPairFromPrivateKey(priv)
		if err != nil {
			t.Fatalf("recipient %d: key pair: %v", i, err)
		}
		got, err := sealedsender.DecryptToUSMCAndValidate(
			mustDecodeHex(t, r.Received), recipient, p.trustRoot, time.UnixMilli(1_500_000_000_000).UTC())
		if err != nil {
			t.Fatalf("recipient %d: Go DecryptToUSMCAndValidate: %v", i, err)
		}
		p.assertRecoveredUSMC(t, got)
	}
}
