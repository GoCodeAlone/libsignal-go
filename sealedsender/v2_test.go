// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package sealedsender

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
)

// v2Recipient bundles a recipient's identity key pair with the ServiceID/device
// metadata SealV2 needs, so a test can both seal to it and decrypt as it.
type v2Recipient struct {
	identity curve.KeyPair
	rcpt     SealV2Recipient
}

func newV2Recipient(t *testing.T, seed byte, uuidByte byte, deviceID, regID uint32) v2Recipient {
	t.Helper()
	id := genKey(t, seed)
	var uuid [16]byte
	copy(uuid[:], bytes.Repeat([]byte{uuidByte}, len(uuid)))
	return v2Recipient{
		identity: id,
		rcpt: SealV2Recipient{
			ServiceID:      address.NewACI(uuid),
			IdentityKey:    id.PublicKey,
			DeviceID:       deviceID,
			RegistrationID: regID,
		},
	}
}

func TestSealV2SingleRecipient(t *testing.T) {
	f := newSealFixture(t)
	r := newV2Recipient(t, 110, 0xAA, 1, 1234)

	sent, err := SealV2(f.usmc, []SealV2Recipient{r.rcpt}, f.senderIdentity, rand.Reader)
	if err != nil {
		t.Fatalf("SealV2: %v", err)
	}
	received, err := sent.ReceivedMessageForRecipient(0)
	if err != nil {
		t.Fatalf("ReceivedMessageForRecipient: %v", err)
	}
	if received[0] != sealedSenderV2FullVersion {
		t.Fatalf("received version byte = 0x%02x, want 0x%02x", received[0], sealedSenderV2FullVersion)
	}

	got, err := DecryptToUSMC(received, r.identity)
	if err != nil {
		t.Fatalf("DecryptToUSMC: %v", err)
	}
	if !bytes.Equal(got.Contents(), f.contents) {
		t.Fatalf("contents = %q, want %q", got.Contents(), f.contents)
	}
	if got.Sender().SenderUUID() != "sender-uuid" {
		t.Fatalf("sender uuid = %q", got.Sender().SenderUUID())
	}
	// Validate the recovered sender cert against the trust root.
	if _, err := DecryptToUSMCAndValidate(received, r.identity, f.trustRoot, time.UnixMilli(1_500_000_000_000).UTC()); err != nil {
		t.Fatalf("DecryptToUSMCAndValidate: %v", err)
	}
}

func TestSealV2ThreeRecipients(t *testing.T) {
	f := newSealFixture(t)
	rs := []v2Recipient{
		newV2Recipient(t, 120, 0x01, 1, 1001),
		newV2Recipient(t, 121, 0x02, 1, 1002),
		newV2Recipient(t, 122, 0x03, 1, 1003),
	}
	rcpts := []SealV2Recipient{rs[0].rcpt, rs[1].rcpt, rs[2].rcpt}

	sent, err := SealV2(f.usmc, rcpts, f.senderIdentity, rand.Reader)
	if err != nil {
		t.Fatalf("SealV2: %v", err)
	}

	// Each recipient recovers the same plaintext from its own fan-out message.
	for i, r := range rs {
		received, err := sent.ReceivedMessageForRecipient(i)
		if err != nil {
			t.Fatalf("recipient %d: ReceivedMessageForRecipient: %v", i, err)
		}
		got, err := DecryptToUSMC(received, r.identity)
		if err != nil {
			t.Fatalf("recipient %d: DecryptToUSMC: %v", i, err)
		}
		if !bytes.Equal(got.Contents(), f.contents) {
			t.Fatalf("recipient %d: contents = %q, want %q", i, got.Contents(), f.contents)
		}
	}

	// A recipient cannot decrypt another recipient's fan-out message (the
	// per-recipient C/AT are keyed to that recipient's identity).
	otherReceived, err := sent.ReceivedMessageForRecipient(1)
	if err != nil {
		t.Fatalf("ReceivedMessageForRecipient: %v", err)
	}
	if _, err := DecryptToUSMC(otherReceived, rs[0].identity); err == nil {
		t.Fatal("recipient 0 decrypted recipient 1's message")
	}
}

func TestSealV2Tampered(t *testing.T) {
	f := newSealFixture(t)
	r := newV2Recipient(t, 130, 0xBB, 1, 1234)
	sent, err := SealV2(f.usmc, []SealV2Recipient{r.rcpt}, f.senderIdentity, rand.Reader)
	if err != nil {
		t.Fatalf("SealV2: %v", err)
	}
	received, err := sent.ReceivedMessageForRecipient(0)
	if err != nil {
		t.Fatalf("ReceivedMessageForRecipient: %v", err)
	}

	// Flip a byte in the AEAD ciphertext tail -> GCM-SIV tag failure.
	tampered := append([]byte(nil), received...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := DecryptToUSMC(tampered, r.identity); !errors.Is(err, ErrBadCiphertext) {
		t.Fatalf("tampered ciphertext: err = %v, want ErrBadCiphertext", err)
	}

	// Flip a byte in the encrypted message key C -> derived ephemeral mismatch.
	tampered2 := append([]byte(nil), received...)
	tampered2[1] ^= 0x01 // first byte of C (after the version byte)
	if _, err := DecryptToUSMC(tampered2, r.identity); err == nil {
		t.Fatal("tampered C decrypted successfully")
	}
}

func TestSealV2WrongRecipient(t *testing.T) {
	f := newSealFixture(t)
	r := newV2Recipient(t, 140, 0xCC, 1, 1234)
	sent, err := SealV2(f.usmc, []SealV2Recipient{r.rcpt}, f.senderIdentity, rand.Reader)
	if err != nil {
		t.Fatalf("SealV2: %v", err)
	}
	received, err := sent.ReceivedMessageForRecipient(0)
	if err != nil {
		t.Fatalf("ReceivedMessageForRecipient: %v", err)
	}
	wrong := genKey(t, 150)
	if _, err := DecryptToUSMC(received, wrong); err == nil {
		t.Fatal("wrong recipient decrypted a v2 message")
	}
}

func TestSealV2NoRecipients(t *testing.T) {
	f := newSealFixture(t)
	if _, err := SealV2(f.usmc, nil, f.senderIdentity, rand.Reader); !errors.Is(err, ErrInvalidUSMC) {
		t.Fatalf("no recipients: err = %v, want ErrInvalidUSMC", err)
	}
}

// FuzzDecryptToUSMC confirms the v1 and v2 sealed-sender decrypt entry never
// panics on arbitrary bytes. Seeds with a valid v1 and a valid v2 received
// message plus a fresh recipient key.
func FuzzDecryptToUSMC(f *testing.F) {
	recipient, err := seedKey(160)
	if err == nil {
		if v1, v2, ok := buildSealedSeeds(recipient); ok {
			f.Add(v1)
			f.Add(v2)
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x11})
	f.Add([]byte{0x22})
	f.Add([]byte{0x23, 0x01})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = DecryptToUSMC(data, recipient)
	})
}

// buildSealedSeeds builds a valid v1 message and a valid v2 received message for
// the given recipient, for the fuzz seed corpus. Returns ok=false on any
// (unexpected) construction error.
func buildSealedSeeds(recipient curve.KeyPair) (v1Msg, v2Msg []byte, ok bool) {
	trustRoot, err := seedKey(161)
	if err != nil {
		return nil, nil, false
	}
	serverKey, err := seedKey(162)
	if err != nil {
		return nil, nil, false
	}
	senderIdentity, err := seedKey(163)
	if err != nil {
		return nil, nil, false
	}
	server, err := NewServerCertificate(1, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader)
	if err != nil {
		return nil, nil, false
	}
	senderCert, err := NewSenderCertificate("u", nil, senderIdentity.PublicKey, 1,
		time.UnixMilli(2_000_000_000_000).UTC(), server, serverKey.PrivateKey, rand.Reader)
	if err != nil {
		return nil, nil, false
	}
	usmc, err := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("seed"), ContentHintResendable, nil)
	if err != nil {
		return nil, nil, false
	}
	v1Msg, err = SealV1(usmc, senderIdentity, recipient.PublicKey, rand.Reader)
	if err != nil {
		return nil, nil, false
	}
	var uuid [16]byte
	sent, err := SealV2(usmc, []SealV2Recipient{{
		ServiceID:      address.NewACI(uuid),
		IdentityKey:    recipient.PublicKey,
		DeviceID:       1,
		RegistrationID: 1,
	}}, senderIdentity, rand.Reader)
	if err != nil {
		return nil, nil, false
	}
	v2Msg, err = sent.ReceivedMessageForRecipient(0)
	if err != nil {
		return nil, nil, false
	}
	return v1Msg, v2Msg, true
}
