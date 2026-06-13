// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package sealedsender

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/protocol"
)

// sealTestFixture builds a sender identity, recipient identity, and a valid USMC
// sealed-sender-ready (sender cert signed by a server cert under a trust root).
type sealTestFixture struct {
	senderIdentity    curve.KeyPair
	recipientIdentity curve.KeyPair
	trustRoot         curve.PublicKey
	usmc              *UnidentifiedSenderMessageContent
	contents          []byte
}

func newSealFixture(t *testing.T) *sealTestFixture {
	t.Helper()
	trustRoot := genKey(t, 70)
	serverKey := genKey(t, 71)
	senderIdentity := genKey(t, 72)
	recipientIdentity := genKey(t, 73)

	server, err := NewServerCertificate(1, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("NewServerCertificate: %v", err)
	}
	senderCert, err := NewSenderCertificate("sender-uuid", nil, senderIdentity.PublicKey, 1,
		time.UnixMilli(2_000_000_000_000).UTC(), server, serverKey.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("NewSenderCertificate: %v", err)
	}
	contents := []byte("sealed sender payload")
	usmc, err := NewUnidentifiedSenderMessageContent(protocol.MessageTypeWhisper, senderCert, contents, ContentHintResendable, []byte("group-1"))
	if err != nil {
		t.Fatalf("New USMC: %v", err)
	}
	return &sealTestFixture{
		senderIdentity:    senderIdentity,
		recipientIdentity: recipientIdentity,
		trustRoot:         trustRoot.PublicKey,
		usmc:              usmc,
		contents:          contents,
	}
}

func TestSealV1RoundTrip(t *testing.T) {
	f := newSealFixture(t)

	sealed, err := SealV1(f.usmc, f.senderIdentity, f.recipientIdentity.PublicKey, rand.Reader)
	if err != nil {
		t.Fatalf("SealV1: %v", err)
	}
	if sealed[0] != sealedSenderV1FullVersion {
		t.Fatalf("version byte = 0x%02x, want 0x%02x", sealed[0], sealedSenderV1FullVersion)
	}

	// Decrypt without validation: recovers the USMC and its fields.
	got, err := DecryptToUSMC(sealed, f.recipientIdentity)
	if err != nil {
		t.Fatalf("DecryptToUSMC: %v", err)
	}
	if !bytes.Equal(got.Contents(), f.contents) {
		t.Fatalf("contents = %q, want %q", got.Contents(), f.contents)
	}
	if got.MessageType() != protocol.MessageTypeWhisper {
		t.Fatalf("msg type = %d", got.MessageType())
	}
	if got.ContentHint() != ContentHintResendable {
		t.Fatalf("content hint = %v", got.ContentHint())
	}
	if gid, ok := got.GroupID(); !ok || !bytes.Equal(gid, []byte("group-1")) {
		t.Fatalf("group id = %x ok=%v", gid, ok)
	}
	// The recovered sender certificate names our sender and validates.
	if got.Sender().SenderUUID() != "sender-uuid" {
		t.Fatalf("sender uuid = %q", got.Sender().SenderUUID())
	}

	// Decrypt-and-validate enforces the trust root + expiry on the sender cert.
	validated, err := DecryptToUSMCAndValidate(sealed, f.recipientIdentity, f.trustRoot, time.UnixMilli(1_500_000_000_000).UTC())
	if err != nil {
		t.Fatalf("DecryptToUSMCAndValidate: %v", err)
	}
	if !bytes.Equal(validated.Contents(), f.contents) {
		t.Fatal("validated contents mismatch")
	}
}

func TestSealV1WrongRecipient(t *testing.T) {
	f := newSealFixture(t)
	sealed, err := SealV1(f.usmc, f.senderIdentity, f.recipientIdentity.PublicKey, rand.Reader)
	if err != nil {
		t.Fatalf("SealV1: %v", err)
	}
	// A different recipient identity cannot decrypt (MAC on the encrypted-static
	// fails under the wrong ephemeral keys).
	wrong := genKey(t, 80)
	if _, err := DecryptToUSMC(sealed, wrong); !errors.Is(err, ErrBadCiphertext) {
		t.Fatalf("wrong recipient: err = %v, want ErrBadCiphertext", err)
	}
}

func TestSealV1Tampered(t *testing.T) {
	f := newSealFixture(t)
	sealed, err := SealV1(f.usmc, f.senderIdentity, f.recipientIdentity.PublicKey, rand.Reader)
	if err != nil {
		t.Fatalf("SealV1: %v", err)
	}
	// Flip a byte in the encrypted message region (near the end, before nothing
	// structural) -> MAC failure.
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := DecryptToUSMC(tampered, f.recipientIdentity); !errors.Is(err, ErrBadCiphertext) {
		t.Fatalf("tampered: err = %v, want ErrBadCiphertext", err)
	}
}

func TestSealV1ExpiredCertRejected(t *testing.T) {
	f := newSealFixture(t)
	sealed, err := SealV1(f.usmc, f.senderIdentity, f.recipientIdentity.PublicKey, rand.Reader)
	if err != nil {
		t.Fatalf("SealV1: %v", err)
	}
	// Validate at a time past the cert's expiration (2_000_000_000_000) -> the
	// decrypt succeeds but validation fails.
	_, err = DecryptToUSMCAndValidate(sealed, f.recipientIdentity, f.trustRoot, time.UnixMilli(2_000_000_000_001).UTC())
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expired cert: err = %v, want ErrInvalidCertificate", err)
	}
}

func TestDecryptUnknownVersion(t *testing.T) {
	recipient := genKey(t, 90)
	if _, err := DecryptToUSMC([]byte{0x99, 0x00}, recipient); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("unknown version: err = %v, want ErrUnknownVersion", err)
	}
	if _, err := DecryptToUSMC(nil, recipient); !errors.Is(err, ErrInvalidSealedSenderMessage) {
		t.Fatalf("empty: err = %v, want ErrInvalidSealedSenderMessage", err)
	}
}
