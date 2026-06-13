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
	"github.com/GoCodeAlone/libsignal-go/proto"
	googleproto "google.golang.org/protobuf/proto"
)

// fixedReader yields deterministic bytes for reproducible key generation.
type fixedReader struct{ b byte }

func (r *fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
		r.b++
	}
	return len(p), nil
}

func genKey(t *testing.T, seed byte) curve.KeyPair {
	t.Helper()
	kp, err := curve.GenerateKeyPair(&fixedReader{b: seed})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

// --- ServerCertificate ---

func TestServerCertificateValidate(t *testing.T) {
	trustRoot := genKey(t, 1)
	serverKey := genKey(t, 2)

	sc, err := NewServerCertificate(99, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("NewServerCertificate: %v", err)
	}

	// Round-trip through the wire form.
	parsed, err := DeserializeServerCertificate(sc.Serialized())
	if err != nil {
		t.Fatalf("DeserializeServerCertificate: %v", err)
	}
	if parsed.KeyID() != 99 {
		t.Fatalf("key id = %d, want 99", parsed.KeyID())
	}
	if !bytes.Equal(parsed.PublicKey().Serialize(), serverKey.PublicKey.Serialize()) {
		t.Fatal("parsed server key mismatch")
	}

	// Valid signature against the real trust root.
	if !parsed.Validate(trustRoot.PublicKey) {
		t.Fatal("valid server certificate failed to validate against its trust root")
	}

	// Wrong trust root -> invalid.
	wrongRoot := genKey(t, 3)
	if parsed.Validate(wrongRoot.PublicKey) {
		t.Fatal("server certificate validated against the wrong trust root")
	}
}

func TestServerCertificateRevokedKeyID(t *testing.T) {
	trustRoot := genKey(t, 4)
	serverKey := genKey(t, 5)

	// 0xDEADC357 is the revoked test id: a valid trust-root signature must still
	// be rejected.
	sc, err := NewServerCertificate(0xDEADC357, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("NewServerCertificate: %v", err)
	}
	if sc.Validate(trustRoot.PublicKey) {
		t.Fatal("revoked server certificate id was accepted")
	}
}

func TestServerCertificateDeserializeRejectsMalformed(t *testing.T) {
	if _, err := DeserializeServerCertificate([]byte{0xFF, 0xFF, 0xFF}); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("garbage bytes: err = %v, want ErrInvalidCertificate", err)
	}
	// Outer wrapper present but inner certificate missing required fields.
	empty, _ := googleproto.Marshal(&proto.ServerCertificate{
		Certificate: []byte{}, // decodes to an empty inner cert (no id/key)
		Signature:   []byte{0x01},
	})
	if _, err := DeserializeServerCertificate(empty); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("empty inner cert: err = %v, want ErrInvalidCertificate", err)
	}
}

// --- SenderCertificate ---

// makeSenderCert builds a full valid chain: trust root -> server cert -> sender
// cert, with the sender certificate expiring at expiration. Returns the sender
// cert and the trust-root public key for validation.
func makeSenderCert(t *testing.T, expiration time.Time) (*SenderCertificate, curve.PublicKey) {
	t.Helper()
	trustRoot := genKey(t, 10)
	serverKey := genKey(t, 11)
	senderIdentity := genKey(t, 12)

	server, err := NewServerCertificate(7, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("NewServerCertificate: %v", err)
	}
	e164 := "+15551234567"
	sender, err := NewSenderCertificate(
		"de305d54-75b4-431b-adb2-eb6b9e546014",
		&e164,
		senderIdentity.PublicKey,
		3,
		expiration,
		server,
		serverKey.PrivateKey,
		rand.Reader,
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate: %v", err)
	}
	return sender, trustRoot.PublicKey
}

func TestSenderCertificateValidChain(t *testing.T) {
	expiration := time.UnixMilli(2_000_000_000_000).UTC() // far future
	sender, trustRoot := makeSenderCert(t, expiration)

	// Round-trip.
	parsed, err := DeserializeSenderCertificate(sender.Serialized())
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate: %v", err)
	}
	if parsed.SenderUUID() != "de305d54-75b4-431b-adb2-eb6b9e546014" {
		t.Fatalf("sender uuid = %q", parsed.SenderUUID())
	}
	if parsed.SenderDeviceID() != 3 {
		t.Fatalf("sender device = %d, want 3", parsed.SenderDeviceID())
	}
	if e164, ok := parsed.SenderE164(); !ok || e164 != "+15551234567" {
		t.Fatalf("sender e164 = %q ok=%v", e164, ok)
	}
	if !parsed.Expiration().Equal(expiration) {
		t.Fatalf("expiration = %s, want %s", parsed.Expiration(), expiration)
	}

	// Valid well before expiration.
	ok, err := parsed.Validate(trustRoot, WithClock(expiration.Add(-time.Hour)))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !ok {
		t.Fatal("valid sender certificate failed to validate")
	}
}

func TestSenderCertificateWrongTrustRoot(t *testing.T) {
	expiration := time.UnixMilli(2_000_000_000_000).UTC()
	sender, _ := makeSenderCert(t, expiration)
	wrongRoot := genKey(t, 99)

	ok, err := sender.Validate(wrongRoot.PublicKey, WithClock(expiration.Add(-time.Hour)))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ok {
		t.Fatal("sender certificate validated under the wrong trust root")
	}
}

func TestSenderCertificateInvalidServerSignature(t *testing.T) {
	expiration := time.UnixMilli(2_000_000_000_000).UTC()
	sender, trustRoot := makeSenderCert(t, expiration)

	// Tamper the sender cert's signature so the server-cert chain step fails
	// (the signer cert is still valid under the trust root; only the sender
	// signature is bad).
	raw := sender.Serialized()
	var pb proto.SenderCertificate
	if err := googleproto.Unmarshal(raw, &pb); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sig := pb.GetSignature()
	sig[0] ^= 0x01
	pb.Signature = sig
	tampered, _ := googleproto.Marshal(&pb)

	parsed, err := DeserializeSenderCertificate(tampered)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate: %v", err)
	}
	ok, err := parsed.Validate(trustRoot, WithClock(expiration.Add(-time.Hour)))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ok {
		t.Fatal("sender certificate with a bad server signature was accepted")
	}
}

func TestSenderCertificateExpired(t *testing.T) {
	expiration := time.UnixMilli(1_000_000_000_000).UTC()
	sender, trustRoot := makeSenderCert(t, expiration)

	// At exactly the expiration it is still valid (strict >).
	okAt, err := sender.Validate(trustRoot, WithClock(expiration))
	if err != nil {
		t.Fatalf("Validate at expiration: %v", err)
	}
	if !okAt {
		t.Fatal("sender certificate rejected exactly at expiration (should be inclusive)")
	}

	// One millisecond past expiration -> invalid.
	okPast, err := sender.Validate(trustRoot, WithClock(expiration.Add(time.Millisecond)))
	if err != nil {
		t.Fatalf("Validate past expiration: %v", err)
	}
	if okPast {
		t.Fatal("expired sender certificate was accepted")
	}

	// IsExpired distinguishes expiry and wraps ErrExpiredCertificate.
	expired, eerr := sender.IsExpired(expiration.Add(time.Millisecond))
	if !expired || !errors.Is(eerr, ErrExpiredCertificate) {
		t.Fatalf("IsExpired past = (%v, %v), want (true, ErrExpiredCertificate)", expired, eerr)
	}
	if exp0, _ := sender.IsExpired(expiration); exp0 {
		t.Fatal("IsExpired reported expired exactly at expiration")
	}
}

// TestSenderCertificatePreEpochExpirationRejected confirms NewSenderCertificate
// rejects an expiration before the Unix epoch with a typed error instead of
// silently wrapping the negative epoch-millis into a huge uint64 (the proto's
// fixed64 expires field is unsigned, so a pre-epoch time cannot round-trip).
func TestSenderCertificatePreEpochExpirationRejected(t *testing.T) {
	trustRoot := genKey(t, 60)
	serverKey := genKey(t, 61)
	senderIdentity := genKey(t, 62)
	server, err := NewServerCertificate(1, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("NewServerCertificate: %v", err)
	}

	preEpoch := time.UnixMilli(-1).UTC()
	_, err = NewSenderCertificate("u", nil, senderIdentity.PublicKey, 1, preEpoch, server, serverKey.PrivateKey, rand.Reader)
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("pre-epoch expiration: err = %v, want ErrInvalidCertificate", err)
	}

	// The Unix epoch itself (0 ms) is accepted — only strictly-negative is rejected.
	if _, err := NewSenderCertificate("u", nil, senderIdentity.PublicKey, 1, time.UnixMilli(0).UTC(), server, serverKey.PrivateKey, rand.Reader); err != nil {
		t.Fatalf("epoch-zero expiration unexpectedly rejected: %v", err)
	}
}

func TestSenderCertificateUUIDBytesForm(t *testing.T) {
	// A sender certificate whose uuid is carried as 16 raw bytes must deserialize
	// to the canonical hyphenated string.
	trustRoot := genKey(t, 20)
	serverKey := genKey(t, 21)
	senderIdentity := genKey(t, 22)
	server, err := NewServerCertificate(1, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("NewServerCertificate: %v", err)
	}

	raw16 := []byte{
		0xde, 0x30, 0x5d, 0x54, 0x75, 0xb4, 0x43, 0x1b,
		0xad, 0xb2, 0xeb, 0x6b, 0x9e, 0x54, 0x60, 0x14,
	}
	device := uint32(2)
	expires := uint64(2_000_000_000_000)
	identityKey := senderIdentity.PublicKey.Serialize()
	certData := &proto.SenderCertificate_Certificate{
		SenderUuid:   &proto.SenderCertificate_Certificate_UuidBytes{UuidBytes: raw16},
		SenderDevice: &device,
		Expires:      &expires,
		IdentityKey:  identityKey,
		Signer:       &proto.SenderCertificate_Certificate_Certificate{Certificate: server.Serialized()},
	}
	certBytes, _ := googleproto.Marshal(certData)
	sig, err := serverKey.PrivateKey.CalculateSignature(rand.Reader, certBytes)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	wire, _ := googleproto.Marshal(&proto.SenderCertificate{Certificate: certBytes, Signature: sig})

	parsed, err := DeserializeSenderCertificate(wire)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate: %v", err)
	}
	if want := "de305d54-75b4-431b-adb2-eb6b9e546014"; parsed.SenderUUID() != want {
		t.Fatalf("uuid from bytes = %q, want %q", parsed.SenderUUID(), want)
	}
}

func TestSenderCertificateReferenceSignerUnsupported(t *testing.T) {
	// A sender certificate that references its signer by id (rather than
	// embedding it) cannot be validated here — the known-certificate table is not
	// carried in this package — so Validate must report a typed error.
	trustRoot := genKey(t, 30)
	senderIdentity := genKey(t, 31)
	signerKey := genKey(t, 32)

	device := uint32(1)
	expires := uint64(2_000_000_000_000)
	identityKey := senderIdentity.PublicKey.Serialize()
	signerID := uint32(0x1234)
	certData := &proto.SenderCertificate_Certificate{
		SenderUuid:   &proto.SenderCertificate_Certificate_UuidString{UuidString: "u"},
		SenderDevice: &device,
		Expires:      &expires,
		IdentityKey:  identityKey,
		Signer:       &proto.SenderCertificate_Certificate_Id{Id: signerID},
	}
	certBytes, _ := googleproto.Marshal(certData)
	sig, _ := signerKey.PrivateKey.CalculateSignature(rand.Reader, certBytes)
	wire, _ := googleproto.Marshal(&proto.SenderCertificate{Certificate: certBytes, Signature: sig})

	parsed, err := DeserializeSenderCertificate(wire)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate: %v", err)
	}
	if id, ok := parsed.SignerID(); !ok || id != signerID {
		t.Fatalf("SignerID = (%d, %v), want (%d, true)", id, ok, signerID)
	}
	ok, verr := parsed.Validate(trustRoot.PublicKey)
	if ok {
		t.Fatal("reference-signer sender certificate validated")
	}
	if !errors.Is(verr, ErrUnknownServerCertificateID) {
		t.Fatalf("Validate err = %v, want ErrUnknownServerCertificateID", verr)
	}
}

func TestSenderCertificateDeserializeRejectsMalformed(t *testing.T) {
	if _, err := DeserializeSenderCertificate([]byte{0x07, 0x07, 0x07}); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("garbage: err = %v, want ErrInvalidCertificate", err)
	}
}

// seedKey builds a keypair from a fixed seed without a *testing.T, for use in
// fuzz seed-corpus construction (where generation from a fixed reader cannot
// fail in practice).
func seedKey(seed byte) (curve.KeyPair, error) {
	return curve.GenerateKeyPair(&fixedReader{b: seed})
}

// FuzzDeserializeServerCertificate confirms parsing arbitrary bytes never panics.
func FuzzDeserializeServerCertificate(f *testing.F) {
	if trustRoot, err := seedKey(40); err == nil {
		if serverKey, err := seedKey(41); err == nil {
			if sc, err := NewServerCertificate(1, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader); err == nil {
				f.Add(sc.Serialized())
			}
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = DeserializeServerCertificate(data)
	})
}

// FuzzDeserializeSenderCertificate confirms parsing arbitrary bytes never panics.
func FuzzDeserializeSenderCertificate(f *testing.F) {
	if seed := buildSenderCertSeed(); seed != nil {
		f.Add(seed)
	}
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x02})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = DeserializeSenderCertificate(data)
	})
}

// buildSenderCertSeed assembles a valid serialized SenderCertificate for the
// fuzz seed corpus, returning nil on any (unexpected) construction error.
func buildSenderCertSeed() []byte {
	trustRoot, err := seedKey(42)
	if err != nil {
		return nil
	}
	serverKey, err := seedKey(43)
	if err != nil {
		return nil
	}
	senderIdentity, err := seedKey(44)
	if err != nil {
		return nil
	}
	server, err := NewServerCertificate(1, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader)
	if err != nil {
		return nil
	}
	sender, err := NewSenderCertificate("u", nil, senderIdentity.PublicKey, 1,
		time.UnixMilli(2_000_000_000_000).UTC(), server, serverKey.PrivateKey, rand.Reader)
	if err != nil {
		return nil
	}
	return sender.Serialized()
}
