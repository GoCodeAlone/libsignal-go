// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package sealedsender implements Signal's sealed sender certificates and
// message content (the UnidentifiedSenderMessageContent, "USMC"), a pure-Go
// port of rust/protocol/src/sealed_sender.rs validated against upstream
// libsignal v0.91.0.
//
// A ServerCertificate binds a server signing key to a key id and is signed by
// the trust root. A SenderCertificate binds a sender's identity key + address
// to an expiration and is signed by a ServerCertificate's key (the chain:
// trust-root -> server cert -> sender cert). USMC wraps an inner ciphertext
// with its sender certificate, message type, content hint, and optional group
// id for the sealed-sender encryption layer (added in a later task).
package sealedsender

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/proto"
	googleproto "google.golang.org/protobuf/proto"
)

// Errors returned by certificate parsing and validation. All are
// %w-wrappable so callers can match with errors.Is.
var (
	// ErrInvalidCertificate is returned when certificate bytes are structurally
	// invalid: bad protobuf, a missing required field, or unusable key material.
	ErrInvalidCertificate = errors.New("sealedsender: invalid certificate")
	// ErrExpiredCertificate marks an expired-but-well-formed sender certificate.
	// SenderCertificate.Validate reports overall validity via its bool result
	// (returning false when expired, matching upstream), and additionally exposes
	// IsExpired for callers that want to distinguish expiry from a bad signature;
	// this typed error is what IsExpired-aware callers can wrap/match.
	ErrExpiredCertificate = errors.New("sealedsender: certificate expired")
	// ErrUnknownServerCertificateID is returned for a SenderCertificate that
	// references its signing ServerCertificate by id (the space-saving "known
	// certificate" form) rather than embedding it. The known-certificate table is
	// not carried in this package yet (it arrives with the sealed-sender v1/v2
	// encrypt/decrypt layer); only embedded signer certificates are resolvable
	// here. Mirrors upstream's UnknownSealedSenderServerCertificateId.
	ErrUnknownServerCertificateID = errors.New("sealedsender: unknown server certificate id")
)

// revokedServerCertificateKeyIDs lists server-certificate key ids that must be
// rejected even with a valid trust-root signature. 0xDEADC357 is upstream's
// revocation-logic test id (REVOKED_SERVER_CERTIFICATE_KEY_IDS in
// sealed_sender.rs); no production certificate has been revoked.
var revokedServerCertificateKeyIDs = map[uint32]struct{}{
	0xDEADC357: {},
}

// ServerCertificate is a server signing key (with its key id) signed by the
// trust root. Mirrors ServerCertificate in sealed_sender.rs.
type ServerCertificate struct {
	keyID       uint32
	key         curve.PublicKey
	certificate []byte // serialized inner Certificate (the signed bytes)
	signature   []byte // trust-root XEdDSA signature over certificate
	serialized  []byte // serialized outer ServerCertificate
}

// DeserializeServerCertificate parses a serialized ServerCertificate. It decodes
// the outer wrapper, then the inner Certificate (key id + key), and fails with
// ErrInvalidCertificate on any missing field or bad key material. It performs no
// signature check — call Validate for that.
func DeserializeServerCertificate(data []byte) (*ServerCertificate, error) {
	var pb proto.ServerCertificate
	if err := googleproto.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("%w: server certificate protobuf: %v", ErrInvalidCertificate, err)
	}
	if pb.Certificate == nil || pb.Signature == nil {
		return nil, fmt.Errorf("%w: server certificate missing certificate/signature", ErrInvalidCertificate)
	}

	var certData proto.ServerCertificate_Certificate
	if err := googleproto.Unmarshal(pb.GetCertificate(), &certData); err != nil {
		return nil, fmt.Errorf("%w: server certificate body protobuf: %v", ErrInvalidCertificate, err)
	}
	if certData.Id == nil || certData.Key == nil {
		return nil, fmt.Errorf("%w: server certificate body missing id/key", ErrInvalidCertificate)
	}
	key, err := curve.DeserializePublicKey(certData.GetKey())
	if err != nil {
		return nil, fmt.Errorf("%w: server certificate key: %v", ErrInvalidCertificate, err)
	}

	return &ServerCertificate{
		keyID:       certData.GetId(),
		key:         key,
		certificate: cloneBytes(pb.GetCertificate()),
		signature:   cloneBytes(pb.GetSignature()),
		serialized:  cloneBytes(data),
	}, nil
}

// NewServerCertificate builds and signs a ServerCertificate: it encodes the
// inner Certificate (keyID + key), signs it with the trust-root private key
// (XEdDSA, nonce drawn from rng), and assembles the serialized wrapper. Mirrors
// ServerCertificate::new.
func NewServerCertificate(keyID uint32, key curve.PublicKey, trustRoot curve.PrivateKey, rng io.Reader) (*ServerCertificate, error) {
	id := keyID
	keyBytes := key.Serialize()
	certData := &proto.ServerCertificate_Certificate{
		Id:  &id,
		Key: keyBytes,
	}
	certificate, err := googleproto.Marshal(certData)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: marshal server certificate body: %w", err)
	}
	signature, err := trustRoot.CalculateSignature(rng, certificate)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: sign server certificate: %w", err)
	}
	serialized, err := googleproto.Marshal(&proto.ServerCertificate{
		Certificate: certificate,
		Signature:   signature,
	})
	if err != nil {
		return nil, fmt.Errorf("sealedsender: marshal server certificate: %w", err)
	}
	return &ServerCertificate{
		keyID:       keyID,
		key:         key,
		certificate: certificate,
		signature:   signature,
		serialized:  serialized,
	}, nil
}

// Validate reports whether the certificate is signed by trustRoot. A revoked
// key id is rejected (returns false) regardless of signature, mirroring
// ServerCertificate::validate. Signature failure also returns false (not an
// error); a malformed certificate cannot reach here (deserialize validates).
func (c *ServerCertificate) Validate(trustRoot curve.PublicKey) bool {
	if _, revoked := revokedServerCertificateKeyIDs[c.keyID]; revoked {
		return false
	}
	return trustRoot.VerifySignature(c.signature, c.certificate)
}

// KeyID returns the server certificate's key id.
func (c *ServerCertificate) KeyID() uint32 { return c.keyID }

// PublicKey returns the server's signing public key.
func (c *ServerCertificate) PublicKey() curve.PublicKey { return c.key }

// Certificate returns the serialized inner Certificate (the signed bytes).
func (c *ServerCertificate) Certificate() []byte { return cloneBytes(c.certificate) }

// Signature returns the trust-root signature over the inner certificate.
func (c *ServerCertificate) Signature() []byte { return cloneBytes(c.signature) }

// Serialized returns the full serialized ServerCertificate wire form.
func (c *ServerCertificate) Serialized() []byte { return cloneBytes(c.serialized) }

// SenderCertificate binds a sender's identity key and address (uuid, optional
// e164, device id) to an expiration, signed by a ServerCertificate's key.
// Mirrors SenderCertificate in sealed_sender.rs.
type SenderCertificate struct {
	signer         *ServerCertificate // nil when the signer is referenced by id (unsupported here)
	signerID       *uint32            // set when the signer is referenced by id
	key            curve.PublicKey
	senderDeviceID uint32
	senderUUID     string
	senderE164     *string
	expiration     time.Time
	certificate    []byte // serialized inner Certificate (the signed bytes)
	signature      []byte // server XEdDSA signature over certificate
	serialized     []byte // serialized outer SenderCertificate
}

// DeserializeSenderCertificate parses a serialized SenderCertificate: the outer
// wrapper, then the inner Certificate (sender address, identity key, expiration,
// and the signer — an embedded ServerCertificate or a reference id). A uuid is
// accepted as a string or as 16 raw bytes (rendered to canonical string form).
// No signature/expiry check is done — call Validate. Fails with
// ErrInvalidCertificate on any missing field or bad material.
func DeserializeSenderCertificate(data []byte) (*SenderCertificate, error) {
	var pb proto.SenderCertificate
	if err := googleproto.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("%w: sender certificate protobuf: %v", ErrInvalidCertificate, err)
	}
	if pb.Certificate == nil || pb.Signature == nil {
		return nil, fmt.Errorf("%w: sender certificate missing certificate/signature", ErrInvalidCertificate)
	}

	var certData proto.SenderCertificate_Certificate
	if err := googleproto.Unmarshal(pb.GetCertificate(), &certData); err != nil {
		return nil, fmt.Errorf("%w: sender certificate body protobuf: %v", ErrInvalidCertificate, err)
	}

	if certData.SenderDevice == nil {
		return nil, fmt.Errorf("%w: sender certificate missing sender device", ErrInvalidCertificate)
	}
	if certData.Expires == nil {
		return nil, fmt.Errorf("%w: sender certificate missing expiration", ErrInvalidCertificate)
	}
	if certData.IdentityKey == nil {
		return nil, fmt.Errorf("%w: sender certificate missing identity key", ErrInvalidCertificate)
	}
	key, err := curve.DeserializePublicKey(certData.GetIdentityKey())
	if err != nil {
		return nil, fmt.Errorf("%w: sender certificate identity key: %v", ErrInvalidCertificate, err)
	}

	out := &SenderCertificate{
		key:            key,
		senderDeviceID: certData.GetSenderDevice(),
		// expires is fixed64 milliseconds since the Unix epoch.
		//nolint:gosec // G115: epoch-millis; an out-of-range value just yields a
		// far-future/past time, which the expiration check in Validate handles.
		expiration:  time.UnixMilli(int64(certData.GetExpires())).UTC(),
		certificate: cloneBytes(pb.GetCertificate()),
		signature:   cloneBytes(pb.GetSignature()),
		serialized:  cloneBytes(data),
	}

	// Signer oneof: embedded ServerCertificate or a reference id.
	switch signer := certData.GetSigner().(type) {
	case *proto.SenderCertificate_Certificate_Certificate:
		sc, err := DeserializeServerCertificate(signer.Certificate)
		if err != nil {
			return nil, fmt.Errorf("%w: embedded server certificate: %v", ErrInvalidCertificate, err)
		}
		out.signer = sc
	case *proto.SenderCertificate_Certificate_Id:
		id := signer.Id
		out.signerID = &id
	default:
		return nil, fmt.Errorf("%w: sender certificate missing signer", ErrInvalidCertificate)
	}

	// Sender uuid oneof: string or 16 raw bytes.
	switch u := certData.GetSenderUuid().(type) {
	case *proto.SenderCertificate_Certificate_UuidString:
		out.senderUUID = u.UuidString
	case *proto.SenderCertificate_Certificate_UuidBytes:
		s, err := uuidStringFromBytes(u.UuidBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: sender uuid bytes: %v", ErrInvalidCertificate, err)
		}
		out.senderUUID = s
	default:
		return nil, fmt.Errorf("%w: sender certificate missing sender uuid", ErrInvalidCertificate)
	}

	if certData.SenderE164 != nil {
		e164 := certData.GetSenderE164()
		out.senderE164 = &e164
	}

	return out, nil
}

// NewSenderCertificate builds and signs a SenderCertificate with an embedded
// signer ServerCertificate: it encodes the inner Certificate, signs it with
// signerKey (the server's private key matching signer.PublicKey, XEdDSA nonce
// from rng), and assembles the wire form. expiration is stored to millisecond
// granularity (the proto's fixed64). Mirrors SenderCertificate::new.
func NewSenderCertificate(
	senderUUID string,
	senderE164 *string,
	key curve.PublicKey,
	senderDeviceID uint32,
	expiration time.Time,
	signer *ServerCertificate,
	signerKey curve.PrivateKey,
	rng io.Reader,
) (*SenderCertificate, error) {
	if signer == nil {
		return nil, fmt.Errorf("%w: nil signer", ErrInvalidCertificate)
	}
	deviceID := senderDeviceID
	// Store and serialize at the proto's millisecond granularity. The wire field
	// is fixed64 (UNSIGNED), so a pre-epoch expiration cannot round-trip: casting
	// its negative epoch-millis to uint64 would wrap to a huge value that
	// deserializes as a far-future expiry. Reject it up front (no panic, no
	// silent wrap).
	expirationMillis := expiration.UnixMilli()
	if expirationMillis < 0 {
		return nil, fmt.Errorf("%w: expiration is before the Unix epoch (%s)", ErrInvalidCertificate, expiration.UTC())
	}
	expiresMillis := uint64(expirationMillis) //nolint:gosec // G115: just checked >= 0
	identityKey := key.Serialize()
	certData := &proto.SenderCertificate_Certificate{
		SenderUuid:   &proto.SenderCertificate_Certificate_UuidString{UuidString: senderUUID},
		SenderDevice: &deviceID,
		Expires:      &expiresMillis,
		IdentityKey:  identityKey,
		Signer:       &proto.SenderCertificate_Certificate_Certificate{Certificate: signer.Serialized()},
	}
	if senderE164 != nil {
		e164 := *senderE164
		certData.SenderE164 = &e164
	}
	certificate, err := googleproto.Marshal(certData)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: marshal sender certificate body: %w", err)
	}
	signature, err := signerKey.CalculateSignature(rng, certificate)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: sign sender certificate: %w", err)
	}
	serialized, err := googleproto.Marshal(&proto.SenderCertificate{
		Certificate: certificate,
		Signature:   signature,
	})
	if err != nil {
		return nil, fmt.Errorf("sealedsender: marshal sender certificate: %w", err)
	}

	return &SenderCertificate{
		signer:         signer,
		key:            key,
		senderDeviceID: senderDeviceID,
		senderUUID:     senderUUID,
		senderE164:     senderE164,
		expiration:     time.UnixMilli(expirationMillis).UTC(),
		certificate:    certificate,
		signature:      signature,
		serialized:     serialized,
	}, nil
}

// ValidateOption configures Validate (currently only the validation clock).
type ValidateOption func(*validateConfig)

type validateConfig struct {
	now time.Time
}

// WithClock overrides the validation time used for the expiration check. When
// unset, Validate uses time.Now(). Injecting a clock makes expiry deterministic
// in tests.
func WithClock(now time.Time) ValidateOption {
	return func(c *validateConfig) { c.now = now }
}

// Validate reports whether the certificate chain is valid against trustRoot:
//  1. the signer ServerCertificate validates under trustRoot (and is embedded —
//     a reference-by-id signer returns ErrUnknownServerCertificateID, since the
//     known-certificate table is not carried here yet),
//  2. the sender certificate's signature verifies under the signer's key, and
//  3. the validation time is not past the expiration.
//
// A well-formed but invalid chain (bad signature, expired) returns (false, nil);
// only an unresolvable signer reference returns a non-nil error. Mirrors
// SenderCertificate::validate. The validation clock is time.Now() unless
// overridden with WithClock.
func (c *SenderCertificate) Validate(trustRoot curve.PublicKey, opts ...ValidateOption) (bool, error) {
	cfg := validateConfig{now: time.Now()}
	for _, opt := range opts {
		opt(&cfg)
	}

	if c.signer == nil {
		// Referenced-by-id signer: the known-certificate table that would resolve
		// it is not available in this package yet.
		if c.signerID != nil {
			return false, fmt.Errorf("%w: %#x", ErrUnknownServerCertificateID, *c.signerID)
		}
		return false, fmt.Errorf("%w: sender certificate has no signer", ErrInvalidCertificate)
	}

	// 1. The signer must be signed by the trust root.
	if !c.signer.Validate(trustRoot) {
		return false, nil
	}
	// 2. The sender certificate must be signed by the signer's key.
	if !c.signer.PublicKey().VerifySignature(c.signature, c.certificate) {
		return false, nil
	}
	// 3. Expiration: invalid once the validation time is strictly past it,
	// mirroring upstream's `validation_time > self.expiration`.
	if cfg.now.After(c.expiration) {
		return false, nil
	}
	return true, nil
}

// Signer returns the embedded signing ServerCertificate, or nil when the signer
// is referenced by id (see SignerID).
func (c *SenderCertificate) Signer() *ServerCertificate { return c.signer }

// SignerID returns the referenced signer key id and true when the signer is
// referenced rather than embedded, else (0, false).
func (c *SenderCertificate) SignerID() (uint32, bool) {
	if c.signerID == nil {
		return 0, false
	}
	return *c.signerID, true
}

// Key returns the sender's identity public key.
func (c *SenderCertificate) Key() curve.PublicKey { return c.key }

// SenderDeviceID returns the sender's device id.
func (c *SenderCertificate) SenderDeviceID() uint32 { return c.senderDeviceID }

// SenderUUID returns the sender's uuid (canonical string form).
func (c *SenderCertificate) SenderUUID() string { return c.senderUUID }

// SenderE164 returns the sender's optional e164 phone number, or (\"\", false).
func (c *SenderCertificate) SenderE164() (string, bool) {
	if c.senderE164 == nil {
		return "", false
	}
	return *c.senderE164, true
}

// Expiration returns the certificate's expiration time (millisecond precision).
func (c *SenderCertificate) Expiration() time.Time { return c.expiration }

// IsExpired reports whether the certificate is expired at now and, when it is,
// returns a wrapped ErrExpiredCertificate describing the times. now is strictly
// compared against the expiration, mirroring Validate's expiry check
// (`validation_time > expiration`). Validate already folds expiry into its bool
// result; IsExpired lets a caller tell expiry apart from a signature failure.
func (c *SenderCertificate) IsExpired(now time.Time) (bool, error) {
	if now.After(c.expiration) {
		return true, fmt.Errorf("%w: expiration %s, now %s", ErrExpiredCertificate, c.expiration, now.UTC())
	}
	return false, nil
}

// Certificate returns the serialized inner Certificate (the signed bytes).
func (c *SenderCertificate) Certificate() []byte { return cloneBytes(c.certificate) }

// Signature returns the server's signature over the inner certificate.
func (c *SenderCertificate) Signature() []byte { return cloneBytes(c.signature) }

// Serialized returns the full serialized SenderCertificate wire form.
func (c *SenderCertificate) Serialized() []byte { return cloneBytes(c.serialized) }
