// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package sealedsender

import (
	"errors"
	"fmt"
	"time"

	"github.com/GoCodeAlone/libsignal-go/curve"
)

// Errors returned by sealed-sender message decryption.
var (
	// ErrInvalidSealedSenderMessage is returned for a structurally invalid sealed
	// sender message: empty input, an unknown version, bad protobuf/framing, or
	// unusable embedded key material.
	ErrInvalidSealedSenderMessage = errors.New("sealedsender: invalid sealed sender message")
	// ErrUnknownVersion is returned when the message's version byte names a
	// sealed-sender major version this implementation does not support.
	ErrUnknownVersion = errors.New("sealedsender: unknown sealed sender version")
	// ErrBadCiphertext is returned when authenticated decryption fails: a bad
	// AES-CTR+HMAC tag (v1) or a bad AES-256-GCM-SIV tag (v2), or a truncated
	// ciphertext.
	ErrBadCiphertext = errors.New("sealedsender: ciphertext authentication failed")
)

// Sealed-sender major versions, extracted from the high nibble of the version
// byte ((requiredVersion << 4) | currentVersion).
const (
	sealedSenderV1MajorVersion = 1
	sealedSenderV2MajorVersion = 2
)

// DecryptToUSMC decrypts a sealed sender message (v1 or v2 received form) with
// the recipient's identity key pair and returns the recovered
// UnidentifiedSenderMessageContent WITHOUT validating its sender certificate —
// the caller must validate Sender() against a trust root (see
// DecryptToUSMCAndValidate). The version is taken from the high nibble of the
// leading byte; v0 is accepted as v1, matching upstream's lenient v1 path.
// Mirrors sealed_sender_decrypt_to_usmc.
func DecryptToUSMC(message []byte, ourIdentity curve.KeyPair) (*UnidentifiedSenderMessageContent, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("%w: empty message", ErrInvalidSealedSenderMessage)
	}
	version := message[0] >> 4
	body := message[1:]

	switch version {
	case 0, sealedSenderV1MajorVersion:
		return decryptV1(body, ourIdentity)
	case sealedSenderV2MajorVersion:
		return decryptV2Received(body, ourIdentity)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownVersion, version)
	}
}

// DecryptToUSMCAndValidate decrypts a sealed sender message and then validates
// the recovered sender certificate against trustRoot (chain + expiry), returning
// the USMC only when the certificate is valid. validationTime is the clock used
// for the expiry check. This is the typical recipient entry point: decryption
// proves the message was sealed to us; certificate validation proves the claimed
// sender is authorized.
func DecryptToUSMCAndValidate(message []byte, ourIdentity curve.KeyPair, trustRoot curve.PublicKey, validationTime time.Time) (*UnidentifiedSenderMessageContent, error) {
	usmc, err := DecryptToUSMC(message, ourIdentity)
	if err != nil {
		return nil, err
	}
	valid, err := usmc.Sender().Validate(trustRoot, WithClock(validationTime))
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("%w: sender certificate did not validate", ErrInvalidCertificate)
	}
	return usmc, nil
}
