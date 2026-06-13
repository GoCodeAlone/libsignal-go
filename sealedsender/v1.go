// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package sealedsender

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/internal/crypto"
	"github.com/GoCodeAlone/libsignal-go/proto"
	googleproto "google.golang.org/protobuf/proto"
)

// Sealed sender version bytes. The byte is (requiredVersion << 4) | currentVersion
// (sealed_sender.rs SEALED_SENDER_*_VERSION). v1 is 0x11.
const (
	sealedSenderV1FullVersion uint8 = 0x11

	// keyLen is the length of each of the chain/cipher/MAC keys derived for v1.
	keyLen = 32
)

// v1SaltPrefix is the HKDF salt prefix for the v1 ephemeral-key derivation
// ("UnidentifiedDelivery" in sealed_sender.rs).
var v1SaltPrefix = []byte("UnidentifiedDelivery")

// direction selects the ordering of the two public keys in the v1 ephemeral
// salt (and elsewhere), mirroring upstream's Direction::{Sending,Receiving}.
type direction int

const (
	directionSending direction = iota
	directionReceiving
)

// v1EphemeralKeys are the symmetric keys derived from the ECDH between the
// sender's ephemeral key and the recipient's identity key: a chain key (fed into
// the static-key derivation), a cipher key, and a MAC key. Mirrors
// sealed_sender_v1::EphemeralKeys.
type v1EphemeralKeys struct {
	chainKey  [keyLen]byte
	cipherKey [keyLen]byte
	macKey    [keyLen]byte
}

// calculateV1EphemeralKeys derives the ephemeral keys. The HKDF salt is
// "UnidentifiedDelivery" || pubA || pubB, where (pubA, pubB) is
// (their_pub, our_pub) when sending and (our_pub, their_pub) when receiving, so
// both sides compute the same salt. ikm is the ECDH agreement; info is empty;
// output is 96 bytes split into chain/cipher/MAC keys. Mirrors
// EphemeralKeys::calculate.
func calculateV1EphemeralKeys(ourKeys curve.KeyPair, theirPublic curve.PublicKey, dir direction) (*v1EphemeralKeys, error) {
	ourPub := ourKeys.PublicKey.Serialize()
	theirPub := theirPublic.Serialize()

	var salt []byte
	switch dir {
	case directionSending:
		salt = concatBytes(v1SaltPrefix, theirPub, ourPub)
	default:
		salt = concatBytes(v1SaltPrefix, ourPub, theirPub)
	}

	shared, err := ourKeys.PrivateKey.CalculateAgreement(theirPublic)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: v1 ephemeral agreement: %w", err)
	}
	okm, err := crypto.HKDFSHA256(shared, salt, nil, 3*keyLen)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: v1 ephemeral HKDF: %w", err)
	}
	var ek v1EphemeralKeys
	copy(ek.chainKey[:], okm[0:keyLen])
	copy(ek.cipherKey[:], okm[keyLen:2*keyLen])
	copy(ek.macKey[:], okm[2*keyLen:3*keyLen])
	return &ek, nil
}

// v1StaticKeys are the symmetric keys derived from the ECDH between the sender's
// and recipient's identity keys, salted by the ephemeral chain key and the
// encrypted-static ciphertext. Mirrors sealed_sender_v1::StaticKeys.
type v1StaticKeys struct {
	cipherKey [keyLen]byte
	macKey    [keyLen]byte
}

// calculateV1StaticKeys derives the static keys. salt is chainKey || ctext; ikm
// is the identity-key ECDH agreement; HKDF emits 96 bytes whose first 32 are
// discarded (mirroring the ephemeral derivation's chain key), then cipher/MAC.
// Mirrors StaticKeys::calculate.
func calculateV1StaticKeys(ourIdentity curve.KeyPair, theirKey curve.PublicKey, chainKey [keyLen]byte, ctext []byte) (*v1StaticKeys, error) {
	salt := concatBytes(chainKey[:], ctext)
	shared, err := ourIdentity.PrivateKey.CalculateAgreement(theirKey)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: v1 static agreement: %w", err)
	}
	okm, err := crypto.HKDFSHA256(shared, salt, nil, 3*keyLen)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: v1 static HKDF: %w", err)
	}
	var sk v1StaticKeys
	// okm[0:32] is intentionally discarded (parallels the ephemeral chain key).
	copy(sk.cipherKey[:], okm[keyLen:2*keyLen])
	copy(sk.macKey[:], okm[2*keyLen:3*keyLen])
	return &sk, nil
}

// SealV1 produces a sealed sender v1 message for a single recipient from a USMC.
// It generates a fresh ephemeral key, derives the ephemeral keys against the
// recipient's identity public key, AES-CTR+HMAC-encrypts the sender's identity
// public key (the "encrypted static"), derives the static keys, AES-CTR+HMAC-
// encrypts the USMC bytes, and frames the result as
// 0x11 || proto{ephemeral_public, encrypted_static, encrypted_message}.
// Mirrors sealed_sender_encrypt_from_usmc.
//
// ourIdentity is the sender's identity key pair; theirIdentity is the
// recipient's identity public key; rng supplies the ephemeral key and must be a
// CSPRNG (crypto/rand.Reader) in production.
func SealV1(usmc *UnidentifiedSenderMessageContent, ourIdentity curve.KeyPair, theirIdentity curve.PublicKey, rng io.Reader) ([]byte, error) {
	if usmc == nil {
		return nil, fmt.Errorf("%w: nil USMC", ErrInvalidUSMC)
	}

	ephemeral, err := curve.GenerateKeyPair(rng)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: generate v1 ephemeral key: %w", err)
	}

	ephKeys, err := calculateV1EphemeralKeys(ephemeral, theirIdentity, directionSending)
	if err != nil {
		return nil, err
	}

	staticCtext, err := aes256CtrHmacSha256Encrypt(ourIdentity.PublicKey.Serialize(), ephKeys.cipherKey[:], ephKeys.macKey[:])
	if err != nil {
		return nil, fmt.Errorf("sealedsender: encrypt static key: %w", err)
	}

	staticKeys, err := calculateV1StaticKeys(ourIdentity, theirIdentity, ephKeys.chainKey, staticCtext)
	if err != nil {
		return nil, err
	}

	messageData, err := aes256CtrHmacSha256Encrypt(usmc.Serialized(), staticKeys.cipherKey[:], staticKeys.macKey[:])
	if err != nil {
		return nil, fmt.Errorf("sealedsender: encrypt message: %w", err)
	}

	ephPub := ephemeral.PublicKey.Serialize()
	body, err := googleproto.Marshal(&proto.UnidentifiedSenderMessage{
		EphemeralPublic:  ephPub,
		EncryptedStatic:  staticCtext,
		EncryptedMessage: messageData,
	})
	if err != nil {
		return nil, fmt.Errorf("sealedsender: marshal v1 message: %w", err)
	}

	// Seed with the version byte and append the body. Avoids a pre-computed
	// capacity (1+len(body)) — CodeQL's allocation-size-overflow flags that
	// arithmetic; the capacity was only a hint, so the output is identical.
	out := []byte{sealedSenderV1FullVersion}
	out = append(out, body...)
	return out, nil
}

// decryptV1 decrypts a sealed sender v1 message body (the bytes after the
// version byte) using ourIdentity. It parses the proto, derives the ephemeral
// keys (receiving direction), decrypts and parses the sender's identity public
// key, derives the static keys against that key, and decrypts the inner USMC
// bytes. Returns the recovered USMC. Mirrors the v1 branch of
// sealed_sender_decrypt_to_usmc.
func decryptV1(body []byte, ourIdentity curve.KeyPair) (*UnidentifiedSenderMessageContent, error) {
	var pb proto.UnidentifiedSenderMessage
	if err := googleproto.Unmarshal(body, &pb); err != nil {
		return nil, fmt.Errorf("%w: v1 protobuf: %v", ErrInvalidSealedSenderMessage, err)
	}
	if pb.EphemeralPublic == nil || pb.EncryptedStatic == nil || pb.EncryptedMessage == nil {
		return nil, fmt.Errorf("%w: v1 message missing a required field", ErrInvalidSealedSenderMessage)
	}

	ephemeralPublic, err := curve.DeserializePublicKey(pb.GetEphemeralPublic())
	if err != nil {
		return nil, fmt.Errorf("%w: v1 ephemeral key: %v", ErrInvalidSealedSenderMessage, err)
	}

	ephKeys, err := calculateV1EphemeralKeys(ourIdentity, ephemeralPublic, directionReceiving)
	if err != nil {
		return nil, err
	}

	staticKeyBytes, err := aes256CtrHmacSha256Decrypt(pb.GetEncryptedStatic(), ephKeys.cipherKey[:], ephKeys.macKey[:])
	if err != nil {
		return nil, fmt.Errorf("sealedsender: decrypt static key: %w", err)
	}
	senderPublic, err := curve.DeserializePublicKey(staticKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: v1 sender static key: %v", ErrInvalidSealedSenderMessage, err)
	}

	staticKeys, err := calculateV1StaticKeys(ourIdentity, senderPublic, ephKeys.chainKey, pb.GetEncryptedStatic())
	if err != nil {
		return nil, err
	}

	messageBytes, err := aes256CtrHmacSha256Decrypt(pb.GetEncryptedMessage(), staticKeys.cipherKey[:], staticKeys.macKey[:])
	if err != nil {
		return nil, fmt.Errorf("sealedsender: decrypt message: %w", err)
	}

	usmc, err := DeserializeUnidentifiedSenderMessageContent(messageBytes)
	if err != nil {
		return nil, err
	}
	// The static key recovered from the handshake must equal the sender
	// certificate's identity key — otherwise the message was sealed by a
	// different key than the certificate claims. Mirrors the ct_eq check in
	// sealed_sender_decrypt_to_usmc (v1 branch). Constant-time compare.
	if subtle.ConstantTimeCompare(staticKeyBytes, usmc.Sender().Key().Serialize()) != 1 {
		return nil, fmt.Errorf("%w: sender certificate key does not match message key", ErrInvalidSealedSenderMessage)
	}
	return usmc, nil
}

// concatBytes returns the concatenation of the given byte slices in a fresh
// buffer.
func concatBytes(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
