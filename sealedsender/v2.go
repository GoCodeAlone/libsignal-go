// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package sealedsender

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/internal/crypto"
	"github.com/GoCodeAlone/libsignal-go/internal/crypto/gcmsiv"
	"google.golang.org/protobuf/encoding/protowire"
)

// sealedSenderV2ServiceIDSentVersion is the version byte of the multi-recipient
// SENT message (0x23). It differs from the per-recipient RECEIVED message
// (0x22): the sent form is server-bound and fanned out, never decrypted directly.
const sealedSenderV2ServiceIDSentVersion uint8 = 0x23

// validRegistrationIDMask bounds a registration id to 14 bits; the top bit of
// the u16 field is the device-list "has_more" marker (sealed_sender.rs
// VALID_REGISTRATION_ID_MASK / the 0x8000 flag).
const validRegistrationIDMask = 0x3FFF

// hasMoreDevicesFlag is OR'd into a device's registration-id field for every
// device of a recipient except the last, marking that more devices follow.
const hasMoreDevicesFlag uint16 = 0x8000

// Sealed sender v2 constants (sealed_sender.rs sealed_sender_v2). The version
// byte is 0x22 for the UUID form. Lengths are fixed for Curve25519 + GCM-SIV.
const (
	sealedSenderV2FullVersion uint8 = 0x22

	v2MessageKeyLen = 32 // M and the per-recipient C_i
	v2CipherKeyLen  = 32 // AES-256-GCM-SIV key K
	v2AuthTagLen    = 16 // per-recipient authentication tag AT_i
	v2PublicKeyLen  = 32 // raw Curve25519 public key (no type byte)
)

// HKDF "label" strings used as the info argument in the v2 derivations
// (sealed_sender.rs LABEL_*). The salt-date suffix on LABEL_R is part of the
// wire contract and must not change.
var (
	v2LabelR   = []byte("Sealed Sender v2: r (2023-08)")
	v2LabelK   = []byte("Sealed Sender v2: K")
	v2LabelDH  = []byte("Sealed Sender v2: DH")
	v2LabelDHS = []byte("Sealed Sender v2: DH-sender")
)

// v2DerivedKeys derives, from the per-message random seed M, the ephemeral key
// pair E (from label_r) and the symmetric AEAD key K (from label_K), each via
// HKDF-SHA256 with no salt and M as IKM. Mirrors sealed_sender_v2::DerivedKeys.
type v2DerivedKeys struct {
	m []byte
}

func newV2DerivedKeys(m []byte) *v2DerivedKeys {
	return &v2DerivedKeys{m: m}
}

// deriveE expands label_r to 32 bytes, clamps them into a Curve25519 private
// key, and returns the key pair. Mirrors DerivedKeys::derive_e.
func (d *v2DerivedKeys) deriveE() (curve.KeyPair, error) {
	r, err := crypto.HKDFSHA256(d.m, nil, v2LabelR, v2PublicKeyLen)
	if err != nil {
		return curve.KeyPair{}, fmt.Errorf("sealedsender: v2 derive r: %w", err)
	}
	priv, err := curve.DeserializePrivateKey(r)
	if err != nil {
		return curve.KeyPair{}, fmt.Errorf("sealedsender: v2 derive E private key: %w", err)
	}
	return curve.KeyPairFromPrivateKey(priv)
}

// deriveK expands label_K to the 32-byte AES-256-GCM-SIV key. Mirrors
// DerivedKeys::derive_k.
func (d *v2DerivedKeys) deriveK() ([]byte, error) {
	k, err := crypto.HKDFSHA256(d.m, nil, v2LabelK, v2CipherKeyLen)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: v2 derive K: %w", err)
	}
	return k, nil
}

// applyAgreementXor XORs input (the 32-byte M, or C_i on the way back) with an
// HKDF stream keyed by the ECDH agreement and the two public keys in
// direction-dependent order, mirroring sealed_sender_v2::apply_agreement_xor.
// Sending and Receiving (with our/their keys swapped) invert each other.
func applyAgreementXor(ourKeys curve.KeyPair, theirKey curve.PublicKey, dir direction, input []byte) ([]byte, error) {
	if len(input) != v2MessageKeyLen {
		return nil, fmt.Errorf("sealedsender: v2 agreement input must be %d bytes, got %d", v2MessageKeyLen, len(input))
	}
	agreement, err := ourKeys.PrivateKey.CalculateAgreement(theirKey)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: v2 agreement: %w", err)
	}
	ourPub := ourKeys.PublicKey.Serialize()
	theirPub := theirKey.Serialize()

	var ikm []byte
	switch dir {
	case directionSending:
		ikm = concatBytes(agreement, ourPub, theirPub)
	default:
		ikm = concatBytes(agreement, theirPub, ourPub)
	}
	stream, err := crypto.HKDFSHA256(ikm, nil, v2LabelDH, v2MessageKeyLen)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: v2 DH HKDF: %w", err)
	}
	out := make([]byte, v2MessageKeyLen)
	for i := range out {
		out[i] = stream[i] ^ input[i]
	}
	return out, nil
}

// computeAuthenticationTag derives the 16-byte per-recipient authentication tag
// AT from the sender/recipient identity ECDH, the ephemeral public key, the
// encrypted message key C_i, and the two identity public keys in
// direction-dependent order. Mirrors sealed_sender_v2::compute_authentication_tag.
func computeAuthenticationTag(ourIdentity curve.KeyPair, theirIdentity curve.PublicKey, dir direction, ephemeralPub curve.PublicKey, encryptedMessageKey []byte) ([]byte, error) {
	agreement, err := ourIdentity.PrivateKey.CalculateAgreement(theirIdentity)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: v2 auth-tag agreement: %w", err)
	}
	ikm := concatBytes(agreement, ephemeralPub.Serialize(), encryptedMessageKey)
	ourPub := ourIdentity.PublicKey.Serialize()
	theirPub := theirIdentity.Serialize()
	switch dir {
	case directionSending:
		ikm = concatBytes(ikm, ourPub, theirPub)
	default:
		ikm = concatBytes(ikm, theirPub, ourPub)
	}
	tag, err := crypto.HKDFSHA256(ikm, nil, v2LabelDHS, v2AuthTagLen)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: v2 auth-tag HKDF: %w", err)
	}
	return tag, nil
}

// decryptV2Received decrypts the sealed sender v2 ReceivedMessage body (after
// the version byte): C[32] || AT[16] || E_pub[32] || ciphertext. It recovers M
// via apply_agreement_xor (receiving), re-derives E and checks it matches the
// carried ephemeral public key, AES-256-GCM-SIV-decrypts the message (zero
// nonce, no AAD), parses the USMC, and verifies the authentication tag against
// the recovered sender identity key. Mirrors the V2 branch of
// sealed_sender_decrypt_to_usmc.
func decryptV2Received(body []byte, ourIdentity curve.KeyPair) (*UnidentifiedSenderMessageContent, error) {
	const prefixLen = v2MessageKeyLen + v2AuthTagLen + v2PublicKeyLen
	if len(body) < prefixLen {
		return nil, fmt.Errorf("%w: v2 message too short", ErrInvalidSealedSenderMessage)
	}
	encryptedMessageKey := body[0:v2MessageKeyLen]
	authTag := body[v2MessageKeyLen : v2MessageKeyLen+v2AuthTagLen]
	ephemeralRaw := body[v2MessageKeyLen+v2AuthTagLen : prefixLen]
	encryptedMessage := body[prefixLen:]

	ephemeralPublic, err := curve.NewPublicKey(ephemeralRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: v2 ephemeral key: %v", ErrInvalidSealedSenderMessage, err)
	}

	m, err := applyAgreementXor(ourIdentity, ephemeralPublic, directionReceiving, encryptedMessageKey)
	if err != nil {
		return nil, err
	}

	keys := newV2DerivedKeys(m)
	derivedE, err := keys.deriveE()
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(derivedE.PublicKey.Serialize(), ephemeralPublic.Serialize()) != 1 {
		return nil, fmt.Errorf("%w: derived ephemeral key did not match the message", ErrInvalidSealedSenderMessage)
	}

	k, err := keys.deriveK()
	if err != nil {
		return nil, err
	}
	// AES-256-GCM-SIV with a zero nonce (the key is single-use) and no AAD. The
	// tag is at the end of encryptedMessage, which gcmsiv.Open expects.
	messageBytes, err := gcmsiv.Open(k, make([]byte, gcmsivNonceLen), encryptedMessage, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: v2 AEAD: %v", ErrBadCiphertext, err)
	}

	usmc, err := DeserializeUnidentifiedSenderMessageContent(messageBytes)
	if err != nil {
		return nil, err
	}

	at, err := computeAuthenticationTag(ourIdentity, usmc.Sender().Key(), directionReceiving, ephemeralPublic, encryptedMessageKey)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(at, authTag) != 1 {
		return nil, fmt.Errorf("%w: sender certificate key does not match authentication tag", ErrInvalidSealedSenderMessage)
	}
	return usmc, nil
}

// SealV2Recipient identifies one recipient of a multi-recipient v2 message: its
// ServiceId, identity public key, and per-device registration ids. A recipient
// with multiple devices repeats the same identity key; one PerRecipientData
// block is emitted per ServiceId with a device list.
type SealV2Recipient struct {
	ServiceID      address.ServiceID
	IdentityKey    curve.PublicKey
	DeviceID       uint32
	RegistrationID uint32
}

// SealV2SentMessage is a sealed sender v2 multi-recipient SENT message: the flat
// server-bound wire form carrying every recipient's per-recipient block plus the
// single shared ciphertext. ReceivedMessageForRecipient fans it out to the
// per-recipient RECEIVED form that DecryptToUSMC consumes.
type SealV2SentMessage struct {
	serialized       []byte
	ephemeralPublic  curve.PublicKey
	encryptedMessage []byte
	perRecipient     []v2PerRecipient
}

// v2PerRecipient is the recovered C_i + AT_i for one (ServiceId, device).
type v2PerRecipient struct {
	serviceID           address.ServiceID
	deviceID            uint32
	encryptedMessageKey []byte // C_i, 32 bytes
	authTag             []byte // AT_i, 16 bytes
}

// gcmsivNonceLen is the AES-256-GCM-SIV nonce length (12 bytes); v2 always uses
// an all-zero nonce because the derived key K is single-use.
const gcmsivNonceLen = 12

// SealV2 produces a sealed sender v2 multi-recipient SentMessage from a USMC for
// the given recipients. It generates one shared random seed M, derives E and K,
// AES-256-GCM-SIV-encrypts the USMC once under K, and for each recipient device
// emits C_i = M ⊕ HKDF(DH(E, R_i)…) and AT_i over the sender/recipient identity
// ECDH. Recipients are grouped by ServiceId (contiguous) into PerRecipientData
// blocks with a device list. Mirrors sealed_sender_multi_recipient_encrypt.
//
// ourIdentity is the sender's identity key pair; rng must be a CSPRNG. The result
// is fanned out per recipient via ReceivedMessageForRecipient.
func SealV2(usmc *UnidentifiedSenderMessageContent, recipients []SealV2Recipient, ourIdentity curve.KeyPair, rng io.Reader) (*SealV2SentMessage, error) {
	if usmc == nil {
		return nil, fmt.Errorf("%w: nil USMC", ErrInvalidUSMC)
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%w: no recipients", ErrInvalidUSMC)
	}

	m := make([]byte, v2MessageKeyLen)
	if _, err := io.ReadFull(rng, m); err != nil {
		return nil, fmt.Errorf("sealedsender: v2 random seed: %w", err)
	}
	keys := newV2DerivedKeys(m)
	e, err := keys.deriveE()
	if err != nil {
		return nil, err
	}
	k, err := keys.deriveK()
	if err != nil {
		return nil, err
	}

	// One AEAD encryption of the USMC under K, shared across recipients.
	ciphertext, err := gcmsiv.Seal(k, make([]byte, gcmsivNonceLen), usmc.Serialized(), nil)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: v2 AEAD seal: %w", err)
	}

	perRecipient := make([]v2PerRecipient, 0, len(recipients))
	for _, r := range recipients {
		ci, err := applyAgreementXor(e, r.IdentityKey, directionSending, m)
		if err != nil {
			return nil, err
		}
		at, err := computeAuthenticationTag(ourIdentity, r.IdentityKey, directionSending, e.PublicKey, ci)
		if err != nil {
			return nil, err
		}
		perRecipient = append(perRecipient, v2PerRecipient{
			serviceID:           r.ServiceID,
			deviceID:            r.DeviceID,
			encryptedMessageKey: ci,
			authTag:             at,
		})
	}

	serialized, err := encodeV2SentMessage(recipients, perRecipient, e.PublicKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return &SealV2SentMessage{
		serialized:       serialized,
		ephemeralPublic:  e.PublicKey,
		encryptedMessage: ciphertext,
		perRecipient:     perRecipient,
	}, nil
}

// Serialized returns the full SentMessage wire form (server-bound).
func (s *SealV2SentMessage) Serialized() []byte { return cloneBytes(s.serialized) }

// ReceivedMessageForRecipient builds the per-recipient v2 ReceivedMessage form
// (0x22 || C_i || AT_i || E_pub || ciphertext) for the recipient at index i in
// the recipients slice passed to SealV2. This is what the server would route to
// that recipient and what DecryptToUSMC consumes.
func (s *SealV2SentMessage) ReceivedMessageForRecipient(i int) ([]byte, error) {
	if i < 0 || i >= len(s.perRecipient) {
		return nil, fmt.Errorf("sealedsender: recipient index %d out of range", i)
	}
	pr := s.perRecipient[i]
	out := make([]byte, 0, 1+v2MessageKeyLen+v2AuthTagLen+v2PublicKeyLen+len(s.encryptedMessage))
	out = append(out, sealedSenderV2FullVersion)
	out = append(out, pr.encryptedMessageKey...)
	out = append(out, pr.authTag...)
	// The wire carries the raw 32-byte DJB key (the KDF, separately, uses the
	// typed 33-byte serialization — see applyAgreementXor).
	out = append(out, s.ephemeralPublic.PublicKeyBytes()...)
	out = append(out, s.encryptedMessage...)
	return out, nil
}

// encodeV2SentMessage assembles the flat multi-recipient SENT wire form:
//
//	0x23 || count:varint || PerRecipientData[count] || E_pub[32] || ciphertext
//
// where count is the number of recipient GROUPS (consecutive entries sharing a
// ServiceID), and each PerRecipientData is
//
//	service_id_fixed_width[17] || (device_id:u8 || reg_id:u16be)[devices] || C[32] || AT[16]
//
// with the 0x8000 "has_more" bit set in reg_id for every device of the group but
// the last. recipients and perRecipient are index-aligned. Mirrors
// sealed_sender_multi_recipient_encrypt's serialization.
func encodeV2SentMessage(recipients []SealV2Recipient, perRecipient []v2PerRecipient, ephemeralPublic curve.PublicKey, ciphertext []byte) ([]byte, error) {
	// Group consecutive entries by ServiceID (upstream chunks by name).
	type group struct {
		start, count int
	}
	var groups []group
	for i := 0; i < len(recipients); {
		j := i + 1
		for j < len(recipients) && recipients[j].ServiceID == recipients[i].ServiceID {
			j++
		}
		groups = append(groups, group{start: i, count: j - i})
		i = j
	}

	out := []byte{sealedSenderV2ServiceIDSentVersion}
	out = protowire.AppendVarint(out, uint64(len(groups)))

	for _, g := range groups {
		first := recipients[g.start]
		fixed := first.ServiceID.ServiceIDFixedWidthBinary()
		out = append(out, fixed[:]...)

		for d := 0; d < g.count; d++ {
			r := recipients[g.start+d]
			// All devices of one ServiceID must carry the same identity key: the
			// per-recipient C_i/AT_i are emitted once per group (keyed to the
			// first device's identity), so a divergent key on a later device would
			// silently produce a SENT message that recipient can't decrypt.
			// Upstream can't hit this — its identity store maps a name to a single
			// identity, fetched once per group (sealed_sender.rs:1431-1457) — but
			// our per-entry SealV2Recipient.IdentityKey can, so guard it here.
			if !r.IdentityKey.Equal(first.IdentityKey) {
				return nil, fmt.Errorf("%w: devices of ServiceID %s have differing identity keys", ErrInvalidUSMC, first.ServiceID.ServiceIDString())
			}
			if r.DeviceID == 0 || r.DeviceID > 0xFF {
				return nil, fmt.Errorf("%w: device id %d out of byte range", ErrInvalidUSMC, r.DeviceID)
			}
			if r.RegistrationID&validRegistrationIDMask != r.RegistrationID {
				return nil, fmt.Errorf("%w: registration id %d out of 14-bit range", ErrInvalidUSMC, r.RegistrationID)
			}
			//nolint:gosec // G115: just bounds-checked to 14 bits, fits in u16.
			regID := uint16(r.RegistrationID)
			if d != g.count-1 {
				regID |= hasMoreDevicesFlag // more devices follow in this group
			}
			out = append(out, byte(r.DeviceID))
			out = binary.BigEndian.AppendUint16(out, regID)
		}

		// C_i and AT_i are shared across a group's devices (same identity key);
		// upstream emits them once per group, after the device list. Use the
		// group's first entry.
		pr := perRecipient[g.start]
		out = append(out, pr.encryptedMessageKey...)
		out = append(out, pr.authTag...)
	}

	out = append(out, ephemeralPublic.PublicKeyBytes()...)
	out = append(out, ciphertext...)
	return out, nil
}
