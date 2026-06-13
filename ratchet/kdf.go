// Package ratchet implements the Double Ratchet key schedule: the chain-key
// step, message-key derivation, root-key/DH ratchet step, and the PQXDH master
// secret. It is a pure-Go port of rust/protocol/src/ratchet/keys.rs and
// rust/protocol/src/ratchet.rs, and its outputs are vector-locked against
// upstream libsignal v0.91.0 (see compat/vectors/hkdf.json).
package ratchet

import (
	"github.com/GoCodeAlone/libsignal-go/internal/crypto"
)

// HKDF info strings and seed bytes, from rust/protocol/src/ratchet/keys.rs and
// ratchet.rs. These are part of the wire/key-schedule contract and never change.
const (
	// messageKeysInfo is the HKDF info for deriving a MessageKeys triple from a
	// chain key's message-key seed.
	messageKeysInfo = "WhisperMessageKeys"
	// rootChainInfo is the HKDF info for the root-key/DH ratchet step.
	rootChainInfo = "WhisperRatchet"
	// pqxdhInfo is the HKDF info for the PQXDH master-secret derivation. The
	// label names the X25519 + SHA-256 + Kyber-1024 ciphersuite.
	pqxdhInfo = "WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024"
)

// chainKeySeed and messageKeySeed are the single-byte HMAC inputs that derive,
// respectively, the next chain key and a message-key seed from a chain key
// (ChainKey::CHAIN_KEY_SEED / MESSAGE_KEY_SEED in keys.rs).
const (
	chainKeySeed   = 0x02
	messageKeySeed = 0x01
)

// Key/output sizes (bytes).
const (
	chainKeyLen  = 32
	rootKeyLen   = 32
	cipherKeyLen = 32
	macKeyLen    = 32
	ivLen        = 16

	// discontinuityLen is the count of 0xFF "discontinuity" bytes that prefix
	// the PQXDH master secret (ratchet.rs initialize_alice_session).
	discontinuityLen = 32
	// agreementLen is the length of an X25519 ECDH shared secret.
	agreementLen = 32
)

// pqxdhSecret assembles the PQXDH master secret in the upstream byte order
// (ratchet.rs initialize_alice_session / initialize_bob_session):
//
//	0xFF*32 || DH1 || DH2 || DH3 || DH4 || kyber_shared_secret
//
// The leading 32 0xFF bytes are the "discontinuity bytes". Each DH input is a
// 32-byte X25519 agreement; kyberSharedSecret is the KEM shared secret. The
// caller supplies the four agreements already computed in the upstream order
// (DH1 = IK_a x SPK_b, DH2 = EK_a x IK_b, DH3 = EK_a x SPK_b, DH4 = EK_a x OPK_b).
func pqxdhSecret(dh1, dh2, dh3, dh4, kyberSharedSecret []byte) []byte {
	out := make([]byte, 0, discontinuityLen+4*agreementLen+len(kyberSharedSecret))
	for i := 0; i < discontinuityLen; i++ {
		out = append(out, 0xFF)
	}
	out = append(out, dh1...)
	out = append(out, dh2...)
	out = append(out, dh3...)
	out = append(out, dh4...)
	out = append(out, kyberSharedSecret...)
	return out
}

// hkdfSplit derives length bytes via HKDF-SHA256(ikm, salt, info) and returns
// them. The single error path is an over-long output request, which is
// impossible for the fixed callers in this package.
func hkdfSplit(ikm, salt []byte, info string, length int) ([]byte, error) {
	return crypto.HKDFSHA256(ikm, salt, []byte(info), length)
}
