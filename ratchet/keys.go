package ratchet

import (
	"fmt"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/internal/crypto"
)

// ChainKey is a symmetric chain key in the Double Ratchet sending or receiving
// chain. It advances by HMAC and yields per-message MessageKeys, mirroring
// ChainKey in rust/protocol/src/ratchet/keys.rs.
type ChainKey struct {
	key   [chainKeyLen]byte
	index uint32
}

// NewChainKey builds a ChainKey from a 32-byte key and its chain index. It
// returns an error if key is not 32 bytes.
func NewChainKey(key []byte, index uint32) (ChainKey, error) {
	if len(key) != chainKeyLen {
		return ChainKey{}, fmt.Errorf("ratchet: chain key must be %d bytes, got %d", chainKeyLen, len(key))
	}
	var ck ChainKey
	copy(ck.key[:], key)
	ck.index = index
	return ck, nil
}

// Key returns a copy of the 32-byte chain key material.
func (c ChainKey) Key() []byte {
	out := make([]byte, chainKeyLen)
	copy(out, c.key[:])
	return out
}

// Index returns the chain key's index (message counter within the chain).
func (c ChainKey) Index() uint32 { return c.index }

// baseMaterial computes HMAC-SHA256(chainKey, seed) — ChainKey's
// calculate_base_material. seed is CHAIN_KEY_SEED (0x02) or MESSAGE_KEY_SEED
// (0x01).
func (c ChainKey) baseMaterial(seed byte) []byte {
	return crypto.HMACSHA256(c.key[:], []byte{seed})
}

// Next returns the next chain key: its material is HMAC-SHA256(key, 0x02) and
// its index is incremented by one.
func (c ChainKey) Next() ChainKey {
	var next ChainKey
	copy(next.key[:], c.baseMaterial(chainKeySeed))
	next.index = c.index + 1
	return next
}

// MessageKeys derives the per-message keys for this chain index: the message
// key seed is HMAC-SHA256(key, 0x01), then HKDF-SHA256(seed, salt=nil,
// info="WhisperMessageKeys") yields 32B cipher key || 32B MAC key || 16B IV.
func (c ChainKey) MessageKeys() (MessageKeys, error) {
	seed := c.baseMaterial(messageKeySeed)
	okm, err := hkdfSplit(seed, nil, messageKeysInfo, cipherKeyLen+macKeyLen+ivLen)
	if err != nil {
		return MessageKeys{}, fmt.Errorf("ratchet: deriving message keys: %w", err)
	}
	var mk MessageKeys
	copy(mk.cipherKey[:], okm[0:cipherKeyLen])
	copy(mk.macKey[:], okm[cipherKeyLen:cipherKeyLen+macKeyLen])
	copy(mk.iv[:], okm[cipherKeyLen+macKeyLen:cipherKeyLen+macKeyLen+ivLen])
	mk.index = c.index
	return mk, nil
}

// String redacts the key material so chain keys never leak into logs.
func (c ChainKey) String() string {
	return fmt.Sprintf("ChainKey{index: %d, key: [redacted]}", c.index)
}

// Format intercepts every fmt verb — including Go-syntax %#v and %x — so the
// key material can never leak through formatting that bypasses String().
// Mirrors curve.PrivateKey.Format.
func (c ChainKey) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "ratchet.ChainKey{index: %d, key: [REDACTED]}", c.index)
}

// MessageKeys is the triple of symmetric keys for a single message: an AES
// cipher key, an HMAC key, and an IV, plus the chain index they were derived
// at. Mirrors MessageKeys in rust/protocol/src/ratchet/keys.rs.
type MessageKeys struct {
	cipherKey [cipherKeyLen]byte
	macKey    [macKeyLen]byte
	iv        [ivLen]byte
	index     uint32
}

// CipherKey returns a copy of the 32-byte AES cipher key.
func (m MessageKeys) CipherKey() []byte {
	out := make([]byte, cipherKeyLen)
	copy(out, m.cipherKey[:])
	return out
}

// MACKey returns a copy of the 32-byte HMAC key.
func (m MessageKeys) MACKey() []byte {
	out := make([]byte, macKeyLen)
	copy(out, m.macKey[:])
	return out
}

// IV returns a copy of the 16-byte initialization vector.
func (m MessageKeys) IV() []byte {
	out := make([]byte, ivLen)
	copy(out, m.iv[:])
	return out
}

// Index returns the chain index these message keys were derived at.
func (m MessageKeys) Index() uint32 { return m.index }

// String redacts the key material.
func (m MessageKeys) String() string {
	return fmt.Sprintf("MessageKeys{index: %d, cipherKey/macKey/iv: [redacted]}", m.index)
}

// Format intercepts every fmt verb (incl. %#v and %x) so the cipher key, MAC
// key, and IV can never leak through formatting that bypasses String().
func (m MessageKeys) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "ratchet.MessageKeys{index: %d, cipherKey/macKey/iv: [REDACTED]}", m.index)
}

// RootKey is the Double Ratchet root key. Each DH ratchet step consumes the
// current root key plus a fresh ECDH agreement to produce the next root key and
// a new sending/receiving chain key. Mirrors RootKey in keys.rs.
type RootKey struct {
	key [rootKeyLen]byte
}

// NewRootKey builds a RootKey from 32 bytes, erroring if the length is wrong.
func NewRootKey(key []byte) (RootKey, error) {
	if len(key) != rootKeyLen {
		return RootKey{}, fmt.Errorf("ratchet: root key must be %d bytes, got %d", rootKeyLen, len(key))
	}
	var rk RootKey
	copy(rk.key[:], key)
	return rk, nil
}

// Key returns a copy of the 32-byte root key material.
func (r RootKey) Key() []byte {
	out := make([]byte, rootKeyLen)
	copy(out, r.key[:])
	return out
}

// CreateChain performs one DH ratchet step (RootKey::create_chain): it computes
// the ECDH agreement between ourRatchetKey and theirRatchetKey, then
// HKDF-SHA256(ikm=agreement, salt=currentRootKey, info="WhisperRatchet") to
// derive 32B next root key || 32B chain key. The returned chain key starts at
// index 0.
func (r RootKey) CreateChain(theirRatchetKey curve.PublicKey, ourRatchetKey curve.PrivateKey) (RootKey, ChainKey, error) {
	shared, err := ourRatchetKey.CalculateAgreement(theirRatchetKey)
	if err != nil {
		return RootKey{}, ChainKey{}, fmt.Errorf("ratchet: DH agreement for root step: %w", err)
	}
	okm, err := hkdfSplit(shared, r.key[:], rootChainInfo, rootKeyLen+chainKeyLen)
	if err != nil {
		return RootKey{}, ChainKey{}, fmt.Errorf("ratchet: deriving root/chain keys: %w", err)
	}
	var nextRoot RootKey
	copy(nextRoot.key[:], okm[0:rootKeyLen])
	var chain ChainKey
	copy(chain.key[:], okm[rootKeyLen:rootKeyLen+chainKeyLen])
	chain.index = 0
	return nextRoot, chain, nil
}

// String redacts the key material.
func (r RootKey) String() string { return "RootKey{key: [redacted]}" }

// Format intercepts every fmt verb (incl. %#v and %x) so the root key material
// can never leak through formatting that bypasses String().
func (r RootKey) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "ratchet.RootKey{key: [REDACTED]}")
}

// InitialKeys is the output of the PQXDH master-secret derivation: the initial
// root key, the initial chain key, and the seed for the post-quantum ratchet
// (SPQR). Mirrors the (RootKey, ChainKey, InitialPQRKey) tuple from
// ratchet.rs derive_keys.
type InitialKeys struct {
	RootKey  RootKey
	ChainKey ChainKey
	// PQRSeed is the 32-byte initial seed for the Sparse Post-Quantum Ratchet.
	// SPQR itself is ported later (PR phase per the plan); this carries the
	// seed through so the derivation is complete and vector-exact now.
	PQRSeed [32]byte
}

// DeriveInitialKeys runs the PQXDH master-secret key schedule
// (ratchet.rs derive_keys): it assembles the master secret
// (0xFF*32 || DH1..DH4 || kyber_shared_secret), then
// HKDF-SHA256(ikm=secret, salt=nil, info=pqxdhInfo) -> 32B root || 32B chain ||
// 32B pqr. The four DH agreements must already be in the upstream order.
func DeriveInitialKeys(dh1, dh2, dh3, dh4, kyberSharedSecret []byte) (InitialKeys, error) {
	secret := pqxdhSecret(dh1, dh2, dh3, dh4, kyberSharedSecret)
	okm, err := hkdfSplit(secret, nil, pqxdhInfo, rootKeyLen+chainKeyLen+32)
	if err != nil {
		return InitialKeys{}, fmt.Errorf("ratchet: deriving PQXDH initial keys: %w", err)
	}
	var ik InitialKeys
	copy(ik.RootKey.key[:], okm[0:rootKeyLen])
	copy(ik.ChainKey.key[:], okm[rootKeyLen:rootKeyLen+chainKeyLen])
	ik.ChainKey.index = 0
	copy(ik.PQRSeed[:], okm[rootKeyLen+chainKeyLen:rootKeyLen+chainKeyLen+32])
	return ik, nil
}

// PQXDHSecret exposes the PQXDH master-secret assembly (0xFF*32 || DH1..DH4 ||
// kyber_ss) for callers/tests that need to verify the pre-KDF byte layout
// against upstream. The session layer (later task) computes the DH agreements;
// this only concatenates them in the fixed order.
func PQXDHSecret(dh1, dh2, dh3, dh4, kyberSharedSecret []byte) []byte {
	return pqxdhSecret(dh1, dh2, dh3, dh4, kyberSharedSecret)
}
