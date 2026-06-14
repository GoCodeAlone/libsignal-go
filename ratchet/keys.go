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

// MessageKeys returns the message-key generator for this chain index. The
// message-key seed is HMAC-SHA256(key, 0x01); the generator defers the final
// HKDF until GenerateKeys is called with the (optional) Sparse Post-Quantum
// Ratchet message key, so the SPQR secret can be folded in per message — and
// so a SKIPPED message's seed can be cached and the keys derived later, once
// that specific message (and thus its SPQR key) arrives. Mirrors
// ChainKey::message_keys in rust/protocol/src/ratchet/keys.rs.
func (c ChainKey) MessageKeys() MessageKeyGenerator {
	return NewMessageKeyGeneratorFromSeed(c.baseMaterial(messageKeySeed), c.index)
}

// MessageKeyGenerator produces a message's MessageKeys, either by deferring the
// final key derivation from a stored seed (the common case, allowing the SPQR
// per-message key to be mixed in at derivation time) or by holding an already
// materialized MessageKeys (for cached keys from older, pre-SPQR sessions).
// Mirrors MessageKeyGenerator in rust/protocol/src/ratchet/keys.rs.
type MessageKeyGenerator struct {
	// Exactly one of (seed) / (keys) is live, selected by fromSeed.
	fromSeed bool
	seed     []byte
	counter  uint32
	keys     MessageKeys
}

// NewMessageKeyGeneratorFromSeed builds a Seed-variant generator: the keys are
// derived later from seed at the given counter. Mirrors
// MessageKeyGenerator::new_from_seed.
func NewMessageKeyGeneratorFromSeed(seed []byte, counter uint32) MessageKeyGenerator {
	return MessageKeyGenerator{fromSeed: true, seed: append([]byte(nil), seed...), counter: counter}
}

// NewMessageKeyGeneratorFromKeys builds a Keys-variant generator wrapping
// already-derived MessageKeys (used when reloading cached keys produced by a
// pre-SPQR session, which stored the derived keys rather than the seed).
func NewMessageKeyGeneratorFromKeys(keys MessageKeys) MessageKeyGenerator {
	return MessageKeyGenerator{fromSeed: false, keys: keys}
}

// FromSeed reports whether this generator defers derivation from a seed (true)
// or wraps already-materialized keys (false). The session storage codec uses
// this to decide whether to persist the seed or the derived keys.
func (g MessageKeyGenerator) FromSeed() bool { return g.fromSeed }

// String redacts the secret material so the deferred seed (Seed variant) or the
// wrapped MessageKeys (Keys variant) never leak into logs.
func (g MessageKeyGenerator) String() string {
	return "ratchet.MessageKeyGenerator{[redacted]}"
}

// Format intercepts every fmt verb — including Go-syntax %#v and hex %x — so the
// seed (Seed variant) or the embedded MessageKeys bytes (Keys variant) can never
// leak through formatting that bypasses String(). The generator needs its OWN
// Format: %#v of the outer struct recurses into the embedded MessageKeys by
// reflection, which does NOT invoke MessageKeys' Format. Mirrors the pattern on
// every other secret-bearing ratchet type (MessageKeys/ChainKey/RootKey).
func (g MessageKeyGenerator) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "ratchet.MessageKeyGenerator{[redacted]}")
}

// Seed returns the stored seed and counter for a Seed-variant generator; the
// bool is false for a Keys-variant generator.
func (g MessageKeyGenerator) Seed() ([]byte, uint32, bool) {
	if !g.fromSeed {
		return nil, 0, false
	}
	return append([]byte(nil), g.seed...), g.counter, true
}

// GenerateKeys materializes the MessageKeys, mixing in the optional Sparse
// Post-Quantum Ratchet message key (pqrKey) as the HKDF salt. A nil/empty
// pqrKey means no SPQR key for this message (V0 or pre-negotiation), which
// yields exactly the pre-SPQR derivation (salt=nil) — preserving backward
// compatibility. Mirrors MessageKeyGenerator::generate_keys.
//
// For a Keys-variant generator (cached pre-SPQR keys) pqrKey MUST be nil:
// pre-SPQR sessions never mix a PQR key, and the keys are already derived.
func (g MessageKeyGenerator) GenerateKeys(pqrKey []byte) (MessageKeys, error) {
	if !g.fromSeed {
		if len(pqrKey) != 0 {
			return MessageKeys{}, fmt.Errorf("ratchet: PQR key supplied for an already-derived (pre-SPQR) message-key generator")
		}
		return g.keys, nil
	}
	return deriveMessageKeys(g.seed, pqrKey, g.counter)
}

// deriveMessageKeys runs HKDF-SHA256(ikm=seed, salt=pqrKey, info=
// "WhisperMessageKeys") -> 32B cipher key || 32B MAC key || 16B IV. With a
// nil salt this is the original pre-SPQR derivation. Mirrors
// MessageKeys::derive_keys.
func deriveMessageKeys(seed, pqrKey []byte, counter uint32) (MessageKeys, error) {
	okm, err := hkdfSplit(seed, pqrKey, messageKeysInfo, cipherKeyLen+macKeyLen+ivLen)
	if err != nil {
		return MessageKeys{}, fmt.Errorf("ratchet: deriving message keys: %w", err)
	}
	var mk MessageKeys
	copy(mk.cipherKey[:], okm[0:cipherKeyLen])
	copy(mk.macKey[:], okm[cipherKeyLen:cipherKeyLen+macKeyLen])
	copy(mk.iv[:], okm[cipherKeyLen+macKeyLen:cipherKeyLen+macKeyLen+ivLen])
	mk.index = counter
	return mk, nil
}

// NewMessageKeys assembles a MessageKeys from its component byte slices (used
// when reloading cached, already-derived keys from session storage). It
// validates each length.
func NewMessageKeys(cipherKey, macKey, iv []byte, index uint32) (MessageKeys, error) {
	if len(cipherKey) != cipherKeyLen {
		return MessageKeys{}, fmt.Errorf("ratchet: cipher key must be %d bytes, got %d", cipherKeyLen, len(cipherKey))
	}
	if len(macKey) != macKeyLen {
		return MessageKeys{}, fmt.Errorf("ratchet: MAC key must be %d bytes, got %d", macKeyLen, len(macKey))
	}
	if len(iv) != ivLen {
		return MessageKeys{}, fmt.Errorf("ratchet: IV must be %d bytes, got %d", ivLen, len(iv))
	}
	var mk MessageKeys
	copy(mk.cipherKey[:], cipherKey)
	copy(mk.macKey[:], macKey)
	copy(mk.iv[:], iv)
	mk.index = index
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

// String redacts all key material (root key, chain key, and the PQR seed).
func (k InitialKeys) String() string {
	return "InitialKeys{rootKey/chainKey/pqrSeed: [redacted]}"
}

// Format intercepts every fmt verb (incl. %#v and %x) so neither the embedded
// keys nor the raw PQRSeed [32]byte can leak through formatting that bypasses
// String(). Without this, %#v on InitialKeys dumps PQRSeed as a byte array.
func (k InitialKeys) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "ratchet.InitialKeys{rootKey/chainKey/pqrSeed: [REDACTED]}")
}

// DeriveInitialKeys runs the PQXDH master-secret key schedule
// (ratchet.rs derive_keys): it assembles the master secret
// (0xFF*32 || DH1 || DH2 || DH3 [|| DH4] || kyber_shared_secret), then
// HKDF-SHA256(ikm=secret, salt=nil, info=pqxdhInfo) -> 32B root || 32B chain ||
// 32B pqr. The DH agreements must already be in the upstream order.
//
// DH4 (= ephemeral × one-time prekey) is OPTIONAL: the one-time prekey is not
// always present in a PreKeyBundle. When it is absent, callers pass an empty
// dh4 and it is omitted from the master secret, exactly as upstream conditions
// the fourth agreement on Some(one_time_prekey) (rust/protocol/src/pqxdh.rs:220
// for the initiator and :360 for the recipient). DH1..DH3 are always present.
func DeriveInitialKeys(dh1, dh2, dh3, dh4, kyberSharedSecret []byte) (InitialKeys, error) {
	// DH1..DH3 are mandatory and must each be exactly agreementLen bytes.
	// Upstream's typed keys guarantee this; here the inputs are []byte, so
	// validate it explicitly rather than silently producing a wrong-length
	// master secret.
	for i, dh := range [3][]byte{dh1, dh2, dh3} {
		if len(dh) != agreementLen {
			return InitialKeys{}, fmt.Errorf("ratchet: DH%d agreement must be %d bytes, got %d", i+1, agreementLen, len(dh))
		}
	}
	// DH4 is optional: empty means no one-time prekey (omit it from the secret);
	// otherwise it must be a full agreement. Any other length is a bug.
	if len(dh4) != 0 && len(dh4) != agreementLen {
		return InitialKeys{}, fmt.Errorf("ratchet: DH4 agreement must be %d bytes or absent, got %d", agreementLen, len(dh4))
	}
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
