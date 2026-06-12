package session

import (
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/kem"
)

// PreKeyBundle is the set of public key material a server hands an initiator so
// it can start a session with a recipient without the recipient online: the
// recipient's registration id, device id, identity key, a signed pre-key (with
// its XEdDSA signature), a signed Kyber pre-key (with its signature), and an
// optional one-time EC pre-key. Mirrors PreKeyBundle in
// rust/protocol/src/state/bundle.rs.
//
// At the v4 protocol surface the Kyber pre-key is mandatory; a bundle without
// one is rejected at processing time (ErrNoKyberPreKey).
type PreKeyBundle struct {
	registrationID uint32
	deviceID       uint32

	// One-time EC pre-key (optional). preKeyID is meaningful only when
	// hasPreKey is true.
	hasPreKey bool
	preKeyID  uint32
	preKey    curve.PublicKey

	signedPreKeyID  uint32
	signedPreKey    curve.PublicKey
	signedPreKeySig []byte

	kyberPreKeyID  uint32
	kyberPreKey    kem.PublicKey
	kyberPreKeySig []byte

	identityKey curve.PublicKey
}

// PreKeyBundleParams carries the fields for NewPreKeyBundle. A nil PreKey/
// PreKeyID (both must agree) means no one-time pre-key is offered.
type PreKeyBundleParams struct {
	RegistrationID uint32
	DeviceID       uint32

	// PreKey is the optional one-time EC pre-key. When set, PreKeyID must also
	// be set; leave PreKey nil to omit the one-time pre-key.
	PreKeyID *uint32
	PreKey   *curve.PublicKey

	SignedPreKeyID  uint32
	SignedPreKey    curve.PublicKey
	SignedPreKeySig []byte

	KyberPreKeyID  uint32
	KyberPreKey    kem.PublicKey
	KyberPreKeySig []byte

	IdentityKey curve.PublicKey
}

// NewPreKeyBundle assembles a PreKeyBundle from its parts. The Kyber pre-key is
// required (v4); the one-time EC pre-key is optional (set both PreKey and
// PreKeyID, or neither).
func NewPreKeyBundle(p PreKeyBundleParams) (*PreKeyBundle, error) {
	b := &PreKeyBundle{
		registrationID:  p.RegistrationID,
		deviceID:        p.DeviceID,
		signedPreKeyID:  p.SignedPreKeyID,
		signedPreKey:    p.SignedPreKey,
		signedPreKeySig: append([]byte(nil), p.SignedPreKeySig...),
		kyberPreKeyID:   p.KyberPreKeyID,
		kyberPreKey:     p.KyberPreKey,
		kyberPreKeySig:  append([]byte(nil), p.KyberPreKeySig...),
		identityKey:     p.IdentityKey,
	}
	switch {
	case p.PreKey != nil && p.PreKeyID != nil:
		b.hasPreKey = true
		b.preKeyID = *p.PreKeyID
		b.preKey = *p.PreKey
	case p.PreKey == nil && p.PreKeyID == nil:
		// No one-time pre-key offered — valid.
	default:
		return nil, ErrInvalidPreKeyBundle
	}
	return b, nil
}

// RegistrationID returns the recipient's registration id.
func (b *PreKeyBundle) RegistrationID() uint32 { return b.registrationID }

// DeviceID returns the recipient's device id.
func (b *PreKeyBundle) DeviceID() uint32 { return b.deviceID }

// PreKey returns the optional one-time EC pre-key (id, public key) and whether
// one is present.
func (b *PreKeyBundle) PreKey() (uint32, curve.PublicKey, bool) {
	return b.preKeyID, b.preKey, b.hasPreKey
}

// SignedPreKeyID returns the signed pre-key id.
func (b *PreKeyBundle) SignedPreKeyID() uint32 { return b.signedPreKeyID }

// SignedPreKey returns the signed pre-key public key.
func (b *PreKeyBundle) SignedPreKey() curve.PublicKey { return b.signedPreKey }

// SignedPreKeySignature returns the XEdDSA signature over the serialized signed
// pre-key, produced by the recipient's identity key.
func (b *PreKeyBundle) SignedPreKeySignature() []byte { return b.signedPreKeySig }

// KyberPreKeyID returns the Kyber pre-key id.
func (b *PreKeyBundle) KyberPreKeyID() uint32 { return b.kyberPreKeyID }

// KyberPreKey returns the Kyber pre-key public key.
func (b *PreKeyBundle) KyberPreKey() kem.PublicKey { return b.kyberPreKey }

// KyberPreKeySignature returns the XEdDSA signature over the serialized Kyber
// pre-key, produced by the recipient's identity key.
func (b *PreKeyBundle) KyberPreKeySignature() []byte { return b.kyberPreKeySig }

// IdentityKey returns the recipient's identity public key.
func (b *PreKeyBundle) IdentityKey() curve.PublicKey { return b.identityKey }
