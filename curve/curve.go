// Package curve implements the Curve25519 (Djb) key types used by the Signal
// protocol: X25519 key agreement and the 33-byte serialized public-key wire
// format.
//
// It is a pure-Go port of rust/core/src/curve.rs. Serialization is
// wire-compatible with upstream libsignal: a public key is one type byte
// (0x05 for the Djb key type) followed by the 32-byte Montgomery-u
// coordinate; a private key is the 32-byte clamped scalar.
//
// XEdDSA signing and verification (calculate_signature / verify_signature) are
// implemented separately in xeddsa.go.
package curve

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyType identifies the elliptic curve a key belongs to. Only the Djb
// (Curve25519) type is defined.
type KeyType uint8

const (
	// KeyTypeDjb is the Curve25519 key type; its serialized type byte is 0x05.
	KeyTypeDjb KeyType = 0x05
)

// String implements fmt.Stringer.
func (k KeyType) String() string {
	switch k {
	case KeyTypeDjb:
		return "Djb"
	default:
		return fmt.Sprintf("KeyType(0x%02x)", uint8(k))
	}
}

// keyTypeFromByte maps a serialized type byte to a KeyType, rejecting unknown
// values with a [BadKeyTypeError].
func keyTypeFromByte(b byte) (KeyType, error) {
	switch b {
	case byte(KeyTypeDjb):
		return KeyTypeDjb, nil
	default:
		return 0, BadKeyTypeError{Type: b}
	}
}

const (
	// PublicKeyLength is the length of the raw Montgomery-u public key.
	PublicKeyLength = 32
	// PrivateKeyLength is the length of the raw (clamped) private scalar.
	PrivateKeyLength = 32
	// AgreementLength is the length of an X25519 shared secret.
	AgreementLength = 32
	// SerializedPublicKeyLength is the length of the wire form of a public
	// key: one type byte followed by the raw public key.
	SerializedPublicKeyLength = 1 + PublicKeyLength
)

// ErrNoKeyTypeIdentifier is returned when deserializing a public key from an
// empty input that carries no type byte.
type ErrNoKeyTypeIdentifier struct{}

func (ErrNoKeyTypeIdentifier) Error() string { return "no key type identifier" }

// BadKeyTypeError is returned when a serialized key carries an unrecognized
// type byte.
type BadKeyTypeError struct {
	Type byte
}

func (e BadKeyTypeError) Error() string {
	return fmt.Sprintf("bad key type <0x%02x>", e.Type)
}

// BadKeyLengthError is returned when a serialized key has the wrong length for
// its key type.
type BadKeyLengthError struct {
	KeyType KeyType
	Length  int
}

func (e BadKeyLengthError) Error() string {
	return fmt.Sprintf("bad key length <%d> for key with type <%s>", e.Length, e.KeyType)
}

// ErrInvalidKeyAgreement is returned when a key agreement produces the
// all-zero shared secret, which indicates a low-order or otherwise malicious
// peer public key.
type ErrInvalidKeyAgreement struct{}

func (ErrInvalidKeyAgreement) Error() string {
	return "invalid key agreement output (all-zero shared secret)"
}

// PublicKey is a Curve25519 public key.
type PublicKey struct {
	keyType KeyType
	data    [PublicKeyLength]byte
}

// NewPublicKey constructs a Djb public key from its raw 32-byte Montgomery-u
// coordinate, rejecting inputs of the wrong length with a [BadKeyLengthError].
func NewPublicKey(bytes []byte) (PublicKey, error) {
	if len(bytes) != PublicKeyLength {
		return PublicKey{}, BadKeyLengthError{KeyType: KeyTypeDjb, Length: len(bytes)}
	}
	var pk PublicKey
	pk.keyType = KeyTypeDjb
	copy(pk.data[:], bytes)
	return pk, nil
}

// DeserializePublicKey parses the wire form of a public key: a one-byte key
// type followed by the raw key. Trailing data after a Djb key is permitted for
// backward compatibility (matching upstream), but a key body shorter than 32
// bytes is rejected.
func DeserializePublicKey(value []byte) (PublicKey, error) {
	if len(value) == 0 {
		return PublicKey{}, ErrNoKeyTypeIdentifier{}
	}
	keyType, err := keyTypeFromByte(value[0])
	if err != nil {
		return PublicKey{}, err
	}
	body := value[1:]
	switch keyType {
	case KeyTypeDjb:
		if len(body) < PublicKeyLength {
			// Length reported as the full input length, mirroring upstream's
			// value.len() + 1 accounting.
			return PublicKey{}, BadKeyLengthError{KeyType: KeyTypeDjb, Length: len(body) + 1}
		}
		// Trailing data after the public key is currently allowed.
		return NewPublicKey(body[:PublicKeyLength])
	default:
		return PublicKey{}, BadKeyTypeError{Type: value[0]}
	}
}

// KeyType reports the key type of the public key.
func (p PublicKey) KeyType() KeyType { return p.keyType }

// PublicKeyBytes returns a copy of the raw 32-byte public key, without the
// type byte.
func (p PublicKey) PublicKeyBytes() []byte {
	out := make([]byte, PublicKeyLength)
	copy(out, p.data[:])
	return out
}

// Serialize returns the wire form of the public key: the type byte followed by
// the raw public key.
func (p PublicKey) Serialize() []byte {
	out := make([]byte, SerializedPublicKeyLength)
	out[0] = byte(p.keyType)
	copy(out[1:], p.data[:])
	return out
}

// Equal reports whether two public keys are equal, comparing the key body in
// constant time once the key types match.
func (p PublicKey) Equal(other PublicKey) bool {
	if p.keyType != other.keyType {
		return false
	}
	return subtle.ConstantTimeCompare(p.data[:], other.data[:]) == 1
}

// PrivateKey is a Curve25519 private key (a clamped X25519 scalar).
type PrivateKey struct {
	keyType KeyType
	data    [PrivateKeyLength]byte
}

// DeserializePrivateKey parses a raw 32-byte private key. The scalar is clamped
// per X25519; clamping is not strictly necessary but is kept for backward
// compatibility, matching upstream.
func DeserializePrivateKey(value []byte) (PrivateKey, error) {
	if len(value) != PrivateKeyLength {
		return PrivateKey{}, BadKeyLengthError{KeyType: KeyTypeDjb, Length: len(value)}
	}
	var pk PrivateKey
	pk.keyType = KeyTypeDjb
	copy(pk.data[:], value)
	clamp(&pk.data)
	return pk, nil
}

// privateKeyFromBytes builds a clamped private key from an exact 32-byte array.
func privateKeyFromBytes(bytes [PrivateKeyLength]byte) PrivateKey {
	pk := PrivateKey{keyType: KeyTypeDjb, data: bytes}
	clamp(&pk.data)
	return pk
}

// KeyType reports the key type of the private key.
func (p PrivateKey) KeyType() KeyType { return p.keyType }

// Serialize returns the raw 32-byte (clamped) private key.
func (p PrivateKey) Serialize() []byte {
	out := make([]byte, PrivateKeyLength)
	copy(out, p.data[:])
	return out
}

// PublicKey derives the public key corresponding to this private key.
func (p PrivateKey) PublicKey() (PublicKey, error) {
	// Use X25519 with the standard basepoint rather than ScalarBaseMult, as
	// recommended by the curve25519 package docs; this returns an error for
	// degenerate scalars instead of silently producing a low-order result.
	out, err := curve25519.X25519(p.data[:], curve25519.Basepoint)
	if err != nil {
		return PublicKey{}, err
	}
	var pub [PublicKeyLength]byte
	copy(pub[:], out)
	return PublicKey{keyType: KeyTypeDjb, data: pub}, nil
}

// CalculateAgreement performs an X25519 Diffie-Hellman with the peer's public
// key and returns the 32-byte shared secret. An all-zero shared secret (from a
// low-order peer key) is rejected with [ErrInvalidKeyAgreement].
func (p PrivateKey) CalculateAgreement(theirKey PublicKey) ([]byte, error) {
	shared, err := curve25519.X25519(p.data[:], theirKey.data[:])
	if err != nil {
		// curve25519.X25519 returns an error for low-order input points,
		// which would otherwise yield the all-zero shared secret.
		return nil, ErrInvalidKeyAgreement{}
	}
	return shared, nil
}

// String implements fmt.Stringer, redacting the secret key material.
func (p PrivateKey) String() string {
	return "curve.PrivateKey{REDACTED}"
}

// Format implements fmt.Formatter, redacting the secret key material under every
// verb so the scalar never leaks into logs.
func (p PrivateKey) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "curve.PrivateKey{REDACTED}")
}

// clamp applies the standard X25519 scalar clamping in place: clear the three
// low bits of the first byte, clear the high bit of the last byte, and set the
// second-highest bit of the last byte.
func clamp(scalar *[PrivateKeyLength]byte) {
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
}
