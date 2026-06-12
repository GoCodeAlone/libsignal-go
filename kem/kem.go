// Package kem implements key encapsulation mechanisms (KEMs) for the Signal
// protocol. Kyber1024 (round-3, type byte 0x08) is the active KEM; the
// ML-KEM-1024 type byte (0x0A) is recognized for forward compatibility but is
// not yet enabled.
//
// It is a pure-Go port of rust/protocol/src/kem.rs over
// github.com/cloudflare/circl. Serialization is wire-compatible with upstream
// libsignal: a key or ciphertext is one KeyType byte followed by the raw bytes
// circl produces (verified against upstream fixtures in TestUpstreamKeyFixtures).
package kem

import (
	"crypto/subtle"
	"fmt"
	"io"
)

// KeyType identifies a supported KEM protocol by its one-byte wire tag.
type KeyType uint8

const (
	// KeyTypeKyber1024 is round-3 Kyber1024; its serialized type byte is 0x08.
	KeyTypeKyber1024 KeyType = 0x08
	// KeyTypeMLKEM1024 is ML-KEM-1024 (FIPS 203); its type byte 0x0A is
	// recognized on the wire but not currently enabled.
	KeyTypeMLKEM1024 KeyType = 0x0A
)

// String implements fmt.Stringer.
func (k KeyType) String() string {
	switch k {
	case KeyTypeKyber1024:
		return "Kyber1024"
	case KeyTypeMLKEM1024:
		return "MLKEM1024"
	default:
		return fmt.Sprintf("KeyType(0x%02x)", uint8(k))
	}
}

// kemParameters bridges a KeyType to its concrete KEM implementation, mirroring
// the DynParameters trait in kem.rs.
type kemParameters interface {
	keyType() KeyType
	publicKeyLength() int
	secretKeyLength() int
	ciphertextLength() int
	sharedSecretLength() int
	seedSize() int
	generate(rng []byte) (pub, sec []byte, err error)
	encapsulate(pubKey []byte) (ss, ct []byte, err error)
	decapsulate(secretKey, ciphertext []byte) (ss []byte, err error)
}

// parametersFor returns the implementation for a KeyType. The ML-KEM-1024 tag
// is recognized but not enabled, returning [UnsupportedKEMKeyTypeError]. Unknown
// tags return [BadKEMKeyTypeError].
func parametersFor(k KeyType) (kemParameters, error) {
	switch k {
	case KeyTypeKyber1024:
		return kyber1024Parameters{}, nil
	case KeyTypeMLKEM1024:
		return nil, UnsupportedKEMKeyTypeError{Type: byte(k)}
	default:
		return nil, BadKEMKeyTypeError{Type: byte(k)}
	}
}

// keyTypeFromByte maps a wire tag byte to a KeyType, accepting only recognized
// tags (0x08 and 0x0A). Unknown tags return [BadKEMKeyTypeError].
func keyTypeFromByte(b byte) (KeyType, error) {
	switch b {
	case byte(KeyTypeKyber1024):
		return KeyTypeKyber1024, nil
	case byte(KeyTypeMLKEM1024):
		return KeyTypeMLKEM1024, nil
	default:
		return 0, BadKEMKeyTypeError{Type: b}
	}
}

// ErrNoKeyTypeIdentifier is returned when deserializing from empty input that
// carries no KeyType byte.
type ErrNoKeyTypeIdentifier struct{}

func (ErrNoKeyTypeIdentifier) Error() string { return "no key type identifier" }

// BadKEMKeyTypeError is returned for an unrecognized KEM key-type byte.
type BadKEMKeyTypeError struct {
	Type byte
}

func (e BadKEMKeyTypeError) Error() string {
	return fmt.Sprintf("bad KEM key type <0x%02x>", e.Type)
}

// UnsupportedKEMKeyTypeError is returned for a key type that is recognized on
// the wire but not currently enabled (ML-KEM-1024).
type UnsupportedKEMKeyTypeError struct {
	Type byte
}

func (e UnsupportedKEMKeyTypeError) Error() string {
	return fmt.Sprintf("unsupported KEM key type <0x%02x>", e.Type)
}

// BadKEMKeyLengthError is returned when a serialized key has the wrong length
// for its key type.
type BadKEMKeyLengthError struct {
	KeyType KeyType
	Length  int
}

func (e BadKEMKeyLengthError) Error() string {
	return fmt.Sprintf("bad KEM key length <%d> for key type <%s>", e.Length, e.KeyType)
}

// BadKEMCiphertextLengthError is returned when a serialized ciphertext has the
// wrong length for its key type.
type BadKEMCiphertextLengthError struct {
	KeyType KeyType
	Length  int
}

func (e BadKEMCiphertextLengthError) Error() string {
	return fmt.Sprintf("bad KEM ciphertext length <%d> for key type <%s>", e.Length, e.KeyType)
}

// WrongKEMKeyTypeError is returned when a ciphertext's key type does not match
// the secret key used to decapsulate it.
type WrongKEMKeyTypeError struct {
	Got      byte
	Expected byte
}

func (e WrongKEMKeyTypeError) Error() string {
	return fmt.Sprintf("wrong KEM key type <0x%02x>, expected <0x%02x>", e.Got, e.Expected)
}

// PublicKey is a KEM public key, able to encapsulate a shared secret.
type PublicKey struct {
	keyType KeyType
	data    []byte
}

// SecretKey is a KEM secret key, able to decapsulate a shared secret.
type SecretKey struct {
	keyType KeyType
	data    []byte
}

// KeyType reports the KEM protocol of the public key.
func (p PublicKey) KeyType() KeyType { return p.keyType }

// KeyType reports the KEM protocol of the secret key.
func (s SecretKey) KeyType() KeyType { return s.keyType }

// Serialize returns the wire form of the public key: the KeyType byte followed
// by the raw key.
func (p PublicKey) Serialize() []byte {
	return serializeTagged(p.keyType, p.data)
}

// Serialize returns the wire form of the secret key: the KeyType byte followed
// by the raw key.
func (s SecretKey) Serialize() []byte {
	return serializeTagged(s.keyType, s.data)
}

// String implements fmt.Stringer for the public key, reporting only the key
// type and length (the public key body is not secret, but we keep the Debug
// form compact and consistent with the secret key, mirroring upstream).
func (p PublicKey) String() string {
	return fmt.Sprintf("kem.PublicKey{key_type: %s, bytes_len: %d}", p.keyType, len(p.data))
}

// String implements fmt.Stringer for the secret key, redacting the key body so
// secret material never leaks into logs.
func (s SecretKey) String() string {
	return fmt.Sprintf("kem.SecretKey{key_type: %s, bytes_len: %d, key: REDACTED}", s.keyType, len(s.data))
}

// Format implements fmt.Formatter for the secret key, redacting under every
// verb.
func (s SecretKey) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, s.String())
}

// Equal reports whether two public keys are equal, comparing the key body in
// constant time once the key types match.
func (p PublicKey) Equal(other PublicKey) bool {
	if p.keyType != other.keyType {
		return false
	}
	return subtle.ConstantTimeCompare(p.data, other.data) == 1
}

// serializeTagged builds the wire form: type byte followed by raw key bytes.
func serializeTagged(keyType KeyType, data []byte) []byte {
	out := make([]byte, 1+len(data))
	out[0] = byte(keyType)
	copy(out[1:], data)
	return out
}

// DeserializePublicKey parses the wire form of a public key, validating the
// KeyType byte and the body length for that type.
func DeserializePublicKey(value []byte) (PublicKey, error) {
	keyType, body, params, err := parseTagged(value)
	if err != nil {
		return PublicKey{}, err
	}
	if len(body) != params.publicKeyLength() {
		return PublicKey{}, BadKEMKeyLengthError{KeyType: keyType, Length: len(value)}
	}
	return PublicKey{keyType: keyType, data: cloneBytes(body)}, nil
}

// DeserializeSecretKey parses the wire form of a secret key, validating the
// KeyType byte and the body length for that type.
func DeserializeSecretKey(value []byte) (SecretKey, error) {
	keyType, body, params, err := parseTagged(value)
	if err != nil {
		return SecretKey{}, err
	}
	if len(body) != params.secretKeyLength() {
		return SecretKey{}, BadKEMKeyLengthError{KeyType: keyType, Length: len(value)}
	}
	return SecretKey{keyType: keyType, data: cloneBytes(body)}, nil
}

// parseTagged splits and validates a type-tagged buffer, returning the key
// type, the body slice, and the parameters for the type.
func parseTagged(value []byte) (KeyType, []byte, kemParameters, error) {
	if len(value) == 0 {
		return 0, nil, nil, ErrNoKeyTypeIdentifier{}
	}
	keyType, err := keyTypeFromByte(value[0])
	if err != nil {
		return 0, nil, nil, err
	}
	params, err := parametersFor(keyType)
	if err != nil {
		return 0, nil, nil, err
	}
	return keyType, value[1:], params, nil
}

// Encapsulate produces a fresh shared secret and a serialized ciphertext for
// the recipient holding the matching secret key. Randomness is drawn from the
// underlying KEM's cryptographically secure source.
func (p PublicKey) Encapsulate() (sharedSecret, ciphertext []byte, err error) {
	params, err := parametersFor(p.keyType)
	if err != nil {
		return nil, nil, err
	}
	ss, ct, err := params.encapsulate(p.data)
	if err != nil {
		return nil, nil, err
	}
	return ss, serializeTagged(p.keyType, ct), nil
}

// Decapsulate recovers the shared secret from a serialized ciphertext. The
// ciphertext's key type must match this secret key's type.
func (s SecretKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	ctKeyType, ctBody, _, err := parseTaggedCiphertext(ciphertext)
	if err != nil {
		return nil, err
	}
	if ctKeyType != s.keyType {
		return nil, WrongKEMKeyTypeError{Got: byte(ctKeyType), Expected: byte(s.keyType)}
	}
	params, err := parametersFor(s.keyType)
	if err != nil {
		return nil, err
	}
	return params.decapsulate(s.data, ctBody)
}

// parseTaggedCiphertext splits and validates a serialized ciphertext, checking
// the body length against the key type's ciphertext length.
func parseTaggedCiphertext(value []byte) (KeyType, []byte, kemParameters, error) {
	if len(value) == 0 {
		return 0, nil, nil, ErrNoKeyTypeIdentifier{}
	}
	keyType, err := keyTypeFromByte(value[0])
	if err != nil {
		return 0, nil, nil, err
	}
	params, err := parametersFor(keyType)
	if err != nil {
		return 0, nil, nil, err
	}
	body := value[1:]
	if len(body) != params.ciphertextLength() {
		return 0, nil, nil, BadKEMCiphertextLengthError{KeyType: keyType, Length: len(value)}
	}
	return keyType, body, params, nil
}

// KeyPair is a KEM public/secret key pair.
type KeyPair struct {
	PublicKey PublicKey
	SecretKey SecretKey
}

// GenerateKeyPair generates a new key pair for the given KEM type, drawing seed
// entropy from rng. rng must be a cryptographically secure source.
func GenerateKeyPair(keyType KeyType, rng io.Reader) (KeyPair, error) {
	params, err := parametersFor(keyType)
	if err != nil {
		return KeyPair{}, err
	}
	seed := make([]byte, params.seedSize())
	if _, err := io.ReadFull(rng, seed); err != nil {
		return KeyPair{}, err
	}
	pub, sec, err := params.generate(seed)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		PublicKey: PublicKey{keyType: keyType, data: pub},
		SecretKey: SecretKey{keyType: keyType, data: sec},
	}, nil
}

// NewKeyPair pairs a public and secret key. It returns an error if their key
// types differ.
func NewKeyPair(publicKey PublicKey, secretKey SecretKey) (KeyPair, error) {
	if publicKey.keyType != secretKey.keyType {
		return KeyPair{}, WrongKEMKeyTypeError{Got: byte(secretKey.keyType), Expected: byte(publicKey.keyType)}
	}
	return KeyPair{PublicKey: publicKey, SecretKey: secretKey}, nil
}

// KeyPairFromPublicAndSecret deserializes a key pair from the wire forms of a
// public and secret key, requiring matching key types.
func KeyPairFromPublicAndSecret(publicKey, secretKey []byte) (KeyPair, error) {
	pub, err := DeserializePublicKey(publicKey)
	if err != nil {
		return KeyPair{}, err
	}
	sec, err := DeserializeSecretKey(secretKey)
	if err != nil {
		return KeyPair{}, err
	}
	return NewKeyPair(pub, sec)
}

// cloneBytes returns an independent copy of b so deserialized keys do not alias
// caller-owned buffers.
func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
