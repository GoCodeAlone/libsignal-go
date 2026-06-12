package curve

import (
	"io"
)

// KeyPair is a Curve25519 public/private key pair.
type KeyPair struct {
	PublicKey  PublicKey
	PrivateKey PrivateKey
}

// GenerateKeyPair generates a new key pair, drawing 32 bytes of private-key
// entropy from rng. The scalar is clamped per X25519 and the public key is
// derived from it. rng must be a cryptographically secure source; passing a
// deterministic reader yields a deterministic key pair, which is used in tests.
func GenerateKeyPair(rng io.Reader) (KeyPair, error) {
	var seed [PrivateKeyLength]byte
	if _, err := io.ReadFull(rng, seed[:]); err != nil {
		return KeyPair{}, err
	}
	priv := privateKeyFromBytes(seed)
	pub, err := priv.PublicKey()
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// NewKeyPair pairs an existing public and private key.
func NewKeyPair(publicKey PublicKey, privateKey PrivateKey) KeyPair {
	return KeyPair{PublicKey: publicKey, PrivateKey: privateKey}
}

// KeyPairFromPublicAndPrivate deserializes a key pair from the wire form of a
// public key and the raw bytes of a private key.
func KeyPairFromPublicAndPrivate(publicKey, privateKey []byte) (KeyPair, error) {
	pub, err := DeserializePublicKey(publicKey)
	if err != nil {
		return KeyPair{}, err
	}
	priv, err := DeserializePrivateKey(privateKey)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// KeyPairFromPrivateKey derives the public key from privateKey and returns the
// resulting key pair.
func KeyPairFromPrivateKey(privateKey PrivateKey) (KeyPair, error) {
	pub, err := privateKey.PublicKey()
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{PublicKey: pub, PrivateKey: privateKey}, nil
}

// CalculateAgreement performs the X25519 agreement between this key pair's
// private key and theirKey.
func (kp KeyPair) CalculateAgreement(theirKey PublicKey) ([]byte, error) {
	return kp.PrivateKey.CalculateAgreement(theirKey)
}
