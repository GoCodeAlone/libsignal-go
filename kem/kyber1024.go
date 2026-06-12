package kem

import (
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

// kyber1024Parameters adapts circl's round-3 Kyber1024 implementation to the
// kemParameters interface. circl's kyber1024 is the round-3 CCAKEM as submitted
// to NIST PQC round 3 (pq-crystals/kyber round-3 spec), which is the same
// construction Signal uses via libcrux-ml-kem's "kyber" feature — its
// serialized key, ciphertext, and shared-secret encodings are byte-compatible
// with upstream libsignal (verified by TestUpstreamKeyFixtures).
type kyber1024Parameters struct{}

// kyber1024Scheme is circl's Kyber1024 KEM scheme.
func kyber1024Scheme() kem.Scheme { return kyber1024.Scheme() }

func (kyber1024Parameters) keyType() KeyType { return KeyTypeKyber1024 }

func (kyber1024Parameters) publicKeyLength() int  { return kyber1024Scheme().PublicKeySize() }
func (kyber1024Parameters) secretKeyLength() int  { return kyber1024Scheme().PrivateKeySize() }
func (kyber1024Parameters) ciphertextLength() int { return kyber1024Scheme().CiphertextSize() }
func (kyber1024Parameters) sharedSecretLength() int {
	return kyber1024Scheme().SharedKeySize()
}

func (kyber1024Parameters) generate(rng []byte) (pub, sec []byte, err error) {
	scheme := kyber1024Scheme()
	// DeriveKeyPair needs exactly SeedSize() bytes; callers pass that many.
	pk, sk := scheme.DeriveKeyPair(rng)
	pkb, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	skb, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pkb, skb, nil
}

func (p kyber1024Parameters) encapsulate(pubKey []byte) (ss, ct []byte, err error) {
	scheme := kyber1024Scheme()
	pk, err := scheme.UnmarshalBinaryPublicKey(pubKey)
	if err != nil {
		return nil, nil, BadKEMKeyLengthError{KeyType: p.keyType(), Length: len(pubKey)}
	}
	ct, ss, err = scheme.Encapsulate(pk)
	if err != nil {
		return nil, nil, err
	}
	return ss, ct, nil
}

// encapsulateDeterministically is used only by the KAT test to drive circl's
// derandomized API with a fixed encapsulation seed.
func (p kyber1024Parameters) encapsulateDeterministically(pubKey, seed []byte) (ss, ct []byte, err error) {
	scheme := kyber1024Scheme()
	pk, err := scheme.UnmarshalBinaryPublicKey(pubKey)
	if err != nil {
		return nil, nil, BadKEMKeyLengthError{KeyType: p.keyType(), Length: len(pubKey)}
	}
	ct, ss, err = scheme.EncapsulateDeterministically(pk, seed)
	if err != nil {
		return nil, nil, err
	}
	return ss, ct, nil
}

func (p kyber1024Parameters) decapsulate(secretKey, ciphertext []byte) (ss []byte, err error) {
	scheme := kyber1024Scheme()
	sk, err := scheme.UnmarshalBinaryPrivateKey(secretKey)
	if err != nil {
		return nil, BadKEMKeyLengthError{KeyType: p.keyType(), Length: len(secretKey)}
	}
	if len(ciphertext) != scheme.CiphertextSize() {
		return nil, BadKEMCiphertextLengthError{KeyType: p.keyType(), Length: len(ciphertext)}
	}
	ss, err = scheme.Decapsulate(sk, ciphertext)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

// encapsulationSeedSize reports the seed length circl's
// EncapsulateDeterministically expects; used by the KAT test.
func (kyber1024Parameters) encapsulationSeedSize() int {
	return kyber1024Scheme().EncapsulationSeedSize()
}

// seedSize reports the seed length DeriveKeyPair expects.
func (kyber1024Parameters) seedSize() int {
	return kyber1024Scheme().SeedSize()
}
