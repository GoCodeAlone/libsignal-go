package accountkeys

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

// SVRKey is the account's private Secure Value Recovery master key.
type SVRKey struct {
	bytes [SVRKeyLen]byte
}

// NewSVRKey wraps an existing Secure Value Recovery master key.
func NewSVRKey(raw [SVRKeyLen]byte) SVRKey { return SVRKey{bytes: raw} }

// SVRKey derives a typed Secure Value Recovery master key from account entropy.
func (p AccountEntropyPool) SVRKey() SVRKey { return NewSVRKey(p.DeriveSVRKey()) }

// String redacts the key rather than exposing secret bytes.
func (k SVRKey) String() string { return "[REDACTED SVRKey]" }

// GoString redacts the key in Go-syntax formatting.
func (k SVRKey) GoString() string { return k.String() }

// Format redacts the key for every format verb, flag, width and precision.
func (k SVRKey) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(k.String())) }

// DeriveRegistrationLock derives the registration-lock token.
func (k SVRKey) DeriveRegistrationLock() [32]byte {
	return keyedHash(k.bytes[:], []byte("Registration Lock"))
}

// DeriveRegistrationRecoveryPassword derives the account recovery password.
func (k SVRKey) DeriveRegistrationRecoveryPassword() [32]byte {
	return keyedHash(k.bytes[:], []byte("Registration Recovery"))
}

// DeriveStorageServiceKey derives the storage-service root encryption key.
func (k SVRKey) DeriveStorageServiceKey() [32]byte {
	return keyedHash(k.bytes[:], []byte("Storage Service Encryption"))
}

// DeriveLoggingKey derives the logging pseudonym key.
func (k SVRKey) DeriveLoggingKey() [32]byte {
	return keyedHash(k.bytes[:], []byte("Logging Key"))
}

// EncodeMasterKey authenticates and encrypts masterKey using upstream's PIN SIV format.
func (h PinHash) EncodeMasterKey(masterKey [32]byte) [48]byte {
	defer clear(masterKey[:])
	authKey := keyedHash(h.EncryptionKey[:], []byte("auth"))
	defer clear(authKey[:])
	encKey := keyedHash(h.EncryptionKey[:], []byte("enc"))
	defer clear(encKey[:])
	iv := keyedHash(authKey[:], masterKey[:])
	defer clear(iv[:])
	mask := keyedHash(encKey[:], iv[:16])
	defer clear(mask[:])
	var out [48]byte
	copy(out[:16], iv[:16])
	for i := range masterKey {
		out[16+i] = masterKey[i] ^ mask[i]
	}
	return out
}

// DecodeMasterKey authenticates and decrypts an upstream PIN SIV master key.
func (h PinHash) DecodeMasterKey(ciphertext [48]byte) ([32]byte, error) {
	authKey := keyedHash(h.EncryptionKey[:], []byte("auth"))
	defer clear(authKey[:])
	encKey := keyedHash(h.EncryptionKey[:], []byte("enc"))
	defer clear(encKey[:])
	mask := keyedHash(encKey[:], ciphertext[:16])
	defer clear(mask[:])
	var masterKey [32]byte
	for i := range masterKey {
		masterKey[i] = ciphertext[16+i] ^ mask[i]
	}
	iv := keyedHash(authKey[:], masterKey[:])
	defer clear(iv[:])
	if subtle.ConstantTimeCompare(iv[:16], ciphertext[:16]) != 1 {
		clear(masterKey[:])
		return [32]byte{}, errors.New("invalid PIN master-key authentication")
	}
	return masterKey, nil
}

func keyedHash(key, input []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(input)
	var out [32]byte
	mac.Sum(out[:0])
	return out
}
