package accountkeys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/GoCodeAlone/libsignal-go/internal/accountkeysproto"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const (
	// MFAMetadataCiphertextLen is the fixed size of encrypted MFA key metadata.
	MFAMetadataCiphertextLen = 160
	// MFAKeyNameMaxLen is the maximum MFA key name length in UTF-8 bytes.
	MFAKeyNameMaxLen = 98

	mfaPaddedPlaintextLen = 112
	mfaAuthenticatedLen   = aes.BlockSize + mfaPaddedPlaintextLen
)

var errInvalidMFAMetadata = errors.New("invalid MFA metadata")

// MFAMetadata describes an MFA key without any service or account operations.
type MFAMetadata struct {
	name                 string
	createdAtEpochMillis uint64
}

// EncryptedMFAMetadata is the opaque, authenticated fixed-size MFA metadata blob.
type EncryptedMFAMetadata [MFAMetadataCiphertextLen]byte

// NewMFAMetadata validates metadata for an MFA key.
func NewMFAMetadata(name string, createdAtEpochMillis uint64) (MFAMetadata, error) {
	if !utf8.ValidString(name) || strings.ContainsRune(name, 0) || len(name) > MFAKeyNameMaxLen {
		return MFAMetadata{}, errors.New("invalid MFA key name")
	}
	return MFAMetadata{name: name, createdAtEpochMillis: createdAtEpochMillis}, nil
}

// Name returns the MFA key's name.
func (m MFAMetadata) Name() string { return m.name }

// CreatedAtEpochMillis returns the creation time in milliseconds.
func (m MFAMetadata) CreatedAtEpochMillis() uint64 { return m.createdAtEpochMillis }

// Encrypt authenticates and encrypts metadata using key and a cryptographic rng.
func (m MFAMetadata) Encrypt(key SVRKey, rng io.Reader) (EncryptedMFAMetadata, error) {
	if _, err := NewMFAMetadata(m.name, m.createdAtEpochMillis); err != nil {
		return EncryptedMFAMetadata{}, err
	}
	if rng == nil {
		return EncryptedMFAMetadata{}, errors.New("MFA metadata requires a cryptographic random source")
	}
	plaintext, err := proto.Marshal(&accountkeysproto.MfaKeyMetadataPlaintext{
		CreationEpochTimeSeconds: m.createdAtEpochMillis / 1000,
		KeyName:                  m.name,
	})
	if err != nil {
		return EncryptedMFAMetadata{}, errInvalidMFAMetadata
	}
	defer clear(plaintext)
	if len(plaintext) >= mfaPaddedPlaintextLen {
		return EncryptedMFAMetadata{}, errInvalidMFAMetadata
	}
	// Upstream pads to this fixed size, not to the next AES block boundary.
	var padded [mfaPaddedPlaintextLen]byte
	defer clear(padded[:])
	copy(padded[:], plaintext)
	padding := byte(mfaPaddedPlaintextLen - len(plaintext)) // #nosec G115 -- length guard bounds padding to 1..112.
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = padding
	}
	var out EncryptedMFAMetadata
	if _, err := io.ReadFull(rng, out[:aes.BlockSize]); err != nil {
		return EncryptedMFAMetadata{}, fmt.Errorf("MFA metadata randomness: %w", err)
	}
	cipherKey, authKey := key.mfaMetadataKeys()
	defer clear(cipherKey[:])
	defer clear(authKey[:])
	block, err := aes.NewCipher(cipherKey[:])
	if err != nil {
		return EncryptedMFAMetadata{}, errInvalidMFAMetadata
	}
	cipher.NewCBCEncrypter(block, out[:aes.BlockSize]).CryptBlocks(out[aes.BlockSize:mfaAuthenticatedLen], padded[:])
	mac := keyedHash(authKey[:], out[:mfaAuthenticatedLen])
	copy(out[mfaAuthenticatedLen:], mac[:])
	clear(mac[:])
	return out, nil
}

// ParseEncryptedMFAMetadata copies a fixed-size ciphertext from raw.
func ParseEncryptedMFAMetadata(raw []byte) (EncryptedMFAMetadata, error) {
	if len(raw) != MFAMetadataCiphertextLen {
		return EncryptedMFAMetadata{}, errInvalidMFAMetadata
	}
	return EncryptedMFAMetadata(raw), nil
}

// Bytes returns a copy of the encrypted metadata's fixed-width representation.
func (m EncryptedMFAMetadata) Bytes() [MFAMetadataCiphertextLen]byte { return m }

// Decrypt authenticates and decrypts metadata, rejecting malformed plaintext.
func (m EncryptedMFAMetadata) Decrypt(key SVRKey) (MFAMetadata, error) {
	cipherKey, authKey := key.mfaMetadataKeys()
	defer clear(cipherKey[:])
	defer clear(authKey[:])
	mac := keyedHash(authKey[:], m[:mfaAuthenticatedLen])
	defer clear(mac[:])
	if !hmac.Equal(mac[:], m[mfaAuthenticatedLen:]) {
		return MFAMetadata{}, errInvalidMFAMetadata
	}
	block, err := aes.NewCipher(cipherKey[:])
	if err != nil {
		return MFAMetadata{}, errInvalidMFAMetadata
	}
	var padded [mfaPaddedPlaintextLen]byte
	defer clear(padded[:])
	cipher.NewCBCDecrypter(block, m[:aes.BlockSize]).CryptBlocks(padded[:], m[aes.BlockSize:mfaAuthenticatedLen])
	padding := int(padded[len(padded)-1])
	if padding == 0 || padding > len(padded) {
		return MFAMetadata{}, errInvalidMFAMetadata
	}
	valid := 1
	for _, b := range padded[len(padded)-padding:] {
		valid &= subtle.ConstantTimeByteEq(b, byte(padding))
	}
	if valid != 1 {
		return MFAMetadata{}, errInvalidMFAMetadata
	}
	var plaintext accountkeysproto.MfaKeyMetadataPlaintext
	encoded, validWire := mfaProtoPlaintext(padded[:len(padded)-padding])
	defer clear(encoded)
	if !validWire {
		return MFAMetadata{}, errInvalidMFAMetadata
	}
	if err := proto.Unmarshal(encoded, &plaintext); err != nil {
		return MFAMetadata{}, errInvalidMFAMetadata
	}
	if plaintext.CreationEpochTimeSeconds > math.MaxUint64/1000 {
		return MFAMetadata{}, errInvalidMFAMetadata
	}
	metadata, err := NewMFAMetadata(plaintext.KeyName, plaintext.CreationEpochTimeSeconds*1000)
	if err != nil {
		return MFAMetadata{}, errInvalidMFAMetadata
	}
	return metadata, nil
}

func (k SVRKey) mfaMetadataKeys() (cipherKey, authKey [32]byte) {
	return keyedHash(k.bytes[:], []byte("20260831 TOTP Metadata Encryption")),
		keyedHash(k.bytes[:], []byte("20260831 TOTP Metadata Authentication"))
}

// Rust protobuf 3.7 decodes tags and byte lengths as five-byte u32 varints;
// Go accepts longer encodings. Check those bounds without replacing generated
// decoding. Rust discards unknown groups, accepting any valid end-group tag;
// omit those groups here while retaining ordinary unknown fields.
func mfaProtoPlaintext(raw []byte) ([]byte, bool) {
	encoded := make([]byte, 0, len(raw))
	groups := 0
	for len(raw) > 0 {
		field := raw
		tag, n := protowire.ConsumeVarint(raw)
		if n < 0 || n > 5 || tag > math.MaxUint32 {
			return encoded, false
		}
		num, typ := protowire.DecodeTag(tag)
		if !num.IsValid() {
			return encoded, false
		}
		raw = raw[n:]
		switch typ {
		case protowire.StartGroupType:
			groups++
			continue
		case protowire.EndGroupType:
			if groups == 0 {
				return encoded, false
			}
			groups--
			continue
		case protowire.BytesType:
			length, prefix := protowire.ConsumeVarint(raw)
			if prefix < 0 || prefix > 5 || length > math.MaxUint32 || length > uint64(len(raw)-prefix) {
				return encoded, false
			}
			n = prefix + int(length) // #nosec G115 -- length is bounded by the remaining 111-byte plaintext.
		default:
			n = protowire.ConsumeFieldValue(num, typ, raw)
			if n < 0 {
				return encoded, false
			}
		}
		if groups == 0 {
			encoded = append(encoded, field[:len(field)-len(raw)+n]...)
		}
		raw = raw[n:]
	}
	return encoded, groups == 0
}
