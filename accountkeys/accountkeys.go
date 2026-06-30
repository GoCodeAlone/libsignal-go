// Package accountkeys implements Signal account-level key derivations.
//
// It is a pure-Go port of upstream libsignal rust/account-keys at v0.96.4.
// The package deliberately contains no network or storage behavior.
package accountkeys

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/internal/crypto"
	"golang.org/x/crypto/argon2"
)

const (
	accountEntropyPoolLen  = 64
	accountEntropyAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

	// SVRKeyLen is the length in bytes of a derived SVR master key.
	SVRKeyLen = 32

	// BackupKeyLen is the length in bytes of an account backup key.
	BackupKeyLen = 32
	// LocalBackupMetadataKeyLen is the length in bytes of local backup metadata keys.
	LocalBackupMetadataKeyLen = 32
	// MediaIDLen is the length in bytes of a derived backup media ID.
	MediaIDLen = 15
	// BackupForwardSecrecyTokenLen is the length in bytes of backup forward secrecy tokens.
	BackupForwardSecrecyTokenLen = 32
	// MediaEncryptionKeyLen is the length in bytes of backup media encryption key data.
	MediaEncryptionKeyLen = 64
)

var (
	// ErrInvalidAccountEntropyPool reports malformed account entropy input.
	ErrInvalidAccountEntropyPool = errors.New("invalid account entropy pool")
	// ErrInvalidPHCString reports malformed or unsupported PHC password hash input.
	ErrInvalidPHCString = errors.New("invalid PHC string")
)

// AccountEntropyPool stores the 64-character account entropy pool.
type AccountEntropyPool struct {
	bytes [accountEntropyPoolLen]byte
}

// GenerateAccountEntropyPool creates a new account entropy pool using crypto/rand.
func GenerateAccountEntropyPool() (AccountEntropyPool, error) {
	return GenerateAccountEntropyPoolFrom(rand.Reader)
}

// GenerateAccountEntropyPoolFrom creates a new account entropy pool using r.
func GenerateAccountEntropyPoolFrom(r io.Reader) (AccountEntropyPool, error) {
	var out AccountEntropyPool
	var b [1]byte
	for i := range out.bytes {
		for {
			if _, err := io.ReadFull(r, b[:]); err != nil {
				return AccountEntropyPool{}, err
			}
			// 252 is the largest multiple of 36 below 256. Rejecting the top
			// four byte values preserves the uniform alphabet sampling used by
			// upstream's slice::Choose distribution.
			if b[0] < 252 {
				out.bytes[i] = accountEntropyAlphabet[int(b[0])%len(accountEntropyAlphabet)]
				break
			}
		}
	}
	return out, nil
}

// ParseAccountEntropyPool validates and parses a serialized account entropy pool.
func ParseAccountEntropyPool(s string) (AccountEntropyPool, error) {
	if len(s) != accountEntropyPoolLen {
		return AccountEntropyPool{}, fmt.Errorf("%w: expected %d ASCII characters, got %d bytes", ErrInvalidAccountEntropyPool, accountEntropyPoolLen, len(s))
	}
	var out AccountEntropyPool
	copy(out.bytes[:], s)
	for _, b := range out.bytes {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'z')) {
			return AccountEntropyPool{}, fmt.Errorf("%w: invalid character %q", ErrInvalidAccountEntropyPool, b)
		}
	}
	return out, nil
}

func (p AccountEntropyPool) String() string {
	return string(p.bytes[:])
}

// Bytes returns the fixed-width byte representation of the account entropy pool.
func (p AccountEntropyPool) Bytes() [accountEntropyPoolLen]byte {
	return p.bytes
}

// DeriveSVRKey derives the account SVR master key.
func (p AccountEntropyPool) DeriveSVRKey() [SVRKeyLen]byte {
	return array32(mustHKDF(p.bytes[:], nil, []byte("20240801_SIGNAL_SVR_MASTER_KEY"), SVRKeyLen))
}

// BackupKey is the root account backup key derived from account entropy.
type BackupKey [BackupKeyLen]byte

// BackupID is the per-account identifier for backup storage.
type BackupID [16]byte

// BackupForwardSecrecyToken is the token input length used by backup forward secrecy derivations.
type BackupForwardSecrecyToken [BackupForwardSecrecyTokenLen]byte

// BackupForwardSecrecyPassword is the PIN-derived forward secrecy password value.
type BackupForwardSecrecyPassword [32]byte

// BackupForwardSecrecyEncryptionKey contains cipher and HMAC keys for backup forward secrecy.
type BackupForwardSecrecyEncryptionKey struct {
	CipherKey [32]byte
	HMACKey   [32]byte
}

// DeriveBackupKey derives the root backup key from account entropy.
func DeriveBackupKey(p AccountEntropyPool) BackupKey {
	return BackupKey(array32(mustHKDF(p.bytes[:], nil, []byte("20240801_SIGNAL_BACKUP_KEY"), BackupKeyLen)))
}

// DeriveBackupID derives the account backup ID for the given ACI.
func (k BackupKey) DeriveBackupID(aci address.ServiceID) BackupID {
	info := append([]byte("20241024_SIGNAL_BACKUP_ID:"), aci.ServiceIDBinary()...)
	return BackupID(array16(mustHKDF(k[:], nil, info, 16)))
}

// DeriveECKey derives the backup identity private key for the given ACI.
func (k BackupKey) DeriveECKey(aci address.ServiceID) (curve.PrivateKey, error) {
	info := append([]byte("20241024_SIGNAL_BACKUP_ID_KEYPAIR:"), aci.ServiceIDBinary()...)
	bytes := mustHKDF(k[:], nil, info, curve.PrivateKeyLength)
	return curve.DeserializePrivateKey(bytes)
}

// DeriveLocalBackupMetadataKey derives the local backup metadata key.
func (k BackupKey) DeriveLocalBackupMetadataKey() [LocalBackupMetadataKeyLen]byte {
	return array32(mustHKDF(k[:], nil, []byte("20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY"), LocalBackupMetadataKeyLen))
}

// DeriveMediaID derives a backup media ID for mediaName.
func (k BackupKey) DeriveMediaID(mediaName string) [MediaIDLen]byte {
	info := append([]byte("20241007_SIGNAL_BACKUP_MEDIA_ID:"), []byte(mediaName)...)
	return array15(mustHKDF(k[:], nil, info, MediaIDLen))
}

// DeriveMediaEncryptionKeyData derives backup media encryption key data.
func (k BackupKey) DeriveMediaEncryptionKeyData(mediaID [MediaIDLen]byte) [MediaEncryptionKeyLen]byte {
	info := append([]byte("20241007_SIGNAL_BACKUP_ENCRYPT_MEDIA:"), mediaID[:]...)
	return array64(mustHKDF(k[:], nil, info, MediaEncryptionKeyLen))
}

// DeriveThumbnailTransitEncryptionKeyData derives backup thumbnail transit encryption key data.
func (k BackupKey) DeriveThumbnailTransitEncryptionKeyData(mediaID [MediaIDLen]byte) [MediaEncryptionKeyLen]byte {
	info := append([]byte("20241030_SIGNAL_BACKUP_ENCRYPT_THUMBNAIL:"), mediaID[:]...)
	return array64(mustHKDF(k[:], nil, info, MediaEncryptionKeyLen))
}

// DeriveForwardSecrecyPassword derives the backup forward secrecy PIN password.
func (k BackupKey) DeriveForwardSecrecyPassword(salt []byte) BackupForwardSecrecyPassword {
	return BackupForwardSecrecyPassword(array32(mustHKDF(k[:], salt, []byte("Signal Message Backup 20250627:SVR PIN"), 32)))
}

// DeriveForwardSecrecyEncryptionKey derives backup forward secrecy encryption keys.
func (k BackupKey) DeriveForwardSecrecyEncryptionKey(salt []byte) BackupForwardSecrecyEncryptionKey {
	bytes := mustHKDF(k[:], salt, []byte("Signal Message Backup 20250627:BackupForwardSecrecyToken Encryption Key"), 64)
	var out BackupForwardSecrecyEncryptionKey
	copy(out.CipherKey[:], bytes[:32])
	copy(out.HMACKey[:], bytes[32:])
	return out
}

// PinHash contains the two keys produced by Signal's Argon2id PIN hashing.
type PinHash struct {
	EncryptionKey [32]byte
	AccessKey     [32]byte
}

// CreatePinHash derives Signal PIN encryption and access keys.
func CreatePinHash(pin []byte, salt [32]byte) PinHash {
	key := argon2.IDKey(pin, salt[:], 32, 16*1024, 1, 64)
	var out PinHash
	copy(out.EncryptionKey[:], key[:32])
	copy(out.AccessKey[:], key[32:])
	return out
}

// MakePINSalt derives a Signal PIN salt from a username and backup group ID.
func MakePINSalt(username string, groupID uint64) [32]byte {
	var group [8]byte
	for i := 7; i >= 0; i-- {
		group[i] = byte(groupID)
		groupID >>= 8
	}
	return array32(mustHKDF([]byte(username), group[:], nil, 32))
}

// LocalPINHash creates a PHC-encoded local PIN hash with a random salt.
func LocalPINHash(pin []byte) (string, error) {
	var salt [16]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return "", err
	}
	return LocalPINHashWithSalt(pin, salt), nil
}

// LocalPINHashWithSalt creates a PHC-encoded local PIN hash with salt.
func LocalPINHashWithSalt(pin []byte, salt [16]byte) string {
	hash := argon2.Key(pin, salt[:], 64, 512, 1, 32)
	return fmt.Sprintf("$argon2i$v=19$m=512,t=64,p=1$%s$%s", phcB64(salt[:]), phcB64(hash))
}

// VerifyLocalPINHash verifies pin against a PHC-encoded local PIN hash.
func VerifyLocalPINHash(encoded string, pin []byte) (bool, error) {
	params, salt, want, err := parsePHC(encoded)
	if err != nil {
		return false, err
	}
	if params.alg != "argon2i" || params.version != 19 || params.memory != 512 || params.time != 64 || params.parallelism != 1 || len(want) != 32 {
		return false, fmt.Errorf("%w: unsupported argon2 parameters", ErrInvalidPHCString)
	}
	got := argon2.Key(pin, salt, 64, 512, 1, 32)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

type phcParams struct {
	alg         string
	version     int
	memory      int
	time        int
	parallelism int
}

func parsePHC(encoded string) (phcParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return phcParams{}, nil, nil, ErrInvalidPHCString
	}
	params := phcParams{alg: parts[1]}
	if !strings.HasPrefix(parts[2], "v=") {
		return phcParams{}, nil, nil, ErrInvalidPHCString
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil {
		return phcParams{}, nil, nil, err
	}
	params.version = version
	for _, kv := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(kv, "=", 2)
		if len(pair) != 2 {
			return phcParams{}, nil, nil, ErrInvalidPHCString
		}
		value, err := strconv.Atoi(pair[1])
		if err != nil {
			return phcParams{}, nil, nil, err
		}
		switch pair[0] {
		case "m":
			params.memory = value
		case "t":
			params.time = value
		case "p":
			params.parallelism = value
		default:
			return phcParams{}, nil, nil, ErrInvalidPHCString
		}
	}
	salt, err := phcDecode(parts[4])
	if err != nil {
		return phcParams{}, nil, nil, err
	}
	hash, err := phcDecode(parts[5])
	if err != nil {
		return phcParams{}, nil, nil, err
	}
	return params, salt, hash, nil
}

func phcB64(in []byte) string {
	return base64.RawStdEncoding.EncodeToString(in)
}

func phcDecode(in string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(in)
}

func mustHKDF(ikm, salt, info []byte, length int) []byte {
	bytes, err := crypto.HKDFSHA256(ikm, salt, info, length)
	if err != nil {
		panic(err)
	}
	return bytes
}

func array15(in []byte) (out [15]byte) {
	if len(in) != len(out) {
		panic("invalid [15] conversion length")
	}
	copy(out[:], in)
	return out
}

func array16(in []byte) (out [16]byte) {
	if len(in) != len(out) {
		panic("invalid [16] conversion length")
	}
	copy(out[:], in)
	return out
}

func array32(in []byte) (out [32]byte) {
	if len(in) != len(out) {
		panic("invalid [32] conversion length")
	}
	copy(out[:], in)
	return out
}

func array64(in []byte) (out [64]byte) {
	if len(in) != len(out) {
		panic("invalid [64] conversion length")
	}
	copy(out[:], in)
	return out
}
