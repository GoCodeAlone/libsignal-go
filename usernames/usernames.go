// Package usernames implements Signal username validation and username links.
//
// It is a pure-Go port of the non-zk parts of upstream libsignal
// rust/usernames at v0.96.4. Username proof APIs require the upstream
// poksho proof stack and are intentionally not exposed here yet.
package usernames

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/GoCodeAlone/libsignal-go/internal/crypto"
	"github.com/gtank/ristretto255"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	maxNicknameLength = 48
	linkAESBlockSize  = 16

	// LinkEntropySize is the byte length of username-link entropy.
	LinkEntropySize = 32
)

const (
	linkHMACLen = 32
	linkKeySize = 32
	linkIVSize  = 16
)

var (
	// ErrMissingSeparator reports a username without a "." separator.
	ErrMissingSeparator = errors.New("username must contain a separator")
	// ErrNicknameCannotBeEmpty reports an empty username nickname.
	ErrNicknameCannotBeEmpty = errors.New("nickname cannot be empty")
	// ErrNicknameCannotStartWithDigit reports a nickname beginning with a digit.
	ErrNicknameCannotStartWithDigit = errors.New("nickname cannot start with digit")
	// ErrBadNicknameCharacter reports a nickname containing a disallowed character.
	ErrBadNicknameCharacter = errors.New("bad nickname character")
	// ErrNicknameTooShort reports a nickname below the configured soft minimum.
	ErrNicknameTooShort = errors.New("nickname too short")
	// ErrNicknameTooLong reports a nickname above the configured soft or hard maximum.
	ErrNicknameTooLong = errors.New("nickname too long")
	// ErrDiscriminatorCannotBeEmpty reports an empty discriminator.
	ErrDiscriminatorCannotBeEmpty = errors.New("discriminator cannot be empty")
	// ErrDiscriminatorCannotBeZero reports a zero discriminator.
	ErrDiscriminatorCannotBeZero = errors.New("discriminator cannot be zero")
	// ErrDiscriminatorCannotBeSingleDigit reports a single-digit discriminator.
	ErrDiscriminatorCannotBeSingleDigit = errors.New("discriminator cannot be a single digit")
	// ErrDiscriminatorCannotHaveLeadingZeros reports a multi-digit discriminator with leading zeros.
	ErrDiscriminatorCannotHaveLeadingZeros = errors.New("discriminator cannot have leading zeros")
	// ErrBadDiscriminatorCharacter reports a discriminator containing non-digits.
	ErrBadDiscriminatorCharacter = errors.New("bad discriminator character")
	// ErrDiscriminatorTooLarge reports a discriminator too large for uint64.
	ErrDiscriminatorTooLarge = errors.New("discriminator too large")

	// ErrInputDataTooLong reports username-link plaintext that exceeds Signal's four-block bound.
	ErrInputDataTooLong = errors.New("username link input data too long")
	// ErrInvalidEntropyDataLength reports entropy that is not LinkEntropySize bytes.
	ErrInvalidEntropyDataLength = errors.New("invalid username link entropy length")
	// ErrUsernameLinkDataTooShort reports encrypted username-link data missing IV/ciphertext/HMAC.
	ErrUsernameLinkDataTooShort = errors.New("username link data too short")
	// ErrHMACMismatch reports a username-link authentication failure.
	ErrHMACMismatch = errors.New("username link hmac mismatch")
	// ErrBadCiphertext reports username-link ciphertext that fails AES-CBC decryption.
	ErrBadCiphertext = errors.New("bad username link ciphertext")
	// ErrInvalidDecryptedDataStructure reports username-link plaintext that is not valid UsernameData.
	ErrInvalidDecryptedDataStructure = errors.New("invalid username link decrypted data")
)

var discriminatorRanges = [][2]int{
	{1, 100},
	{100, 1_000},
	{1_000, 10_000},
	{10_000, 100_000},
	{100_000, 1_000_000},
	{1_000_000, 10_000_000},
	{10_000_000, 100_000_000},
	{100_000_000, 1_000_000_000},
}

var candidatesPerRange = []int{4, 3, 3, 2, 2, 2, 2, 2}

var usernameHashBasePoints = func() []*ristretto255.Element {
	raw := [][32]byte{
		{0x60, 0xb9, 0x93, 0x66, 0x3a, 0x3d, 0xae, 0xcc, 0x4c, 0x85, 0x2f, 0x53, 0x35, 0x47, 0xe3, 0x05, 0x38, 0x8c, 0x2a, 0x50, 0xa5, 0x83, 0x93, 0xea, 0x27, 0x7d, 0xe4, 0xab, 0xf3, 0xde, 0x54, 0x3a},
		{0xf2, 0xb6, 0xf1, 0xc8, 0x26, 0xfa, 0x36, 0x40, 0x20, 0x6f, 0x3b, 0x58, 0xb2, 0x28, 0x6b, 0xde, 0xfd, 0xfd, 0xa6, 0xa5, 0x4f, 0xf9, 0x02, 0xf2, 0x04, 0xa7, 0x2d, 0xe7, 0x37, 0xd2, 0x61, 0x57},
		{0x06, 0x06, 0xbd, 0x3a, 0xbf, 0xce, 0x4e, 0x96, 0x17, 0xd4, 0x48, 0xfb, 0x2c, 0xae, 0xb6, 0xcc, 0x02, 0x8e, 0xc9, 0xa2, 0xb6, 0x2b, 0x10, 0xb3, 0xd9, 0xeb, 0x29, 0x48, 0xda, 0x6f, 0x3f, 0x53},
	}
	points := make([]*ristretto255.Element, 0, len(raw))
	for _, encoded := range raw {
		point, err := new(ristretto255.Element).SetCanonicalBytes(encoded[:])
		if err != nil {
			panic(fmt.Sprintf("usernames: invalid upstream hash base point: %v", err))
		}
		points = append(points, point)
	}
	return points
}()

// NicknameLimits defines the soft nickname length bounds for validation.
type NicknameLimits struct {
	Min int
	Max int
}

// DefaultNicknameLimits returns Signal's default 3..32 nickname limits.
func DefaultNicknameLimits() NicknameLimits {
	return NicknameLimits{Min: 3, Max: 32}
}

// NewNicknameLimits constructs nickname limits, panicking for invalid bounds.
func NewNicknameLimits(minLen, maxLen int) NicknameLimits {
	if maxLen > maxNicknameLength {
		panic(fmt.Sprintf("long nicknames are not supported: max %d", maxNicknameLength))
	}
	if minLen >= maxLen {
		panic(fmt.Sprintf("invalid nickname size limits: %d..%d", minLen, maxLen))
	}
	return NicknameLimits{Min: minLen, Max: maxLen}
}

// Validate checks n against the configured nickname length bounds.
func (l NicknameLimits) Validate(n int) error {
	if n < l.Min {
		return ErrNicknameTooShort
	}
	if n > l.Max {
		return ErrNicknameTooLong
	}
	return nil
}

// Username is a parsed Signal username.
type Username struct {
	nickname      string
	discriminator uint64
}

// UsernameHash is the 32-byte compressed Ristretto username hash used by
// username reservation APIs.
type UsernameHash [32]byte

// Parse validates and parses a full username such as "signal.42".
func Parse(s string) (Username, error) {
	nickname, discriminator, ok := strings.Cut(s, ".")
	if !ok {
		return Username{}, ErrMissingSeparator
	}
	if rest := strings.LastIndexByte(s, '.'); rest > len(nickname) {
		nickname = s[:rest]
		discriminator = s[rest+1:]
	}
	return fromPartsWithoutSoftLimit(nickname, discriminator)
}

// FromParts validates and parses a nickname/discriminator pair.
func FromParts(nickname, discriminator string, limits NicknameLimits) (Username, error) {
	u, err := fromPartsWithoutSoftLimit(nickname, discriminator)
	if err != nil {
		return Username{}, err
	}
	if err := limits.Validate(len(nickname)); err != nil {
		return Username{}, err
	}
	return u, nil
}

// Nickname returns the username nickname with original casing.
func (u Username) Nickname() string {
	return u.nickname
}

// Discriminator returns the numeric username discriminator.
func (u Username) Discriminator() uint64 {
	return u.discriminator
}

// String formats the username, preserving nickname casing and two-digit minimum discriminators.
func (u Username) String() string {
	return fmt.Sprintf("%s.%02d", u.nickname, u.discriminator)
}

// ReserveUsernameHash computes Signal's username reservation hash for username.
//
// The hash is vector-backed against upstream rust/usernames at v0.96.4. This
// API does not create or verify username proofs.
func ReserveUsernameHash(username string) (UsernameHash, error) {
	parsed, err := Parse(username)
	if err != nil {
		return UsernameHash{}, err
	}
	return parsed.ReserveHash()
}

// ReserveHash computes Signal's username reservation hash for a parsed username.
func (u Username) ReserveHash() (UsernameHash, error) {
	nickname := strings.ToLower(u.nickname)
	scalars, err := usernameHashScalars(nickname, u.discriminator)
	if err != nil {
		return UsernameHash{}, err
	}
	point := new(ristretto255.Element).MultiScalarMult(scalars, usernameHashBasePoints)
	var out UsernameHash
	copy(out[:], point.Bytes())
	return out, nil
}

// Bytes returns the fixed-width hash bytes.
func (h UsernameHash) Bytes() [32]byte {
	return [32]byte(h)
}

// String returns the lower-case hexadecimal hash.
func (h UsernameHash) String() string {
	return hex.EncodeToString(h[:])
}

// CandidatesFrom returns randomized candidate usernames for nickname.
func CandidatesFrom(nickname string, limits NicknameLimits) ([]string, error) {
	return CandidatesFromReader(rand.Reader, nickname, limits)
}

// CandidatesFromReader returns randomized candidate usernames for nickname using r.
func CandidatesFromReader(r io.Reader, nickname string, limits NicknameLimits) ([]string, error) {
	if r == nil {
		r = rand.Reader
	}
	if err := validateNickname(nickname, limits); err != nil {
		return nil, err
	}
	out := make([]string, 0, 20)
	for i, count := range candidatesPerRange {
		start, end := discriminatorRanges[i][0], discriminatorRanges[i][1]
		values, err := sampleRange(r, start, end, count)
		if err != nil {
			return nil, err
		}
		for _, v := range values {
			out = append(out, formatParts(nickname, v))
		}
	}
	return out, nil
}

func fromPartsWithoutSoftLimit(nickname, discriminator string) (Username, error) {
	if err := validatePrefix(nickname); err != nil {
		return Username{}, err
	}
	d, err := validateDiscriminator(discriminator)
	if err != nil {
		return Username{}, err
	}
	if err := validateNicknameHard(nickname); err != nil {
		return Username{}, err
	}
	return Username{nickname: nickname, discriminator: d}, nil
}

func validateNickname(nickname string, limits NicknameLimits) error {
	if err := validatePrefix(nickname); err != nil {
		return err
	}
	if err := validateNicknameHard(nickname); err != nil {
		return err
	}
	return limits.Validate(len(nickname))
}

func validatePrefix(s string) error {
	if s == "" {
		return ErrNicknameCannotBeEmpty
	}
	if s[0] >= '0' && s[0] <= '9' {
		return ErrNicknameCannotStartWithDigit
	}
	return nil
}

func validateNicknameHard(nickname string) error {
	lower := strings.ToLower(nickname)
	for i := 0; i < len(lower); i++ {
		if !validNicknameByte(lower[i]) {
			return ErrBadNicknameCharacter
		}
	}
	if len(lower) > maxNicknameLength {
		return ErrNicknameTooLong
	}
	return nil
}

func validNicknameByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func usernameHashScalars(nickname string, discriminator uint64) ([]*ristretto255.Scalar, error) {
	nicknameScalar, err := usernameNicknameScalar(nickname)
	if err != nil {
		return nil, err
	}
	return []*ristretto255.Scalar{
		usernameSHAScalar(nickname, discriminator),
		nicknameScalar,
		scalarFromUint64(discriminator),
	}, nil
}

func usernameSHAScalar(nickname string, discriminator uint64) *ristretto255.Scalar {
	h := sha512.New()
	_, _ = h.Write([]byte(nickname))
	_, _ = h.Write([]byte{0x00})
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], discriminator)
	_, _ = h.Write(be[:])
	scalar, err := new(ristretto255.Scalar).SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic("sha512 output must be 64 bytes for ristretto255 scalar")
	}
	return scalar
}

func usernameNicknameScalar(nickname string) (*ristretto255.Scalar, error) {
	if nickname == "" {
		return nil, ErrNicknameCannotBeEmpty
	}
	if len(nickname) > maxNicknameLength {
		return nil, ErrNicknameTooLong
	}
	bytes := make([]byte, 0, len(nickname))
	for i := range len(nickname) {
		value, ok := usernameHashCharToByte(nickname[i])
		if !ok {
			return nil, ErrBadNicknameCharacter
		}
		bytes = append(bytes, value)
	}

	thirtySeven := scalarFromUint64(37)
	twentySeven := scalarFromUint64(27)
	scalar := new(ristretto255.Scalar)
	for i := len(bytes) - 1; i >= 1; i-- {
		scalar.Multiply(scalar, thirtySeven)
		scalar.Add(scalar, scalarFromUint64(uint64(bytes[i])))
	}
	scalar.Multiply(scalar, twentySeven)
	scalar.Add(scalar, scalarFromUint64(uint64(bytes[0])))
	return scalar, nil
}

func usernameHashCharToByte(b byte) (byte, bool) {
	switch {
	case b == '_':
		return 1, true
	case b >= 'a' && b <= 'z':
		return b - 'a' + 2, true
	case b >= '0' && b <= '9':
		return b - '0' + 28, true
	default:
		return 0, false
	}
}

func scalarFromUint64(v uint64) *ristretto255.Scalar {
	var canonical [32]byte
	binary.LittleEndian.PutUint64(canonical[:], v)
	scalar, err := new(ristretto255.Scalar).SetCanonicalBytes(canonical[:])
	if err != nil {
		panic(fmt.Sprintf("usernames: invalid small scalar: %v", err))
	}
	return scalar
}

func validateDiscriminator(discriminator string) (uint64, error) {
	if discriminator == "" {
		return 0, ErrDiscriminatorCannotBeEmpty
	}
	if discriminator[0] < '0' || discriminator[0] > '9' {
		return 0, ErrBadDiscriminatorCharacter
	}
	for i := 1; i < len(discriminator); i++ {
		if discriminator[i] < '0' || discriminator[i] > '9' {
			return 0, ErrBadDiscriminatorCharacter
		}
	}
	n, err := strconv.ParseUint(discriminator, 10, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, ErrDiscriminatorTooLarge
		}
		return 0, ErrBadDiscriminatorCharacter
	}
	if n == 0 {
		return 0, ErrDiscriminatorCannotBeZero
	}
	switch {
	case len(discriminator) == 1:
		return 0, ErrDiscriminatorCannotBeSingleDigit
	case len(discriminator) == 2:
		return n, nil
	case discriminator[0] >= '1' && discriminator[0] <= '9':
		return n, nil
	default:
		return 0, ErrDiscriminatorCannotHaveLeadingZeros
	}
}

func formatParts(nickname string, discriminator int) string {
	return fmt.Sprintf("%s.%02d", nickname, discriminator)
}

func sampleRange(r io.Reader, start, end, amount int) ([]int, error) {
	length := end - start
	seen := make(map[int]struct{}, amount)
	out := make([]int, 0, amount)
	for len(out) < amount {
		n, err := rand.Int(r, big.NewInt(int64(length)))
		if err != nil {
			return nil, err
		}
		v := start + int(n.Int64())
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out, nil
}

// Link contains a username-link entropy/ciphertext pair.
type Link struct {
	Entropy           [LinkEntropySize]byte
	EncryptedUsername []byte
}

// Buffer returns the bridge-compatible entropy||encrypted_username form.
func (l Link) Buffer() []byte {
	out := make([]byte, 0, LinkEntropySize+len(l.EncryptedUsername))
	out = append(out, l.Entropy[:]...)
	out = append(out, l.EncryptedUsername...)
	return out
}

// ParseLinkBuffer parses the bridge-compatible entropy||encrypted_username form.
func ParseLinkBuffer(buf []byte) (Link, error) {
	if len(buf) < LinkEntropySize {
		return Link{}, ErrInvalidEntropyDataLength
	}
	var entropy [LinkEntropySize]byte
	copy(entropy[:], buf[:LinkEntropySize])
	return Link{Entropy: entropy, EncryptedUsername: cloneBytes(buf[LinkEntropySize:])}, nil
}

// CreateLink creates an encrypted username link using crypto/rand.
func CreateLink(username string, entropy *[LinkEntropySize]byte) (Link, error) {
	return CreateLinkFromReader(rand.Reader, username, entropy)
}

// CreateLinkFromReader creates an encrypted username link using r for entropy and IV bytes.
func CreateLinkFromReader(r io.Reader, username string, entropy *[LinkEntropySize]byte) (Link, error) {
	if r == nil {
		r = rand.Reader
	}
	var linkEntropy [LinkEntropySize]byte
	if entropy == nil {
		if _, err := io.ReadFull(r, linkEntropy[:]); err != nil {
			return Link{}, err
		}
	} else {
		linkEntropy = *entropy
	}
	var iv [linkIVSize]byte
	if _, err := io.ReadFull(r, iv[:]); err != nil {
		return Link{}, err
	}
	encrypted, err := encryptUsernameLink(username, linkEntropy, iv)
	if err != nil {
		return Link{}, err
	}
	return Link{Entropy: linkEntropy, EncryptedUsername: encrypted}, nil
}

// DecryptUsername decrypts encryptedUsername with entropy and returns the username.
func DecryptUsername(entropy [LinkEntropySize]byte, encryptedUsername []byte) (string, error) {
	if len(encryptedUsername) <= linkIVSize+linkHMACLen {
		return "", ErrUsernameLinkDataTooShort
	}
	macKey := usernameLinkHKDF(entropy[:], []byte("Signal Username Link Authentication Key"))
	ivAndCiphertext := encryptedUsername[:len(encryptedUsername)-linkHMACLen]
	wantMAC := encryptedUsername[len(encryptedUsername)-linkHMACLen:]
	gotMAC := crypto.HMACSHA256(macKey[:], ivAndCiphertext)
	if subtle.ConstantTimeCompare(gotMAC, wantMAC) != 1 {
		return "", ErrHMACMismatch
	}
	iv := ivAndCiphertext[:linkIVSize]
	ciphertext := ivAndCiphertext[linkIVSize:]
	aesKey := usernameLinkHKDF(entropy[:], []byte("Signal Username Link Encryption Key"))
	plaintext, err := crypto.DecryptCBC(ciphertext, aesKey[:], iv)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadCiphertext, err)
	}
	username, err := decodeUsernameData(plaintext)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidDecryptedDataStructure, err)
	}
	return username, nil
}

func encryptUsernameLink(username string, entropy [LinkEntropySize]byte, iv [linkIVSize]byte) ([]byte, error) {
	padding := 0
	if len(username) < linkAESBlockSize*3 {
		padding = linkAESBlockSize*3 - len(username)
	}
	plaintext := encodeUsernameData(username, make([]byte, padding))
	if len(plaintext) >= linkAESBlockSize*4 {
		return nil, ErrInputDataTooLong
	}
	aesKey := usernameLinkHKDF(entropy[:], []byte("Signal Username Link Encryption Key"))
	ciphertext, err := crypto.EncryptCBC(plaintext, aesKey[:], iv[:])
	if err != nil {
		return nil, err
	}
	macKey := usernameLinkHKDF(entropy[:], []byte("Signal Username Link Authentication Key"))
	out := make([]byte, 0, linkIVSize+len(ciphertext)+linkHMACLen)
	out = append(out, iv[:]...)
	out = append(out, ciphertext...)
	out = append(out, crypto.HMACSHA256(macKey[:], out)...)
	return out, nil
}

func usernameLinkHKDF(entropy, label []byte) [linkKeySize]byte {
	bytes, err := crypto.HKDFSHA256(entropy, nil, label, linkKeySize)
	if err != nil {
		panic(err)
	}
	var out [linkKeySize]byte
	copy(out[:], bytes)
	return out
}

func encodeUsernameData(username string, padding []byte) []byte {
	var out []byte
	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendString(out, username)
	if len(padding) > 0 {
		out = protowire.AppendTag(out, 2, protowire.BytesType)
		out = protowire.AppendBytes(out, padding)
	}
	return out
}

func decodeUsernameData(in []byte) (string, error) {
	var username string
	for len(in) > 0 {
		num, typ, n := protowire.ConsumeTag(in)
		if n < 0 {
			return "", protowire.ParseError(n)
		}
		in = in[n:]
		switch num {
		case 1:
			if typ != protowire.BytesType {
				return "", fmt.Errorf("username field has wire type %v", typ)
			}
			value, n := protowire.ConsumeString(in)
			if n < 0 {
				return "", protowire.ParseError(n)
			}
			username = value
			in = in[n:]
		case 2:
			if typ != protowire.BytesType {
				return "", fmt.Errorf("padding field has wire type %v", typ)
			}
			_, n := protowire.ConsumeBytes(in)
			if n < 0 {
				return "", protowire.ParseError(n)
			}
			in = in[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, in)
			if n < 0 {
				return "", protowire.ParseError(n)
			}
			in = in[n:]
		}
	}
	return username, nil
}

func cloneBytes(in []byte) []byte {
	return append([]byte(nil), in...)
}
