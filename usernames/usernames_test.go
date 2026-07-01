package usernames

import (
	"bytes"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/proofreport"
)

func TestParseValidUsernames(t *testing.T) {
	for _, input := range []string{"He110.01", "usr.999999999", "_identifier.42", "LOUD.700"} {
		parsed, err := Parse(input)
		if err != nil {
			t.Fatalf("Parse(%q): %v", input, err)
		}
		if got := parsed.String(); got != input {
			t.Fatalf("Parse(%q).String() = %q", input, got)
		}
	}
}

func TestInvalidNicknames(t *testing.T) {
	cases := []struct {
		nickname string
		want     error
	}{
		{"", ErrNicknameCannotBeEmpty},
		{"ab🦀d", ErrBadNicknameCharacter},
		{"s p a c e s", ErrBadNicknameCharacter},
		{"0start", ErrNicknameCannotStartWithDigit},
		{"nickname_too_big7890123456789012345678901234567890", ErrNicknameTooLong},
	}
	for _, tc := range cases {
		if _, err := FromParts(tc.nickname, "42", DefaultNicknameLimits()); !errors.Is(err, tc.want) {
			t.Fatalf("FromParts(%q, 42) err = %v, want %v", tc.nickname, err, tc.want)
		}
		if _, err := Parse(formatParts(tc.nickname, 42)); err == nil {
			t.Fatalf("Parse accepted invalid nickname %q", tc.nickname)
		}
	}
}

func TestNicknameSoftLimits(t *testing.T) {
	if _, err := FromParts("abcd", "42", DefaultNicknameLimits()); err != nil {
		t.Fatalf("FromParts default limits: %v", err)
	}
	if _, err := FromParts("abcd", "42", NewNicknameLimits(2, 3)); !errors.Is(err, ErrNicknameTooLong) {
		t.Fatalf("too-long soft limit err = %v", err)
	}
	if _, err := FromParts("abcd", "42", NewNicknameLimits(5, 10)); !errors.Is(err, ErrNicknameTooShort) {
		t.Fatalf("too-short soft limit err = %v", err)
	}
}

func TestInvalidDiscriminators(t *testing.T) {
	cases := []struct {
		discriminator string
		want          error
	}{
		{"", ErrDiscriminatorCannotBeEmpty},
		{"0", ErrDiscriminatorCannotBeZero},
		{"00", ErrDiscriminatorCannotBeZero},
		{"001", ErrDiscriminatorCannotHaveLeadingZeros},
		{"0123", ErrDiscriminatorCannotHaveLeadingZeros},
		{"1", ErrDiscriminatorCannotBeSingleDigit},
		{"+1", ErrBadDiscriminatorCharacter},
		{"-1", ErrBadDiscriminatorCharacter},
		{"+01", ErrBadDiscriminatorCharacter},
		{"-01", ErrBadDiscriminatorCharacter},
		{"+123", ErrBadDiscriminatorCharacter},
		{"-123", ErrBadDiscriminatorCharacter},
		{"123456789012345678901234567890", ErrDiscriminatorTooLarge},
		{"a1", ErrBadDiscriminatorCharacter},
	}
	for _, tc := range cases {
		if _, err := FromParts("ehren", tc.discriminator, DefaultNicknameLimits()); !errors.Is(err, tc.want) {
			t.Fatalf("FromParts(ehren, %q) err = %v, want %v", tc.discriminator, err, tc.want)
		}
	}
}

func TestCandidatesFromReader(t *testing.T) {
	candidates, err := CandidatesFrom("_SiGNA1", DefaultNicknameLimits())
	if err != nil {
		t.Fatalf("CandidatesFromReader: %v", err)
	}
	if len(candidates) != 20 {
		t.Fatalf("CandidatesFromReader produced %d candidates, want 20", len(candidates))
	}
	for _, candidate := range candidates {
		if !strings.HasPrefix(candidate, "_SiGNA1.") {
			t.Fatalf("candidate %q missing nickname prefix", candidate)
		}
		if _, err := Parse(candidate); err != nil {
			t.Fatalf("candidate %q did not parse: %v", candidate, err)
		}
	}
}

func TestUsernameLinkRoundTrip(t *testing.T) {
	entropy := mustHex32(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	iv := mustHex(t, "202122232425262728292a2b2c2d2e2f")
	link, err := CreateLinkFromReader(bytes.NewReader(iv), "test_username.42", &entropy)
	if err != nil {
		t.Fatalf("CreateLinkFromReader: %v", err)
	}
	got, err := DecryptUsername(link.Entropy, link.EncryptedUsername)
	if err != nil {
		t.Fatalf("DecryptUsername: %v", err)
	}
	if got != "test_username.42" {
		t.Fatalf("DecryptUsername = %q", got)
	}
	parsed, err := ParseLinkBuffer(link.Buffer())
	if err != nil {
		t.Fatalf("ParseLinkBuffer: %v", err)
	}
	if parsed.Entropy != link.Entropy || !bytes.Equal(parsed.EncryptedUsername, link.EncryptedUsername) {
		t.Fatal("ParseLinkBuffer did not round-trip link buffer")
	}
}

func TestUsernameLinkFailures(t *testing.T) {
	var entropy [LinkEntropySize]byte
	if _, err := DecryptUsername(entropy, make([]byte, linkIVSize+linkHMACLen)); !errors.Is(err, ErrUsernameLinkDataTooShort) {
		t.Fatalf("short decrypt err = %v, want ErrUsernameLinkDataTooShort", err)
	}
	if _, err := DecryptUsername(entropy, make([]byte, linkIVSize+linkHMACLen+16)); !errors.Is(err, ErrHMACMismatch) {
		t.Fatalf("bad hmac err = %v, want ErrHMACMismatch", err)
	}
	longUsername := strings.Repeat("abcdefghijklmnopqrstuvwxyz", 5)
	if _, err := CreateLinkFromReader(bytes.NewReader(make([]byte, linkIVSize)), longUsername, &entropy); !errors.Is(err, ErrInputDataTooLong) {
		t.Fatalf("long username link err = %v, want ErrInputDataTooLong", err)
	}
}

func TestProofReportTracksUsernameCoverage(t *testing.T) {
	report, err := proofreport.Report()
	if err != nil {
		t.Fatalf("proof report: %v", err)
	}
	rows := report.ByDomain()

	link := rows["username-links"]
	if link.Status != proofreport.StatusVectorBacked {
		t.Fatalf("username-links status = %q, want %q", link.Status, proofreport.StatusVectorBacked)
	}
	if link.Fixture != "vectors/username-links.json" || link.FixtureSHA256 == "" {
		t.Fatalf("fixture = %q digest=%q, want username-link fixture and digest", link.Fixture, link.FixtureSHA256)
	}
	if !slices.Contains(link.Packages, "usernames") {
		t.Fatalf("username-links packages = %v, want usernames", link.Packages)
	}

	hashProof := rows["username-hash-proof"]
	if hashProof.Status != proofreport.StatusDeferred {
		t.Fatalf("username-hash-proof status = %q, want %q", hashProof.Status, proofreport.StatusDeferred)
	}
	if hashProof.Reason == "" || hashProof.NextUpstreamInput == "" {
		t.Fatalf("username-hash-proof reason=%q next=%q, want both set", hashProof.Reason, hashProof.NextUpstreamInput)
	}
	if hashProof.ParityClaim {
		t.Fatal("username-hash-proof must not claim parity while deferred")
	}
}

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	raw := mustHex(t, s)
	if len(raw) != 32 {
		t.Fatalf("hex decoded to %d bytes, want 32", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
