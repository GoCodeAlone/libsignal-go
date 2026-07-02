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

func TestReserveUsernameHashKnownVectors(t *testing.T) {
	cases := []struct {
		username string
		want     string
	}{
		{"He110.01", "40bb2ef5ee0623030702e2fe4968b8ecd7362f429dd9435ae4c4616458394e77"},
		{"usr.999999999", "ee73aba64f73a01d76f60dd228806c6b4941a0db1381d3e85fba4c87160d9215"},
		{"_identifier.42", "58d2b1c0d69a791cc69a31388291c2ee051ad0bbf41a1b292f095844101f9865"},
		{"LOUD.700", "4ee6243df79ec22d8da80aa8b4a834ed56d911a165490fa90199135e7888314e"},
		{"test_username.42", "9cdd889c3ae89a345c5ebfce990212485ec43974a67a26ee30bc4efb67049c7a"},
	}
	for _, tc := range cases {
		got, err := ReserveUsernameHash(tc.username)
		if err != nil {
			t.Fatalf("ReserveUsernameHash(%q): %v", tc.username, err)
		}
		if got.String() != tc.want {
			t.Fatalf("ReserveUsernameHash(%q) = %s, want %s", tc.username, got, tc.want)
		}
		if len(got.Bytes()) != 32 {
			t.Fatalf("ReserveUsernameHash(%q) returned %d bytes, want 32", tc.username, len(got.Bytes()))
		}
	}
}

func TestReserveUsernameHashIsCaseInsensitive(t *testing.T) {
	upper, err := ReserveUsernameHash("LOUD.700")
	if err != nil {
		t.Fatalf("ReserveUsernameHash upper: %v", err)
	}
	lower, err := ReserveUsernameHash("loud.700")
	if err != nil {
		t.Fatalf("ReserveUsernameHash lower: %v", err)
	}
	if upper != lower {
		t.Fatalf("case-insensitive hash mismatch: %s != %s", upper, lower)
	}
}

func TestReserveUsernameHashRejectsInvalidUsername(t *testing.T) {
	for _, username := range []string{"no-discriminator", "0start.42", "bad space.42", "valid.01.extra"} {
		if _, err := ReserveUsernameHash(username); err == nil {
			t.Fatalf("ReserveUsernameHash accepted invalid username %q", username)
		}
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

	reserveHash := rows["username-reserve-hash"]
	if reserveHash.Status != proofreport.StatusVectorBacked {
		t.Fatalf("username-reserve-hash status = %q, want %q", reserveHash.Status, proofreport.StatusVectorBacked)
	}
	if reserveHash.Fixture != "vectors/username-links.json" || reserveHash.FixtureSHA256 == "" {
		t.Fatalf("reserve hash fixture = %q digest=%q, want username-link fixture and digest", reserveHash.Fixture, reserveHash.FixtureSHA256)
	}
	if reserveHash.ParityClaim != true {
		t.Fatal("username-reserve-hash should claim vector-backed parity")
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
