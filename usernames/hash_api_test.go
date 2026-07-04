package usernames

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"
)

type usernameHashVectorFile struct {
	Source      string               `json:"source"`
	UpstreamTag string               `json:"upstream_tag"`
	Cases       []usernameHashVector `json:"cases"`
}

type usernameHashVector struct {
	Username      string `json:"username"`
	Nickname      string `json:"nickname"`
	Discriminator uint64 `json:"discriminator"`
	HashHex       string `json:"hash_hex"`
}

func TestUsernameHashAPIsMatchUpstreamVectors(t *testing.T) {
	vectors := loadUsernameHashVectors(t)
	if vectors.Source == "" {
		t.Fatal("hash vector source is required")
	}
	if vectors.UpstreamTag != "v0.96.4" {
		t.Fatalf("upstream tag = %q, want v0.96.4", vectors.UpstreamTag)
	}

	for _, tc := range vectors.Cases {
		parsed, err := Parse(tc.Username)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.Username, err)
		}

		fromMethod, err := parsed.Hash()
		if err != nil {
			t.Fatalf("Username.Hash(%q): %v", tc.Username, err)
		}
		if fromMethod.String() != tc.HashHex {
			t.Fatalf("Username.Hash(%q) = %s, want %s", tc.Username, fromMethod, tc.HashHex)
		}

		fromFunction, err := Hash(tc.Username)
		if err != nil {
			t.Fatalf("Hash(%q): %v", tc.Username, err)
		}
		if fromFunction != fromMethod {
			t.Fatalf("Hash(%q) = %s, want %s", tc.Username, fromFunction, fromMethod)
		}

		fromParts, err := HashFromParts(tc.Nickname, tc.Discriminator)
		if err != nil {
			t.Fatalf("HashFromParts(%q, %d): %v", tc.Nickname, tc.Discriminator, err)
		}
		if fromParts != fromMethod {
			t.Fatalf("HashFromParts(%q, %d) = %s, want %s", tc.Nickname, tc.Discriminator, fromParts, fromMethod)
		}

		hashHex, err := HashHex(tc.Username)
		if err != nil {
			t.Fatalf("HashHex(%q): %v", tc.Username, err)
		}
		if hashHex != tc.HashHex {
			t.Fatalf("HashHex(%q) = %s, want %s", tc.Username, hashHex, tc.HashHex)
		}
	}
}

func TestUsernameHashAPIsRejectInvalidInputs(t *testing.T) {
	if _, err := Hash("bad space.42"); err == nil {
		t.Fatal("Hash accepted an invalid username")
	}
	if _, err := HashHex("0start.42"); err == nil {
		t.Fatal("HashHex accepted an invalid username")
	}
	if _, err := HashFromParts("bad space", 42); err == nil {
		t.Fatal("HashFromParts accepted an invalid nickname")
	}
	if _, err := HashFromParts("valid", 0); err == nil {
		t.Fatal("HashFromParts accepted discriminator 0")
	}
}

func TestUsernameCandidatesWithHashes(t *testing.T) {
	candidates, err := CandidatesWithHashesFromReader(rand.Reader, "_SiGNA1", DefaultNicknameLimits())
	if err != nil {
		t.Fatalf("CandidatesWithHashesFromReader: %v", err)
	}
	if len(candidates) != 20 {
		t.Fatalf("CandidatesWithHashesFromReader produced %d candidates, want 20", len(candidates))
	}
	for _, candidate := range candidates {
		want, err := Hash(candidate.Username)
		if err != nil {
			t.Fatalf("Hash(%q): %v", candidate.Username, err)
		}
		if candidate.Hash != want {
			t.Fatalf("candidate %q hash = %s, want %s", candidate.Username, candidate.Hash, want)
		}
		if candidate.HashHex != want.String() {
			t.Fatalf("candidate %q hash hex = %s, want %s", candidate.Username, candidate.HashHex, want.String())
		}
	}
}

func loadUsernameHashVectors(t *testing.T) usernameHashVectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/username_hash_vectors_v0_96_4.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors usernameHashVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("username hash vector file has no cases")
	}
	return vectors
}
