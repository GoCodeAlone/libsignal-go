package upstream

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestManifestTracksRequiredUpstreamDomains(t *testing.T) {
	manifest, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if manifest.UpstreamTag != "v0.96.4" {
		t.Fatalf("upstream tag = %q, want v0.96.4", manifest.UpstreamTag)
	}

	byName := manifest.ByDomain()
	for _, name := range []string{"message-backup", "account-keys", "svr2", "svrb", "usernames"} {
		row, ok := byName[name]
		if !ok {
			t.Fatalf("missing upstream domain %q", name)
		}
		if row.UpstreamPath == "" {
			t.Fatalf("%s missing upstream path", name)
		}
		if row.LocalPath == "" && row.ReportPath == "" {
			t.Fatalf("%s missing local path or report path", name)
		}
		if row.CoverageStatus == "" {
			t.Fatalf("%s missing coverage status", name)
		}
		if row.ChecksumSHA256 == "" && row.StructuralOnlyReason == "" {
			t.Fatalf("%s missing checksum or structural-only reason", name)
		}
		if row.OfficialAppInteropClaim {
			t.Fatalf("%s must not claim official Signal app interoperability", name)
		}
	}
}

func TestManifestVectorBackedRowsMatchCommittedFiles(t *testing.T) {
	manifest, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	root := filepath.Join("..", "..")
	for _, row := range manifest.Domains {
		if row.CoverageStatus != CoverageStatusVectorBacked {
			continue
		}
		if row.ChecksumSHA256 == "" {
			t.Fatalf("%s is vector-backed without checksum", row.Name)
		}
		checksumPath := filepath.Clean(row.ChecksumPath)
		if filepath.IsAbs(checksumPath) || checksumPath == ".." || strings.HasPrefix(checksumPath, ".."+string(os.PathSeparator)) {
			t.Fatalf("%s checksum path escapes repository: %q", row.Name, row.ChecksumPath)
		}
		raw, err := os.ReadFile(filepath.Join(root, checksumPath)) // #nosec G304 -- manifest checksum paths are validated above.
		if err != nil {
			t.Fatalf("read checksum path for %s: %v", row.Name, err)
		}
		if got := SHA256Hex(raw); got != row.ChecksumSHA256 {
			t.Fatalf("%s checksum = %s, want %s", row.Name, got, row.ChecksumSHA256)
		}
		if row.StructuralOnlyReason != "" {
			t.Fatalf("%s is vector-backed with structural-only reason", row.Name)
		}
	}
}

func TestManifestStructuralRowsDoNotOverclaim(t *testing.T) {
	manifest, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, name := range []string{"message-backup", "svr2", "svrb"} {
		row, ok := manifest.ByDomain()[name]
		if !ok {
			t.Fatalf("missing upstream domain %q", name)
		}
		if !slices.Contains([]CoverageStatus{CoverageStatusStructuralOnly, CoverageStatusDeferred}, row.CoverageStatus) {
			t.Fatalf("%s status = %q, want structural-only or deferred", name, row.CoverageStatus)
		}
		if row.StructuralOnlyReason == "" {
			t.Fatalf("%s missing structural-only reason", name)
		}
		if row.ChecksumSHA256 != "" {
			t.Fatalf("%s has checksum despite structural-only status", name)
		}
		if row.OfficialAppInteropClaim {
			t.Fatalf("%s must not claim official Signal app interoperability", name)
		}
	}
}

func TestValidateRejectsOfficialAppInteropClaims(t *testing.T) {
	err := Validate(Manifest{
		UpstreamTag: "v0.96.4",
		Domains: []Domain{{
			Name:                    "account-keys",
			UpstreamPath:            "rust/account-keys",
			LocalPath:               "accountkeys",
			CoverageStatus:          CoverageStatusVectorBacked,
			ChecksumPath:            "compat/vectors/account-keys.json",
			ChecksumSHA256:          "539d5ae3f25007aea4430c84dbb4c93a23af2c9bf5e654a5d5a0569f012e5b3d",
			OfficialAppInteropClaim: true,
		}},
	})
	if err == nil {
		t.Fatal("Validate accepted official app interop claim")
	}
}
