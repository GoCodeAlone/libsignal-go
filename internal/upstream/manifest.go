// Package upstream records the upstream monorepo domains that this fork tracks.
package upstream

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
)

//go:embed manifest.json
var manifestFS embed.FS

// CoverageStatus describes how much local evidence backs an upstream domain.
type CoverageStatus string

// Coverage status values used by the upstream manifest.
const (
	CoverageStatusVectorBacked   CoverageStatus = "vector-backed"
	CoverageStatusStructuralOnly CoverageStatus = "structural-only"
	CoverageStatusDeferred       CoverageStatus = "deferred"
)

// Manifest describes local coverage for selected upstream libsignal monorepo
// domains at a pinned upstream release.
type Manifest struct {
	UpstreamTag string   `json:"upstream_tag"`
	Domains     []Domain `json:"domains"`
}

// Domain records one upstream monorepo domain and the local evidence boundary.
type Domain struct {
	Name                    string         `json:"name"`
	UpstreamPath            string         `json:"upstream_path"`
	LocalPath               string         `json:"local_path,omitempty"`
	ReportPath              string         `json:"report_path,omitempty"`
	CoverageStatus          CoverageStatus `json:"coverage_status"`
	ChecksumPath            string         `json:"checksum_path,omitempty"`
	ChecksumSHA256          string         `json:"checksum_sha256,omitempty"`
	StructuralOnlyReason    string         `json:"structural_only_reason,omitempty"`
	OfficialAppInteropClaim bool           `json:"official_app_interop_claim"`
	Notes                   string         `json:"notes,omitempty"`
}

// Load returns the embedded upstream manifest after validating conservative
// coverage claims.
func Load() (Manifest, error) {
	raw, err := manifestFS.ReadFile("manifest.json")
	if err != nil {
		return Manifest{}, fmt.Errorf("read upstream manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode upstream manifest: %w", err)
	}
	if err := Validate(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// ByDomain indexes manifest domains by name.
func (m Manifest) ByDomain() map[string]Domain {
	domains := make(map[string]Domain, len(m.Domains))
	for _, domain := range m.Domains {
		domains[domain.Name] = domain
	}
	return domains
}

// Validate checks that the manifest has enough metadata and does not overclaim.
func Validate(m Manifest) error {
	if m.UpstreamTag == "" {
		return fmt.Errorf("upstream manifest missing upstream tag")
	}
	seen := make(map[string]struct{}, len(m.Domains))
	for _, domain := range m.Domains {
		if domain.Name == "" {
			return fmt.Errorf("upstream manifest row missing name")
		}
		if _, ok := seen[domain.Name]; ok {
			return fmt.Errorf("upstream manifest has duplicate domain %q", domain.Name)
		}
		seen[domain.Name] = struct{}{}
		if domain.UpstreamPath == "" {
			return fmt.Errorf("%s missing upstream path", domain.Name)
		}
		if domain.LocalPath == "" && domain.ReportPath == "" {
			return fmt.Errorf("%s missing local path or report path", domain.Name)
		}
		if !slices.Contains(validCoverageStatuses, domain.CoverageStatus) {
			return fmt.Errorf("%s has unsupported coverage status %q", domain.Name, domain.CoverageStatus)
		}
		if domain.OfficialAppInteropClaim {
			return fmt.Errorf("%s must not claim official app interoperability", domain.Name)
		}

		switch domain.CoverageStatus {
		case CoverageStatusVectorBacked:
			if domain.ChecksumPath == "" || len(domain.ChecksumSHA256) != 64 {
				return fmt.Errorf("%s is vector-backed without checksum path and digest", domain.Name)
			}
			if domain.StructuralOnlyReason != "" {
				return fmt.Errorf("%s is vector-backed with structural-only reason", domain.Name)
			}
		case CoverageStatusStructuralOnly:
			if domain.StructuralOnlyReason == "" {
				return fmt.Errorf("%s is structural-only without reason", domain.Name)
			}
			if domain.ChecksumPath != "" || domain.ChecksumSHA256 != "" {
				return fmt.Errorf("%s is structural-only with checksum data", domain.Name)
			}
		case CoverageStatusDeferred:
			if domain.StructuralOnlyReason == "" {
				return fmt.Errorf("%s is deferred without structural-only reason", domain.Name)
			}
			if domain.ChecksumPath != "" || domain.ChecksumSHA256 != "" {
				return fmt.Errorf("%s is deferred with checksum data", domain.Name)
			}
		}
	}
	return nil
}

// SHA256Hex returns the lower-case SHA-256 digest for raw bytes.
func SHA256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

var validCoverageStatuses = []CoverageStatus{
	CoverageStatusVectorBacked,
	CoverageStatusStructuralOnly,
	CoverageStatusDeferred,
}
