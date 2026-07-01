package compat

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
)

//go:embed coverage_manifest.json vectors/account-keys.json vectors/username-links.json
var coverageManifestFS embed.FS

// CoverageStatus classifies how strongly a proof or backup domain is covered.
type CoverageStatus string

// Coverage status values used by the proof inventory.
const (
	CoverageStatusVectorBacked CoverageStatus = "vector-backed"
	CoverageStatusStructural   CoverageStatus = "structural"
	CoverageStatusDeferred     CoverageStatus = "deferred"
)

// CoverageInventory is the machine-readable upstream coverage manifest.
type CoverageInventory struct {
	UpstreamTag string        `json:"upstream_tag"`
	Rows        []CoverageRow `json:"domains"`
}

// CoverageRow records one proof, backup, or protocol-adjacent coverage domain.
type CoverageRow struct {
	Domain            string         `json:"name"`
	Status            CoverageStatus `json:"status"`
	Vector            string         `json:"vector,omitempty"`
	VectorSHA256      string         `json:"-"`
	Reason            string         `json:"reason,omitempty"`
	NextUpstreamInput string         `json:"next_upstream_input,omitempty"`
	Packages          []string       `json:"packages,omitempty"`
	Notes             string         `json:"notes,omitempty"`
}

// ProofInventory returns the embedded coverage manifest with vector digests.
func ProofInventory() (CoverageInventory, error) {
	raw, err := coverageManifestFS.ReadFile("coverage_manifest.json")
	if err != nil {
		return CoverageInventory{}, fmt.Errorf("read coverage manifest: %w", err)
	}

	var inventory CoverageInventory
	if err := json.Unmarshal(raw, &inventory); err != nil {
		return CoverageInventory{}, fmt.Errorf("decode coverage manifest: %w", err)
	}
	if err := inventory.hydrateVectorDigests(); err != nil {
		return CoverageInventory{}, err
	}
	if err := inventory.Validate(); err != nil {
		return CoverageInventory{}, err
	}
	return inventory, nil
}

func (i *CoverageInventory) hydrateVectorDigests() error {
	for idx := range i.Rows {
		row := &i.Rows[idx]
		if row.Vector == "" {
			continue
		}
		raw, err := coverageManifestFS.ReadFile(row.Vector)
		if err != nil {
			return fmt.Errorf("read coverage vector %s: %w", row.Vector, err)
		}
		sum := sha256.Sum256(raw)
		row.VectorSHA256 = hex.EncodeToString(sum[:])
	}
	return nil
}

// ByDomain indexes coverage rows by domain name.
func (i CoverageInventory) ByDomain() map[string]CoverageRow {
	rows := make(map[string]CoverageRow, len(i.Rows))
	for _, row := range i.Rows {
		rows[row.Domain] = row
	}
	return rows
}

// Validate checks that coverage rows do not overclaim parity.
func (i CoverageInventory) Validate() error {
	if i.UpstreamTag == "" {
		return fmt.Errorf("coverage inventory missing upstream tag")
	}

	seen := make(map[string]struct{}, len(i.Rows))
	for _, row := range i.Rows {
		if row.Domain == "" {
			return fmt.Errorf("coverage inventory row missing domain")
		}
		if _, ok := seen[row.Domain]; ok {
			return fmt.Errorf("coverage inventory has duplicate domain %q", row.Domain)
		}
		seen[row.Domain] = struct{}{}

		if !slices.Contains(validCoverageStatuses, row.Status) {
			return fmt.Errorf("%s has unsupported status %q", row.Domain, row.Status)
		}
		switch row.Status {
		case CoverageStatusVectorBacked:
			if row.Vector == "" {
				return fmt.Errorf("%s is vector-backed without vector", row.Domain)
			}
			if row.Reason != "" {
				return fmt.Errorf("%s is vector-backed with deferred reason", row.Domain)
			}
			if row.NextUpstreamInput != "" {
				return fmt.Errorf("%s is vector-backed with deferred next upstream input", row.Domain)
			}
		case CoverageStatusStructural:
			if row.Reason == "" {
				return fmt.Errorf("%s is structural without reason", row.Domain)
			}
			if row.Vector != "" || row.VectorSHA256 != "" {
				return fmt.Errorf("%s is structural with vector data", row.Domain)
			}
			if row.NextUpstreamInput != "" {
				return fmt.Errorf("%s is structural with deferred next upstream input", row.Domain)
			}
		case CoverageStatusDeferred:
			if row.Reason == "" {
				return fmt.Errorf("%s is deferred without reason", row.Domain)
			}
			if row.NextUpstreamInput == "" {
				return fmt.Errorf("%s is deferred without next upstream input", row.Domain)
			}
			if row.Vector != "" {
				return fmt.Errorf("%s is deferred with vector %q", row.Domain, row.Vector)
			}
		}
	}
	return nil
}

var validCoverageStatuses = []CoverageStatus{
	CoverageStatusVectorBacked,
	CoverageStatusStructural,
	CoverageStatusDeferred,
}
