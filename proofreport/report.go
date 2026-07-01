// Package proofreport exposes conservative Signal proof and backup coverage
// metadata for downstream readiness checks.
package proofreport

import (
	"fmt"
	"slices"

	"github.com/GoCodeAlone/libsignal-go/compat"
)

// Status classifies report rows by their upstream evidence strength.
type Status = compat.CoverageStatus

// Report status values.
const (
	StatusVectorBacked = compat.CoverageStatusVectorBacked
	StatusStructural   = compat.CoverageStatusStructural
	StatusDeferred     = compat.CoverageStatusDeferred
)

// CompatibilityReport summarizes coverage against one upstream libsignal tag.
type CompatibilityReport struct {
	UpstreamTag string `json:"upstream_tag"`
	Rows        []Row  `json:"rows"`
}

// Row describes one proof, backup, or protocol-adjacent compatibility domain.
type Row struct {
	Domain            string   `json:"domain"`
	Status            Status   `json:"status"`
	UpstreamTag       string   `json:"upstream_tag,omitempty"`
	Fixture           string   `json:"fixture,omitempty"`
	FixtureSHA256     string   `json:"fixture_sha256,omitempty"`
	ParityClaim       bool     `json:"parity_claim"`
	Reason            string   `json:"reason,omitempty"`
	NextUpstreamInput string   `json:"next_upstream_input,omitempty"`
	Packages          []string `json:"packages,omitempty"`
	Notes             string   `json:"notes,omitempty"`
}

// Report returns the current proof and backup coverage report.
func Report() (CompatibilityReport, error) {
	inventory, err := compat.ProofInventory()
	if err != nil {
		return CompatibilityReport{}, err
	}

	report := CompatibilityReport{
		UpstreamTag: inventory.UpstreamTag,
		Rows:        make([]Row, 0, len(inventory.Rows)),
	}
	for _, coverage := range inventory.Rows {
		row := Row{
			Domain:            coverage.Domain,
			Status:            coverage.Status,
			Reason:            coverage.Reason,
			NextUpstreamInput: coverage.NextUpstreamInput,
			Packages:          slices.Clone(coverage.Packages),
			Notes:             coverage.Notes,
		}
		if coverage.Status == StatusVectorBacked {
			row.UpstreamTag = inventory.UpstreamTag
			row.Fixture = coverage.Vector
			row.FixtureSHA256 = coverage.VectorSHA256
			row.ParityClaim = true
		}
		report.Rows = append(report.Rows, row)
	}

	if err := Validate(report); err != nil {
		return CompatibilityReport{}, err
	}
	return report, nil
}

// ByDomain indexes report rows by domain name.
func (r CompatibilityReport) ByDomain() map[string]Row {
	rows := make(map[string]Row, len(r.Rows))
	for _, row := range r.Rows {
		rows[row.Domain] = row
	}
	return rows
}

// Validate checks that report rows do not overclaim upstream parity.
func Validate(r CompatibilityReport) error {
	if r.UpstreamTag == "" {
		return fmt.Errorf("proof report missing upstream tag")
	}
	seen := make(map[string]struct{}, len(r.Rows))
	for _, row := range r.Rows {
		if row.Domain == "" {
			return fmt.Errorf("proof report row missing domain")
		}
		if _, ok := seen[row.Domain]; ok {
			return fmt.Errorf("proof report has duplicate domain %q", row.Domain)
		}
		seen[row.Domain] = struct{}{}

		switch row.Status {
		case StatusVectorBacked:
			if row.UpstreamTag == "" {
				return fmt.Errorf("%s is vector-backed without upstream tag", row.Domain)
			}
			if row.Fixture == "" {
				return fmt.Errorf("%s is vector-backed without fixture path", row.Domain)
			}
			if len(row.FixtureSHA256) != 64 {
				return fmt.Errorf("%s is vector-backed without fixture digest", row.Domain)
			}
			if !row.ParityClaim {
				return fmt.Errorf("%s is vector-backed without parity claim", row.Domain)
			}
			if row.Reason != "" || row.NextUpstreamInput != "" {
				return fmt.Errorf("%s is vector-backed with deferred fields", row.Domain)
			}
		case StatusStructural:
			if row.ParityClaim {
				return fmt.Errorf("%s is structural but claims parity", row.Domain)
			}
			if row.Reason == "" {
				return fmt.Errorf("%s is structural without reason", row.Domain)
			}
		case StatusDeferred:
			if row.ParityClaim {
				return fmt.Errorf("%s is deferred but claims parity", row.Domain)
			}
			if row.Reason == "" || row.NextUpstreamInput == "" {
				return fmt.Errorf("%s is deferred without reason and next upstream input", row.Domain)
			}
			if row.Fixture != "" || row.FixtureSHA256 != "" {
				return fmt.Errorf("%s is deferred with fixture data", row.Domain)
			}
		default:
			return fmt.Errorf("%s has unsupported status %q", row.Domain, row.Status)
		}
	}
	return nil
}
