// Package svr reports the local evidence boundary for Signal SVR and SVR2.
package svr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/GoCodeAlone/libsignal-go/proofreport"
)

const parameterRefresh = "2026Q2 production parameter refresh"

// Status classifies SVR evidence strength.
type Status string

// Report status values.
const (
	StatusVectorBacked   Status = "vector-backed"
	StatusStructuralOnly Status = "structural-only"
)

// CompatibilityReport summarizes SVR/SVR2 coverage.
type CompatibilityReport struct {
	UpstreamTag      string `json:"upstream_tag"`
	ParameterRefresh string `json:"parameter_refresh"`
	Rows             []Row  `json:"rows"`
}

// Row describes one SVR/SVR2 report row.
type Row struct {
	Domain                  string `json:"domain"`
	Status                  Status `json:"status"`
	ParameterRefresh        string `json:"parameter_refresh"`
	Fixture                 string `json:"fixture,omitempty"`
	FixtureSHA256           string `json:"fixture_sha256,omitempty"`
	Descriptor              string `json:"descriptor"`
	DescriptorSHA256        string `json:"descriptor_sha256"`
	Reason                  string `json:"reason,omitempty"`
	NextUpstreamInput       string `json:"next_upstream_input,omitempty"`
	LiveServiceClaim        bool   `json:"live_service_claim"`
	OfficialAppInteropClaim bool   `json:"official_app_interop_claim"`
}

// Report returns the conservative SVR/SVR2 compatibility report.
func Report() (CompatibilityReport, error) {
	proof, err := proofreport.Report()
	if err != nil {
		return CompatibilityReport{}, err
	}
	fixtureRow, ok := proof.ByDomain()["svr-key"]
	if !ok || fixtureRow.FixtureSHA256 == "" {
		return CompatibilityReport{}, fmt.Errorf("proof report missing SVR key vector digest")
	}
	report := CompatibilityReport{
		UpstreamTag:      proof.UpstreamTag,
		ParameterRefresh: parameterRefresh,
		Rows: []Row{
			vectorRow("svr-key-derivation", fixtureRow),
			structuralRow(proof.UpstreamTag, "svr2-service-proof", "SVR2 service proof semantics require carried zkcredential/poksho verification surfaces before parity can be claimed.", "Upstream SVR2 proof fixtures and the proof-system package boundary."),
		},
	}
	if err := Validate(report); err != nil {
		return CompatibilityReport{}, err
	}
	return report, nil
}

// Validate checks that SVR rows do not overclaim live-service behavior.
func Validate(r CompatibilityReport) error {
	if r.UpstreamTag == "" {
		return fmt.Errorf("svr report missing upstream tag")
	}
	if r.ParameterRefresh != parameterRefresh {
		return fmt.Errorf("svr report parameter refresh = %q", r.ParameterRefresh)
	}
	seen := make(map[string]struct{}, len(r.Rows))
	for _, row := range r.Rows {
		if row.Domain == "" {
			return fmt.Errorf("svr report row missing domain")
		}
		if _, ok := seen[row.Domain]; ok {
			return fmt.Errorf("svr report has duplicate domain %q", row.Domain)
		}
		seen[row.Domain] = struct{}{}
		if !slices.Contains(validStatuses, row.Status) {
			return fmt.Errorf("%s has unsupported status %q", row.Domain, row.Status)
		}
		if row.ParameterRefresh != r.ParameterRefresh {
			return fmt.Errorf("%s parameter refresh drift", row.Domain)
		}
		if row.LiveServiceClaim {
			return fmt.Errorf("%s must not claim live service behavior", row.Domain)
		}
		if row.OfficialAppInteropClaim {
			return fmt.Errorf("%s must not claim official app interoperability", row.Domain)
		}
		if row.Descriptor == "" || row.DescriptorSHA256 != digest(row.Descriptor) {
			return fmt.Errorf("%s descriptor digest drift", row.Domain)
		}
		switch row.Status {
		case StatusVectorBacked:
			if row.Fixture == "" || len(row.FixtureSHA256) != 64 {
				return fmt.Errorf("%s is vector-backed without fixture digest", row.Domain)
			}
			if row.Reason != "" || row.NextUpstreamInput != "" {
				return fmt.Errorf("%s is vector-backed with structural fields", row.Domain)
			}
		case StatusStructuralOnly:
			if row.Reason == "" || row.NextUpstreamInput == "" {
				return fmt.Errorf("%s missing reason or next upstream input", row.Domain)
			}
			if row.Fixture != "" || row.FixtureSHA256 != "" {
				return fmt.Errorf("%s has fixture data without vector-backed status", row.Domain)
			}
		}
	}
	return nil
}

func vectorRow(domain string, fixture proofreport.Row) Row {
	descriptor := strings.Join([]string{
		"svr", fixture.UpstreamTag, domain, parameterRefresh, string(StatusVectorBacked), fixture.Fixture, fixture.FixtureSHA256,
	}, ":")
	return Row{
		Domain:           domain,
		Status:           StatusVectorBacked,
		ParameterRefresh: parameterRefresh,
		Fixture:          fixture.Fixture,
		FixtureSHA256:    fixture.FixtureSHA256,
		Descriptor:       descriptor,
		DescriptorSHA256: digest(descriptor),
	}
}

func structuralRow(upstreamTag, domain, reason, next string) Row {
	descriptor := strings.Join([]string{
		"svr", upstreamTag, domain, parameterRefresh, string(StatusStructuralOnly), reason, next,
	}, ":")
	return Row{
		Domain:            domain,
		Status:            StatusStructuralOnly,
		ParameterRefresh:  parameterRefresh,
		Descriptor:        descriptor,
		DescriptorSHA256:  digest(descriptor),
		Reason:            reason,
		NextUpstreamInput: next,
	}
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var validStatuses = []Status{StatusVectorBacked, StatusStructuralOnly}
