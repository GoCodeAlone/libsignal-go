// Package svrb reports the local evidence boundary for Signal SVRB.
package svrb

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/GoCodeAlone/libsignal-go/proofreport"
)

const parameterRefresh = "2026Q2 production parameter refresh"

// Status classifies SVRB evidence strength.
type Status string

// Report status values.
const (
	StatusStructuralOnly Status = "structural-only"
)

// CompatibilityReport summarizes SVRB coverage.
type CompatibilityReport struct {
	UpstreamTag      string `json:"upstream_tag"`
	ParameterRefresh string `json:"parameter_refresh"`
	Rows             []Row  `json:"rows"`
}

// Row describes one SVRB report row.
type Row struct {
	Domain                  string `json:"domain"`
	Status                  Status `json:"status"`
	ParameterRefresh        string `json:"parameter_refresh"`
	Descriptor              string `json:"descriptor"`
	DescriptorSHA256        string `json:"descriptor_sha256"`
	Reason                  string `json:"reason"`
	NextUpstreamInput       string `json:"next_upstream_input"`
	LiveServiceClaim        bool   `json:"live_service_claim"`
	OfficialAppInteropClaim bool   `json:"official_app_interop_claim"`
}

// Report returns the conservative SVRB compatibility report.
func Report() (CompatibilityReport, error) {
	proof, err := proofreport.Report()
	if err != nil {
		return CompatibilityReport{}, err
	}
	report := CompatibilityReport{
		UpstreamTag:      proof.UpstreamTag,
		ParameterRefresh: parameterRefresh,
		Rows: []Row{
			structuralRow(proof.UpstreamTag, "svrb-recovery-proof", "SVRB recovery proof semantics require upstream proof-system and service-boundary packages that are not part of this protocol-core module.", "Upstream SVRB proof fixtures and the proof-system package boundary."),
			structuralRow(proof.UpstreamTag, "svrb-backup-auth", "SVRB backup authorization is a service contract and proof verification boundary; this module carries no live service egress.", "Stable upstream SVRB service contract fixtures or a separate service-contract package."),
		},
	}
	if err := Validate(report); err != nil {
		return CompatibilityReport{}, err
	}
	return report, nil
}

// Validate checks that SVRB rows do not overclaim live-service behavior.
func Validate(r CompatibilityReport) error {
	if r.UpstreamTag == "" {
		return fmt.Errorf("svrb report missing upstream tag")
	}
	if r.ParameterRefresh != parameterRefresh {
		return fmt.Errorf("svrb report parameter refresh = %q", r.ParameterRefresh)
	}
	seen := make(map[string]struct{}, len(r.Rows))
	for _, row := range r.Rows {
		if row.Domain == "" {
			return fmt.Errorf("svrb report row missing domain")
		}
		if _, ok := seen[row.Domain]; ok {
			return fmt.Errorf("svrb report has duplicate domain %q", row.Domain)
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
		if row.Reason == "" || row.NextUpstreamInput == "" {
			return fmt.Errorf("%s missing reason or next upstream input", row.Domain)
		}
	}
	return nil
}

func structuralRow(upstreamTag, domain, reason, next string) Row {
	descriptor := strings.Join([]string{
		"svrb", upstreamTag, domain, parameterRefresh, string(StatusStructuralOnly), reason, next,
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

var validStatuses = []Status{StatusStructuralOnly}
