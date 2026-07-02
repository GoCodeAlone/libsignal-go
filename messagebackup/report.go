// Package messagebackup reports the local evidence boundary for Signal
// message-backup-adjacent derivations.
package messagebackup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/GoCodeAlone/libsignal-go/proofreport"
)

// Status classifies message-backup evidence strength.
type Status string

// Report status values.
const (
	StatusVectorBacked   Status = "vector-backed"
	StatusStructuralOnly Status = "structural-only"
	StatusDeferred       Status = "deferred"
)

// CompatibilityReport summarizes message-backup-related local coverage.
type CompatibilityReport struct {
	UpstreamTag string `json:"upstream_tag"`
	Rows        []Row  `json:"rows"`
}

// Row describes one message-backup subdomain.
type Row struct {
	Subdomain               string `json:"subdomain"`
	Status                  Status `json:"status"`
	Fixture                 string `json:"fixture,omitempty"`
	FixtureSHA256           string `json:"fixture_sha256,omitempty"`
	Descriptor              string `json:"descriptor"`
	DescriptorSHA256        string `json:"descriptor_sha256"`
	Reason                  string `json:"reason,omitempty"`
	NextUpstreamInput       string `json:"next_upstream_input,omitempty"`
	LiveServiceClaim        bool   `json:"live_service_claim"`
	OfficialAppInteropClaim bool   `json:"official_app_interop_claim"`
}

// Report returns the conservative message-backup compatibility report.
func Report() (CompatibilityReport, error) {
	proof, err := proofreport.Report()
	if err != nil {
		return CompatibilityReport{}, err
	}
	fixtureRow, ok := proof.ByDomain()["account-backup-derivations"]
	if !ok || fixtureRow.FixtureSHA256 == "" {
		return CompatibilityReport{}, fmt.Errorf("proof report missing account backup vector digest")
	}

	report := CompatibilityReport{
		UpstreamTag: proof.UpstreamTag,
		Rows: []Row{
			vectorRow("backup-key", fixtureRow),
			vectorRow("backup-id", fixtureRow),
			structuralRow(proof.UpstreamTag, "local-metadata-key", "Derivation is implemented in accountkeys, but the committed upstream fixture batch does not yet pin local metadata key bytes.", "Upstream local backup metadata key fixtures."),
			structuralRow(proof.UpstreamTag, "media-derivations", "Media ID, media encryption key, thumbnail transit key, and forward-secrecy derivations are implemented, but current committed vectors pin only backup key and backup ID.", "Upstream media and backup forward-secrecy derivation fixtures."),
			structuralRow(proof.UpstreamTag, "message-backup-manifest", "Upstream message-backup manifest serialization, validation, and app storage schemas are not carried by this protocol-core module.", "Stable upstream message-backup manifest fixtures and a selected Go package boundary."),
		},
	}
	if err := Validate(report); err != nil {
		return CompatibilityReport{}, err
	}
	return report, nil
}

// BySubdomain indexes rows by subdomain.
func (r CompatibilityReport) BySubdomain() map[string]Row {
	rows := make(map[string]Row, len(r.Rows))
	for _, row := range r.Rows {
		rows[row.Subdomain] = row
	}
	return rows
}

// Validate checks that message-backup rows do not overclaim local evidence.
func Validate(r CompatibilityReport) error {
	if r.UpstreamTag == "" {
		return fmt.Errorf("messagebackup report missing upstream tag")
	}
	seen := make(map[string]struct{}, len(r.Rows))
	for _, row := range r.Rows {
		if row.Subdomain == "" {
			return fmt.Errorf("messagebackup report row missing subdomain")
		}
		if _, ok := seen[row.Subdomain]; ok {
			return fmt.Errorf("messagebackup report has duplicate subdomain %q", row.Subdomain)
		}
		seen[row.Subdomain] = struct{}{}
		if !slices.Contains(validStatuses, row.Status) {
			return fmt.Errorf("%s has unsupported status %q", row.Subdomain, row.Status)
		}
		if row.LiveServiceClaim {
			return fmt.Errorf("%s must not claim live service behavior", row.Subdomain)
		}
		if row.OfficialAppInteropClaim {
			return fmt.Errorf("%s must not claim official app interoperability", row.Subdomain)
		}
		if row.Descriptor == "" || row.DescriptorSHA256 != digest(row.Descriptor) {
			return fmt.Errorf("%s descriptor digest drift", row.Subdomain)
		}
		switch row.Status {
		case StatusVectorBacked:
			if row.Fixture == "" || len(row.FixtureSHA256) != 64 {
				return fmt.Errorf("%s is vector-backed without fixture digest", row.Subdomain)
			}
			if row.Reason != "" || row.NextUpstreamInput != "" {
				return fmt.Errorf("%s is vector-backed with structural/deferred fields", row.Subdomain)
			}
		case StatusStructuralOnly, StatusDeferred:
			if row.Reason == "" || row.NextUpstreamInput == "" {
				return fmt.Errorf("%s missing reason or next upstream input", row.Subdomain)
			}
			if row.Fixture != "" || row.FixtureSHA256 != "" {
				return fmt.Errorf("%s has fixture data without vector-backed status", row.Subdomain)
			}
		}
	}
	return nil
}

func vectorRow(subdomain string, fixture proofreport.Row) Row {
	descriptor := strings.Join([]string{
		"messagebackup", fixture.UpstreamTag, subdomain, string(StatusVectorBacked), fixture.Fixture, fixture.FixtureSHA256,
	}, ":")
	return Row{
		Subdomain:        subdomain,
		Status:           StatusVectorBacked,
		Fixture:          fixture.Fixture,
		FixtureSHA256:    fixture.FixtureSHA256,
		Descriptor:       descriptor,
		DescriptorSHA256: digest(descriptor),
	}
}

func structuralRow(upstreamTag, subdomain, reason, next string) Row {
	descriptor := strings.Join([]string{
		"messagebackup", upstreamTag, subdomain, string(StatusStructuralOnly), reason, next,
	}, ":")
	return Row{
		Subdomain:         subdomain,
		Status:            StatusStructuralOnly,
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

var validStatuses = []Status{StatusVectorBacked, StatusStructuralOnly, StatusDeferred}
