package proofreport

import (
	"strings"
	"testing"
)

func TestReportIncludesProofInventoryRows(t *testing.T) {
	report, err := Report()
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if report.UpstreamTag != "v0.96.4" {
		t.Fatalf("upstream tag = %q, want v0.96.4", report.UpstreamTag)
	}

	rows := report.ByDomain()
	for _, domain := range []string{
		"username-links",
		"username-hash-proof",
		"account-backup-derivations",
		"backup-manifest",
		"message-backup",
		"svr-svrb-proof",
		"key-transparency",
	} {
		if _, ok := rows[domain]; !ok {
			t.Fatalf("missing report row %q", domain)
		}
	}
}

func TestReportVectorBackedRowsIncludeFixtureDigestAndUpstreamTag(t *testing.T) {
	report, err := Report()
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	for _, row := range report.Rows {
		if row.Status != StatusVectorBacked {
			continue
		}
		if row.UpstreamTag != report.UpstreamTag {
			t.Fatalf("%s upstream tag = %q, want %q", row.Domain, row.UpstreamTag, report.UpstreamTag)
		}
		if row.Fixture == "" {
			t.Fatalf("%s missing fixture path", row.Domain)
		}
		if len(row.FixtureSHA256) != 64 {
			t.Fatalf("%s fixture digest length = %d, want 64", row.Domain, len(row.FixtureSHA256))
		}
		if !row.ParityClaim {
			t.Fatalf("%s is vector-backed without parity claim", row.Domain)
		}
	}
}

func TestReportStructuralRowsCannotClaimParity(t *testing.T) {
	err := Validate(CompatibilityReport{
		UpstreamTag: "v0.96.4",
		Rows: []Row{{
			Domain:      "structural-example",
			Status:      StatusStructural,
			Reason:      "shape only",
			ParityClaim: true,
		}},
	})
	if err == nil {
		t.Fatal("Validate accepted structural parity claim")
	}
}

func TestReportVectorBackedRowsDiagnoseMissingFixturePath(t *testing.T) {
	err := Validate(CompatibilityReport{
		UpstreamTag: "v0.96.4",
		Rows: []Row{{
			Domain:        "missing-fixture",
			Status:        StatusVectorBacked,
			UpstreamTag:   "v0.96.4",
			FixtureSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ParityClaim:   true,
		}},
	})
	if err == nil {
		t.Fatal("Validate accepted vector-backed row without fixture path")
	}
	if !strings.Contains(err.Error(), "fixture path") {
		t.Fatalf("error = %q, want fixture path diagnostic", err)
	}
}

func TestReportDeferredRowsIncludeReasonAndNextUpstreamInput(t *testing.T) {
	report, err := Report()
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	for _, row := range report.Rows {
		if row.Status != StatusDeferred {
			continue
		}
		if row.Reason == "" {
			t.Fatalf("%s missing reason", row.Domain)
		}
		if row.NextUpstreamInput == "" {
			t.Fatalf("%s missing next upstream input", row.Domain)
		}
		if row.ParityClaim {
			t.Fatalf("%s is deferred but claims parity", row.Domain)
		}
	}
}
