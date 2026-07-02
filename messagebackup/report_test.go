package messagebackup

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReportTracksBackupSubdomains(t *testing.T) {
	report, err := Report()
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if report.UpstreamTag != "v0.96.4" {
		t.Fatalf("upstream tag = %q, want v0.96.4", report.UpstreamTag)
	}

	rows := report.BySubdomain()
	for _, name := range []string{"backup-key", "backup-id", "local-metadata-key", "media-derivations", "message-backup-manifest"} {
		row, ok := rows[name]
		if !ok {
			t.Fatalf("missing message-backup subdomain %q", name)
		}
		if row.Status == "" {
			t.Fatalf("%s missing status", name)
		}
		if row.Descriptor == "" || row.DescriptorSHA256 == "" {
			t.Fatalf("%s missing stable descriptor", name)
		}
	}
	if rows["message-backup-manifest"].Status != StatusStructuralOnly {
		t.Fatalf("manifest status = %q, want structural-only", rows["message-backup-manifest"].Status)
	}
}

func TestReportDescriptorsDetectDrift(t *testing.T) {
	report, err := Report()
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	report.Rows[0].DescriptorSHA256 = strings.Repeat("0", 64)
	if err := Validate(report); err == nil {
		t.Fatal("Validate accepted descriptor digest drift")
	}
}

func TestReportContainsNoSecretOrLiveServiceClaims(t *testing.T) {
	report, err := Report()
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	for _, row := range report.Rows {
		if row.LiveServiceClaim {
			t.Fatalf("%s claims live service behavior", row.Subdomain)
		}
		if row.OfficialAppInteropClaim {
			t.Fatalf("%s claims official app interoperability", row.Subdomain)
		}
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{"secret_bytes", "private_key", "official signal app interop"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("report JSON contains forbidden phrase %q: %s", forbidden, raw)
		}
	}
}
