package svr

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReportNamesProductionParameterRefresh(t *testing.T) {
	report, err := Report()
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if report.UpstreamTag != "v0.96.4" {
		t.Fatalf("upstream tag = %q, want v0.96.4", report.UpstreamTag)
	}
	if report.ParameterRefresh != "2026Q2 production parameter refresh" {
		t.Fatalf("parameter refresh = %q", report.ParameterRefresh)
	}
	for _, row := range report.Rows {
		if row.ParameterRefresh != report.ParameterRefresh {
			t.Fatalf("%s parameter refresh = %q, want report marker", row.Domain, row.ParameterRefresh)
		}
		if row.Descriptor == "" || row.DescriptorSHA256 == "" {
			t.Fatalf("%s missing stable descriptor", row.Domain)
		}
	}
}

func TestReportDescriptorsDetectDrift(t *testing.T) {
	report, err := Report()
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	report.Rows[0].DescriptorSHA256 = strings.Repeat("f", 64)
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
			t.Fatalf("%s claims live service behavior", row.Domain)
		}
		if row.OfficialAppInteropClaim {
			t.Fatalf("%s claims official app interoperability", row.Domain)
		}
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{"secret_bytes", "private_key", "login", "send_message"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("report JSON contains forbidden phrase %q: %s", forbidden, raw)
		}
	}
}
