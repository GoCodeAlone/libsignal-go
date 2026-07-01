package compat

import (
	"testing"
)

func TestProofInventoryTracksSignalProofAndBackupDomains(t *testing.T) {
	inventory, err := ProofInventory()
	if err != nil {
		t.Fatalf("ProofInventory: %v", err)
	}
	if inventory.UpstreamTag != "v0.96.4" {
		t.Fatalf("upstream tag = %q, want v0.96.4", inventory.UpstreamTag)
	}

	rows := inventory.ByDomain()
	assertProofRow(t, rows, "username-links", CoverageStatusVectorBacked, "vectors/username-links.json", false)
	assertProofRow(t, rows, "username-hash-proof", CoverageStatusDeferred, "", true)
	assertProofRow(t, rows, "account-backup-derivations", CoverageStatusVectorBacked, "vectors/account-keys.json", false)
	assertProofRow(t, rows, "backup-manifest", CoverageStatusDeferred, "", true)
	assertProofRow(t, rows, "message-backup", CoverageStatusDeferred, "", true)
	assertProofRow(t, rows, "svr-svrb-proof", CoverageStatusDeferred, "", true)
	assertProofRow(t, rows, "key-transparency", CoverageStatusDeferred, "", true)
}

func TestProofInventoryVectorBackedRowsHaveExistingFixtures(t *testing.T) {
	inventory, err := ProofInventory()
	if err != nil {
		t.Fatalf("ProofInventory: %v", err)
	}
	for _, row := range inventory.Rows {
		if row.Status != CoverageStatusVectorBacked {
			continue
		}
		if row.Vector == "" {
			t.Fatalf("%s is vector-backed but has no vector path", row.Domain)
		}
		assertVectorHasCases(t, vectorFilename(t, row.Vector))
		if row.Reason != "" {
			t.Fatalf("%s is vector-backed but has deferred reason %q", row.Domain, row.Reason)
		}
	}
}

func TestProofInventoryDeferredRowsExplainNextUpstreamInput(t *testing.T) {
	inventory, err := ProofInventory()
	if err != nil {
		t.Fatalf("ProofInventory: %v", err)
	}
	for _, row := range inventory.Rows {
		if row.Status != CoverageStatusDeferred {
			continue
		}
		if row.Reason == "" {
			t.Fatalf("%s is deferred without reason", row.Domain)
		}
		if row.NextUpstreamInput == "" {
			t.Fatalf("%s is deferred without next upstream input", row.Domain)
		}
		if row.Vector != "" {
			t.Fatalf("%s is deferred but sets vector %q", row.Domain, row.Vector)
		}
	}
}

func assertProofRow(t *testing.T, rows map[string]CoverageRow, domain string, status CoverageStatus, vector string, wantReason bool) {
	t.Helper()
	row, ok := rows[domain]
	if !ok {
		t.Fatalf("missing proof inventory row %q", domain)
	}
	if row.Domain != domain {
		t.Fatalf("%s row domain = %q", domain, row.Domain)
	}
	if row.Status != status {
		t.Fatalf("%s status = %q, want %q", domain, row.Status, status)
	}
	if row.Vector != vector {
		t.Fatalf("%s vector = %q, want %q", domain, row.Vector, vector)
	}
	if wantReason && row.Reason == "" {
		t.Fatalf("%s missing reason", domain)
	}
	if !wantReason && row.Reason != "" {
		t.Fatalf("%s reason = %q, want empty", domain, row.Reason)
	}
}
