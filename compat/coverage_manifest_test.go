package compat

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCoverageManifestTracksSignalWorkflowDomains(t *testing.T) {
	raw, err := os.ReadFile("coverage_manifest.json")
	if err != nil {
		t.Fatalf("read coverage manifest: %v", err)
	}
	var manifest struct {
		UpstreamTag string `json:"upstream_tag"`
		Domains     []struct {
			Name     string   `json:"name"`
			Status   string   `json:"status"`
			Vector   string   `json:"vector"`
			Reason   string   `json:"reason"`
			Packages []string `json:"packages"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode coverage manifest: %v", err)
	}
	if manifest.UpstreamTag != "v0.96.4" {
		t.Fatalf("upstream tag = %q, want v0.96.4", manifest.UpstreamTag)
	}
	byName := map[string]struct {
		Status   string
		Vector   string
		Reason   string
		Packages []string
	}{}
	for _, domain := range manifest.Domains {
		byName[domain.Name] = struct {
			Status   string
			Vector   string
			Reason   string
			Packages []string
		}{Status: domain.Status, Vector: domain.Vector, Reason: domain.Reason, Packages: domain.Packages}
	}

	for _, name := range []string{"account-keys", "svr-key", "backup-id", "username-links"} {
		domain, ok := byName[name]
		if !ok {
			t.Fatalf("missing coverage domain %q", name)
		}
		if domain.Status != "vector-backed" {
			t.Fatalf("%s status = %q, want vector-backed", name, domain.Status)
		}
		if domain.Vector == "" {
			t.Fatalf("%s missing vector file", name)
		}
		assertVectorHasCases(t, vectorFilename(t, domain.Vector))
	}

	for _, name := range []string{"username-hash-proof", "message-backup", "svr-svrb-proof"} {
		domain, ok := byName[name]
		if !ok {
			t.Fatalf("missing deferred coverage domain %q", name)
		}
		if domain.Status != "deferred" || domain.Reason == "" {
			t.Fatalf("%s = %+v, want deferred with reason", name, domain)
		}
	}
}

func TestUpstreamPinAutomationRegeneratesAllVectorBackedDomains(t *testing.T) {
	raw, err := os.ReadFile("../scripts/update-upstream-pin.sh")
	if err != nil {
		t.Fatalf("read update script: %v", err)
	}
	script := string(raw)
	for _, domain := range []string{"username-links", "sealedsender"} {
		if !strings.Contains(script, domain) {
			t.Fatalf("update-upstream-pin.sh does not regenerate %s", domain)
		}
	}
	for _, path := range []string{
		"compat/coverage_manifest.json",
		"compat/coverage_manifest_test.go",
		"proofreport/report_test.go",
		"accountkeys/accountkeys_test.go",
		"usernames/usernames_test.go",
	} {
		if !strings.Contains(script, path) {
			t.Fatalf("update-upstream-pin.sh does not update %s during repin", path)
		}
	}
	for _, pkg := range []string{"./compat/", "./proofreport", "./accountkeys", "./usernames"} {
		if !strings.Contains(script, pkg) {
			t.Fatalf("update-upstream-pin.sh does not run proof coverage tests for %s", pkg)
		}
	}

	workflow, err := os.ReadFile("../.github/workflows/compat-drift.yml")
	if err != nil {
		t.Fatalf("read compat-drift workflow: %v", err)
	}
	for _, domain := range []string{"username-links"} {
		if !strings.Contains(string(workflow), domain) {
			t.Fatalf("compat-drift pin leg does not check %s", domain)
		}
	}

	upstreamPin, err := os.ReadFile("../.github/workflows/upstream-pin.yml")
	if err != nil {
		t.Fatalf("read upstream-pin workflow: %v", err)
	}
	for _, phrase := range []string{"proof report", "proofreport.Report()"} {
		if !strings.Contains(string(upstreamPin), phrase) {
			t.Fatalf("upstream-pin workflow does not document %q", phrase)
		}
	}
}

func vectorFilename(t *testing.T, path string) string {
	t.Helper()
	if !strings.HasPrefix(path, "vectors/") {
		t.Fatalf("vector path %q must be under vectors/", path)
	}
	name := strings.TrimPrefix(path, "vectors/")
	if strings.Contains(name, "/") || strings.Contains(name, "..") || !strings.HasSuffix(name, ".json") {
		t.Fatalf("vector path %q must be vectors/<file>.json", path)
	}
	return name
}

func assertVectorHasCases(t *testing.T, filename string) {
	t.Helper()
	raw, err := readCoverageVector(filename)
	if err != nil {
		t.Fatalf("read vector %s: %v", filename, err)
	}
	var batch struct {
		Cases    []json.RawMessage `json:"cases"`
		PinCases []json.RawMessage `json:"pin_cases"`
	}
	if err := json.Unmarshal(raw, &batch); err != nil {
		t.Fatalf("decode vector %s: %v", filename, err)
	}
	if len(batch.Cases)+len(batch.PinCases) == 0 {
		t.Fatalf("vector %s has no cases", filename)
	}
}

func readCoverageVector(filename string) ([]byte, error) {
	switch filename {
	case "account-keys.json":
		return os.ReadFile("vectors/account-keys.json")
	case "username-links.json":
		return os.ReadFile("vectors/username-links.json")
	default:
		return nil, os.ErrNotExist
	}
}
