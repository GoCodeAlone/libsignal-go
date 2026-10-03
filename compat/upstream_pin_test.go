package compat

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func upstreamPinFixture(t *testing.T, manifest string) (root, script string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("upstream updater requires bash")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("upstream updater requires jq")
	}
	root = t.TempDir()
	scriptDir := filepath.Join(root, "scripts")
	harnessDir := filepath.Join(root, "compat", "rust-harness")
	binDir := filepath.Join(root, "bin")
	for _, dir := range []string{scriptDir, harnessDir, binDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile("../scripts/update-upstream-pin.sh")
	if err != nil {
		t.Fatal(err)
	}
	script = filepath.Join(scriptDir, "update-upstream-pin.sh")
	if err := os.WriteFile(script, raw, 0o600); err != nil { // #nosec G703 -- fixed child path inside t.TempDir, never user input.
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(harnessDir, "Cargo.toml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	// Substitute only Cargo metadata, not the updater being exercised.
	const cargo = `#!/bin/sh
printf '%s\n' '{"packages":[{"name":"rust-harness","metadata":{"libsignal":{"upstream_tag":"v0.104.0"}},"dependencies":[{"name":"libsignal-protocol","source":"git+https://github.com/signalapp/libsignal?rev=257105c55a7389ca6b1e85185e2769465e6729f1"}]}]}'
`
	if err := os.WriteFile(filepath.Join(binDir, "cargo"), []byte(cargo), 0o700); err != nil { // #nosec G306 -- owner-only executable test dependency.
		t.Fatal(err)
	}
	return root, script
}

func runUpstreamPin(t *testing.T, root, script, tag string) ([]byte, error) {
	t.Helper()
	binDir := filepath.Join(root, "bin")
	cmd := exec.CommandContext(t.Context(), "bash", script, tag) // #nosec G204 -- local updater and fixed test tags.
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return cmd.CombinedOutput()
}

func TestUpstreamPinReadsImmutableReleaseMetadata(t *testing.T) {
	for _, pin := range []string{`rev = "257105c55a7389ca6b1e85185e2769465e6729f1"`, `tag = "v0.104.0"`} {
		manifest := `libsignal-protocol = { git = "https://github.com/signalapp/libsignal", ` + pin + " }\n"
		root, script := upstreamPinFixture(t, manifest)
		if strings.HasPrefix(pin, "tag") {
			if err := os.WriteFile(filepath.Join(root, "bin", "cargo"), []byte("#!/bin/sh\nexit 88\n"), 0o700); err != nil { // #nosec G306 -- owner-only executable test dependency.
				t.Fatal(err)
			}
		}
		out, err := runUpstreamPin(t, root, script, "v0.104.0")
		if err != nil || !strings.Contains(string(out), "already pinned to v0.104.0") {
			t.Fatalf("pin no-op failed: %v\n%s", err, out)
		}
		unchanged, err := os.ReadFile(filepath.Join(root, "compat", "rust-harness", "Cargo.toml")) // #nosec G304 -- fixed child of the test-owned temporary directory.
		if err != nil || string(unchanged) != manifest {
			t.Fatal("same-release updater modified its pin")
		}
	}
}

func TestUpstreamPinMovesAllImmutableDependencies(t *testing.T) {
	const current = "257105c55a7389ca6b1e85185e2769465e6729f1"
	const next = "2222222222222222222222222222222222222222"
	manifest := "[package.metadata.libsignal]\nupstream_tag = \"v0.104.0\"\n[dependencies]\n"
	for _, name := range []string{"libsignal-protocol", "libsignal-account-keys", "usernames"} {
		manifest += name + ` = { git = "https://github.com/signalapp/libsignal", rev = "` + current + "\" }\n"
	}
	root, script := upstreamPinFixture(t, manifest)
	for _, path := range []string{
		"README.md", "compat/README.md", "compat/coverage_manifest.json", "compat/coverage_manifest_test.go",
		"proofreport/report_test.go", "accountkeys/accountkeys_test.go", "usernames/usernames_test.go",
		"compat/rust-harness/README.md", "compat/session_interop_test.go", ".github/workflows/compat.yml", ".github/workflows/compat-drift.yml",
	} {
		file := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const gh = `#!/bin/sh
case "$2" in
*/git/ref/tags/*) printf '%s\n' '{"sha":"3333333333333333333333333333333333333333","type":"tag"}' ;;
*/git/tags/*) printf '%s\n' '{"sha":"2222222222222222222222222222222222222222","type":"commit"}' ;;
*) exit 90 ;;
esac
`
	if err := os.WriteFile(filepath.Join(root, "bin", "gh"), []byte(gh), 0o700); err != nil { // #nosec G306 -- owner-only executable test dependency.
		t.Fatal(err)
	}
	cargoPath := filepath.Join(root, "bin", "cargo")
	cargo, err := os.ReadFile(cargoPath) // #nosec G304 -- fixed child of the test-owned temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	// Stop at the build boundary; no network, dependency resolution or Go tests.
	cargo = bytes.Replace(cargo, []byte("#!/bin/sh\n"), []byte("#!/bin/sh\nif [ \"$1\" != metadata ]; then exit 77; fi\n"), 1)
	if err := os.WriteFile(cargoPath, cargo, 0o700); err != nil { // #nosec G306 G703 -- owner-only executable at a fixed t.TempDir child, never user input.
		t.Fatal(err)
	}
	out, err := runUpstreamPin(t, root, script, "v0.105.0")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 77 {
		t.Fatalf("updater failed before mocked build boundary: %v\n%s", err, out)
	}
	updated, err := os.ReadFile(filepath.Join(root, "compat", "rust-harness", "Cargo.toml")) // #nosec G304 -- fixed child of the test-owned temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(updated), next) != 3 || strings.Contains(string(updated), current) || !strings.Contains(string(updated), `upstream_tag = "v0.105.0"`) {
		t.Fatal("updater did not move all three libsignal revisions and release metadata together")
	}
}
