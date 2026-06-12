// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build interop

// Package compat's interop test drives the live Rust harness (built from
// compat/rust-harness, pinned to upstream libsignal v0.91.0) over its
// line-delimited JSON-RPC loop and asserts the pure-Go implementation agrees
// with upstream on live operations — complementing the committed-vector tests
// in vectors_test.go, which need no Rust toolchain.
//
// It is gated behind the `interop` build tag so the default `go test ./...`
// (which has no harness binary) never compiles or runs it. Run it with the
// harness path in COMPAT_HARNESS_BIN:
//
//	cargo build --release --manifest-path compat/rust-harness/Cargo.toml
//	COMPAT_HARNESS_BIN=$(pwd)/compat/rust-harness/target/release/rust-harness \
//	  go test ./compat/ -tags=interop -v
//
// If COMPAT_HARNESS_BIN is unset the test skips with a clear message rather than
// failing, so the tag-less suite and tag-on-but-no-binary runs both stay green.
//
// Coverage now: curve sign/verify (both directions) + ECDH agreement, KEM
// encapsulate/decapsulate round-trips, and SenderKeyMessage serialize ->
// upstream-parse field equality. The harness exposes more domains via committed
// vectors (see vectors_test.go); the interop leg checks the operations that are
// only meaningful live. Session/group/sealed-sender flows arrive in T19 by
// adding methods to the harness dispatch and helper calls here — the client
// (newHarness/call) is built to extend without change.
package compat

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/kem"
	"github.com/GoCodeAlone/libsignal-go/protocol"
)

// callTimeout bounds a single request/response exchange. The watchdog guards
// against a harness that hangs or dies mid-line, so a broken harness fails the
// test in bounded time instead of blocking the suite.
const callTimeout = 60 * time.Second

// rpcRequest is one JSON-RPC request line. Params is an arbitrary object whose
// byte-string fields are hex-encoded (the harness decodes them with hex).
type rpcRequest struct {
	ID     int            `json:"id"`
	Method string         `json:"method"`
	Params map[string]any `json:"params"`
}

// rpcResponse is one JSON-RPC response line. On success Ok is true and Result
// carries the method's output object; on failure Ok is false and Error holds
// the harness's message. Result is deferred decoding so each call site picks
// out the fields it needs.
type rpcResponse struct {
	ID     int             `json:"id"`
	Ok     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}

// harness owns the running harness subprocess and its stdio pipes. It is not
// safe for concurrent use: requests are issued sequentially with a monotonic id
// so each response can be matched to its request.
type harness struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	nextID int
}

// newHarness starts the harness binary named by COMPAT_HARNESS_BIN in `interop`
// mode and returns a client for it. It skips the test (does not fail) when the
// env var is unset, so the suite is a no-op without a built harness. The
// subprocess is torn down via t.Cleanup.
func newHarness(t *testing.T) *harness {
	t.Helper()
	bin := os.Getenv("COMPAT_HARNESS_BIN")
	if bin == "" {
		t.Skip("COMPAT_HARNESS_BIN unset; build compat/rust-harness and set it to the binary path to run interop tests")
	}
	// COMPAT_HARNESS_BIN is an operator/CI-supplied path to the harness binary
	// this test exists to drive; it is not attacker-controlled input. The Stat
	// and exec of it are the intended behavior, not a path-traversal/subprocess
	// vulnerability.
	if _, err := os.Stat(bin); err != nil { //nolint:gosec // G703: operator-supplied harness path, by design
		t.Fatalf("COMPAT_HARNESS_BIN=%q: %v", bin, err)
	}

	cmd := exec.Command(bin, "interop") //nolint:gosec // G204: operator-supplied harness path, by design
	cmd.Stderr = os.Stderr              // surface harness diagnostics in the test log
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start harness %q: %v", bin, err)
	}

	h := &harness{t: t, cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), nextID: 1}
	t.Cleanup(h.close)
	return h
}

// close shuts the harness down: closing stdin ends its read loop, then Wait
// reaps the process. A non-zero exit from the loop itself is not a test failure
// (the loop exits 0 on clean EOF), but a failure to reap is logged.
func (h *harness) close() {
	_ = h.stdin.Close()
	if err := h.cmd.Wait(); err != nil {
		h.t.Logf("harness wait: %v", err)
	}
}

// call sends one request and returns the decoded response, enforcing the
// per-call watchdog. A transport error (write failure, EOF, timeout) fails the
// test immediately; a harness-level error response (ok=false) is returned to
// the caller, which decides whether that is expected.
func (h *harness) call(method string, params map[string]any) rpcResponse {
	h.t.Helper()
	req := rpcRequest{ID: h.nextID, Method: method, Params: params}
	h.nextID++

	line, err := json.Marshal(req)
	if err != nil {
		h.t.Fatalf("marshal request: %v", err)
	}
	line = append(line, '\n')

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	type readResult struct {
		resp rpcResponse
		err  error
	}
	done := make(chan readResult, 1)
	go func() {
		if _, werr := h.stdin.Write(line); werr != nil {
			done <- readResult{err: fmt.Errorf("write request: %w", werr)}
			return
		}
		respLine, rerr := h.stdout.ReadBytes('\n')
		if rerr != nil {
			done <- readResult{err: fmt.Errorf("read response: %w", rerr)}
			return
		}
		var resp rpcResponse
		if jerr := json.Unmarshal(respLine, &resp); jerr != nil {
			done <- readResult{err: fmt.Errorf("decode response %q: %w", respLine, jerr)}
			return
		}
		done <- readResult{resp: resp}
	}()

	select {
	case <-ctx.Done():
		h.t.Fatalf("harness call %q timed out after %s", method, callTimeout)
	case r := <-done:
		if r.err != nil {
			h.t.Fatalf("harness call %q: %v", method, r.err)
		}
		if r.resp.ID != req.ID {
			h.t.Fatalf("harness call %q: response id %d != request id %d", method, r.resp.ID, req.ID)
		}
		return r.resp
	}
	panic("unreachable")
}

// ok issues a call and fails the test if the harness returned an error
// response, decoding the result into dst. Use call directly when an error
// response is the expected outcome.
func (h *harness) ok(method string, params map[string]any, dst any) {
	h.t.Helper()
	resp := h.call(method, params)
	if !resp.Ok {
		h.t.Fatalf("harness call %q failed: %s", method, resp.Error)
	}
	if dst != nil {
		if err := json.Unmarshal(resp.Result, dst); err != nil {
			h.t.Fatalf("decode %q result: %v", method, err)
		}
	}
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestInteropPing is the liveness check: the harness answers `ping` before any
// crypto is exercised, so a setup failure (wrong binary, bad mode) is reported
// distinctly from a crypto disagreement.
func TestInteropPing(t *testing.T) {
	h := newHarness(t)
	var res struct {
		Pong bool `json:"pong"`
	}
	h.ok("ping", nil, &res)
	if !res.Pong {
		t.Fatal("ping: pong != true")
	}
}

// TestInteropCurveSignVerify checks XEdDSA agreement in both directions:
//
//	Go signs  -> Rust verifies (curve.verify)
//	Rust signs (curve.sign) -> Go verifies
//
// XEdDSA signatures are randomized (the nonce differs per signer), so the two
// directions are bridged by verification, not signature-byte equality. (Byte
// equality under a replayed nonce is covered by the committed curve vectors.)
func TestInteropCurveSignVerify(t *testing.T) {
	h := newHarness(t)

	for i := 0; i < 8; i++ {
		kp, err := curve.GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		msg := []byte(fmt.Sprintf("interop curve message %d", i))

		// Go signs -> Rust verifies.
		goSig, err := kp.PrivateKey.CalculateSignature(rand.Reader, msg)
		if err != nil {
			t.Fatalf("CalculateSignature: %v", err)
		}
		var verRes struct {
			Verified bool `json:"verified"`
		}
		h.ok("curve.verify", map[string]any{
			"public_key": hx(kp.PublicKey.Serialize()),
			"message":    hx(msg),
			"signature":  hx(goSig),
		}, &verRes)
		if !verRes.Verified {
			t.Fatalf("case %d: Rust failed to verify Go signature", i)
		}

		// Rust signs -> Go verifies.
		var signRes struct {
			Signature string `json:"signature"`
			PublicKey string `json:"public_key"`
		}
		h.ok("curve.sign", map[string]any{
			"private_key": hx(kp.PrivateKey.Serialize()),
			"message":     hx(msg),
		}, &signRes)
		// The harness echoes the public key it derived; it must match ours.
		if signRes.PublicKey != hx(kp.PublicKey.Serialize()) {
			t.Fatalf("case %d: harness derived public key %s != %s", i, signRes.PublicKey, hx(kp.PublicKey.Serialize()))
		}
		rustSig := mustDecodeHex(t, signRes.Signature)
		if !kp.PublicKey.VerifySignature(rustSig, msg) {
			t.Fatalf("case %d: Go failed to verify Rust signature", i)
		}
	}
}

// TestInteropCurveAgree checks X25519 ECDH agreement: Go computes the shared
// secret locally and the harness computes it from the other side; the two must
// be byte-identical and symmetric.
func TestInteropCurveAgree(t *testing.T) {
	h := newHarness(t)

	for i := 0; i < 8; i++ {
		a, err := curve.GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKeyPair a: %v", err)
		}
		b, err := curve.GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKeyPair b: %v", err)
		}

		goShared, err := a.PrivateKey.CalculateAgreement(b.PublicKey)
		if err != nil {
			t.Fatalf("case %d: Go agreement: %v", i, err)
		}

		// Harness agrees from b's private + a's public; result must match Go's.
		var res struct {
			Shared string `json:"shared"`
		}
		h.ok("curve.agree", map[string]any{
			"private_key": hx(b.PrivateKey.Serialize()),
			"public_key":  hx(a.PublicKey.Serialize()),
		}, &res)
		if !bytes.Equal(mustDecodeHex(t, res.Shared), goShared) {
			t.Fatalf("case %d: Rust ECDH %s != Go %s", i, res.Shared, hx(goShared))
		}
	}
}

// TestInteropKEM checks Kyber1024 KEM agreement: Go generates a key pair and
// encapsulates to its own public key, then the harness decapsulates with the
// secret key and must recover the same shared secret. Go also decapsulates its
// own ciphertext as a self-consistency check. (Rust-encapsulate -> Go-decaps is
// covered by the committed kem-decaps vectors, since the harness exposes only
// decapsulate over JSON-RPC.)
func TestInteropKEM(t *testing.T) {
	h := newHarness(t)

	for i := 0; i < 8; i++ {
		kp, err := kem.GenerateKeyPair(kem.KeyTypeKyber1024, rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		ss, ct, err := kp.PublicKey.Encapsulate()
		if err != nil {
			t.Fatalf("case %d: Encapsulate: %v", i, err)
		}

		// Go decapsulates its own ciphertext (self-consistency).
		goSS, err := kp.SecretKey.Decapsulate(ct)
		if err != nil {
			t.Fatalf("case %d: Go Decapsulate: %v", i, err)
		}
		if !bytes.Equal(goSS, ss) {
			t.Fatalf("case %d: Go decaps != Go encaps shared secret", i)
		}

		// Rust decapsulates the Go ciphertext; must recover the same secret.
		var res struct {
			SharedSecret string `json:"shared_secret"`
		}
		h.ok("kem.decapsulate", map[string]any{
			"secret_key": hx(kp.SecretKey.Serialize()),
			"ciphertext": hx(ct),
		}, &res)
		if !bytes.Equal(mustDecodeHex(t, res.SharedSecret), ss) {
			t.Fatalf("case %d: Rust decaps %s != Go encaps secret %s", i, res.SharedSecret, hx(ss))
		}
	}
}

// TestInteropSenderKeyMessage checks the message wire format live: Go builds and
// serializes a SenderKeyMessage, the harness parses it with the genuine upstream
// type, and the parsed header fields must match what Go put in. (Upstream ->
// Go re-serialize byte equality is covered by the committed messages vectors.)
func TestInteropSenderKeyMessage(t *testing.T) {
	h := newHarness(t)

	for i := 0; i < 8; i++ {
		var distID [16]byte
		if _, err := rand.Read(distID[:]); err != nil {
			t.Fatalf("rand distID: %v", err)
		}
		signKP, err := curve.GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		chainID := uint32(9 + i)
		iteration := uint32(3 + i)
		ciphertext := []byte(fmt.Sprintf("interop skm ciphertext %d", i))

		msg, err := protocol.NewSenderKeyMessage(distID, chainID, iteration, ciphertext, rand.Reader, signKP.PrivateKey)
		if err != nil {
			t.Fatalf("case %d: NewSenderKeyMessage: %v", i, err)
		}

		var res struct {
			DistributionID string `json:"distribution_id"`
			ChainID        uint32 `json:"chain_id"`
			Iteration      uint32 `json:"iteration"`
		}
		h.ok("message.parse_sender_key", map[string]any{
			"serialized": hx(msg.Serialized()),
		}, &res)

		if res.ChainID != chainID || res.Iteration != iteration {
			t.Fatalf("case %d: harness parsed chainID/iteration %d/%d, want %d/%d",
				i, res.ChainID, res.Iteration, chainID, iteration)
		}
		gotID := parseUUID16(t, res.DistributionID)
		if gotID != distID {
			t.Fatalf("case %d: harness parsed distribution id %x, want %x", i, gotID, distID)
		}
	}
}

// TestInteropUnknownMethod confirms the harness never crashes on a bad request:
// an unknown method returns an error response and the loop stays alive (a
// subsequent ping still succeeds on the same process).
func TestInteropUnknownMethod(t *testing.T) {
	h := newHarness(t)

	resp := h.call("does.not.exist", nil)
	if resp.Ok {
		t.Fatal("unknown method returned ok=true")
	}
	if resp.Error == "" {
		t.Fatal("unknown method returned empty error")
	}

	// Loop survived: ping still answers on the same subprocess.
	var res struct {
		Pong bool `json:"pong"`
	}
	h.ok("ping", nil, &res)
	if !res.Pong {
		t.Fatal("harness did not survive an unknown-method request")
	}
}
