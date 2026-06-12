# Pure Go libsignal Implementation Plan

> **For the implementing agent:** REQUIRED SUB-SKILL: Use autodev:executing-plans to implement this plan task-by-task.

**Goal:** Pure Go (no cgo/C/Rust) Signal client protocol core in `github.com/GoCodeAlone/libsignal-go`, wire-compatible with `signalapp/libsignal`, gated by cross-implementation compat contracts as required PR checks.

**Architecture:** Idiomatic Go domain packages traced to `rust/protocol` (+ minimal `rust/core`, `rust/crypto`) behavior; two-layer compat (committed Rust-generated vectors + live Rust↔Go interop harness); staged compat pinning per ADR 0001 (Stage 1 = upstream tag v0.91.1, Stage 2 = latest tag after SPQR port).

**Tech Stack:** Go 1.26.4 (toolchain directive), `filippo.io/edwards25519`, `golang.org/x/crypto`, `github.com/cloudflare/circl` (Kyber1024), `google.golang.org/protobuf`; Rust harness (cargo git-dep on upstream tag) for compat only.

**Base branch:** main

**Design:** `docs/plans/2026-06-12-pure-go-libsignal-design.md` (rev 3, review PASS cycle 3)
**Guidance:** `docs/design-guidance.md` | **ADR:** `decisions/0001-spqr-staged-compat.md`

---

## Scope Manifest

**PR Count:** 11
**Tasks:** 30
**Estimated Lines of Change:** ~25,000 (informational; not enforced)

**Out of scope:**
- zkgroup/zkcredential/poksho, usernames, keytrans, SVR/svrb, account-keys, device-transfer, media, message-backup, net
- Language bridges (java/swift/node) — deleted, not ported
- `incremental_mac`, HPKE, `session_cipher_legacy` (upstream test-only)
- X3DH v3 session *initiation* (v3 decrypt/state compat retained)
- ML-KEM-1024 *activation* (wire type 0x0A parsing reserved only)
- FIPS certification; key-material zeroization guarantees beyond documented Go posture

**PR Grouping:**

| PR # | Title | Tasks | Branch |
|------|-------|-------|--------|
| 1 | Scaffold: Go module, CI, cruft purge round 1 | Task 1, Task 2 | feat/go-p1-scaffold |
| 2 | Crypto primitives, curve (X25519/XEdDSA), address types | Task 3, Task 4, Task 5, Task 6 | feat/go-p2-prims |
| 3 | KEM (Kyber1024), protobuf codegen, wire messages | Task 7, Task 8, Task 9, Task 10 | feat/go-p3-wire |
| 4 | Compat harness: vectors + interop + required checks | Task 11, Task 12, Task 13 | feat/go-p4-compat |
| 5 | Ratchet keys, session state, stores | Task 14, Task 15, Task 16 | feat/go-p5-ratchet |
| 6 | PQXDH session builder + session cipher + interop | Task 17, Task 18, Task 19 | feat/go-p6-session |
| 7 | Groups: sender keys + group cipher + interop | Task 20, Task 21 | feat/go-p7-groups |
| 8 | Sealed sender v1/v2 + AES-GCM-SIV + interop | Task 22, Task 23, Task 24 | feat/go-p8-sealed |
| 9 | Fingerprints + API polish + scope matrix | Task 25, Task 26 | feat/go-p9-polish |
| 10 | SPQR port + re-pin to latest upstream + full-suite revalidation | Task 27, Task 28, Task 29 | feat/go-p10-spqr |
| 11 | Cleanup: remove reference trees, final docs, v0.1.0 | Task 30 | feat/go-p11-cleanup |

**Status:** Locked 2026-06-12T05:22:09Z

---

## Conventions (all tasks)

- Commits: author `codingsloth@pm.me` (repo-local git config already set). Conventional Commits style.
- Every Go task: `CGO_ENABLED=0 go build ./... && go test ./...` + `gofmt -l . → empty` + `golangci-lint run --new-from-rev=origin/main → exit 0` before push.
- ⊥ invent crypto constants: every KDF info string, version byte, MAC layout, proto field number is **extracted from the cited rust source file** and locked by a vector test. When plan cites `rust/...:line`, implementer reads that source as the contract.
- Public API: no panics; errors wrap w/ typed sentinels; key types' `String()` redacts.
- Deterministic RNG: constructors take `io.Reader`; default `crypto/rand.Reader`; tests inject seeded readers.
- Every PR updates README status section (doc-currency rule, design D15).
- PR merge rule: CI green + no unresolved Copilot comments → merge (admin merge permitted). Use `autodev:pr-monitoring`.
- Parallelization (P9, owner "agent team" directive): PRs 7, 8, 9 depend only on PR 6 and are dependency-independent — execute via worktree-isolated parallel agents (`autodev:dispatching-parallel-agents`) when capacity allows; all other PRs sequential per dependency chain. Caveat (P13): T21/T24/T25 all append to `compat/rust-harness/src/main.rs` + `compat/interop_test.go` — conflicts are append-shaped; last-to-merge rebases (merge order: 7 → 8 → 9).

---

## PR 1 — Scaffold

### Task 1: Cruft purge round 1 + workflow retirement + branch protection

**Files:**
- Delete: `java/ swift/ node/ bin/ acknowledgments/ doc/ .cargo/ .cbindgen-version .clippy.toml .dockerignore .nvmrc .prettierrc.js .rustfmt.toml .swift-format .taplo-cli-version .taplo.toml .flake8 .tool-versions LibSignalClient.podspec justfile RELEASE.md RELEASE_NOTES.md TESTING.md CODING_GUIDELINES.md`
- Delete: `.github/workflows/{android_integration,ios_artifacts,jni_artifacts,npm,build_and_test,lints,slow_tests,check_versions,docs,release_notes}.yml` + `.github/workflows/README.md` (P5) (keep `stale.yml`)
- Keep: `rust/ Cargo.toml Cargo.lock rust-toolchain LICENSE SECURITY.md .github/workflows/stale.yml .gitattributes .gitignore .editorconfig`

**Steps:**
1. `git rm -r` the delete list (verify each exists first; `git rm` fails loudly otherwise).
2. Audit branch protection: `gh api repos/GoCodeAlone/libsignal-go/branches/main/protection` → record current required checks. If legacy required checks reference deleted workflows, update via `gh api -X PUT .../required_status_checks` to empty or to-be-added `go` check. If 404 (no protection), note and skip.
3. Trim `.gitignore`/`.gitattributes`/`.editorconfig` to Go-relevant entries (keep rust-relevant lines while `rust/` remains).
4. Commit.

**Verify:** `git status --short → clean`; `ls java swift node bin acknowledgments doc 2>&1 → No such file` ×6; `gh api .../protection | jq '.required_status_checks.contexts' → [] or ["go"]` (no stale contexts).
**Rollback:** `git revert` merge commit; branch protection restored via recorded pre-state JSON (save to PR description).

### Task 2: Go module + CI + README rewrite

**Files:**
- Create: `go.mod` (`module github.com/GoCodeAlone/libsignal-go`, `go 1.26`, `toolchain go1.26.4`), `go.sum`
- Create: `.github/workflows/go.yml`, `.golangci.yml`, `doc.go` (placeholder package comment), `README.md` (rewrite)
- Create: `.github/dependabot.yml` (gomod + github-actions weekly)

**Steps:**
1. `go mod init github.com/GoCodeAlone/libsignal-go`; pin `toolchain go1.26.4`.
2. `doc.go`: module-level doc stating purpose, staged-compat status, AGPL-3.0.
3. `go.yml`: jobs `go` (ubuntu-latest + macos-latest matrix): `actions/setup-go` w/ `go-version-file: go.mod` (P7 — honors toolchain directive), `CGO_ENABLED=0 go build ./...`, `go vet ./...`, `gofmt -l .` (fail if nonempty), `go test -race ./...`, golangci-lint action pinned to a release supporting Go 1.26 (P7). Trigger: PR + push main. Single required-check name: `go`.
4. `.golangci.yml`: golangci-lint v2 schema — `version: "2"` key required (P7); default linters + `errcheck, govet, staticcheck, gosec, revive`; exclude `proto/` generated.
5. README rewrite: project identity (pure Go Signal protocol), status table (per-phase ✅/🚧), compat staging explanation (v0.91.1 → mainline per ADR 0001), reference note (rust/ tree = upstream snapshot, removed at v0.1.0), install/usage placeholder, AGPL-3.0.
6. Add `go` to branch-protection required checks: `gh api -X PATCH` (or PUT contexts `["go"]`).
7. Commit; open PR 1; monitor per `autodev:pr-monitoring`.

**Verify:** `CGO_ENABLED=0 go build ./... → exit 0`; push branch → `gh pr checks → go: pass`; `gh api .../protection | jq → contexts includes "go"`.
**Rollback:** revert merge commit; required-checks PUT back to recorded pre-state.

---

## PR 2 — Primitives

### Task 3: internal/crypto: AES modes + HKDF/HMAC helpers

**Files:**
- Create: `internal/crypto/aescbc.go`, `aesctr.go`, `aesgcm.go`, `kdf.go` + `_test.go` each
- Refs: `rust/crypto/src/{aes_cbc,aes_ctr,aes_gcm}.rs`, `rust/protocol/src/crypto.rs`

**Steps (TDD):**
1. Tests first: NIST/RFC KATs — AES-256-CBC+PKCS7 (encrypt/decrypt round-trip + padding-error case), AES-256-CTR (32-bit counter behavior per `aes_ctr.rs`), AES-256-GCM seal/open + tag-failure case, HKDF-SHA256 (RFC 5869 A.1-A.3 via stdlib `crypto/hkdf`), HMAC-SHA256 (RFC 4231 cases).
2. Run → FAIL (functions undefined).
3. Implement thin wrappers over stdlib mirroring rust/crypto semantics (error taxonomy: bad key len, bad nonce len, padding invalid).
4. Run → PASS. Fuzz: `FuzzCBCRoundTrip`, `FuzzGCMOpen` (malformed inputs never panic).
5. Commit.

**Verify:** `go test ./internal/crypto/ -v → PASS (all KAT cases named)`; `go test -fuzz=FuzzGCMOpen -fuzztime=30s ./internal/crypto/ → no crashes`.

### Task 4: curve: X25519 keys, ECDH, serialization

**Files:**
- Create: `curve/curve.go`, `curve/keypair.go` + tests
- Refs: `rust/core/src/curve.rs` (type byte 0x05 = `KeyType::Djb`, 33-byte serialized public key), `rust/protocol/src/identity_key.rs`

**Steps:**
1. Tests: keypair gen (injected RNG → deterministic), `PublicKey.Serialize() → 33 bytes, [0]==0x05`, `Deserialize` rejects bad type byte/length (error, no panic), ECDH agreement matches RFC 7748 §6.1 vector, clamping per X25519.
2. Implement over `golang.org/x/crypto/curve25519` + `crypto/ecdh` where it fits. Constant-time identity compare via `crypto/subtle`.
3. `PrivateKey.String()/Format` redacts. Fuzz `Deserialize`.
4. Commit.

**Verify:** `go test ./curve/ -v → PASS`; RFC 7748 vector case named in output.

### Task 5: curve: XEd25519 signatures

**Files:**
- Create: `curve/xeddsa.go`, `curve/xeddsa_test.go`
- Refs: XEdDSA spec (signal.org/docs/specifications/xeddsa), upstream usage `rust/core/src/curve.rs` `calculate_signature`/`verify_signature` (curve25519-dalek custom impl under `rust/core/src/curve/curve25519.rs`)

**Steps:**
1. Tests: sign/verify round-trip w/ deterministic nonce input (64-byte random per spec, injected); verify rejects flipped bit in sig/msg/key; cross-check vector extracted from upstream test `rust/core/src/curve/curve25519.rs` tests (signature_agreement) — port the exact test keys/messages.
2. Implement per spec using `filippo.io/edwards25519`: mont→ed birational map w/ sign bit forced 0 (calculate key pair), Schnorr-style sig (`r = hash1(a || M || Z)`, `R = rB`, `h = hash(R || A || M)`, `s = r + ha`); verify via point eq w/ sign-bit handling.
3. Constant-time: scalar ops via edwards25519 (already CT); no secret-dep branches (review by inspection + comment).
4. Fuzz verify (arbitrary sig/msg never panics). Commit.

**Verify:** `go test ./curve/ -run XEd -v → PASS incl. upstream-ported vector case`.

### Task 6: address: ServiceId, ProtocolAddress, DeviceId

**Files:**
- Create: `address/address.go`, `address/serviceid.go` + tests
- Refs: `rust/core/src/address.rs` (ServiceId fixed-width binary: 17-byte PNI-prefixed form, ACI = raw 16-byte UUID; service-id-string forms `ACI:`/`PNI:` prefixes; DeviceId u32 bounds)

**Steps:**
1. Tests: port upstream `address.rs` unit-test cases verbatim (string round-trips, binary round-trips, PNI prefix 0x01, invalid inputs rejected).
2. Implement. 3. Fuzz parse. 4. Commit.

**Verify:** `go test ./address/ -v → PASS`.

---

## PR 3 — KEM + Wire

### Task 7: kem: Kyber1024

**Files:**
- Create: `kem/kem.go`, `kem/kyber1024.go` + tests; testdata: copy `rust/protocol/src/kem/test-data/{pk,sk}.dat`
- Refs: `rust/protocol/src/kem.rs` (KeyType byte 0x08 Kyber1024, 0x0A MLKEM1024 parse-reserved; serialized = type byte ‖ raw key; ss/ct sizes), `kem/kyber1024.rs`

**Steps:**
1. Tests: deserialize upstream `pk.dat`/`sk.dat` fixtures (format compat); serialize round-trip; encaps/decaps self-consistency (`decaps(sk, encaps(pk).ct) == ss`); NIST round-3 Kyber1024 KATs via circl's derandomized API (vendor KAT seeds/expected from circl testdata or pq-crystals round-3 KAT file — cite source in test comment); wire sizes assert (pk 1568+1, ct 1568, ss 32).
2. Implement wrapping `circl/kem/kyber/kyber1024`. KeyType registry mirrors `kem.rs` (0x08 active, 0x0A recognized-not-enabled error).
3. Fuzz deserialize. Commit.

**Verify:** `go test ./kem/ -v → PASS incl. TestUpstreamKeyFixtures + TestKyber1024KAT`. A1 partially closed (format+KAT); fully closed Task 12.

### Task 8: proto: schema port + codegen

**Files:**
- Create: `proto/wire.proto`, `proto/service.proto`, `proto/storage.proto`, `proto/sealed_sender.proto`, `proto/fingerprint.proto` (ported from `rust/protocol/src/proto/*.proto`, package names adjusted, `option go_package`), generated `*.pb.go`, `proto/generate.go` (`//go:generate protoc ...`), Makefile or `tools.go` note
- Refs: `rust/protocol/src/proto/*.proto` — field numbers/types copied EXACTLY incl. `SignalMessage.pq_ratchet = 5`, `SessionStructure.pq_ratchet_state = 15`

**Steps:**
1. Copy each .proto; diff against source to prove field-level identity: `diff <(grep -E '=[ ]*[0-9]+' rust/protocol/src/proto/wire.proto) <(grep -E '=[ ]*[0-9]+' proto/wire.proto) → empty` (same for all five).
2. Generate w/ pinned `protoc-gen-go`; commit generated code (no codegen in CI).
3. Test: marshal/unmarshal round-trip per message; unknown-field preservation test (bytes w/ extra field survive re-marshal — proto3 default, assert anyway: guards pq_ratchet passthrough pre-P10).
4. Commit.

**Verify:** field-number diffs empty ×5; `go test ./proto/ -v → PASS`.

### Task 9: protocol: SignalMessage + PreKeySignalMessage

**Files:**
- Create: `protocol/version.go`, `protocol/signal_message.go`, `protocol/prekey_signal_message.go` + tests
- Refs: `rust/protocol/src/protocol.rs` (version byte = `((message_version & 0xF) << 4) | CIPHERTEXT_MESSAGE_CURRENT_VERSION` on serialize — read lines 100-130 & 280-300 for exact encode/decode + floor checks v3; MAC = HMAC-SHA256(mac_key, sender_identity_pub ‖ receiver_identity_pub ‖ version_byte ‖ proto_bytes)[:8] — extract exact layout from `signal_message.rs` section of protocol.rs)

**Steps:**
1. Tests: construct → serialize → deserialize → field equality; MAC verify pass/fail (flipped byte); version floor (reject <3, >current); truncated input errors not panics. Golden bytes: build one message w/ fixed keys, assert hex (locks layout pre-harness; replaced by upstream vectors in Task 12).
2. Implement. 3. Fuzz deserialize both types. 4. Commit.

**Verify:** `go test ./protocol/ -v → PASS`.

### Task 10: protocol: group + plaintext message types

**Files:**
- Create: `protocol/sender_key_message.go`, `protocol/sender_key_distribution_message.go`, `protocol/plaintext_content.go`, `protocol/decryption_error_message.go` + tests
- Refs: `rust/protocol/src/protocol.rs` (SenderKeyMessage: version byte + proto + 64-byte sig over serialized prefix), `rust/protocol/src/proto/service.proto:9-24` (DecryptionErrorMessage), PlaintextContent body marker (`0xC0` padding-start per protocol.rs — extract exact)

**Steps:** same TDD shape as Task 9 (construct/serialize/round-trip/sig-verify/fuzz).
**Verify:** `go test ./protocol/ -v → PASS`.

---

## PR 4 — Compat Harness (required check from here)

### Task 11: Rust harness crate pinned to v0.91.1

**Files:**
- Create: `compat/rust-harness/Cargo.toml` (own `[workspace] members=["."]`; dep `libsignal-protocol = { git = "https://github.com/signalapp/libsignal", tag = "v0.91.1", package = "libsignal-protocol" }` — pattern proven by `rust/protocol/cross-version-testing/Cargo.toml:21-30`), `compat/rust-harness/src/main.rs`, `compat/rust-harness/rust-toolchain.toml` (match what v0.91.1 builds with; resolve via rustup)
- Modes: `gen-vectors <domain>` (JSON to stdout, seeded `rand_chacha` RNG, seed in header) and `interop` (JSON-RPC over stdin/stdout: methods init-session-alice/bob, encrypt, decrypt, group-create/process/encrypt/decrypt, seal/unseal v1/v2, fingerprint)

**Steps:**
1. Scaffold crate; `cargo build` locally → binary.
2. Implement `gen-vectors` domains: `curve` (sign/verify/ecdh w/ seeded keys), `kem-decaps` (pk,sk,ct,ss triples — deterministic direction), `hkdf` — REQUIRED sub-domains (P1): (a) chain-key step (HMAC 0x02), (b) root-key step w/ DH input, (c) message-keys triple (cipherkey/mackey/iv), (d) PQXDH master-secret derivation (F ‖ DH1..DH4 ‖ kyber_ss IKM) — `messages` (SignalMessage/PreKeySignalMessage/SenderKey* golden bytes w/ fixed keys), `fingerprint`. Session/transcript domains added in later tasks as protocol lands.
3. Implement `interop` loop (serde_json line-delimited).
4. Commit (vectors generated in Task 12).

**Verify:** `cd compat/rust-harness && cargo build --release → exit 0`; `target/release/rust-harness gen-vectors curve | jq '.seed,.cases|length' → seed + count>0`.
**Rollback:** harness is dev/CI-only; revert commit. Pin change = one-line tag edit.

### Task 12: Committed vectors + Go consumption tests

**Files:**
- Create: `compat/vectors/{curve,kem-decaps,hkdf,messages,fingerprint}.json` (generated, committed), `compat/vectors_test.go` (Go side), `compat/README.md` (regen instructions)

**Steps:**
1. Generate each domain → commit JSON.
2. Go tests: for each vector file, run Go impl against cases — curve verify(upstream sig)==ok + Go sign w/ same nonce-seed == upstream sig bytes; ECDH shared secrets equal; kem decaps(sk,ct)==ss (**closes A1**); hkdf outputs equal; message golden bytes byte-equal both directions (replaces Task 9 provisional goldens); fingerprint displayable strings equal.
3. Wire into main `go` job (plain `go test ./compat/` — vectors committed, no Rust needed).
4. Commit.

**Verify:** `go test ./compat/ -v → PASS, case counts logged per domain`; A1 evidence in test output (decaps triples count ≥ 100); `jq '.subdomains|keys' compat/vectors/hkdf.json → ["chain-key","message-keys","pqxdh-secret","root-key"]` each w/ cases ≥ 20 (P1).

### Task 13: Interop CI job + drift workflow + required checks

**Files:**
- Create: `.github/workflows/compat.yml` (job `compat-interop`: triggers `pull_request` (NO path filter — required checks must report on every PR; P4) + `push: main`; checkout, rustup via checkout-local toolchain file (bare `rust-toolchain` or `.toml` both honored by rustup), Swatinem/rust-cache, build harness, `go test ./compat/ -tags=interop`), `.github/workflows/compat-drift.yml` (triggers: weekly cron + `workflow_dispatch` (P4); two-pin — (a) T0 v0.91.1 must-green via main harness; (b) upstream `main` leg builds **`compat/rust-harness-drift/`** — separate micro-crate containing ONLY version-stable generators (curve/hkdf/kem KATs), no session/RPC API surface, so it compiles against `main` regardless of T0-API divergence (P2); `gh issue` dedupe via label `compat-drift` open-issue check), `compat/rust-harness-drift/` (micro-crate, git-dep repointable), `compat/interop_test.go` (build tag `interop`; spawns harness binary path from env `COMPAT_HARNESS_BIN`; skips w/ clear message if unset)
- Constraint (P2): T19/T21/T24/T28 extend ONLY `compat/rust-harness/` (T0-pinned); `rust-harness-drift` never gains protocol-session API surface
- Drift mechanics (P10): `rust-harness-drift` emits the SAME vector JSON schema `compat/vectors_test.go` consumes; main-leg pass/fail = regenerate → run `go test ./compat/` against fresh output; drift crate owns its own `rust-toolchain.toml` (upstream main may need newer toolchain than v0.91.1's)
- Interop coverage at this phase: curve/kem/message ops via RPC (session flows land Task 19)

**Steps:**
1. Write interop_test driver (JSON-RPC client, subprocess lifecycle, 60s watchdog).
2. compat.yml; ensure name `compat-interop`.
3. Add `compat-interop` to required checks alongside `go` (gh api PUT, record pre-state).
4. compat-drift.yml per design (never PR-gating).
5. Commit; PR; observe both checks green.

**Verify:** `gh pr checks → go: pass, compat-interop: pass`; `gh api .../protection | jq '.required_status_checks.contexts' → ["go","compat-interop"]`; manually `gh workflow run compat-drift.yml → both legs complete, T0 leg green`.
**Rollback:** required-checks PUT to recorded pre-state; revert merge commit.

---

## PR 5 — Ratchet + State + Stores

### Task 14: ratchet: chain/root/message keys

**Files:**
- Create: `ratchet/keys.go`, `ratchet/kdf.go` + tests
- Refs: `rust/protocol/src/ratchet/keys.rs` (MessageKeys derivation: HKDF info `"WhisperMessageKeys"`-class strings — extract EXACT bytes from source; chain key next = HMAC(ck, 0x02), message-key seed = HMAC(ck, 0x01) — extract exact constants), `rust/protocol/src/ratchet/params.rs`, `rust/protocol/src/kdf.rs` if present at fork HEAD

**Steps:**
1. Tests: derivations against `compat/vectors/hkdf.json` (already committed Task 12 — vector domains enumerated there must include chain-key step, root-key step w/ DH input, message-keys triple (cipherkey/mackey/iv), PQXDH secret derivation w/ kyber ss appended).
2. Implement. 3. Commit.

**Verify:** `go test ./ratchet/ -v → PASS, vector counts logged`.

### Task 15: session state: SessionRecord / SessionState

**Files:**
- Create: `session/state.go`, `session/record.go` + tests
- Refs: `rust/protocol/src/state/session.rs` (SessionStructure proto mapping, sender/receiver chains, skipped message keys, archive semantics: ARCHIVED_STATES_MAX_LENGTH 40 promote/demote), `rust/protocol/src/consts.rs`

**Steps:**
1. Tests: new→serialize→deserialize round-trip (proto-backed); chain add/get; skipped-key insert/take w/ caps (MAX_MESSAGE_KEYS 2000 eviction, MAX_RECEIVER_CHAINS 5); archive promotes current, drops >40; `pq_ratchet_state` bytes preserved opaque.
2. Implement over generated `proto.SessionStructure`. 3. Fuzz Deserialize. 4. Commit.

**Verify:** `go test ./session/ -v → PASS`.

### Task 16: stores: interfaces + in-memory

**Files:**
- Create: `stores/stores.go` (IdentityKeyStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore, SessionStore, SenderKeyStore — ctx-first methods, error returns), `stores/inmem/inmem.go` + tests
- Refs: `rust/protocol/src/storage/traits.rs` + `inmem.rs` (identity trust: first-use trust + direction (Sending/Receiving) semantics — port decision table)

**Steps:** 1. Tests incl. identity trust table (unknown→trusted, changed→untrusted, same→trusted). 2. Implement. 3. Commit.
**Verify:** `go test ./stores/... -v → PASS`.

---

## PR 6 — Sessions

### Task 17: session builder: PQXDH (v4) init + prekey bundles

**Files:**
- Create: `session/bundle.go` (PreKeyBundle), `session/builder.go` (alice: process bundle → initial session; bob: process PreKeySignalMessage → session) + tests
- Refs: `rust/protocol/src/pqxdh.rs` (secret = KDF(F ‖ DH1..DH4 ‖ kyber_ss, info — extract exact F=0xFF*32 discriminator + info string from source:118-260), `rust/protocol/src/session.rs` (process_prekey paths, signed-prekey sig verification, one-time prekey consumption), `ratchet.rs:60-160` alice/bob session init (minus spqr fields until P10 — `pq_ratchet_state` left empty; message `pq_ratchet` field absent = matches v0.91.1 `Version::V0`-negotiated behavior ?→ confirm in harness: v0.91.1 session WITHOUT spqr negotiation interops — cross-version-testing proves yes)

**Steps:**
1. Tests: alice+bob in-Go round-trip (bundle → alice session → PreKeySignalMessage → bob session → both derive same root/chain); signed-prekey bad sig rejected (`ErrInvalidSignature`); missing kyber prekey rejected (v4 requires); untrusted identity → `ErrUntrustedIdentity`.
2. Implement. 3. Commit.

**Verify:** `go test ./session/ -run Builder -v → PASS`.

### Task 18: session cipher: encrypt/decrypt

**Files:**
- Create: `session/cipher.go` + tests
- Refs: `rust/protocol/src/session_cipher.rs` (encrypt: chain step, AES-256-CBC w/ message keys, MAC; decrypt: try current+archived states clone-then-commit, skipped keys, MAX_FORWARD_JUMPS 25000, duplicate detection → `ErrDuplicateMessage`), `session_management.rs:60-100` (stale unacked session 30d → `ErrSessionNotFound` on encrypt)

**Steps:**
1. Tests: full in-Go conversation (init via Task 17, 50 msgs alternating); out-of-order delivery (skip 5, deliver later); cross-chain ratchet steps; duplicate rejected; forward-jump cap enforced; decrypt failure leaves stored session unmodified (assert store bytes unchanged after failed decrypt); stale-session encrypt error w/ injected clock.
2. Implement (clock injectable: `WithClock(func() time.Time)`).
3. Fuzz decrypt entry. 4. Commit.

**Verify:** `go test ./session/ -v → PASS`; `go test -fuzz=FuzzDecrypt -fuzztime=60s ./session/ → no crashes`.

### Task 19: session interop vs Rust harness

**Files:**
- Modify: `compat/rust-harness/src/main.rs` (add session RPC methods + `gen-vectors sessions` w/ deterministic transcript incl. v3-decrypt fixtures from upstream frozen test data), `compat/interop_test.go`, `compat/vectors/sessions.json`
- Coverage: Rust=Alice/Go=Bob and Go=Alice/Rust=Bob: PQXDH handshake → 20-message exchange w/ out-of-order + skipped; session persistence mid-conversation (Go serializes SessionRecord, reloads, continues — proves storage.proto structural compat); v3 SignalMessage decrypt vectors (Go decrypts upstream-generated v3 message given session state blob)

**Steps:** 1. Extend harness + regenerate vectors. 2. Go interop tests. 3. Commit; PR must show `compat-interop` green.
**Verify:** `COMPAT_HARNESS_BIN=... go test ./compat/ -tags=interop -run Session -v → PASS both role assignments`; explicit case (P6, discharges T17 `?`): v4 session w/ `pq_ratchet` absent + `pq_ratchet_state` empty interops both roles vs v0.91.1 harness; CI `compat-interop: pass`.

---

## PR 7 — Groups

### Task 20: sender key state + SKDM processing

**Files:**
- Create: `groups/state.go`, `groups/builder.go` + tests
- Refs: `rust/protocol/src/sender_keys.rs` (SenderKeyState proto, MAX_SENDER_KEY_STATES 5, chain iteration), distribution flow in `group_cipher.rs`

**Steps:** TDD: create distribution message → process on second participant → states match; state cap eviction; persistence round-trip.
**Verify:** `go test ./groups/ -v → PASS`.

### Task 21: group cipher + interop

**Files:**
- Create: `groups/cipher.go` + tests; Modify: harness (group RPCs + vectors), `compat/interop_test.go`
- Refs: `rust/protocol/src/group_cipher.rs` (encrypt w/ sender key sig, decrypt w/ skip handling, out-of-order caps)

**Steps:** 1. In-Go group of 3 fan-out tests + out-of-order + signature-tamper reject. 2. Interop: Rust distributes→Go encrypts→Rust decrypts and inverse. 3. Commit.
**Verify:** `go test ./groups/ -v → PASS`; interop `-run Group → PASS both directions`; CI green.

---

## PR 8 — Sealed Sender

### Task 22: internal/crypto/gcmsiv: AES-256-GCM-SIV

**Files:**
- Create: `internal/crypto/gcmsiv/{gcmsiv.go,polyval.go}` + tests
- Refs: RFC 8452; design §AES-256-GCM-SIV (constant-time POLYVAL: limb-based carry-less mult, no secret-indexed tables)

**Steps:**
1. **Reuse evaluation first (design requirement):** inspect Go stdlib internals + known pure-Go impls (e.g. mirror of `crypto/internal/fips140/aes/gcm` siv? — stdlib has no public GCM-SIV); if a vetted pure-Go lib exists w/ compatible license + maintenance, ADR + dep; else implement. Record outcome in commit message; expected outcome: implement (no vetted maintained pure-Go GCM-SIV known).
2. Tests: full RFC 8452 Appendix C vectors (AES-256 set, all cases) committed as testdata; wrong-key/tag failure cases.
3. Implement POLYVAL (uint64 limbs, `bits.Mul64`-based clmul emulation, constant-time) + key derivation + seal/open.
4. Fuzz open. Benchmark sanity (`go test -bench . → >50MB/s` informational).
5. Commit.

**Verify:** `go test ./internal/crypto/gcmsiv/ -v → PASS, RFC case count == appendix count`; fuzz 60s clean.

### Task 23: sealedsender: certificates + USMC

**Files:**
- Create: `sealedsender/certs.go`, `sealedsender/usmc.go` + tests
- Refs: `rust/protocol/src/sealed_sender.rs` (ServerCertificate/SenderCertificate: proto + trust-root sig chain validation + expiration; UnidentifiedSenderMessageContent: content-hint, group-id passthrough), `proto/sealed_sender.proto`

**Steps:** TDD: cert chain valid/invalid/expired cases (fixed test trust root); USMC round-trip.
**Verify:** `go test ./sealedsender/ -v → PASS`.

### Task 24: sealedsender: v1 + v2 encrypt/decrypt + interop

**Files:**
- Create: `sealedsender/v1.go`, `sealedsender/v2.go`, `sealedsender/decrypt.go` + tests; Modify: harness (seal/unseal RPCs + vectors)
- Refs: `rust/protocol/src/sealed_sender.rs` (v1: ephemeral keys + HKDF chain (extract exact salt/info layout) + AES-256-CTR+HMAC; v2: `Aes256GcmSiv` per lines ~11-12,1418, multi-recipient encoding (recipient KDF, M-keys), `sealed_sender_multi_recipient` wire format)

**Steps:** 1. In-Go round-trips v1+v2 (single + 3-recipient). 2. Tamper cases. 3. Interop both directions incl. multi-recipient fan-out. 4. Fuzz decrypt. 5. Commit.
**Verify:** `go test ./sealedsender/ -v → PASS`; interop `-run Sealed → PASS`; CI green.

---

## PR 9 — Fingerprints + Polish

### Task 25: fingerprint

**Files:**
- Create: `fingerprint/fingerprint.go` + tests; Modify: harness vectors (`fingerprint` domain done Task 11/12 — extend if gaps)
- Refs: `rust/protocol/src/fingerprint.rs` (numeric: 5200 iterations SHA-512 chain → 30-digit display; scannable: proto + version handling v1/v2 mismatch errors)

**Steps:** TDD against committed vectors (displayable string equality + scannable compare incl. version-mismatch error).
**Verify:** `go test ./fingerprint/ -v → PASS`.

### Task 26: API polish + scope matrix

**Files:**
- Modify: all packages: `doc.go` per package, error-taxonomy audit (every public error documented + `errors.Is`-able), examples (`example_test.go`: session round-trip, group, sealed sender)
- Modify: `README.md` (scope matrix: per-domain implemented/excluded table w/ compat stage; current claim = "compatible with libsignal v0.91.1 protocol surface")

**Steps:** 1. `go vet ./... && golangci-lint run` full-tree clean (not just new-from-rev). 2. Examples compile+run as tests. 3. `go doc` renders sanely. 4. Commit.
**Verify:** `go test ./... → PASS incl. Example tests`; `golangci-lint run → exit 0` full tree.

---

## PR 10 — SPQR + Mainline Re-pin

### Task 27: spqr: core sparse PQ ratchet

**Files:**
- Create: `spqr/` (state machine, chunked ML-KEM key transport, epoch/erasure encoding per upstream crate) + tests
- Refs: clone `signalapp/SparsePostQuantumRatchet` tag v1.5.1 (reference source of truth; vendor its test vectors if present), `rust/protocol/src/state/session.rs:640-670` (spqr send/recv mixing points)
- Note: largest single task; implementer reads spqr crate fully first; sub-commits allowed (state codec → KEM chunking → send/recv machine)

**Steps (3 verified slices — P8):**
1. Slice A: state codec (serialization round-trips vs upstream-generated state blobs). Verify: `go test ./spqr/ -run Codec -v → PASS`. Commit.
2. Slice B: ML-KEM chunked key transport (chunk/reassemble + KEM epoch handling, ported tests). Verify: `go test ./spqr/ -run Chunk -v → PASS`. Commit.
3. Slice C: send/recv state machine (full ported upstream suite green). Verify: `go test ./spqr/ -v → PASS`. Commit.
4. Fuzz state decode. Commit.

### Task 28: session integration: triple ratchet

**Files:**
- Modify: `session/builder.go`, `session/cipher.go`, `ratchet/` (mix spqr send/recv keys into message keys per `state/session.rs:647-664`; populate `pq_ratchet` message field + `pq_ratchet_state`), `protocol/version.go` if version gating changes
- Modify (P11): `compat/rust-harness/src/main.rs` + `compat/interop_test.go` — expose T0-era SPQR-negotiation flag (`UsePQRatchet` param) in init-session RPCs (T19 built them spqr-off)
- Refs: `rust/protocol/src/triple_ratchet.rs`, `ratchet.rs:60-160` (spqr params, `min_version` negotiation)

**Steps:** 1. In-Go tests: session w/ SPQR negotiated end-to-end; downgrade/mixed-version behavior per upstream semantics. 2. SPQR interop vs EXISTING T0 pin (P8): v0.91.1 ships spqr w/ `min_version: V0` — negotiate-up sessions Rust↔Go both roles against un-bumped harness, isolating port bugs from re-pin fallout. 3. Commit.
**Verify:** `go test ./session/ ./spqr/ -v → PASS`; interop `-run SpqrSession → PASS both roles at v0.91.1 pin`.

### Task 29: re-pin harness to latest upstream tag + full revalidation

**Files:**
- Modify: `compat/rust-harness/Cargo.toml` (tag v0.91.1 → Stage-2 target), `compat/rust-harness/rust-toolchain.toml` (match new pin's toolchain — P3), regenerate ALL `compat/vectors/*.json`, README compat claim → current-mainline, drift workflow → full-domain main leg enabled

**Stage-2 target selection rule (P3):** default candidate = `v0.96.0` (latest upstream release at plan-lock, 2026-06-12). At execution: (a) take newest tag then; (b) review drift main-leg history + diff candidate's protocol surface vs Scope Manifest; (c) if surface exceeds manifest (e.g. SPQR v2, ML-KEM activation, new wire fields) → record ADR choosing newest in-scope tag OR explicit scope-lock amendment; (d) update harness toolchain file to candidate's.

**Steps:** 1. Apply selection rule; tag bump; `cargo build`. 2. Regenerate every vector domain; `go test ./compat/ → PASS`. 3. Full interop suite (sessions+groups+sealed+spqr) both roles. 4. README + drift update — full-domain main leg = main harness git-dep repointed to `branch="main"`; compile failure on that leg IS the drift signal (informational, never gating; P12). 5. Commit.
**Verify:** `gh pr checks → go: pass, compat-interop: pass` at NEW pin; vector regen diff committed; interop log shows spqr-negotiated sessions both roles.
**Rollback:** revert merge → returns to v0.91.1 pin + Stage 1 claim (ADR 0001 documented path).

---

## PR 11 — Cleanup

### Task 30: remove reference trees + final docs + v0.1.0

**Files:**
- Delete: `rust/ Cargo.toml Cargo.lock rust-toolchain` + final cruft sweep of remaining non-Go-relevant files (P5: enumerate by `ls -a` at execution; no phantom paths — `git rm` each verified-existing)
- Modify: `README.md` (final), `docs/design-guidance.md` change-log row, retro via `autodev:post-merge-retrospective`

**Steps:**
1. Verify zero references: `grep -rn "rust/" --include="*.go" . → empty` AND `grep -rn "rust-toolchain\|Cargo.toml\|rust/" .github/ docs/ README.md → only repo-history/design-doc mentions` (P5 — catches workflow steps assuming deleted root files; compat/rust-harness{,-drift} stay — they pin upstream remotely, not in-tree, and own their toolchain files).
2. Delete; full CI green (compat unaffected — harness uses remote).
3. Tag `v0.1.0` post-merge: `git tag v0.1.0 && git push origin v0.1.0`.
4. Retro per `autodev:post-merge-retrospective`.

**Verify:** `gh pr checks → all pass`; `go test ./... → PASS`; `gh release view v0.1.0 || git ls-remote --tags origin | grep v0.1.0 → present`.
**Rollback:** revert merge restores reference tree (history preserves it regardless).

---

## Guidance → task mapping

| guidance | tasks |
|---|---|
| pure Go ⊥ cgo | T2 CI `CGO_ENABLED=0`; dep set fixed (T3-T7) |
| Go 1.26.4 | T2 |
| compat contracts as required PR check | T11-T13 (gate live from PR 4); T19/T21/T24/T29 extend |
| constant-time discipline | T3-T5, T22 (POLYVAL); review-by-inspection notes in code |
| no panics public API + fuzz | every deserialization task has fuzz step |
| commits codingsloth@pm.me | repo git config (done pre-plan) |
| doc currency | every PR step list ends w/ README status update (Conventions) |
| staged compat claim (ADR 0001) | T13 (drift two-pin), T26 (matrix), T29 (re-pin) |
