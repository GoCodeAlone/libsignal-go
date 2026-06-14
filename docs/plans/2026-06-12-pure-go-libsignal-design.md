# Design: Pure Go Signal Protocol (libsignal-go)

**Date:** 2026-06-12 (rev 3.1 — adversarial review converged PASS at cycle 3; Minor D13-D15 applied)
**Status:** Approved (owner pre-authorized autonomous execution in kickoff directive)
**Guidance:** `docs/design-guidance.md`
**Review:** `docs/plans/2026-06-12-pure-go-libsignal-design-review.md`
**ADR:** `decisions/0001-spqr-staged-compat.md`

## Goal

Replace `GoCodeAlone/libsignal-go` fork contents with a pure Go (no cgo/C/Rust)
implementation of the Signal client protocol core, wire-compatible with
`signalapp/libsignal` mainline, with cross-implementation compat contracts as a
required PR check. Module: `github.com/GoCodeAlone/libsignal-go`. Go 1.26.4 via
`toolchain` directive.

## Scope

In-scope (mirrors `rust/protocol` + minimal `rust/core` + `rust/crypto`):

| domain | upstream ref | content |
|---|---|---|
| core types | `rust/core/src/{address,curve}.rs` | ServiceId (ACI/PNI), ProtocolAddress, DeviceId, key wire encoding (type byte 0x05 djb) |
| crypto prims | `rust/crypto/src`, `rust/protocol/src/crypto.rs` | AES-256-CBC+PKCS7, AES-256-CTR, AES-256-GCM, AES-256-GCM-SIV (RFC 8452 — see dedicated section), HKDF-SHA256, HMAC-SHA256 |
| curve | `rust/protocol/src/identity_key.rs`, curve25519-dalek usage | X25519 ECDH, XEd25519 sign/verify (signal XEdDSA spec) |
| kem | `rust/protocol/src/kem/` | Kyber1024 (round-3, wire type 0x08); ML-KEM-1024 (wire 0x0A, `kem.rs:219`) ready but inactive |
| wire messages | `proto/wire.proto`, `proto/service.proto`, `protocol.rs` | SignalMessage (v3 decrypt / v4, incl. `pq_ratchet=5` field parse from day one), PreKeySignalMessage, SenderKeyMessage, SenderKeyDistributionMessage, PlaintextContent + DecryptionErrorMessage (`service.proto:9-24`); MAC trailer scheme |
| ratchet | `ratchet/`, `double_ratchet.rs` | root/chain/message keys, KDF info strings, PQXDH (v4) alice/bob init; v3 = decrypt/session-state compat ONLY (upstream init is PQXDH-only: `pqxdh.rs:118,249`, v3 = decrypt floor `protocol.rs:21`) |
| session | `session_cipher` paths, `state/` | SessionRecord (storage.proto port incl. `pq_ratchet_state=15`), encrypt/decrypt, skipped keys (MAX_MESSAGE_KEYS 2000, MAX_FORWARD_JUMPS 25000, MAX_RECEIVER_CHAINS 5, ARCHIVED_STATES_MAX_LENGTH 40), MAX_UNACKNOWLEDGED_SESSION_AGE 30d (stale unacked session → SessionNotFound on encrypt, `session_management.rs:82`), archive/promote |
| stores | `storage/` | IdentityKeyStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore, SessionStore, SenderKeyStore interfaces + in-memory impls |
| groups | `group_cipher.rs`, `sender_keys.rs` | sender key create/process/encrypt/decrypt, MAX_SENDER_KEY_STATES 5 |
| sealed sender | `sealed_sender.rs`, `proto/sealed_sender.proto` | ServerCertificate, SenderCertificate, USMC, SSv1 (Curve+HKDF+CTR+HMAC), SSv2 (X25519+AES-GCM-SIV multi-recipient) |
| fingerprint | `fingerprint.rs`, `proto/fingerprint.proto` | numeric + scannable fingerprints (5200 iterations, v1/v2) |
| **SPQR** | `spqr` crate (signalapp/SparsePostQuantumRatchet v1.5.1), `triple_ratchet.rs`, `session.rs` spqr mixing | sparse PQ ratchet: mandatory at upstream HEAD (`ratchet.rs:87,150` `min_version: spqr::Version::V1`); staged as final protocol phase — see Compat Staging |

Out of scope (per guidance non-goals): zkgroup/zkcredential/poksho, usernames,
keytrans, SVR/svrb, account-keys, device-transfer, media, message-backup, net,
bridges (java/swift/node), `incremental_mac`, HPKE,
`session_cipher_legacy` (test-only upstream: `#![cfg(test)]`, excluded),
X3DH v3 session *initiation* (dead upstream; v3 decrypt/state compat retained).

## Approaches Considered

| # | approach | verdict |
|---|---|---|
| A | mirror Rust crate layout 1:1 in Go | ⊥ rejected: un-idiomatic, fights Go module conventions, no compat benefit (compat = wire, not source) |
| B | idiomatic Go domain packages, behavior traced to Rust src + signal.org specs, compat harness as ground truth | ✅ chosen |
| C | adopt/upgrade existing Go port (e.g. crossle/libsignal-protocol-go) | ⊥ rejected: stale (v3-only, no PQXDH/Kyber, no sealed sender v2), license/quality unknown, contradicts "build in this fork" directive |
| D | interop peer = upstream prebuilt npm/jar artifact instead of cargo-built harness | considered (review option 2): kills cargo/nightly CI risk but binding API hides deterministic-RNG injection needed for vectors & restricts protocol-level control ∴ rejected; cargo harness w/ A2 fallback retained |

## Compat Staging (SPQR decision — ADR 0001)

Upstream HEAD requires SPQR for all new sessions (D1). Staged plan:

- **Stage 1 (P4-P9):** compat harness pinned to upstream tag `T0 = v0.91.0` —
  last release before `cf9a7445c` "Force SPQR v1" (2026-04-03) flipped
  `min_version` V0→V1; SPQR-optional window ran from integration commit
  `b7b8040e3` (2025-06-04). No bisect needed (review cycle 2, D10). Upstream's
  own `rust/protocol/cross-version-testing/` proves the consumption pattern:
  cargo git-dep on a workspace member by tag
  (`libsignal-protocol-v91 = { git = "https://github.com/signalapp/libsignal", tag = "v0.91.0", package = "libsignal-protocol" }`
  + local `[workspace] members = ["."]` stanza) — A2/A9 are near-facts, not
  assumptions. Note: this fork clone has no upstream tags; harness CI fetches
  tags from the signalapp remote. Compat claim = "compatible with libsignal
  `v0.91.0` protocol surface". Go wire/storage protos carry
  `pq_ratchet`/`pq_ratchet_state` fields from day one (parse + preserve, not
  produce).
- **Stage 2 (P10):** port SPQR v1.5.1 (separately versioned spec + Rust
  reference) → re-pin harness to latest upstream tag (one-line tag bump) →
  **regenerate ALL committed vectors at the new pin + full interop suite
  (sessions, groups, sealed sender) green both roles** before merge. P10
  depends on P7,P8,P9 so re-pin cannot land while domain coverage is missing
  or change the required check under in-flight PRs (D9). Only after P10 may
  README claim current-mainline compat.

## Package Layout (chosen)

```
github.com/GoCodeAlone/libsignal-go
├── address/          ServiceId, ProtocolAddress, DeviceId
├── curve/            X25519 keypair, XEd25519 sign/verify, key serialization
├── kem/              Kyber1024 (wraps circl), serialized form, KeyType registry
├── internal/crypto/  aescbc, aesctr, gcmsiv (RFC 8452 impl), hkdf helpers
├── protocol/         wire messages, MAC scheme, versions (v3 decrypt, v4)
├── ratchet/          root/chain/message keys, KDF, alice/bob params + init
├── session/          SessionRecord/SessionState (storage.proto), builder (PQXDH), cipher
├── spqr/             sparse PQ ratchet (P10)
├── stores/           store interfaces; stores/inmem reference impls
├── groups/           sender keys, group cipher
├── sealedsender/     certs, USMC, v1+v2 encrypt/decrypt
├── fingerprint/      numeric/scannable
├── proto/            generated protobuf (google.golang.org/protobuf)
└── compat/           cross-impl contract harness (see below)
```

## Dependencies (all pure Go)

| dep | use | note |
|---|---|---|
| stdlib `crypto/*` | AES, SHA-256, HMAC, rand, `crypto/hkdf` (verified present in Go 1.26) | |
| `filippo.io/edwards25519` | XEdDSA point/scalar ops (exports field arithmetic for mont↔ed) | maintained by Go crypto lead |
| `golang.org/x/crypto` | curve25519 | |
| `github.com/cloudflare/circl` | Kyber1024 round-3 (incl. derandomized API for KATs) | matches upstream `libcrux-ml-kem` "kyber" feature; verification: see Compat layer 1 |
| `google.golang.org/protobuf` | wire/storage proto | |

⊥ cgo anywhere; CI enforces `CGO_ENABLED=0`.

## AES-256-GCM-SIV (self-implemented — riskiest crypto surface, D4)

- First: evaluate vetted pure-Go ports (Go stdlib internal GCM-SIV-adjacent
  code, BoringSSL-derived `gcm_generic`-style POLYVAL) for reuse before
  writing from scratch ?→ plan task.
- POLYVAL: constant-time limb-based carry-less multiplication; no
  table-lookup-by-secret-index, no secret-dependent branches.
- KATs: full RFC 8452 Appendix C vector suite + upstream-generated SSv2
  envelope vectors.
- Fuzz: `go test -fuzz` on open/seal boundary.
- Lands in P8 with sealed sender (sole consumer); not on critical path of
  earlier phases.

## Compat Contract Strategy (core requirement)

Two layers, both wired into PR checks:

1. **Committed vectors** (`compat/vectors/*.json`): generated by Rust harness
   (`compat/rust-harness/`, cargo crate pinned per Compat Staging). Cover:
   curve sign/verify, ECDH, KEM (key-format fixtures `kem/test-data/{pk,sk}.dat`
   + round-3 Kyber1024 NIST KATs via circl derandomized API + Rust-generated
   deterministic decapsulation (pk, ct, ss) triples — encaps is randomized,
   decaps is not; D3), HKDF info-string derivations, message
   serialize/deserialize+MAC, session init (deterministic RNG), full ratchet
   transcripts, sealed-sender certs+envelopes, fingerprints. Go tests consume
   vectors → fast, hermetic, runs in main `go test` job.
2. **Live interop harness** (required PR check `compat-interop`): CI builds Rust
   harness binary (cargo cache; toolchain resolved by running cargo via rustup
   inside the upstream checkout — rustup honors both `rust-toolchain` (actual
   filename at fork HEAD) and `rust-toolchain.toml` (D8, D13)), Go test drives it via
   stdin/stdout JSON-RPC: Rust↔Go both director roles (Rust=Alice/Go=Bob and
   inverse) for PQXDH handshake → N-message double-ratchet exchange w/
   out-of-order + skipped keys, group sender-key fan-out, sealed-sender v1/v2
   round trips. Post-P10: + SPQR.

Determinism: all key-generation paths accept injected `io.Reader` RNG; Rust
harness uses seeded ChaCha RNG (`rand_chacha`) w/ seed in vector header so both
sides reproduce identical keys.

Drift watch (two-pin, stage-aware — D11): weekly workflow runs harness against
**both** pins: (a) `T0` — must stay green; failure = harness rot, real alarm;
(b) upstream `main` — informational only during Stage 1, restricted to
version-stable domains (curve/HKDF/wire constants/KEM KATs) since session-init
API diverged post-T0 (`usePqRatchet` removal etc.); full-domain `main` drift
enabled post-P10. Issue filing dedupes on open issue (no weekly false-alarm
stream). Toolchain resolved via rustup per checkout (honors `rust-toolchain` and
`rust-toolchain.toml`; D13). Never a PR
gate.

## Phasing (PR-per-phase; plan will detail tasks)

| ph | content | depends |
|---|---|---|
| P1 | scaffold: go.mod (1.26.4), CI (`go.yml`: build/test/lint, CGO_ENABLED=0, gofmt, golangci-lint); workflow retirement — exact: delete `android_integration.yml, ios_artifacts.yml, jni_artifacts.yml, npm.yml, build_and_test.yml, lints.yml, slow_tests.yml, check_versions.yml, docs.yml, release_notes.yml` (keep `stale.yml`); **same PR: audit + update branch-protection required checks via `gh api`** (D7); cruft purge round 1 (owner directive 2026-06-12): delete `java/ swift/ node/ bin/ acknowledgments/ doc/` + bridge/tooling dotfiles (`.cargo .cbindgen-version .clippy.toml .dockerignore .nvmrc .prettierrc.js .rustfmt.toml .swift-format .taplo* .flake8 .tool-versions LibSignalClient.podspec justfile RELEASE*.md TESTING.md CODING_GUIDELINES.md`); keep `rust/ Cargo.toml Cargo.lock rust-toolchain` as behavioral reference until P11; README rewrite (Go project identity, staged-compat status section); LICENSE retained (AGPL-3.0) | — |
| P2 | internal/crypto (CBC/CTR/GCM/HKDF helpers) + curve (X25519, XEdDSA) + address: KATs (RFC + upstream-traced) | P1 |
| P3 | kem (Kyber1024: circl wrap, key-format fixtures + NIST round-3 KATs) + proto codegen (wire/service/storage/sealed_sender/fingerprint .proto) + wire messages; tests = public KATs + structural round-trip only — upstream-generated vectors arrive in P4 (D12) | P2 |
| P4 | compat rust-harness (pin tag T0=v0.91.0, cross-version-testing pattern) + vector generation incl. message serialization + KEM decaps triples (closes A1) + `compat-interop` CI job (required check from here on) + two-pin drift workflow | P3 |
| P5 | ratchet + session state/record + stores | P3 |
| P6 | session builder (PQXDH) + session cipher + interop transcripts (v3 decrypt-compat vectors included) | P4,P5 |
| P7 | groups/sender keys + interop | P6 |
| P8 | sealed sender v1/v2 + gcmsiv + interop | P6 |
| P9 | fingerprint + API polish (errors, doc.go, examples) + README scope matrix; doc-currency rule: every phase PR updates README status section (owner directive) | P6 |
| P10 | SPQR port (spqr v1.5.1) + re-pin harness latest upstream tag + regenerate all vectors + full interop suite (sessions/groups/sealed-sender) both roles at new pin | P7,P8,P9 |
| P11 | cleanup: delete rust/java/swift/node trees + remaining legacy files, retro, tag v0.1.0 | P7,P8,P9,P10 |

PR rule: merge when CI green & no unresolved Copilot comments; admin merge
permitted (owner directive). Commits authored `codingsloth@pm.me`.
Doc-currency rule (owner directive, applies P1 onward): every phase PR updates
README status section + any docs invalidated by the change (D15).

## Error Handling

- Sentinel + typed errors per domain (`protocol.ErrInvalidMessage`,
  `session.ErrNoSession`, `session.ErrUntrustedIdentity`,
  `session.ErrDuplicateMessage`, ...) mirroring `error.rs` taxonomy where it
  affects caller behavior; incl. SessionNotFound on stale unacked session (D6).
- No panics across public API; fuzz targets (`go test -fuzz`) on all
  deserialization entry points.
- Decrypt failures return error w/o mutating session state (match upstream
  clone-then-commit semantics).

## Security Review

- Secrets: constant-time compares via `crypto/subtle` (MAC checks, identity
  compares); no secret-dependent branches in XEdDSA/ratchet KDF paths;
  edwards25519/circl/x-crypto are constant-time impls; self-implemented
  GCM-SIV constant-time strategy specified above (D4).
- Key material zeroization: Go GC limits guarantees; document non-goal (same
  posture as other Go crypto libs); avoid fmt/log of key types (`String()`
  redacts).
- RNG: `crypto/rand` default; injected reader only via explicit
  `...WithRNG`/params — deterministic paths land only in compat/test code,
  public API defaults safe.
- Dependency trust: 4 deps, all widely-vetted pure Go; `go.sum` pinned;
  dependabot on.
- Abuse cases: malformed wire input → fuzzed deserializers; MAC-before-decrypt
  order preserved; skipped-key caps enforce DoS bounds.
- License: AGPL-3.0-only retained (fork obligation); file headers updated.

## Infrastructure Impact

- GitHub Actions only. New: `go.yml`, `compat.yml` (vectors + interop, cargo
  cache, toolchain via rustup per checkout — D13), weekly
  `compat-drift.yml`. Removed in P1 (exact list in phasing table). Branch
  protection: required-check audit/update happens atomically with P1 workflow
  removal via `gh api`, re-updated in P4 when `compat-interop` exists (D7).
- No deployed services, no secrets beyond `GITHUB_TOKEN`.

## Multi-Component Validation

- Real-boundary proof = live interop harness (Rust binary ↔ Go tests, both
  roles, full protocol flows) — not mock-only. Gate from P4 onward. Stage 1
  vs tag T0; Stage 2 (post-P10) vs latest upstream tag.
- Session persistence proof: serialize SessionRecord mid-conversation →
  reload → continue ratchet (storage.proto structural compat).

## Assumptions

| id | assumption | challenge | fallback |
|---|---|---|---|
| A1 | circl Kyber1024 == upstream libcrux round-3 Kyber wire/KAT-compatible | KATs/decaps-triples fail | implement Kyber1024 from round-3 spec in-repo, or vendor+patch |
| A2 | ~~upstream git tag buildable as cargo git-dep~~ verified: upstream `rust/protocol/cross-version-testing/` uses exactly this pattern | — | vendored checkout fallback retained |
| A3 | ~~crypto/hkdf availability~~ verified present in Go 1.26 | — | — |
| A4 | wire compat sufficient; bit-exact storage blobs not externally required | hidden cross-device migration use | storage.proto schema ported (P5) → structurally compatible |
| A5 | CI minutes acceptable for Rust harness build (~5-10 min cached) | quota exhausted | prebuilt harness binary as GH release artifact, CI downloads |
| A6 | ~~owner approval to delete~~ confirmed explicitly 2026-06-12: full reorg/delete authority, "no cruft", docs+README kept current | — | deletions still isolated to P1/P11 PRs → git revert |
| A7 | XEdDSA implementable w/ filippo.io/edwards25519 public API | API gap | edwards25519 exports field arithmetic (verified); worst case internal/ed field ops |
| A8 | Copilot review available on repo PRs | not enabled | request via gh API; if unavailable, merge gate = CI green only (merge authority already granted) |
| A9 | ~~T0 identifiable~~ verified: T0 = v0.91.1 (last pre-`cf9a7445c` "Force SPQR v1" release; V0 window 2025-06-04→2026-04-03; upstream `tests/prespqr.rs` confirms both halves) | — | commit-pin fallback retained |
| A10 | SPQR v1.5.1 spec+Rust source sufficient to port pure Go | underspecified internals | port from spqr crate source directly (it is the reference) |

## Top Doubts (self-challenge, rev 3)

1. **SPQR port size (A10/P10)** — sparse PQ ratchet w/ ML-KEM internals is the
   largest single phase; staged pinning keeps it off the critical path of
   P5-P9 but mainline-compat claim waits on it.
2. **Harness consumability (A2/A9)** — cargo git-dep of workspace member at an
   older tag T0 may fight feature/version pins; fallback vendored checkout is
   mechanical.
3. **Scope honesty** — "100% compatible" = implemented protocol core at pinned
   stage; README scope matrix (P9) + staged compat claim (ADR 0001) make the
   claim falsifiable per-domain & per-stage.

## Rollback

Library + CI only; no runtime deploys. Every phase = standalone PR → rollback =
`git revert` of merge commit. Required-check changes (P1, P4) revertible via gh
api branch-protection update. Tree deletions deferred to final PR (P11) so
reference stays available throughout development.

## Global Design Guidance

Source: `docs/design-guidance.md`

| guidance | design response |
|---|---|
| pure Go, ⊥ cgo/FFI | dep table all-pure-Go; CI `CGO_ENABLED=0` |
| Go 1.26.4 | go.mod `toolchain go1.26.4` |
| wire compat w/ mainline = hard req, PR check | two-layer compat strategy; `compat-interop` required check; staged to true-mainline via P10 (ADR 0001) |
| protocol core first, zk/etc non-goals | scope table excludes them; SPQR added (mandatory for mainline compat, guidance Evolution Trigger "new PQ ratchet revisions → extend scope") |
| constant-time discipline | security review + GCM-SIV section |
| commits codingsloth@pm.me | repo-local git config (done) |
| PR flow, green+Copilot → admin merge | phasing PR rule |

### Backport 2026-06-12: curve validity checks fold into T5

Cause: upstream `rust/core/src/curve.rs` exposes `is_torsion_free()` +
`scalar_is_in_range()` public-key validity checks (4 dedicated upstream tests);
neither T4 nor T5 task text named them (spec-review gap finding, T4 cycle).
Change: T5 contract clarified to include both checks + the 4 ported upstream
tests (`honest_keys_are_torsion_free`, `tweaked_keys_are_not_torsion_free`,
`keys_with_the_high_bit_set_are_out_of_range`,
`keys_above_the_prime_modulus_are_out_of_range`). Natural home: same curve/
pkg, same `filippo.io/edwards25519` dep.
Scope: no manifest change (no task added/dropped; PR grouping unchanged —
content clarification of existing T5 within the design's curve-domain row).
Evidence: spec-reviewer + code-reviewer concur the checks belong to no task as
written; security-relevant (malicious peer-key rejection).

### Backport 2026-06-12: T0 tag erratum — v0.91.1 does not exist; T0 = v0.91.0

Cause: design/ADR recorded T0 as "v0.91.1" from `cf9a7445c`'s podspec bump
(0.91.1→0.92.0); 0.91.1 was an untagged in-dev version. Upstream tags jump
v0.91.0 → v0.92.0 (verified `git ls-remote --tags`).
Change: T0 = `v0.91.0`. Verified empirically: at v0.91.0,
`ratchet.rs` sets `min_version: spqr::Version::V0` (SPQR optional, pre-SPQR
interop works); at v0.92.0 it is V1 (required). Harness pin, doc.go, README
references use v0.91.0.
Scope: no manifest change (manifest does not name the tag; T29's Stage-2
selection rule unaffected).
Evidence: curl of `ratchet.rs` at both tags → V0 vs V1 (lead-verified);
`cargo fetch` failure on v0.91.1 (implementer-2).

### Backport 2026-06-12: SessionStore interface lives in session/ (import-cycle fix)

Cause: design package layout put all six store interfaces in stores/ while
SessionStore's signature references *session.SessionRecord — stores/ imports
session/, so session/builder.go (T17) importing stores/ = import cycle
(discovered at T17 implementation; `go build` rejects).
Change: SessionStore interface moves into session/ (as session.Store); the
other five interfaces stay in stores/ (none reference session types —
SenderKeyStore uses the accepted opaque []byte record). stores/ becomes a
leaf package; stores/inmem keeps all impls (impl package may import both).
Scope: no manifest change (no task/PR change; package-layout clarification
within the design's stores/session rows).
Evidence: `go build ./session/` import-cycle error with the literal layout;
Go idiom (consumer-side interface placement) resolves without adapters.

### Backport 2026-06-13: T19 v3 decrypt-fixture descope (upstream-generated)

Cause: T19 item 3 planned "Go decrypts upstream-generated v3 SignalMessage given
session state." Evidence (implementer-2, verified): v0.91.0 cannot PRODUCE a v3
session or v3 message — X3DH fully removed: SessionState::new only ever passes
v4 (ratchet.rs:98,161); decrypt actively rejects v3 prekey messages
("X3DH no longer supported", session.rs:107-115); session_cipher_legacy is a
private mod. So no upstream v0.91.0 harness can emit a v3 fixture.
Change: descope the UPSTREAM-GENERATED v3 decrypt fixture from T19 (lead call
per T19's own STOP-condition). Go's v3 SignalMessage DESERIALIZE capability
(version floor =3, built in T9) is retained and unit-tested Go-side; only the
cross-impl upstream fixture is dropped, documented in compat/README.md + the
sessions vector doc. v3 decrypt-compat against a pre-v0.91.0 tag is a future
item if ever needed.
Scope: no manifest change (T19 stays one task in PR6; only one verification
sub-item's source changes — upstream-fixture → Go-unit-test). Matches design's
"v3 = decrypt/state compat ONLY" scope row.
Evidence: pqxdh.rs / ratchet.rs:98,161 / session.rs:107-115 / lib.rs:43 (cited).

### Backport 2026-06-13: SPQR KEM = incremental ML-KEM-768 (pure-Go port; circl insufficient)

Cause: design/plan assumed circl supplies SPQR's KEM ("ML-KEM-1024 via circl").
False on both counts (verified vs SPQR v1.5.1 cargo f2589fe): SPQR uses ML-KEM-
**768** via libcrux's **incremental** API (chunked encaps-key header/pk2 split,
encapsulate1/2, decapsulate_compressed_key, custom encaps-state byte layout).
circl v1.6.3 has only monolithic standard ML-KEM-768 — cannot produce/consume
SPQR's state-blob bytes; cgo to libcrux is forbidden.
Change: T27 ports incremental ML-KEM-768 to pure Go (fork circl mlkem768 +
incremental/chunked layer + encaps-state codec, KAT'd vs the libcrux reference)
as its first slice, ahead of the SPQR codec/state-machine slices. SPQR not
deferred (owner ruling). Recorded in ADR 0002.
Scope: owner-approved amendment; T27 content expands; PR count 11 / task count
30 unchanged (T27 still ships in PR 10). See decisions/0002-incremental-mlkem768-pure-go.md.
Evidence: SPQR Cargo.toml libcrux-ml-kem features incremental+mlkem768;
src/incremental_mlkem768.rs; circl grep incremental→0 (implementer-2, lead-relayed).

### Backport 2026-06-13: SPQR KEM path resolved by spike — STANDALONE FIPS-203

Cause: ADR 0002 preferred forking circl's mlkem768; the Slice-0 design spike
disproved it. circl mlkem768 is ROUND-3 Kyber (wrong version — byte-incompatible
with libcrux's FIPS-203-final); Go 1.26 stdlib `crypto/mlkem` IS FIPS-203-final
ML-KEM-768 but its real internals (crypto/internal/fips140/mlkem) are
import-locked (monolithic public API only). Neither is a usable BASE.
Change: T27 Slice 0 = STANDALONE pure-Go ML-KEM-768 PKE (field/NTT/sampling/
compress/serialize) modeled on stdlib's fips140/mlkem source (FIPS-203-correct,
BSD — carry Go copyright attribution) + libcrux 0.0.8 incremental split layered
on top. Dual-oracle acceptance: stdlib crypto/mlkem (end-to-end correctness) +
a Rust KAT harness over libcrux 0.0.8 (byte-exact incremental vectors, incl.
issue-1275 bad-encoding). This is the explicit fallback ADR 0002 named; owner's
"write a chunked/incremental implementation" authorizes it. Slice 0 split into
0a (PKE/KEM core) + 0b (incremental layer), each its own reviewed unit.
Scope: within ADR 0002's approved amendment; manifest count/grouping unchanged.
Evidence: spike (implementer-2) — ek=1184B(1152 t̂‖32 ρ), pk2==t̂(1152), hdr/pk1==ρ+hash(64); stdlib API exposes no matrix/NTT/PKE; circl internals are round-3.

### Backport 2026-06-14: v0.91.0 PRODUCES SPQR; session interop verified in T28

Cause: the T0=v0.91.0 erratum (2026-06-12, above) framed v0.91.0 as "SPQR
optional, pre-SPQR interop works", and the T28 plan/ADR-0001 framing implied
v0.91.0 was effectively pre-SPQR (interop deferred to T29). Building T28's
interop slice required resolving this against the cargo checkout.
Change: v0.91.0 DOES produce SPQR. Its Cargo.lock pins spqr v1.5.1 rev f2589fe
(the T27 crate); `initialize_{alice,bob}_session` call `spqr::initial_state(V1,
min_version V0)` UNCONDITIONALLY, and `process_prekey_bundle` has NO
`UsePQRatchet` flag at this tag (added in a later version). So every v0.91.0 v4
SignalMessage carries a NON-EMPTY pq_ratchet field; `min_version V0` only means
a V0-only peer can negotiate down (fall back), NOT that the field is absent.
Therefore SPQR Rust↔Go session interop is testable NOW and STAYS IN T28 (assert
pq_ratchet on the wire both directions); T29's re-pin to v0.96.0 is purely
currency, not SPQR's existence.
Scope: no manifest change (T28 still = session integration + interop; the plan's
"expose UsePQRatchet in the harness" is satisfied by asserting the unconditional
SPQR the harness already emits, since no such flag exists at v0.91.0). See
decisions/0004-spqr-session-interop-in-t28.md.
Evidence: cargo checkout HEAD 8418be45 (v0.91.0), Cargo.lock spqr=v1.5.1/f2589fe
(implementer-1, lead-verified); `go test -tags=interop ./compat -run
TestSessionInterop` PASS with non-empty pq_ratchet asserted both roles.
