# Adversarial Review — Pure Go libsignal Implementation Plan

## Cycle 1

### Adversarial Review Report
**Phase:** plan
**Artifact:** docs/plans/2026-06-12-pure-go-libsignal.md
**Status:** FAIL (3 tangible Important; all small targeted edits)

**Evidence:** ~20 rust/ tree spot-checks all true (wire.proto:15, storage.proto:66, consts, version-byte formula protocol.rs:106/375, chain/message seeds 0x02/0x01 ratchet/keys.rs:108/148-149, cross-version-testing pattern, kem test-data, bare rust-toolchain, fingerprint 5200, spqr v1.5.1). Misses: `rust-segments` phantom (P5), `kdf.rs` correctly hedged. Scope Manifest arithmetic verified (30 tasks = 2+4+4+3+3+3+2+3+2+3+1; 11 rows).

**Findings (Important):**
- `P1` [hidden serial dependency] [T11/T12 vs T14]: hkdf vector content enumeration (chain-key, root-key w/ DH, message-keys triple, PQXDH secret) lived only in T14 (PR 5) as retroactive parenthetical; T11 said merely "info-string derivations" (literal reading excludes PQXDH secret: 4×DH+ss IKM); T12 verified only case counts. Fix: enumerate in T11 step 2 + jq sub-domain assertion in T12 verify. _Resolution: applied._
- `P2` [missing failure mode] [T13 drift]: one harness crate against two divergent API pins cannot compile on `main` leg once T19 adds v0.91.1-API session RPCs → drift permanently red from PR 6. Fix: separate `compat/rust-harness-drift/` micro-crate (version-stable generators only, no session API), repointable to main; T19/T21/T24 extend only T0-pinned harness. _Resolution: applied (option 1)._
- `P3` [unpinned moving target] [T29]: "latest upstream release tag at execution time" = unbounded forward reference in locked plan; harness rust-toolchain.toml update also omitted. Fix: default candidate v0.96.0 (latest at plan-lock) + selection rule (drift history review, surface-vs-manifest diff, ADR or scope-lock amendment if exceeded, toolchain update). _Resolution: applied._

**Findings (Minor):**
- `P4` [infra verification] [T13]: compat-drift lacked `workflow_dispatch` (gh workflow run fails); compat.yml trigger unspecified — required check must report every PR (no path filter). _Resolution: applied._
- `P5` [existence] [T30/T1]: `rust-segments` phantom path; `.github/workflows/README.md` orphaned; T30 grep Go-only. _Resolution: applied (enumerate-at-execution rule, README.md added to T1 delete, grep widened to .github/ docs/)._
- `P6` [unresolved marker] [T17]: `?→ confirm in harness` had no owning verify. _Resolution: applied — T19 verify explicit pq_ratchet-absent both-roles case._
- `P7` [config validation] [T2]: setup-go form unstated (`go-version-file: go.mod`), golangci-lint v2 needs `version: "2"` key + release supporting Go 1.26. _Resolution: applied._
- `P8` [decomposition/integration proof] [T27/T28]: T27 coarsest task (one verify for full SPQR port) → split 3 verified slices; SPQR first cross-impl evidence deferred to T29 → T28 gains SPQR interop vs existing T0 pin (v0.91.1 spqr min_version V0 negotiates up). _Resolution: applied._
- `P9` [user intent] [Conventions]: "agent team" directive unaddressed — PRs 7/8/9 mutually independent (depend only on PR 6), parallelizable via worktree-isolated agents. _Resolution: applied — parallelization note added._

**Bug-class scan transcript:** Project-guidance Clean (guidance→task table accurate); Assumptions Finding(P3); Repo-precedent Clean (cross-version-testing pattern verified); Artifact-class Finding(P5); YAGNI Clean (0x0A reserve + unknown-field test justified); Missing-failure Finding(P2,P4); Security Clean (D4 carried: CT-POLYVAL, RFC 8452 suite, fuzz every deserializer, redacting String(), RNG injection test-only); Infra Finding(P4); Multi-component Finding(P1,P8); Rollback Clean (T1/T2/T11/T13/T29/T30 notes incl. branch-protection pre-state); Simpler-alternative Clean; User-intent Finding(P9 mild); Existence Finding(P5); Over/under-decomposition Finding(P8 minor); Verification-class Finding(P4) else good discipline (gh pr checks observation, API read-backs); Auth/authz Clean (T16 identity-trust direction table, T23 trust-root chain semantics); Hidden-serial Finding(P1) — required-check-from-PR4 vs PR5+ harness extensions analyzed safe (pull_request runs from PR branch, extension+consumer same PR); Missing-rollback Clean; Missing-integration Finding(P8); Infra-verification Finding(P4); Plugin-loader Clean n/a; Config-validation Finding(P7); Identifier/naming Clean (check/branch/package names consistent; manifest arithmetic ✓).

**Options:** (1) split drift harness micro-crate — applied; (2) SPQR interop at T0 pin in T28 — applied; (3) pin Stage-2 target now w/ escape hatch — applied (v0.96.0 default + rule).

**Verdict reasoning:** Unusually well-instrumented plan; design premises survived fresh spot-checks. Three tangible Important defects, all in compat machinery (the project's core requirement): vector contract enumerated one PR late, drift dual-pin compile story absent, Stage-2 target unbounded. FAIL; re-review expected fast pass.

## Cycle 2

### Adversarial Review Report
**Phase:** plan (rev 2 — convergence pass)
**Artifact:** docs/plans/2026-06-12-pure-go-libsignal.md
**Status:** PASS

**Cycle-1 resolution verification:** all 9 (P1-P9) genuinely applied, none a paper fix — jq sub-domain assertion, drift micro-crate + constraint line, Stage-2 selection rule (v0.96.0 default + escape hatch + toolchain), workflow triggers, phantom paths removed, T17 ? discharged by T19 verify, setup-go/golangci v2, T27 3 verified slices, T28 SPQR-at-T0 interop, parallelization note. Scope Manifest recounted: 11 PRs = 11 rows; 30 tasks = 30 headings (T1-T30 no gaps/dupes); per-row distribution 2+4+4+3+3+3+2+3+2+3+1=30. Fresh spot-checks of rev-2-cited lines all held incl. `UsePQRatchet` in pre-mandatory API (T28 premise API-viable).

**Findings (all Minor):**
- `P10` [artifact/verification] [T13]: drift-crate vector schema/pass-fail computation/own-toolchain unstated. _Resolution: applied — Drift mechanics line._
- `P11` [hidden serial, files-scope] [T28]: Files list omitted harness+interop_test extension (UsePQRatchet flag exposure); T13 constraint enumeration omitted T28. _Resolution: applied._
- `P12` [missing failure mode] [T29]: full-domain main leg mechanism unstated (drift crate never gains session API) → main harness repointed branch="main", compile-failure-as-drift-signal, informational only. _Resolution: applied._
- `P13` [parallelization overstated] [Conventions]: PRs 7/8/9 not file-disjoint (T21/T24/T25 share harness files); append-shaped conflicts, rebase order 7→8→9. _Resolution: applied._

**Bug-class transcript:** 23 classes scanned (13 design + 10 plan); findings only in classes that carried fixed cycle-1 findings (artifact P10, missing-failure P12, hidden-serial P11, multi-component P13 mild); all others Clean — full table in agent transcript, key verifications: security posture intact, rollback notes intact, manifest arithmetic ✓, naming consistent ✓, existence re-checks ✓.

**Options:** (1) PASS as-is, fold P10-P13 at execution — chosen alternative was (2) apply now; lead applied all four same-day.

**Verdict reasoning:** No new tangible Critical/Important class; every cycle-2 finding sits in a class whose cycle-1 finding was fixed; convergence rule → PASS with minors applied immediately.
