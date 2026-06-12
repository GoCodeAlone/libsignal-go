# Adversarial Review — Pure Go libsignal Design

## Cycle 1

### Adversarial Review Report
**Phase:** design
**Artifact:** docs/plans/2026-06-12-pure-go-libsignal-design.md
**Status:** FAIL

**Findings (Critical):**

- `D1` [project-guidance conflicts / assumptions / user-intent drift] [Scope, out-of-scope list]: SPQR/triple-ratchet exclusion breaks compatibility with current mainline; "internal-experimental" rationale factually wrong. Evidence: `rust/protocol/src/ratchet.rs:87,150` (`min_version: spqr::Version::V1, // Require that all clients speak SPQR`), `rust/protocol/src/session_management.rs:66` (`OutgoingTripleRatchet` main path), `wire.proto:15` (`pq_ratchet = 5`), `storage.proto:66` (`pq_ratchet_state = 15`), `Cargo.toml:96` (spqr = released external crate v1.5.1, non-optional). Guidance non-goals do NOT list SPQR; guidance names mainline wire compat as top priority. Consequence: `compat-interop` gate vs recent upstream tag cannot pass; "100% compatible" unachievable for new sessions. Recommendation: (a) add SPQR phase, or (b) version-pin compat claim + amend guidance. _Resolution: revised design adopts staged (a): harness pinned pre-SPQR tag through core phases, SPQR phase added, re-pin to latest tag before completion claim._

**Findings (Important):**

- `D2` [YAGNI / assumptions] [Scope ratchet row, P6]: X3DH v3 session *initiation* has no upstream counterpart (upstream init PQXDH-only: `pqxdh.rs:118,249` non-optional kyber; `protocol.rs:21` v3 = decrypt floor; `session_cipher_legacy.rs` is `#![cfg(test)]`). Recommendation: scope v3 to decrypt/state compat only; resolve `session_cipher_legacy` = test-only, excluded. _Resolution: applied in revision._
- `D3` [existence/runtime-validity] [Compat layer 1, A1]: `rust/protocol/src/kem/test-data` holds only key-serialization fixtures (pk.dat/sk.dat/mlkem-*.dat) — no encaps/decaps KATs; A1 closure mechanism as written does not exist. Recommendation: P3 = key-format fixtures + round-3 NIST KATs via circl derandomized API + Rust-generated deterministic decaps (pk,ct,ss) triples. _Resolution: applied in revision._
- `D4` [security] [Security Review]: hand-rolled AES-256-GCM-SIV (POLYVAL) is riskiest self-implemented surface; constant-time strategy/vectors/fuzz unstated. Recommendation: constant-time limb-based carry-less mult, RFC 8452 appendix vectors + upstream SSv2 envelope vectors, fuzz open/seal, evaluate vetted pure-Go port first. _Resolution: applied in revision._

**Findings (Minor):**

- `D5` [artifact-class precedent] [Scope wire row]: `service.proto` omitted; DecryptionErrorMessage/Content live in `service.proto:9-24` not wire.proto. _Resolution: applied._
- `D6` [scope] [session row]: `MAX_UNACKNOWLEDGED_SESSION_AGE` (30d soft-archive, drives SessionNotFound on stale unacked sessions) omitted. _Resolution: applied._
- `D7` [infrastructure] [P1/P4]: workflow inventory imprecise (no "swift" workflow; iOS covers it); deleting Rust CI workflows in P1 while branch protection untouched until P4 strands required checks → blocks PRs. Recommendation: exact file list per phase; audit/update branch protection via gh api in P1 atomically. _Resolution: applied._
- `D8` [missing failure modes] [drift workflow]: upstream pins nightly (`rust-toolchain.toml`, nightly-2026-03-23); drift job must read toolchain from upstream checkout, not hardcode. _Resolution: applied._

**Bug-class scan transcript:**
| Class | Result | Note |
|---|---|---|
| Project-guidance conflicts | Finding (D1) | SPQR exclusion attributed to non-goals that don't list it; compat-first guidance contradicted |
| Assumptions under attack | Findings (D1,D2,D3) | unstated "v4 = PQXDH w/o SPQR" false; A3 verified true (crypto/hkdf exists); A7 plausible |
| Repo-precedent conflicts | Clean | greenfield Go tree per guidance; session_cipher_legacy test-only |
| Artifact-class precedent | Finding (D5) | proto inventory wrong; kem test-data mischaracterized (D3) |
| YAGNI violations | Finding (D2) | v3 initiation dead upstream; ML-KEM-1024 readiness justified (0x0A in kem.rs:219) |
| Missing failure modes | Findings (D7,D8) | required-check stranding; nightly toolchain drift |
| Security/privacy | Finding (D4) | GCM-SIV constant-time risk; other crypto claims verified (0x05, 0x08, MAC-before-decrypt) |
| Infrastructure impact | Finding (D7) | sequencing wrong; otherwise explicit/revertible |
| Multi-component validation | Finding (D1 dep) | harness right idea, unscoped-SPQR makes it unpassable vs recent tags |
| Rollback story | Clean | PR-per-phase revert; deletions deferred |
| Simpler alternative | Finding (option 2) | prebuilt upstream npm/jar artifact as interop peer never weighed |
| User-intent drift | Finding (D1) | "100% compatible" vs SPQR-less core |
| Existence/runtime-validity | Mixed | consts/wire-types/licenses/workflows verified; KAT files & proto locations failed |

**Options the author may not have considered:**
1. Implement SPQR as scoped phase (separately versioned spec, v1.5.1) — true mainline compat achievable.
2. Use upstream prebuilt release artifacts (npm @signalapp/libsignal-client) as interop peer — kills cargo/nightly/CI-minutes risk chain, at cost of driving through binding API.
3. Rust-side deterministic decapsulation vectors as P3 ground truth for A1, decoupled from P4 harness.

**Verdict reasoning:** Structurally strong design, but the load-bearing factual claim about upstream is wrong: SPQR is mandatory at fork HEAD. That invalidates the interop gate as scoped and the compat promise. FAIL until SPQR decision recorded and design amended; D2-D4 folded into same revision; minors absorbed by plan phase.

## Cycle 2

### Adversarial Review Report
**Phase:** design (rev 2)
**Artifact:** docs/plans/2026-06-12-pure-go-libsignal-design.md
**Status:** FAIL (narrow — D1-D8 resolutions all verified genuine; 2 new Important in rev-2 staging machinery)

### Cycle-1 resolution audit
All D1-D8 verified applied & factually accurate (~15 file/line/constant claims spot-checked, all true). Bonus evidence: A9 stronger than design claimed — `min_version: spqr::Version::V0` window ran from `b7b8040e3` (2025-06-04) to `cf9a7445c` "Force SPQR v1" (2026-04-03, 0.91.1→0.92.0). T0 = v0.91.1, no bisect. Upstream `rust/protocol/cross-version-testing/` + `tests/prespqr.rs` confirm staging premise both halves.

**Findings (Important):**
- `D9` [staging contradiction] [P10 row vs ADR 0001]: phase table gave P10 `depends: P6` only → re-pin could land before P7-P9, changing required check under in-flight PRs & claiming Stage-2 compat without groups/sealed-sender coverage at new pin; vectors regen unstated. Fix: P10 depends P7,P8,P9 + regenerate all vectors + full suite at new pin. _Resolution: applied rev 3._
- `D11` [missing failure mode] [drift watch]: Stage-1 weekly drift vs `main` guaranteed red/divergent (harness written against T0 API; `usePqRatchet` removal etc.) → weekly false-alarm stream. Fix: two-pin stage-aware drift (T0 must-green + main informational/version-stable domains only, dedupe), full post-P10. _Resolution: applied rev 3._

**Findings (Minor):**
- `D10` [artifact-class precedent]: upstream `cross-version-testing/` is in-tree precedent for tag-pinned harness (collapses A2/A9 to facts; T0 from one commit); fork clone has no upstream tags fetched — harness CI must fetch from signalapp remote. _Resolution: applied rev 3 (cited in Compat Staging)._
- `D12` [phase sequencing]: P3 "serialization vectors" source unspecified (harness arrives P4). Fix: P3 = public KATs + structural round-trip; upstream vectors in P4. _Resolution: applied rev 3._

**Bug-class scan transcript:** Project-guidance Clean; Assumptions Clean→strengthened (A9 verified, A2 proven, A3 closed); Repo-precedent Finding(D10); Artifact-class Finding(D10); YAGNI Clean (mlkem1024 cfg-gated verified); Missing-failure Finding(D11); Security Clean (SSv2 Aes256GcmSiv verified sealed_sender.rs:11-12,1418); Infra Finding(D11); Multi-component Finding(D9); Rollback Clean; Simpler-alternative Finding(D10 minor); User-intent Clean (staged claim converges on mainline at P10); Existence Clean.

**Options:** (1) adopt cross-version-testing pattern wholesale — applied; (2) re-pin as own micro-phase after P7-P10 — addressed via P10 depends P7,P8,P9; (3) two-pin drift — applied.

**Verdict reasoning:** Rev 2 genuinely resolved D1-D8. New staging machinery had two tangible Important defects (D9, D11), both small edits. FAIL with expectation rev 3 is a quick pass.

## Cycle 3

### Adversarial Review Report
**Phase:** design (rev 3 — convergence pass)
**Artifact:** docs/plans/2026-06-12-pure-go-libsignal-design.md
**Status:** PASS (converged; remaining findings Minor)

### Cycle-2 resolution audit
D9/D11/D10/D12 all verified genuinely applied (phase table, Compat Staging, drift watch, A2/A9 rows consistent; dependency graph acyclic, matches ADR 0001). Owner-directive amendments (P1 cruft purge, A6) attacked with filesystem evidence and hold: all purge paths exist, nothing deleted is referenced by kept rust/ reference (grep zero hits for ../bin, ../doc, acknowledgments; include_bytes!/include_str! all resolve inside rust/), cross-version-testing survives under rust/protocol/, root Cargo.toml workspace members all under rust/, .cargo holds only audit.toml.

**Findings (Minor):**
- `D13` [missing failure mode/existence] [compat layer 2, drift, infra]: toolchain file is `rust-toolchain` (bare), doc said `.toml`; fix = run cargo via rustup per checkout (honors both). _Resolution: applied (rev 3.1)._
- `D14` [doc currency] [header]: stale "rev 2" marker. _Resolution: applied._
- `D15` [wording placement]: doc-currency rule lived only in P9 row. _Resolution: applied — rule added beside PR rule._

**Bug-class scan transcript:** Project-guidance Clean; Assumptions Clean (A2/A9 strikethroughs verified vs cross-version-testing/Cargo.toml:21-30; 0 upstream tags confirmed); Repo-precedent Clean; Artifact-class Finding(D14); YAGNI Clean; Missing-failure Finding(D13); Security Clean; Infra Clean; Multi-component Clean; Rollback Clean; Simpler-alternative Clean; User-intent Clean; Existence Finding(D13).

**Options:** (1) rustup-resolved toolchain (applied); (2) fold D14/D15 into P1 PR (applied immediately instead).

**Verdict reasoning:** Cycle 3 surfaced no new tangible Critical/Important class; two consecutive cycles without new tangible issues → converged. PASS with D13-D15 Minor (all applied same-day).
