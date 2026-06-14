<!--
Copyright 2026 libsignal-go contributors.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Retro: Pure-Go libsignal port — v0.1.0 (the whole locked design, PR1–PR11)

**PRs:** #3–#13 (PR 1/11 … 11/11) — scaffold → crypto → KEM → compat harness →
ratchet/session → groups → sealed sender → fingerprints → SPQR + triple ratchet
+ v0.96.0 re-pin → cleanup + `v0.1.0`
**Merged:** PR1–PR10 to `main`; PR11 (this one) merging at `v0.1.0`
**Branch (final):** `feat/go-p11-cleanup`
**Design:** docs/plans/2026-06-12-pure-go-libsignal-design.md (rev 3)
**Plan:** docs/plans/2026-06-12-pure-go-libsignal.md (Locked 2026-06-12; 11 PRs / 30 tasks)
**Related ADRs:** decisions/0001-spqr-staged-compat.md · 0002-incremental-mlkem768-pure-go.md
· 0003-standalone-mlkem768-triple-oracle.md · 0004-spqr-session-interop-in-t28.md
· 0005-drift-leg-pin-fulldomain-main-minimal.md

This is a project-capstone retro covering the full locked design, not a single
PR. The lock held end-to-end: 11 PRs, 30 tasks, no scope amendment — only
design-doc backports (facts corrected in place, manifest untouched) and five
ADRs for the genuine trade-offs.

## Adversarial-review findings, scored (the load-bearing ones)

| Phase | Finding | Severity | Outcome |
|---|---|---|---|
| design | SPQR KEM = circl mlkem768 fork | Critical | Prescient — disproved by a Slice-0 spike (circl is round-3 Kyber, byte-incompatible); rerouted to a standalone FIPS-203 port (ADR 0002/0003) before any code shipped |
| design | T0 compat pin = the last pre-SPQR tag | Important | Prescient-but-imprecise — the pin boundary mattered; the exact tag was wrong twice (see erratum below) |
| design | in-process state, no concurrency contract | Minor | False positive — the port is a stateless library; callers own concurrency, matching upstream |
| plan | groups skipped-message-key cache deferred | Minor | Resolved upfront — explicitly scoped to the later group-cipher task (YAGNI), no downstream bug |
| plan | SPQR sliced 0a/0b/A/B/C may over-fragment | Important | Resolved upfront — the slicing was exactly right; each slice got its own two-stage review + backstop and the proto-roundtrip invariant caught two real state-machine bugs |

## Gate misses

| Issue | Gate that missed | Why it slipped | Fix idea |
|---|---|---|---|
| `MessageKeyGenerator` (T28) leaked its seed/keys under `%#v` | requesting-code-review (T28 spec stage) | spec-reviewer noted "TestFormatRedaction covers it" — but that test covered `MessageKeys`, not the NEW exported wrapper; the `%#v`-recurses-into-embedded-struct trap bypassed the embedded type's Format | when a NEW exported secret-bearing type is added, its redaction must be DIRECTLY tested (own type, all verbs incl `%#v`) — "covered by a sibling/embedded type's test" is the incomplete-check tell. Caught at code-review stage (the 2nd gate working), but should have been caught at spec stage. |
| `DecapsulationKey768` (T27 0a) `String()`-only → `%#v` leaked d/z/ŝ | requesting-code-review (0a spec stage) | redaction gap was INHERITED from the stdlib re-derivation source (stdlib relies on the type being unexported); "matches the source" ≠ "redacts correctly" | same fix-class as above; this is the recurrence that makes it a pattern (see follow-ups) |

Both misses are the same bug class (secret redaction on a new/ported secret-bearing
type) and both were caught one gate later (code-review), not in production. Two
occurrences = a trend (see plugin follow-ups).

## Missed skill activations

The full pipeline ran across the project's sessions. For PR10/PR11 (this
session's window) the recorded gates:

| Gate | Fired? | Notes |
|---|---|---|
| adversarial-design-review | yes | design + plan phases; the circl-KEM and KEM-port findings reshaped T27 before code |
| scope-lock | yes | claimed/verified at each task (T20–T30); manifest hash stable across the whole project, zero amendments |
| receiving-code-review | yes | T28 redaction fix + the 4 PR#13 Copilot threads triaged with verification, not rubber-stamp |
| pr-monitoring | yes | PR #13 CI + Copilot threads |
| post-merge-retrospective | yes | this document |
| finishing Step 1e (doc-reconciliation) | yes | T30 reconciled README/.gitignore/design-doc for the rust/ removal |

No gate that was expected to fire failed to fire. The misses above are
gate-*content* gaps (a check that ran but didn't cover the new type), not
missing activations.

## What worked

- **The two-layer compat gate (committed vectors + live Rust↔Go interop) was the
  highest-ROI gate by far.** Byte-exact KATs + both-role interop caught real wire
  divergences that unit tests never would, and the SPQR cross-impl interop (T28)
  proved the triple ratchet against the genuine upstream — produce-and-consume,
  both directions.
- **Slicing the hardest crypto (SPQR/ML-KEM) into independently-reviewed units
  with a triple-oracle (stdlib + ACVP + libcrux KAT) for the KEM (ADR 0003)** kept
  the highest-stakes code honest; the deferred-derivation/proto-roundtrip
  invariant in Slice C caught two state-machine bugs the in-memory tests
  tolerated.
- **scope-lock held the whole design** — 11 PRs over the full build with zero
  silent rescope; every trade-off became an ADR, every corrected fact a dated
  design backport.
- **The staged-compat call (ADR 0001) played out as designed**: Stage-1 v0.91.0
  pin while SPQR was ported, Stage-2 re-pin to v0.96.0 once it landed — and the
  re-pin was a TRUE byte-noop (identical protos, unchanged spqr v1.5.1/libcrux
  0.0.8), validating the staging.

## What didn't

- **The secret-redaction check missed a new exported wrapper twice** (0a
  `DecapsulationKey768`, T28 `MessageKeyGenerator`) — both `%#v`/embedded-recurse
  leaks, both caught at code-review rather than spec. The convention ("redact
  String() AND Format(), test every verb") existed; the gap was not RE-running it
  against each newly-added secret-bearing type.
- **The T0 compat pin tag was wrong twice in a row** (v0.91.1, which doesn't
  exist upstream → corrected to v0.91.0; then v0.91.0 was framed as "pre-SPQR"
  when it actually ships spqr v1.5.1 with min_version V0). Both were caught by
  reading the cargo checkout, but the imprecise "min_version V0 = pre-SPQR"
  framing nearly pushed cross-impl interop out of T28 into T29 unnecessarily.

## Plugin-level follow-ups

**Recurring gate miss (2 occurrences) — propose a concrete change.** The secret-
redaction gap recurred across T27-0a and T28. Propose: `adversarial-design-review
--phase=design` (or a `requesting-code-review` checklist line) gain an explicit
bug-class — *"a newly-added or ported EXPORTED type holding secret bytes must
have its OWN String()+Format() and a direct multi-verb redaction test (incl
`%#v`); 'covered by an embedded/sibling type' or 'matches the (unexported) source'
does not count — `%#v` reflection-recurses past an embedded type's Format."* Cite
this retro + secret-redaction-convention. Two occurrences is a trend, not noise.

## Project guidance updates

| Guidance file | Change | Reason |
|---|---|---|
| `docs/design-guidance.md` | no change | The redaction lesson is a code-review bug-class (plugin follow-up above), not a cross-design product/runtime/deployment constraint. No durable design-direction change this cycle — the project completed exactly as the locked design specified. |
