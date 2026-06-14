# 0005. Drift workflow: full-domain on the PIN leg, version-invariant probe on the MAIN leg

**Status:** Accepted
**Date:** 2026-06-14
**Decision-makers:** implementer-2 (T29 implementation + technical read) + implementer-1 (independent backstop, same conclusion) + team-lead (ruling)
**Related:** docs/plans/2026-06-12-pure-go-libsignal.md (T29 step 4 — "full-domain main leg enabled"; plan-review P12 informational-drift intent), decisions/0001-spqr-staged-compat.md (Stage-2 re-pin), `.github/workflows/compat-drift.yml`

## Context

The locked plan's T29 step 4 reads literally: *"full-domain main leg = main
harness git-dep repointed to `branch="main"`; compile failure on that leg IS the
drift signal."* Taken at face value this directs pointing the **full**
`compat/rust-harness` (all session/group/sealed/SPQR RPC surface + vector
domains) at upstream `branch="main"` for the weekly informational drift probe.

The compat-drift workflow has two legs (by design, plan-review P2):
- **pin leg** — rebuild the pinned harness (now v0.96.0), regenerate the
  committed vectors, diff. MUST stay green; a failure is a real alarm.
- **main leg** — build a crate against upstream `main` and diff the
  version-stable primitives; INFORMATIONAL (continue-on-error, files a
  deduplicated issue), never gates a PR.

At T29 execution this surfaced a concrete conflict between the plan prose and
the workflow's design. Pointing the full harness at `branch="main"` is the
literal reading, but the full harness calls **version-volatile** upstream APIs.

## Decision

Keep the drift workflow split as implemented in T29, which is a deliberate
deviation from the step-4 prose:
- **PIN leg → full-domain.** The pinned (v0.96.0) harness regenerates **every**
  committed domain (curve, kem-decaps, hkdf, messages, fingerprint, sessions,
  groups, sealedsender) and diffs byte-for-byte. Full-domain coverage lives
  here, against the stable pinned contract — the meaningful place for it.
- **MAIN leg → minimal version-invariant probe.** The floating `main` leg uses
  the `compat/rust-harness-drift` micro-crate, which generates ONLY the
  version-invariant primitives (curve / hkdf / kem) with no session/RPC surface,
  and remains compile-failure-informational-not-gating.

This is recorded as an ADR (a drift-tooling implementation detail within T29),
NOT a Scope Manifest change — PR count, task count, and feature scope are
unchanged.

Rationale (three concrete reasons the full-harness-vs-`main` leg is the wrong
tool, all independently reached by both implementers):

1. **Volatile-API churn = constant red noise.** The full harness calls
   version-volatile upstream functions — e.g. `process_prekey_bundle` gained a
   7th `local_address` argument between v0.91.0 and v0.96.0 (fixed in this very
   task). Pointing it at `branch="main"` would break-to-build on every such
   upstream signature change, turning the informational leg permanently red and
   drowning the genuine drift signal. That is exactly the failure mode the
   separate micro-crate was introduced to avoid (plan-review P2).
2. **Version-coupled vectors = false "drift".** session / group / sealed vectors
   are coupled to the negotiated protocol version and message framing. Diffing
   them against `main` would flag *intentional* upstream protocol evolution as
   "drift," producing false positives rather than the byte-level-primitive
   early-warning the probe is meant to give.
3. **Full-domain coverage already exists where it belongs.** The pin leg already
   diffs all committed domains against the stable v0.96.0 contract. The `main`
   leg's job is narrower: detect when upstream changes the bytes of a
   *version-invariant primitive* we rely on (a Curve25519 / HKDF / Kyber
   change), which is genuinely newsworthy and rare. The minimal probe serves
   that intent precisely and without noise.

This better serves the plan-review P12 intent (informational drift early-warning
without false-positive noise) than the literal prose would.

Alternatives rejected:
- **Full harness git-dep → `branch="main"`, compile-only, continue-on-error
  (the literal step-4 reading).** Rejected: reasons (1)–(3). It would be
  perpetually red from the first upstream API change and surface no actionable
  signal beyond what the pin leg + the minimal main probe already give.
- **Drop the main leg entirely.** Rejected: the version-invariant primitive
  probe is cheap and is the one genuinely useful `main`-tracking signal; keeping
  it preserves P12's early-warning value.

## Consequences

- + Informational drift signal stays low-noise and actionable (primitive byte
  changes), never a perpetually-red leg.
- + Full-domain byte-compat verification is preserved on the pin leg against the
  stable v0.96.0 contract.
- + No RPC-surface duplication into the micro-crate (it stays
  `no session/RPC API surface`, so it keeps compiling against `main` across
  API churn — the property it exists for).
- − A byte change to a *session/group/sealed* wire format on upstream `main`
  would not be caught by the weekly probe until the next deliberate re-pin
  (T29-style). Accepted: such changes are intentional protocol evolution handled
  by a re-pin + surface-diff (the T29 selection rule), not by an informational
  cron probe.
- Provenance: the deviation is from plan prose only; the workflow's two-leg
  design (plan-review P2) is honored. Scope/manifest unchanged.
- Undo: to adopt the literal prose, repoint `compat/rust-harness`'s
  `libsignal-protocol` dep to `branch="main"` in a `main`-leg job step
  (continue-on-error) — but accept the constant-red-noise consequence first.
