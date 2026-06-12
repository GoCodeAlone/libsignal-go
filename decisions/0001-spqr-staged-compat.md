# 0001. Stage SPQR after protocol core, pin compat target until then

**Status:** Accepted
**Date:** 2026-06-12
**Decision-makers:** Claude (autonomous, owner pre-authorized); trigger = adversarial review finding D1
**Related:** docs/plans/2026-06-12-pure-go-libsignal-design.md, docs/plans/2026-06-12-pure-go-libsignal-design-review.md

## Context

Upstream `signalapp/libsignal` HEAD makes SPQR (Sparse Post-Quantum Ratchet,
`signalapp/SparsePostQuantumRatchet` v1.5.1) mandatory for all new sessions
(`rust/protocol/src/ratchet.rs:87,150` — `min_version: spqr::Version::V1`).
Original design excluded SPQR as "internal-experimental" — factually wrong
(review D1). A SPQR-less Go implementation cannot establish sessions with
current mainline clients, so the live interop gate pinned to a recent tag
would never pass, and the owner's "100% compatible" requirement would be
unachievable.

## Decision

We will implement SPQR, staged as the final protocol phase (P10), and pin the
compat harness in two stages: Stage 1 (P4-P9) pins upstream tag `T0` = last
release interoperating without SPQR; Stage 2 (P10) ports SPQR v1.5.1 and
re-pins to latest upstream tag. Mainline-compat claims are version-bounded
until Stage 2 completes.

Alternatives rejected:
- **Exclude SPQR, pin compat claim to old tag permanently** — contradicts
  guidance (mainline wire compat is top priority; Evolution Triggers name new
  PQ ratchet revisions as scope-extension events) and the owner's ask.
- **Implement SPQR first / inline with ratchet phase** — blocks all session,
  group, and sealed-sender work behind the largest single port; staging keeps
  it off the critical path while protos carry `pq_ratchet` fields from day one.

## Consequences

- + P5-P9 proceed against a stable, passing interop gate.
- + Wire/storage protos include `pq_ratchet`/`pq_ratchet_state` from the start; no schema retrofit.
- − README/compat claims must state the pinned stage until P10 merges (falsifiable, per-stage).
- − P10 is a large port (ML-KEM-based sparse ratchet); risk isolated to one phase, reference source in-tree via cargo tag.
- Undo: revert P10 PR returns to Stage 1 claim; no migration cost for earlier phases.
