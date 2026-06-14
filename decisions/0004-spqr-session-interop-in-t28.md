# 0004. SPQR session interop verified in T28 (not deferred to T29)

**Status:** Accepted
**Date:** 2026-06-14
**Decision-makers:** implementer-1 (finding) + team-lead (independent verification + ruling)
**Related:** decisions/0001-spqr-staged-compat.md (corrects its Erratum's "interops without SPQR" framing), docs/plans/2026-06-12-pure-go-libsignal.md (T28, T29), design backport 2026-06-14

## Context

The plan's T28 step assumed the pinned compat harness "ships spqr with
min_version V0" so SPQR Rust↔Go session interop is testable pre-re-pin. ADR
0001's Erratum then pinned T0 = **v0.91.0** and framed it as "the last release
tag where session establishment interops **without** SPQR." Those two framings
conflict, so before building T28's interop slice we had to resolve, against the
actual cargo checkout, whether v0.91.0 produces SPQR — which decides whether
cross-impl SPQR interop belongs in T28 or must wait for T29's re-pin to v0.96.0.

Verified facts (cargo checkout, independently confirmed by team-lead):

- The harness pins `libsignal-protocol` tag **v0.91.0** (rev `8418be45`); its
  `Cargo.lock` resolves **spqr v1.5.1 rev f2589fe** — the exact crate ported in
  T27.
- v0.91.0's `rust/protocol` integrates SPQR: `ratchet.rs`, `state/session.rs`,
  `session_cipher.rs`, `protocol.rs`, `wire.proto`, `storage.proto` all
  reference `pq_ratchet`/`spqr`.
- `initialize_alice_session` / `initialize_bob_session` call
  `spqr::initial_state(version: V1, min_version: V0, direction: A2B/B2A)`
  **unconditionally**. `process_prekey_bundle` at v0.91.0 takes **no
  `UsePQRatchet` flag** (that knob was added in a later libsignal version).
- Therefore v0.91.0 sessions **always negotiate SPQR**, and every v4
  `SignalMessage` carries a **non-empty `pq_ratchet`** field. The `min_version
  V0` only means a peer that presents no SPQR (an old/V0 client) can still
  interoperate by negotiating down — it does **not** mean the field is absent on
  a v0.91.0↔v0.91.0 session.

So ADR 0001's Erratum phrase "interops without SPQR" is imprecise: v0.91.0
interops **with SPQR at min_version V0** (the field is produced; a V0-only peer
falls back). The decision logic of ADR 0001 (staged compat) is unaffected.

## Decision

SPQR Rust↔Go **session interop is verified in T28**, not deferred to T29. The
v0.91.0 harness already speaks the SPQR wire format the Go port produces, so T28
covers both the in-Go triple-ratchet E2E **and** the cross-impl interop:

- No `UsePQRatchet` harness flag is added (none exists at v0.91.0); the harness
  already emits `pq_ratchet`. The T28 interop slice **asserts** SPQR is on the
  wire (non-empty `pq_ratchet` both directions) and that the Go port mixes the
  SPQR key correctly when sending to and receiving from upstream.
- T29's re-pin to v0.96.0 remains **purely currency / mainline-compat-claim**;
  it does not gate SPQR's existence or its cross-impl interop, so T29 scope is
  unchanged by this resolution.

## Consequences

- + Cross-impl SPQR is proven now (against the real upstream), not two tasks
  later — the highest-value compat signal lands with the implementation.
- + The stale "negotiate without SPQR / pq_ratchet absent" comments in the
  session interop test and the harness `main.rs` are corrected to match reality
  (comment-only; no behavior change).
- − The T28 plan text's "expose `UsePQRatchet` in the harness init-session RPCs"
  instruction is not literally actionable at v0.91.0 (no such flag); it is
  satisfied instead by asserting the unconditional SPQR the harness already
  produces. No manifest scope change (T28 still = session integration + interop).
- Undo: none needed — this records a resolution, not a reversible mechanism.
