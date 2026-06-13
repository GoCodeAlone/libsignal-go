# 0002. Port incremental ML-KEM-768 to pure Go for SPQR

**Status:** Accepted
**Date:** 2026-06-13
**Decision-makers:** repo owner (explicit approval, 2026-06-13 session); team-lead
**Related:** docs/plans/2026-06-12-pure-go-libsignal.md (T27), decisions/0001-spqr-staged-compat.md, docs/plans/2026-06-12-pure-go-libsignal-design.md

## Context

T27 (SPQR sparse PQ ratchet) is the Stage-2 component that ADR 0001 requires
for current-mainline compat. The locked plan assumed `github.com/cloudflare/circl`
provides the KEM (plan text: "use circl's ML-KEM-1024"). At implementation,
that assumption proved false on two counts (implementer-2, verified against
SPQR v1.5.1 cargo checkout f2589fe):

1. SPQR uses ML-KEM-**768**, not 1024 (`Cargo.toml` libcrux-ml-kem
   `features=["incremental","mlkem768"]`; `src/incremental_mlkem768.rs`).
2. SPQR uses libcrux's **incremental** ML-KEM API — encapsulation key split
   into header (pk1) + chunked encaps-key (pk2), two-phase encapsulate1/2,
   decapsulate_compressed_key, plus a specific encaps-state byte layout. circl
   v1.6.3 provides only **monolithic** standard NIST ML-KEM-768
   (GenerateKeyPair/Encapsulate/Decapsulate); grep of circl for
   incremental/encapsulate1/pk1 → zero hits.

SPQR's serialized state blobs embed libcrux's incremental byte layout, so a
circl-based port cannot round-trip the ported upstream test vectors — byte
compat (the entire reason ADR 0001 stages SPQR) is unreachable via circl. cgo
to libcrux is excluded (pure-Go mandate). So byte-compatible SPQR requires a
pure-Go incremental ML-KEM-768.

## Decision

We will implement incremental ML-KEM-768 in pure Go, preferring to **fork/vendor
circl's `mlkem768` internals and add the incremental/chunked API on top** (reuses
circl's vetted standard-ML-KEM core; lower risk than a from-scratch KEM), with a
standalone implementation as the fallback. This lands as the first slice of T27
(its own reviewed component, KAT'd against the libcrux v1.5.1 incremental
reference vectors), ahead of the SPQR state-codec / state-machine slices.

SPQR is NOT deferred. Owner explicitly chose the port over shipping v0.1.0 at the
Stage-1 (v0.91.0) compat claim.

Alternatives rejected:
- **Defer SPQR to v0.2.0** (ship v0.1.0 at v0.91.0 compat): owner declined; the
  mainline-compat finale stays in this milestone.
- **Structural-only SPQR on circl monolithic ML-KEM**: not wire-compatible →
  contradicts ADR 0001's reason for SPQR (mainline interop). Unacceptable.
- **cgo to libcrux**: violates the pure-Go mandate (design guidance).

## Consequences

- + Byte-compatible SPQR → ADR 0001 Stage-2 mainline-compat claim becomes achievable.
- + Forking circl's mlkem768 reuses a vetted ML-KEM core; the new surface is the incremental/chunked layer + encaps-state codec, not the whole KEM.
- − Materially expands T27 beyond the locked estimate (a non-standard KEM port + its byte-exact verification); highest crypto-risk code in the project → gets a GCM-SIV-class deep review (both reviewers, KATs vs the libcrux reference).
- − vendored/forked circl code enters the tree (internal package); track upstream circl + libcrux-incremental for divergence.
- Scope: T27 content expands; PR count (11) and task count (30) unchanged — T27 still ships in PR 10. Owner-approved amendment; manifest grouping unchanged.
- Undo: if the port proves intractable, fall back to the deferral alternative (v0.1.0 at v0.91.0 compat, SPQR → v0.2.0) via a follow-up amendment.
