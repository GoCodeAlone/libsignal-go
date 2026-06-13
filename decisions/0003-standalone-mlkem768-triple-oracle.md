# 0003. Standalone FIPS-203 ML-KEM-768 with triple-oracle verification

**Status:** Accepted
**Date:** 2026-06-13
**Decision-makers:** team-lead + spec-reviewer (Slice-0 design gate); owner (scope greenlight, ADR 0002)
**Related:** decisions/0002-incremental-mlkem768-pure-go.md (refines its KEM-base choice), docs/plans/2026-06-12-pure-go-libsignal.md (T27 Slice 0), design backport 2026-06-13

## Context

ADR 0002 approved porting incremental ML-KEM-768 to pure Go, *preferring* to
fork circl's mlkem768. A pre-code design spike disproved that base:

- circl's exposed mlkem768 internals are **round-3 Kyber**, not FIPS-203 final —
  differs on sampling/encoding/FO-hash. Byte-exactness is the deliverable, so a
  round-3 base risks non-matching bytes.
- Go 1.26.4 stdlib `crypto/mlkem` **is** FIPS-203-final ML-KEM-768 (ek 1184 =
  1152 t̂ ‖ 32 ρ; ct 1088; seed 64), but its PKE internals live in
  `crypto/internal/fips140/mlkem`, which is toolchain-import-locked — usable as
  an oracle, not as a base.

Neither vendor target works. Standalone (ADR 0002's named fallback) becomes the
path. Risk: a hand-rolled FIPS-203 PKE is the highest-stakes crypto in the
project, and a naive correctness check can hide byte-level bugs.

## Decision

Implement ML-KEM-768 **standalone in pure Go** (`internal/mlkem768incr/`),
modeling the FIPS-203 PKE (NTT, reductions, CBD sampling, compress/decompress,
matrix-gen, serialize) on Go stdlib's `crypto/internal/fips140/mlkem` source
(FIPS-203-correct, idiomatic; BSD — carry Go copyright attribution in ported
files), with libcrux 0.0.8's incremental split/serialization layered on top.

Accept it against **three independent oracles**:
1. **stdlib `crypto/mlkem`** — end-to-end shared-secret equality (FIPS-203 correctness).
2. **NIST/ACVP ML-KEM-768 KAT** — pins the PKE *intermediate* bytes independently
   (oracle 1 only compares the final ss, so a compensating-error pair in the PKE
   byte path could pass it; ACVP closes that gap).
3. **libcrux 0.0.8 Rust KAT harness** — byte-exact incremental vectors
   (seed→hdr/ek/dk, encaps1→ct1/state/ss, encaps2→ct2, decaps→ss, + the
   issue-1275 bad-encoding vector).

Ship as sub-commits — PKE-core (gated by oracles 1+2) then incremental-layer
(gated by oracle 3) — so oracle coverage maps to review boundaries.

Alternatives rejected:
- **Fork circl mlkem768** (ADR 0002's preference): round-3, wrong version → byte-incompatible.
- **Wrap stdlib crypto/mlkem**: PKE internals import-locked; monolithic API can't express the incremental chunked split.
- **Dual oracle only** (stdlib + libcrux): the stdlib leg compares only the final ss → can mask compensating PKE byte errors. Added ACVP as the third, intermediate-byte oracle.

## Consequences

- + Eliminates the round-3 byte-mismatch risk; base is provably FIPS-203.
- + Triple oracle pins correctness (stdlib), PKE intermediate bytes (ACVP), and incremental wire bytes (libcrux) — independent failure surfaces.
- − Largest single slice in the project (~600+ lines FIPS-203 PKE + incremental layer); GCM-SIV-class review ×2.
- − Hand-rolled FIPS-203 crypto carries inherent risk; mitigated by 3 oracles + sub-commit review boundaries + constant-time discipline.
- Provenance: stdlib-derived code is BSD→AGPL compatible; attribution headers required in ported files.
- Scope: within ADR 0002's owner-approved amendment; manifest count/grouping unchanged (T27 / PR 10).
- Undo: if the PKE port proves intractable, fall back to the ADR 0001 deferral (ship v0.1.0 at the v0.91.0 Stage-1 compat claim, SPQR → v0.2.0).
