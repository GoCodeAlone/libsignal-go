# Design Guidance

**Status:** Active
**Last updated:** 2026-06-12
**Source:** human directive (repo-owner instruction, 2026-06-12 session)

## Product Direction
- Goal: pure Go implementation of the Signal protocol suite in `GoCodeAlone/libsignal-go`, importable as a standard Go module without cgo, C, or Rust toolchains.
- Optimize for: wire/protocol compatibility with `signalapp/libsignal` (mainline), then idiomatic Go API, then performance.
- The existing Rust/Java/Swift/Node tree exists only as a reference point; it will be replaced incrementally as Go code lands.
- Owner directive (2026-06-12): full authority to reorganize/delete any repo contents that don't support the Go implementation — no cruft. Docs (incl. README) must be kept current with each change.
- Authoritative specs: https://signal.org/docs/ (X3DH, PQXDH, Double Ratchet, Sesame, XEdDSA/VXEdDSA) plus the Rust source in-tree as behavioral reference.

## Architecture Constraints
- Language: Go only for shipped code. Latest stable Go (1.26.4 as of 2026-06-12); `go.mod` pins via `toolchain` directive.
- **Forbidden:** cgo, C/Rust/asm FFI, wrappers around `libsignal-ffi`. Pure Go (stdlib + `golang.org/x/crypto` and similarly vetted pure-Go deps only).
- Module path: `github.com/GoCodeAlone/libsignal-go`.
- Package layout mirrors protocol domains (curve, keys, ratchet, session, groups, etc.), not the Rust crate layout, but stays traceable to it.
- Storage interfaces (sessions, prekeys, identity, sender keys) defined as Go interfaces; in-memory reference implementations provided.

## Quality / Security / Operations
- Compatibility is a hard requirement: cross-implementation test contracts against mainline `signalapp/libsignal` MUST run as a required PR check (test vectors generated from the Rust implementation, committed as fixtures, plus a CI job that can regenerate/verify them against upstream).
- Constant-time discipline for secret-dependent operations; no secret-dependent branches/indexing in hot crypto paths; use `crypto/subtle` where applicable.
- No panics across public API boundaries; errors wrap with context.
- All crypto primitives covered by known-answer tests (RFC vectors and upstream-generated vectors).
- Commits authored as `codingsloth@pm.me`.
- Workflow: changes land via PRs. Merge permitted when CI green and no unresolved Copilot review comments; admin merge allowed for this repo.

## Infrastructure / Integration Impact
- CI: GitHub Actions. Legacy Rust workflows are retired/replaced as the Go tree supplants them; new workflows: go build/test/lint (golangci-lint), compat-contract check.
- No deployed services; this is a library. No secrets beyond CI defaults.

## Multi-Component Validation
- Cross-implementation proof: Go encrypts → Rust-generated vectors decrypt expectations match (and inverse, via committed fixtures). Session-level round-trip tests (X3DH/PQXDH handshake → Double Ratchet message exchange) form the integration boundary proof.

## Non-Goals
- Bindings for other languages (JNI/Swift/Node bridges).
- Server-side zero-knowledge group credentials (zkgroup/zkcredential/poksho), key transparency, SVR, device-transfer, media sanitizers, message-backup — out of initial scope; client protocol core first.
- Network layer (`rust/net` chat/CDSI websockets).
- FIPS certification.

## Evolution Triggers
- Upstream protocol changes (e.g., new PQ ratchet revisions) → regenerate contracts, extend scope.
- Scope expansion into zkgroup/usernames domains requires new design round (ristretto255/poksho are large undertakings).

## Change Log
| Date | Source | Change |
|---|---|---|
| 2026-06-12 | human directive | Initial guidance |
