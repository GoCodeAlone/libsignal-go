<!--
Copyright 2026 libsignal-go contributors.
SPDX-License-Identifier: AGPL-3.0-only
-->

# rust-harness-drift

A deliberately minimal sibling of [`../rust-harness`](../rust-harness) that
tracks upstream [`libsignal`](https://github.com/signalapp/libsignal) **`main`**
instead of the `v0.91.0` pin. Its sole job is to feed the weekly
**compat-drift** workflow (`.github/workflows/compat-drift.yml`): regenerate the
**version-stable** primitive vectors from upstream `main` and diff them against
the committed `v0.91.0` vectors, so a byte-level change to a primitive we rely
on is caught early — without ever gating a PR.

This is a **dev/CI-only** crate. Nothing in the Go module depends on it; it is
not published.

## Why a separate crate

The pinned harness is the behavioral **contract** (`v0.91.0`, ADR 0001). It must
not move. This crate floats on `main`, which would make the pinned harness's
history noisy if they shared a dependency. Splitting them keeps the contract
stable and the drift probe disposable.

## Scope: version-stable domains ONLY

This crate generates only the domains whose bytes are not expected to change
across upstream releases:

- `curve` — XEdDSA sign/verify (deterministic nonce) + X25519 ECDH
- `kem-decaps` — Kyber1024 encapsulate/decapsulate quadruples
- `hkdf` — the Double Ratchet key derivations (chain/message/root/pqxdh)

It carries **no** `messages`, `fingerprint`, or `interop` surface. Those
exercise the session/group/message API that legitimately evolves on `main`;
tracking them here would generate noise, not signal.

> **Hard constraint for later tasks:** T19 / T21 / T24 / T28 extend **only**
> `../rust-harness`. Do **not** add session/group/sealed-sender surface to this
> crate.

## Output schema

Identical to `../rust-harness gen-vectors <domain>` and consumed by the same
`compat/vectors_test.go`: a `{domain, seed, cases[]}` batch (or
`{domain, seed, subdomains{}}` for `hkdf`), with the same `VECTOR_SEED` and
seeded-ChaCha20 draw order. When this crate and the pinned harness link the same
upstream revision, their output is byte-identical; a difference is exactly the
drift signal.

## Build & run

`protoc` is required (same as the pinned harness — see
[`../rust-harness/README.md`](../rust-harness/README.md)).

```sh
cargo build --release
./target/release/rust-harness-drift gen-vectors curve
./target/release/rust-harness-drift gen-vectors kem-decaps
./target/release/rust-harness-drift gen-vectors hkdf
```

To repoint at a specific upstream revision, edit the `branch`/`rev` of the
`libsignal-protocol` git dependency in `Cargo.toml` (it defaults to `main`).
