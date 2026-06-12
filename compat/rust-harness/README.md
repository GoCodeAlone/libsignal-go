<!--
Copyright 2026 libsignal-go contributors.
SPDX-License-Identifier: AGPL-3.0-only
-->

# rust-harness

Compatibility harness that wraps upstream
[`libsignal-protocol`](https://github.com/signalapp/libsignal) and serves as the
behavioral reference oracle for the pure-Go port. It is a **dev/CI-only** crate:
nothing in the Go module depends on it, and it is not published.

The upstream dependency is pinned to a fixed tag, **`v0.91.0`** (see ADR 0001 —
the pin is `v0.91.0`, **not** `v0.91.1`). It lives in its own isolated Cargo
workspace (`[workspace] members = ["."]`) so it is never pulled into a parent
workspace, mirroring `rust/protocol/cross-version-testing/Cargo.toml` upstream.

## Build-time system dependency: `protoc`

**`protoc` (the Protocol Buffers compiler) must be installed to build this
crate.** The upstream `libsignal-protocol` and `spqr` build scripts compile
their `.proto` files via `prost-build` 0.14, which does **not** vendor a
`protoc` binary — a system `protoc` is required. Without it the build fails at
`libsignal-protocol`'s `build.rs` with "Could not find `protoc`".

- macOS (local): `brew install protobuf`
- Debian/Ubuntu (CI): `apt-get install -y protobuf-compiler`
- GitHub Actions: `arduino/setup-protoc` (or the `apt` package above)

If `protoc` is installed somewhere off `PATH`, point the build at it with the
`PROTOC` environment variable.

> CI note for the workflow task (T13): add a `protoc` setup step before
> `cargo build`. This was a non-obvious blocker discovered during T11.

## Toolchain

`rust-toolchain.toml` pins `nightly-2026-03-23`, matching the toolchain
upstream `v0.91.0` itself pins. `rustup` fetches it on demand.

## Usage

Build (release):

```sh
cargo build --release
```

### gen-vectors

Prints a deterministic JSON batch of test vectors to stdout. The batch header
records the `seed`; output is byte-identical across runs (seeded ChaCha20).

```sh
rust-harness gen-vectors <domain>
```

Domains:

- `curve` — XEdDSA sign/verify (deterministic 64-byte signing nonce) and
  X25519 ECDH agreement.
- `kem-decaps` — Kyber1024 `(public_key, secret_key, ciphertext, shared_secret)`
  quadruples with an encapsulate/decapsulate round-trip.
- `hkdf` — the Double Ratchet key derivations, one case per required
  sub-domain: `chain-key`, `message-keys`, `root-key`, `pqxdh-secret`.
- `messages` — golden serialized bytes for `SignalMessage`,
  `PreKeySignalMessage`, `SenderKeyMessage`, and
  `SenderKeyDistributionMessage`, built with fixed keys.
- `fingerprint` — display + scannable fingerprints (v1 and v2) for a fixed
  identity-key pair.

Example:

```sh
rust-harness gen-vectors curve | jq '.seed, (.cases | length)'
```

### interop

A line-delimited JSON-RPC loop over stdin/stdout. Each input line is one request
`{"id": <any>, "method": "<name>", "params": {...}}`; each output line is one
response `{"id": <echoed>, "ok": <bool>, "result"|"error": ...}`. Unknown
methods, malformed JSON, and bad params all produce an error response — the loop
never crashes.

```sh
echo '{"method":"ping"}' | rust-harness interop
```

Methods (extended in later tasks — session/group/sealed-sender ops arrive then):

- `ping`
- `curve.sign` `{ private_key, message }` → `{ signature, public_key }`
- `curve.verify` `{ public_key, message, signature }` → `{ verified }`
- `curve.agree` `{ private_key, public_key }` → `{ shared }`
- `kem.decapsulate` `{ secret_key, ciphertext }` → `{ shared_secret }`
- `message.parse_sender_key` `{ serialized }` →
  `{ distribution_id, chain_id, iteration }`

All byte-string params and results are hex-encoded.

## Notes on the `hkdf` domain

The chain-key / root-key / message-keys / pqxdh-secret derivations are
`pub(crate)` upstream, so the harness reproduces them with the same pinned
crate versions (`hkdf`, `hmac`, `sha2` — matching upstream's pins). The formulas
are taken verbatim from `rust/protocol/src/ratchet/keys.rs` and `ratchet.rs` at
the v0.91.0 tag, which remain the contract. Every other domain calls the genuine
public API.
