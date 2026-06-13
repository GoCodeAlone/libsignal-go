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
- `mlkem-incremental` — byte-exact KATs for libcrux 0.0.8's incremental
  ML-KEM-768 (the KEM SPQR uses): the keygen split (`pk1`/`pk2`/`dk`), two-phase
  encapsulation (`ct1`, `encaps_state`, `ct2`, `shared_secret`), and
  decapsulation. `encaps_state` is the raw libcrux state for this host's backend;
  `encaps_state_fixed` is the cryspen/libcrux#1275-normalized state (equal to
  `encaps_state` on the portable backend, which is what builds here use). Oracle 3
  for the pure-Go `internal/mlkem768incr` incremental layer; the generated batch
  is committed at
  `internal/mlkem768incr/testdata/libcrux_incremental_mlkem768.json`.
- `spqr-chunks` — golden byte vectors for SPQR v1.5.1's GF(2^16) chunked-transport
  erasure code (the `test-utils` feature exposes its `encoding` module): a set of
  `chunk_at(i)` outputs (`cases`) pinning the BIG-endian u16 point/coefficient
  wire, plus GF16 `mul`/`div` triples (`gf_triples`) pinning the field
  (POLY=0x1100b). Oracle leg (c) for the pure-Go `internal/spqr/chunked` package —
  the erasure property test alone is blind to a uniformly-wrong endianness, so the
  golden bytes are required. Committed at
  `internal/spqr/chunked/testdata/spqr_chunks.json`.

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
