<!--
Copyright 2026 libsignal-go contributors.
SPDX-License-Identifier: AGPL-3.0-only
-->

# rust-harness

Compatibility harness that wraps upstream
[`libsignal-protocol`](https://github.com/signalapp/libsignal) and serves as the
behavioral reference oracle for the pure-Go port. It is a **dev/CI-only** crate:
nothing in the Go module depends on it, and it is not published.

The upstream dependencies are pinned to the peeled **`v0.104.0`** release commit
`257105c55a7389ca6b1e85185e2769465e6729f1` (annotated tag object
`03b9987415e6dcb3d83dfde6a16b52d2b59a7b44`, unsigned). This includes
`libsignal-protocol`, `usernames`, and `libsignal-account-keys`, plus their
upstream path dependencies. SPQR is pinned to `v1.6.0`, commit
`06959b4708f9b7b1e94d0f8cc835f3958c077e94`; libcrux-ml-kem is exactly `0.0.10`.
`Cargo.lock` records the complete dependency graph. It lives in its own isolated
Cargo workspace (`[workspace] members =
["."]`) so it is never pulled into a parent workspace, mirroring
`rust/protocol/cross-version-testing/Cargo.toml` upstream.

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

`rust-toolchain.toml` pins Rust `1.98.1`, matching upstream `v0.104.0`'s root
`rust-toolchain`. With working rustup proxies it is selected automatically.
When Homebrew binaries take precedence, selecting Cargo alone can still run
Homebrew's `rustc`; explicitly select the compiler and documentation tool too:

```sh
export RUSTC="$(rustup which --toolchain 1.98.1 rustc)"
export RUSTDOC="$(rustup which --toolchain 1.98.1 rustdoc)"
```

## Usage

Build (release):

```sh
rustup run 1.98.1 cargo build --release --locked
```

### gen-vectors

Prints a deterministic JSON batch of test vectors to stdout. The batch header
records the `seed`; output is byte-identical across runs. Most domains use seeded
ChaCha20; account keys use known-test inputs and explicit MFA IV replay bytes.

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
- `username-links` — username-link entropy, deterministic IV, encrypted username
  bytes (`IV || ciphertext || HMAC`), username reservation hash, and
  upstream-decrypted username from `rust/usernames`.
- `mlkem-incremental` — byte-exact KATs for libcrux 0.0.10's incremental
  ML-KEM-768 (the KEM SPQR uses): the keygen split (`pk1`/`pk2`/`dk`), two-phase
  encapsulation (`ct1`, `encaps_state`, `ct2`, `shared_secret`), and
  decapsulation. `encaps_state` is the raw libcrux state for this host's backend;
  `encaps_state_fixed` is the cryspen/libcrux#1275-normalized state (equal to
  `encaps_state` on the portable backend, which is what builds here use). Oracle 3
  for the pure-Go `internal/mlkem768incr` incremental layer; the generated batch
  is committed at
  `internal/mlkem768incr/testdata/libcrux_incremental_mlkem768.json`.
- `spqr-chunks` — golden byte vectors for SPQR v1.6.0's GF(2^16) chunked-transport
  erasure code (the `test-utils` feature exposes its `encoding` module): a set of
  `chunk_at(i)` outputs (`cases`) pinning the BIG-endian u16 point/coefficient
  wire, plus GF16 `mul`/`div` triples (`gf_triples`) pinning the field
  (POLY=0x1100b). Oracle leg (c) for the pure-Go `internal/spqr/chunked` package —
  the erasure property test alone is blind to a uniformly-wrong endianness, so the
  golden bytes are required. Committed at
  `internal/spqr/chunked/testdata/spqr_chunks.json`.
- `account-keys` — upstream account entropy/backup derivations, SVR-key
  derivations, PIN master-key HMAC-SHA256-SIV, media key splits, and deterministic
  MFA metadata encryption/decryption. See the schema below.

The dependency pin alone does not upgrade the Go protocol/SPQR implementation or
the provenance of previously committed fixtures. Only
`compat/vectors/account-keys.json` is regenerated here; the remaining protocol,
SPQR, and fixture refresh work is tracked separately.

### Account-Key Schema And Replay

All byte strings are lowercase hex. Names/PINs are text; timestamps are unsigned
64-bit JSON integers in milliseconds. Consumers must not decode timestamps
through floating point (the maximum-timestamp case exceeds exact float64 range).
Every derived/encrypted value is generated by the real upstream public API;
only splitting the upstream 64-byte media key into two 32-byte halves is local.

The legacy `domain`, `seed`, `cases` fields (`entropy_pool`, `svr_key`,
`backup_key`, `aci`, `backup_id`), and `pin_cases` fields (`pin`, `salt`,
`access_key`) retain their original values and v0.96.4 provenance. `_note`
identifies these legacy fields separately from the new v0.104.0 oracle additions
and records the annotated tag object and peeled commit. The historical seed is
an input identifier, not a claim that new vectors came from v0.96.4.

| Array | Fields |
|---|---|
| `cases` | Legacy fields plus `media_name`, 15-byte `media_id`, 64-byte `media_encryption_key_data`, 32-byte `media_aes_key`/`media_hmac_key`, and corresponding `thumbnail_transit_encryption_key_data`, `thumbnail_aes_key`, `thumbnail_hmac_key` |
| `pin_cases` | Legacy fields plus 32-byte `encryption_key`/`master_key`/`decoded_master_key`, 48-byte `encrypted_master_key`, and `tampered` entries `{offset, encrypted_master_key, accepted}` |
| `svr_cases` | `label`, 32-byte `svr_key`, `registration_lock`, `registration_recovery_password`, `storage_service_key`, `logging_key` |
| `mfa_cases` | `label`, `svr_key`, `name`, `created_at_millis`, 16-byte `iv`, 160-byte `encrypted_metadata`, `decrypted_name`, `decrypted_created_at_millis` |
| `mfa_invalid_cases` | `label`, `svr_key`, `encrypted_metadata`, `accepted` (false); IV/ciphertext/MAC tamper, wrong key, and 159/161-byte lengths |
| `mfa_invalid_name_cases` | `name`, `created_at_millis`, upstream diagnostic `error`; 99 ASCII bytes, 100 UTF-8 bytes, or embedded NUL |

SVR cases use the account-derived key, all-zero/all-one bytes, and sequential
bytes. PIN cases retain the two original normalized PIN inputs and salts. The
master-key ciphertext is `16-byte synthetic IV || 32-byte ciphertext`.

MFA cases cover empty name/epoch, millisecond truncation to seconds, the 98-byte
ASCII and multibyte UTF-8 name limits, and `u64::MAX` milliseconds. `FixedRng`
replays exactly the recorded IV; upstream consumes exactly 16 bytes. The blob is
`16-byte IV || 112-byte AES-256-CBC ciphertext || 32-byte HMAC-SHA256`. Generation
asserts successful round trips and upstream rejection of every negative entry.
The upstream name error text is diagnostic only, not a Go error-string contract.
Authenticated malformed padding/protobuf/overflow are covered by independent Go
negative tests; this oracle slice does not generate those fixtures or extend the
protocol commands.

From this directory, regenerate and verify:

```sh
rustup run 1.98.1 cargo build --release --locked
./target/release/rust-harness gen-vectors account-keys > ../vectors/account-keys.json
rustup run 1.98.1 cargo test --release --locked
```

For a bounded external build directory, set
`CARGO_TARGET_DIR=/private/tmp/signal-task31-rust-target` and run its
`release/rust-harness` binary instead. The fixture replay test compares the full
generated JSON to the committed fixture; a separate test protects legacy outputs.

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
- `username_link.create` `{ username, entropy, iv }` →
  `{ entropy, encrypted_username }`
- `username_link.decrypt` `{ entropy, encrypted_username }` → `{ username }`
- `message.parse_sender_key` `{ serialized }` →
  `{ distribution_id, chain_id, iteration }`

All byte-string params and results are hex-encoded.

## Notes on the `hkdf` domain

The chain-key / root-key / message-keys / pqxdh-secret derivations are
`pub(crate)` upstream, so the harness reproduces them with the same pinned
crate versions (`hkdf`, `hmac`, `sha2` — matching upstream's pins). The formulas
are taken verbatim from `rust/protocol/src/ratchet/keys.rs` and `ratchet.rs` at
the v0.104.0 commit, which remains the contract.
Every other domain calls the genuine public API.
