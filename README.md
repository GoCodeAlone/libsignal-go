# libsignal-go

[![Go Reference](https://pkg.go.dev/badge/github.com/GoCodeAlone/libsignal-go.svg)](https://pkg.go.dev/github.com/GoCodeAlone/libsignal-go)
[![CI](https://github.com/GoCodeAlone/libsignal-go/actions/workflows/go.yml/badge.svg)](https://github.com/GoCodeAlone/libsignal-go/actions/workflows/go.yml)
[![compat](https://github.com/GoCodeAlone/libsignal-go/actions/workflows/compat.yml/badge.svg)](https://github.com/GoCodeAlone/libsignal-go/actions/workflows/compat.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/GoCodeAlone/libsignal-go)](https://goreportcard.com/report/github.com/GoCodeAlone/libsignal-go)
[![Release](https://img.shields.io/github/v/release/GoCodeAlone/libsignal-go?sort=semver)](https://github.com/GoCodeAlone/libsignal-go/releases)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

A pure-Go implementation of the Signal client protocol core, wire-compatible
with [`signalapp/libsignal`](https://github.com/signalapp/libsignal).

> **Independent fork** — a community reimplementation, **not affiliated with,
> endorsed by, or maintained by Signal Messenger LLC.** Report issues and
> security vulnerabilities in *this* port to this repository (see
> [`SECURITY.md`](SECURITY.md)) — **not** to Signal.

`libsignal-go` is built entirely on the Go standard library and a small set of
pure-Go cryptography dependencies. **There is no cgo, C, or Rust in the
shipped module** — it builds with `CGO_ENABLED=0` and cross-compiles like any
ordinary Go package. The goal is byte-for-byte wire compatibility with the
upstream Rust implementation for the client-side protocol surface, enforced by
cross-implementation compatibility checks as required CI gates.

> Status: **`v0.1.0` released** — the full client protocol is implemented and
> interop-verified byte-compatible with libsignal v0.96.0 (both roles). Early
> development: the API may still change across `0.x` releases; review the
> security posture before production use.

## Status

The protocol is being implemented in phases. Each phase is one or more pull
requests; compatibility is asserted incrementally as domains land.

This table tracks what has merged to the default branch.

| Phase | Scope | Status |
|-------|-------|--------|
| P1 | Scaffold: Go module, CI, repository cleanup | ✅ |
| P2 | Crypto primitives, curve (X25519 / XEdDSA), address types | ✅ |
| P3 | KEM (Kyber1024), protobuf codegen, wire messages | ✅ |
| P4 | Compatibility harness: committed vectors + live Rust interop | ✅ |
| P5 | Ratchet keys, session state, stores | ✅ |
| P6 | PQXDH session builder + session cipher | ✅ |
| P7 | Groups: sender keys + group cipher | ✅ |
| P8 | Sealed sender v1/v2 + AES-256-GCM-SIV | ✅ |
| P9 | Fingerprints + API polish + scope matrix | ✅ |
| P10 | SPQR port + re-pin to mainline + full revalidation | ✅ |
| P11 | Cleanup: remove reference trees, final docs, `v0.1.0` | ✅ |

✅ merged to main. **All 11 phases complete — tagged `v0.1.0`.**

## Compatibility staging

Wire compatibility is asserted against a **pinned upstream tag**, not a moving
target, so that the interop gate is meaningful and reproducible.

- **Stage 1 (superseded):** compatibility was bounded to the **libsignal
  v0.91.0** protocol surface — the last upstream release before the Sparse
  Post-Quantum Ratchet (SPQR) was made mandatory for new sessions — while SPQR
  was being ported (P5–P9 ran against this pin).
- **Stage 2 (current):** SPQR is ported (P10) and the compat harness is
  re-pinned to **libsignal v0.96.0**, the current upstream mainline release. The
  compatibility claim now covers the full current-mainline protocol surface,
  including SPQR-negotiated sessions (v0.96.0 requires SPQR — `min_version: V1`).
  The committed vectors are byte-identical across the re-pin (the protos, the
  `spqr` v1.5.1 pin, and `libcrux-ml-kem` 0.0.8 are unchanged from v0.91.0), and
  the live Rust↔Go interop passes both roles with SPQR on the wire.

The rationale, alternatives considered, and the exact pin boundary are recorded
in [`decisions/0001-spqr-staged-compat.md`](decisions/0001-spqr-staged-compat.md).

## Scope matrix

The per-domain status of the client protocol surface. **Implemented** domains
are wire-checked against upstream **libsignal v0.96.0** (committed Rust-generated
vectors plus live Rust↔Go interop, per the compatibility staging above).
**Staged** domains are deferred to a named phase. **Excluded** domains are
deliberate non-goals for this module.

| Domain | Status | Package | Notes |
|--------|--------|---------|-------|
| X25519 ECDH + XEdDSA sign/verify | ✅ implemented | [`curve`](curve/) | v0.96.0 vectors + interop |
| Kyber1024 KEM (encaps/decaps) | ✅ implemented | [`kem`](kem/) | v0.96.0 decaps vectors + interop |
| Wire messages (Signal, PreKeySignal, SenderKey, SKDM) | ✅ implemented | [`protocol`](protocol/) | golden-byte vectors both directions |
| Symmetric primitives (AES-CBC/CTR/GCM, HKDF, HMAC) | ✅ implemented | [`internal/crypto`](internal/crypto/) | internal building blocks |
| Double Ratchet keys + session state + stores | ✅ implemented | [`ratchet`](ratchet/), [`session`](session/), [`stores`](stores/) | KDF + state KATs |
| PQXDH session establishment + session cipher | ✅ implemented | [`session`](session/) | both roles, with/without one-time pre-key, interop |
| Group messaging (sender keys + group cipher) | ✅ implemented | [`groups`](groups/) | SKDM + cipher, both directions, interop |
| Sealed sender v1 + v2 | ✅ implemented | [`sealedsender`](sealedsender/) | certificate chain + USMC + seal/decrypt, both versions, interop |
| AES-256-GCM-SIV (RFC 8452) | ✅ implemented | [`internal/crypto/gcmsiv`](internal/crypto/gcmsiv/) | nonce-misuse-resistant AEAD for sealed sender v2 |
| Fingerprints (numeric + scannable) | ✅ implemented | [`fingerprint`](fingerprint/) | display + scannable byte-equal vs upstream |
| Sparse Post-Quantum Ratchet (SPQR) | ✅ implemented | [`spqr`](spqr/), [`internal/mlkem768incr`](internal/mlkem768incr/), [`internal/spqr/chunked`](internal/spqr/chunked/) | incremental ML-KEM-768 + GF(2^16) chunked transport + state machine, mixed into the session message keys; SPQR-negotiated interop both roles at v0.96.0 |
| X3DH v3 session *initiation* | ⛔ excluded | — | v3 *decrypt*/state compat retained; v0.96.0 cannot initiate v3 |
| ML-KEM-1024 *activation* | ⛔ excluded | — | wire type `0x0A` parsing reserved only |
| zkgroup / zkcredential / poksho | ⛔ excluded | — | non-goal (server/credential surface) |
| usernames, key transparency, SVR/svrb, account-keys | ⛔ excluded | — | non-goal |
| device transfer, media, message backup, net | ⛔ excluded | — | non-goal |
| `incremental_mac`, HPKE, `session_cipher_legacy` | ⛔ excluded | — | upstream test-only |
| Language bridges (Java / Swift / Node) | ⛔ excluded | — | deleted from this fork, not ported |

Legend: ✅ implemented (v0.96.0 compat) · 🚧 staged to a later phase · ⛔
excluded (deliberate non-goal). FIPS certification and key-material zeroization
guarantees beyond the documented Go posture are also out of scope.

**No ⛔ row is a client-protocol gap.** Every capability a Signal client needs to
send and receive messages — 1:1 sessions (PQXDH), group messaging, sealed sender
(v1 + v2), fingerprints, and the SPQR post-quantum ratchet — is ✅ implemented and
interop-proven against mainline. The excluded rows are deliberate non-goals:
server / credential / service surfaces (zkgroup, usernames, key transparency,
SVR, account-keys), app- and transport-layer features (device transfer, media,
message backup, net), upstream test-only code (`incremental_mac`, the HPKE test
harness, `session_cipher_legacy`), language bindings (this module *is* the Go
binding), or behaviors upstream v0.96.0 itself does not perform — v3 *session
initiation* (v3 *decrypt* is retained) and ML-KEM-1024 *activation* (wire type
`0x0A` is reserved-only, exactly as in mainline).

## Reference tree

During development the upstream Rust sources lived under `rust/` as a read-only
behavioral reference snapshot: every crypto constant, KDF info string, version
byte, MAC layout, and proto field number in the Go code was traced to a cited
line in that tree and locked by a vector test. The `rust/` snapshot (along with
the root Cargo manifests and `rust-toolchain`) was **removed at `v0.1.0`**, now
that the Go implementation is self-sufficient — git history preserves it, and
the provenance comments in the Go sources (`// ported from
rust/protocol/src/…`) still point into that history. Wire compatibility is no
longer asserted against an in-tree snapshot but against the **compat harness**
([`compat/rust-harness/`](compat/rust-harness/)), which pins upstream libsignal
remotely by tag and remains in the repo.

## Installation

```shell
go get github.com/GoCodeAlone/libsignal-go
```

Requires Go 1.26 or newer. The module pins `toolchain go1.26.4`; a matching
toolchain is fetched automatically by the `go` command if your local toolchain
is older.

## Usage

Runnable examples live alongside the packages they document (Go renders them in
`go doc` and runs them under `go test`):

- [`session.Example_sessionRoundTrip`](session/example_test.go) — a PQXDH
  handshake and the first encrypted message between two parties.
- [`groups.Example_groupMessaging`](groups/example_test.go) — sender-key
  distribution and a group-encrypted message.
- [`sealedsender.Example_sealedSender`](sealedsender/example_test.go) — a sealed
  sender v1 message with certificate-chain validation.

Browse the full API with:

```shell
go doc github.com/GoCodeAlone/libsignal-go
go doc github.com/GoCodeAlone/libsignal-go/session
```

## Development

```shell
CGO_ENABLED=0 go build ./...   # build (no cgo, ever)
go vet ./...
gofmt -l .                     # must print nothing
go test -race ./...
golangci-lint run              # lint (config in .golangci.yml)
```

CI runs these checks on Linux and macOS; the cross-implementation
compatibility suite becomes a required gate from P4 onward. A single required
status check named `go` gates merges to `main`.

## Cryptography notice

This distribution includes cryptographic software. The country in which you
currently reside may have restrictions on the import, possession, use, and/or
re-export to another country of encryption software. Before using any
encryption software, please check your country's laws, regulations, and
policies concerning the import, possession, or use, and re-export of encryption
software. See <https://www.wassenaar.org/> for more information.

## License

Copyright the `libsignal-go` contributors.
Portions derived from `signalapp/libsignal`, Copyright 2020-2026 Signal
Messenger, LLC.

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See
[`LICENSE`](LICENSE) for the full text, or
<https://www.gnu.org/licenses/agpl-3.0.html>.
