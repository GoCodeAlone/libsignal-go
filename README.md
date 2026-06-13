# libsignal-go

A pure-Go implementation of the Signal client protocol core, wire-compatible
with [`signalapp/libsignal`](https://github.com/signalapp/libsignal).

`libsignal-go` is built entirely on the Go standard library and a small set of
pure-Go cryptography dependencies. **There is no cgo, C, or Rust in the
shipped module** — it builds with `CGO_ENABLED=0` and cross-compiles like any
ordinary Go package. The goal is byte-for-byte wire compatibility with the
upstream Rust implementation for the client-side protocol surface, to be
enforced by cross-implementation compatibility checks as required CI gates
(landing in P4).

> Status: early development. The API is unstable and will change without
> notice until the `v0.1.0` tag. Not yet suitable for production use.

## Status

The protocol is being implemented in phases. Each phase is one or more pull
requests; compatibility is asserted incrementally as domains land.

| Phase | Scope | Status |
|-------|-------|--------|
| P1 | Scaffold: Go module, CI, repository cleanup | ✅ |
| P2 | Crypto primitives, curve (X25519 / XEdDSA), address types | 🚧 |
| P3 | KEM (Kyber1024), protobuf codegen, wire messages | 🚧 |
| P4 | Compatibility harness: committed vectors + live Rust interop | 🚧 |
| P5 | Ratchet keys, session state, stores | 🚧 |
| P6 | PQXDH session builder + session cipher | 🚧 |
| P7 | Groups: sender keys + group cipher | 🚧 |
| P8 | Sealed sender v1/v2 + AES-256-GCM-SIV | 🚧 |
| P9 | Fingerprints + API polish + scope matrix | 🚧 |
| P10 | SPQR port + re-pin to mainline + full revalidation | 🚧 |
| P11 | Cleanup: remove reference trees, final docs, `v0.1.0` | 🚧 |

✅ landed · 🚧 planned / in progress

## Compatibility staging

Wire compatibility is asserted against a **pinned upstream tag**, not a moving
target, so that the interop gate is meaningful and reproducible.

- **Stage 1 (current):** compatibility claims are bounded to the
  **libsignal v0.91.0** protocol surface. This is the last upstream release
  before the Sparse Post-Quantum Ratchet (SPQR) was made mandatory for new
  sessions. The compat harness is pinned to `v0.91.0` and the committed test
  vectors are generated from it.
- **Stage 2 (after P10):** once SPQR is ported, the harness is re-pinned to the
  current upstream mainline and the compatibility claim is upgraded
  accordingly.

The rationale, alternatives considered, and the exact pin boundary are recorded
in [`decisions/0001-spqr-staged-compat.md`](decisions/0001-spqr-staged-compat.md).

## Scope matrix

The per-domain status of the client protocol surface. **Implemented** domains
are wire-checked against upstream **libsignal v0.91.0** (committed Rust-generated
vectors plus live Rust↔Go interop, per the compatibility staging above).
**Staged** domains are deferred to a named phase. **Excluded** domains are
deliberate non-goals for this module.

| Domain | Status | Package | Notes |
|--------|--------|---------|-------|
| X25519 ECDH + XEdDSA sign/verify | ✅ implemented | [`curve`](curve/) | v0.91.0 vectors + interop |
| Kyber1024 KEM (encaps/decaps) | ✅ implemented | [`kem`](kem/) | v0.91.0 decaps vectors + interop |
| Wire messages (Signal, PreKeySignal, SenderKey, SKDM) | ✅ implemented | [`protocol`](protocol/) | golden-byte vectors both directions |
| Symmetric primitives (AES-CBC/CTR/GCM, HKDF, HMAC) | ✅ implemented | [`internal/crypto`](internal/crypto/) | internal building blocks |
| Double Ratchet keys + session state + stores | ✅ implemented | [`ratchet`](ratchet/), [`session`](session/), [`stores`](stores/) | KDF + state KATs |
| PQXDH session establishment + session cipher | ✅ implemented | [`session`](session/) | both roles, with/without one-time pre-key, interop |
| Group messaging (sender keys + group cipher) | ✅ implemented | [`groups`](groups/) | SKDM + cipher, both directions, interop |
| Sealed sender v1 + v2 | ✅ implemented | [`sealedsender`](sealedsender/) | certificate chain + USMC + seal/decrypt, both versions, interop |
| AES-256-GCM-SIV (RFC 8452) | ✅ implemented | [`internal/crypto/gcmsiv`](internal/crypto/gcmsiv/) | nonce-misuse-resistant AEAD for sealed sender v2 |
| Fingerprints (numeric + scannable) | ✅ implemented | [`fingerprint`](fingerprint/) | display + scannable byte-equal vs upstream |
| Sparse Post-Quantum Ratchet (SPQR) | 🚧 staged (P10) | `spqr` | proto fields parsed + preserved now; negotiation + mainline re-pin land in P10 |
| X3DH v3 session *initiation* | ⛔ excluded | — | v3 *decrypt*/state compat retained; v0.91.0 cannot initiate v3 |
| ML-KEM-1024 *activation* | ⛔ excluded | — | wire type `0x0A` parsing reserved only |
| zkgroup / zkcredential / poksho | ⛔ excluded | — | non-goal (server/credential surface) |
| usernames, key transparency, SVR/svrb, account-keys | ⛔ excluded | — | non-goal |
| device transfer, media, message backup, net | ⛔ excluded | — | non-goal |
| `incremental_mac`, HPKE, `session_cipher_legacy` | ⛔ excluded | — | upstream test-only |
| Language bridges (Java / Swift / Node) | ⛔ excluded | — | deleted from this fork, not ported |

Legend: ✅ implemented (v0.91.0 compat) · 🚧 staged to a later phase · ⛔
excluded (deliberate non-goal). FIPS certification and key-material zeroization
guarantees beyond the documented Go posture are also out of scope.

## Reference tree

The upstream Rust sources live under [`rust/`](rust/) as a behavioral
reference snapshot. They are **not built or shipped** — every crypto constant,
KDF info string, version byte, MAC layout, and proto field number in the Go
code is traced to a cited line in this tree and locked by a vector test. The
`rust/` tree (along with the Cargo manifests and `rust-toolchain`) is removed
at the `v0.1.0` tag once the Go implementation is self-sufficient and the
compat harness no longer needs an in-tree reference. Git history preserves it
regardless.

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
