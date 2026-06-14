# Security Policy

`libsignal-go` is an **independent, community pure-Go reimplementation** of the
Signal client protocol. It is **not affiliated with, endorsed by, or maintained
by Signal Messenger LLC.** Wire compatibility with
[`signalapp/libsignal`](https://github.com/signalapp/libsignal) does not imply
any relationship with — or support from — the upstream project.

## Reporting a vulnerability in this library

If you've found a security issue **in `libsignal-go`** — a flaw in this Go
port's own code (cryptographic, parsing, state-machine, or memory-safety),
including a place where this port diverges from upstream in a security-relevant
way — please report it **privately** to the maintainers:

- **Open a private security advisory:**
  <https://github.com/GoCodeAlone/libsignal-go/security/advisories/new>

Please do **not** open a public issue for a security-sensitive report. We will
acknowledge the report, triage it, and coordinate a fix and disclosure with you.

## Report it to the right project

- **A flaw in this Go port** → report it **here** (`GoCodeAlone/libsignal-go`),
  via the private advisory link above.
- **A flaw in the Signal app, the Signal service, or the upstream Signal
  protocol / Rust `libsignal` itself** → that is **not** this project. Report it
  to Signal at <https://signal.org/security/>.

Please do not send reports about this Go port to Signal (they do not maintain
it), and please do not file upstream-Signal issues here.

## Scope

**In scope:** the shipped Go module — the protocol and cryptography packages
under this repository.

**Out of scope:** the upstream Rust implementation and the Signal
apps/services; the cross-implementation compatibility harness's third-party
build dependencies (report those to their respective projects); and findings
that only restate documented, deliberate scope exclusions (see the README scope
matrix).
