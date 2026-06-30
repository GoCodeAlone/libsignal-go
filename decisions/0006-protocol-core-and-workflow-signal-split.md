# 0006. Split protocol core from Workflow Signal APIs

**Status:** Accepted
**Date:** 2026-06-30
**Decision-makers:** codingsloth, Codex
**Related:** README.md, compat/rust-harness/Cargo.toml

## Context

Upstream `signalapp/libsignal` v0.96.4 adds useful client/service surfaces:
authenticated username reservation, unauthenticated backups APIs, registration
session error payloads, device APIs, donation credentials, gRPC protos, and
bridge improvements. `libsignal-go` is intentionally pure-Go protocol core,
with net, usernames, zkgroup, backups, SVR, and app/service APIs listed as
non-goals.

## Decision

Keep `libsignal-go` as the protocol-core module and re-pin its compatibility
harness to v0.96.4. Do not import upstream monorepo net/bridge packages into
this module. Model server-client and collaboration features as future pure-Go
packages plus Workflow plugins that compose existing messaging, rooms, eventbus,
auth, authz, and audit plugins.

## Consequences

Protocol wire compatibility remains verifiable and low-blast-radius. Workflow
can still expose Signal-like application primitives, but those packages need
separate designs and compatibility gates. Official Signal service interaction
must remain explicit, opt-in, and compliant with the service's allowed client
behavior.
