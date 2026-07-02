# Compatibility Vectors

This directory contains committed fixtures used to keep the pure-Go
implementation pinned to upstream `signalapp/libsignal` behavior.

Vector-backed rows in `compat/coverage_manifest.json` and
`internal/upstream/manifest.json` must cite one of these files and record the
fixture SHA-256 digest. Structural-only rows must not cite a checksum; they must
explain which upstream package boundary or fixture is still missing before this
fork can claim parity.

The current upstream pin is `v0.96.4`. These vectors prove local package
behavior only. They do not claim login, send/receive, linked-device, backup
import/export, or interoperability with the official Signal app.
