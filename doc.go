// Package libsignal is a pure-Go implementation of the Signal client
// protocol core, wire-compatible with signalapp/libsignal.
//
// The implementation contains no cgo, C, or Rust: it is built entirely on the
// Go standard library and a small set of pure-Go cryptography dependencies. It
// targets the client-side protocol surface (curve and KEM primitives, wire
// messages, the Double Ratchet session, group sender keys, sealed sender, and
// fingerprints). Server-only and out-of-scope domains (zkgroup, usernames, key
// transparency, SVR, device transfer, media, and message backup) are not
// implemented; see the README scope matrix for the authoritative list.
//
// # Compatibility staging
//
// Wire compatibility is asserted against a pinned upstream tag rather than a
// moving target. Until the Sparse Post-Quantum Ratchet (SPQR) phase lands,
// compatibility claims are bounded to the libsignal v0.91.0 protocol surface;
// once SPQR is ported the compat harness is re-pinned to the current upstream
// mainline. This staging and its rationale are recorded in
// decisions/0001-spqr-staged-compat.md.
//
// # License
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See the
// LICENSE file at the repository root.
package libsignal
