// Package crypto provides thin, allocation-conscious wrappers over the Go
// standard library's symmetric primitives, with an error taxonomy and
// semantics mirroring upstream signalapp/libsignal (rust/crypto and
// rust/protocol/src/crypto.rs). These are internal building blocks for the
// Signal protocol; they are not part of the module's public API.
//
// The package name intentionally matches the import path mandated by the
// implementation plan (internal/crypto). Being import-restricted to this
// module, the stdlib-name shadowing that revive warns about cannot affect
// external callers (see the scoped exclusion in .golangci.yml).
package crypto

import "errors"

// Sentinel errors returned by this package. They are wrapped with %w so callers
// can match them with errors.Is.
//
// The taxonomy mirrors rust/crypto/src/error.rs and the per-module error enums:
// CBC distinguishes a bad key/IV from corrupt ciphertext; CTR/GCM distinguish
// bad key size, bad nonce size, and (for GCM) tag mismatch. Padding/MAC failures
// are deliberately reported as a single "bad ciphertext" condition because, per
// the upstream comment, message corruption can manifest as either and the cases
// must not be distinguishable to an attacker.
var (
	// ErrInvalidKeySize is returned when a key is not the expected length.
	ErrInvalidKeySize = errors.New("crypto: invalid key size")
	// ErrInvalidNonceSize is returned when a nonce/IV is not the expected length.
	ErrInvalidNonceSize = errors.New("crypto: invalid nonce size")
	// ErrInvalidTag is returned when an AES-GCM authentication tag is the wrong
	// length or fails verification.
	ErrInvalidTag = errors.New("crypto: invalid authentication tag")
	// ErrBadCiphertext is returned when ciphertext is malformed (e.g. wrong
	// length or invalid padding). It intentionally does not distinguish the
	// specific failure mode.
	ErrBadCiphertext = errors.New("crypto: bad ciphertext")
)
