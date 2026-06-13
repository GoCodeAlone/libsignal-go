// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This package is a from-scratch Go port. Its FIPS-203 ML-KEM-768 PKE/KEM core
// (field arithmetic, NTT, sampling, compression, byte encoding) is MODELED ON
// the Go standard library's crypto/internal/fips140/mlkem implementation, which
// carries:
//
//	Copyright 2023 The Go Authors. All rights reserved.
//	Use of this source code is governed by a BSD-style license.
//	(see https://go.googlesource.com/go/+/refs/heads/master/LICENSE)
//
// The Go BSD-3-Clause license is compatible with this project's AGPL-3.0-only.
// We re-derive (do not copy verbatim) the FIPS-203 primitives in idiomatic form;
// the attribution is retained per the BSD license and ADR 0003.

// Package mlkem768incr implements the INCREMENTAL ML-KEM-768 key encapsulation
// used by Signal's Sparse Post-Quantum Ratchet (SPQR), as a pure-Go port (no
// cgo) of the libcrux-ml-kem 0.0.8 `incremental` API that SPQR v1.5.1 depends
// on. Standard ML-KEM-768 transports the whole encapsulation key at once; the
// incremental variant splits it into a small header (pk1) and a chunkable
// encapsulation key (pk2), and encapsulates in two phases (encapsulate1 emits
// the u-ciphertext from the header alone; encapsulate2 emits the v-ciphertext
// once the pk2 chunk arrives). This lets the bulky encapsulation key be
// transported in pieces across SPQR epochs.
//
// The package is built in two layers, each verified independently (ADR 0003):
//
//   - The FIPS-203 ML-KEM-768 PKE/KEM core — modeled on Go stdlib's FIPS-203
//     implementation, and verified against (1) the stdlib crypto/mlkem package
//     for end-to-end shared-secret equality and (2) the NIST/ACVP ML-KEM-768
//     known-answer tests, which pin the intermediate byte encodings (catching a
//     compensating-error pair that an end-to-end-only check could mask).
//
//   - The libcrux incremental split/serialization layer (pk1/pk2 framing,
//     two-phase encapsulation, the EncapsState byte layout including the
//     issue-1275 endianness handling, and decapsulate_compressed_key) — verified
//     byte-for-byte against known-answer vectors generated from libcrux-ml-kem
//     0.0.8 itself (the exact revision SPQR v1.5.1 pins).
//
// Byte-exactness with libcrux is the deliverable: SPQR serializes these KEM
// bytes into its own wire/state, so any divergence breaks mainline interop.
package mlkem768incr
