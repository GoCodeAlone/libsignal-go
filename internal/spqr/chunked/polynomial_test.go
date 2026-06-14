// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package chunked

import (
	"bytes"
	"math/rand"
	"testing"
)

// Slice B oracle leg a: erasure property tests. These mirror the upstream crate's
// polynomial.rs tests (encode_and_decode_small, encode_and_decode_large) plus
// random erasure: any sufficient subset of chunks reconstructs the message. NOTE
// these are BLIND to a uniformly-wrong endianness (encoder and decoder share the
// convention) — the big-endian wire is pinned separately by the golden vectors
// in polynomial_oracle_test.go.

// TestEncodeDecodeSmall mirrors upstream encode_and_decode_small: a 10-byte
// message decodes from chunks 1 and 2 (skipping chunk 0, the literal data).
func TestEncodeDecodeSmall(t *testing.T) {
	msg := []byte("abcdefghij") // 10 bytes → 5 values
	enc, err := NewEncoder(msg)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	dec, err := NewDecoder(len(msg))
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	c1 := enc.ChunkAt(1)
	c2 := enc.ChunkAt(2)
	dec.AddChunk(&c1)
	dec.AddChunk(&c2)
	got := dec.DecodedMessage()
	if got == nil {
		t.Fatal("decode returned nil")
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("decoded %q, want %q", got, msg)
	}
}

// TestEncodeDecodeLargeAllInterpolated mirrors upstream encode_and_decode_large:
// a 1088-byte message (the ML-KEM ciphertext size; here also exercises the
// 1152-byte ek path indirectly) reconstructed entirely from chunks BEYOND the
// original data, so both encoder and decoder must interpolate every value.
func TestEncodeDecodeLargeAllInterpolated(t *testing.T) {
	for _, msgLen := range []int{1088, 1152} {
		msg := bytes.Repeat([]byte{3}, msgLen)
		enc, err := NewEncoder(msg)
		if err != nil {
			t.Fatalf("NewEncoder(%d): %v", msgLen, err)
		}
		chunksNeeded := msgLen/ChunkSize + 1
		dec, err := NewDecoder(msgLen)
		if err != nil {
			t.Fatalf("NewDecoder(%d): %v", msgLen, err)
		}
		decoded := false
		for i := chunksNeeded; i <= chunksNeeded*2+1; i++ {
			c := enc.ChunkAt(uint16(i))
			dec.AddChunk(&c)
			if got := dec.DecodedMessage(); got != nil {
				if !bytes.Equal(got, msg) {
					t.Fatalf("msgLen %d: decoded mismatch", msgLen)
				}
				decoded = true
				break
			}
		}
		if !decoded {
			t.Fatalf("msgLen %d: never decoded", msgLen)
		}
	}
}

// TestEncodeDecodeSequential decodes from the first sufficient run of chunks
// starting at 0 (the common in-order case, where early chunks carry literal
// data).
func TestEncodeDecodeSequential(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, msgLen := range []int{2, 32, 64, 320, 1088, 1152} {
		msg := make([]byte, msgLen)
		rng.Read(msg)
		enc, err := NewEncoder(msg)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		dec, err := NewDecoder(msgLen)
		if err != nil {
			t.Fatalf("NewDecoder: %v", err)
		}
		var got []byte
		for i := 0; i < 2*(msgLen/ChunkSize+2); i++ {
			c := enc.ChunkAt(uint16(i))
			dec.AddChunk(&c)
			if got = dec.DecodedMessage(); got != nil {
				break
			}
		}
		if got == nil {
			t.Fatalf("msgLen %d: never decoded sequentially", msgLen)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("msgLen %d: sequential decode mismatch", msgLen)
		}
	}
}

// TestErasureRandomSubset is the erasure-code property: for a random message,
// any sufficiently large random subset of chunk indices reconstructs it.
func TestErasureRandomSubset(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5151))
	for trial := 0; trial < 200; trial++ {
		msgLen := 2 * (1 + rng.Intn(80)) // even, 2..160 bytes
		msg := make([]byte, msgLen)
		rng.Read(msg)
		enc, err := NewEncoder(msg)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		dec, err := NewDecoder(msgLen)
		if err != nil {
			t.Fatalf("NewDecoder: %v", err)
		}
		// Feed a random permutation of a generous index range until decoded.
		idxs := rng.Perm(msgLen/2 + ChunkSize)
		var got []byte
		for _, idx := range idxs {
			c := enc.ChunkAt(uint16(idx))
			dec.AddChunk(&c)
			if got = dec.DecodedMessage(); got != nil {
				break
			}
		}
		if got == nil {
			t.Fatalf("trial %d (len %d): never decoded from subset", trial, msgLen)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("trial %d (len %d): erasure decode mismatch", trial, msgLen)
		}
	}
}

// TestOddLengthRejected guards the even-length precondition on both ends.
func TestOddLengthRejected(t *testing.T) {
	if _, err := NewEncoder([]byte{1, 2, 3}); err == nil {
		t.Fatal("NewEncoder accepted odd length")
	}
	if _, err := NewDecoder(3); err == nil {
		t.Fatal("NewDecoder accepted odd length")
	}
}
