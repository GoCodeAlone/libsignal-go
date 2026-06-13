// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package chunked

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Slice B oracle leg (c): golden byte vectors captured from the SPQR v1.5.1
// crate (test-utils feature), via the Rust compat harness:
//
//	compat/rust-harness $ cargo build --release
//	./target/release/rust-harness gen-vectors spqr-chunks \
//	    > internal/spqr/chunked/testdata/spqr_chunks.json
//
// This pins the parts the erasure property test is blind to: the GF(2^16)
// arithmetic (mul/div triples) and the BIG-endian u16 point/coefficient wire
// serialization (chunk_at output bytes). A uniformly-wrong endianness would pass
// every property test but fail these golden vectors.

type gfTriple struct {
	A        uint16  `json:"a"`
	B        uint16  `json:"b"`
	Product  uint16  `json:"product"`
	Quotient *uint16 `json:"quotient"` // absent when b == 0
}

type chunkVec struct {
	Index uint16 `json:"index"`
	Data  string `json:"data"`
}

type chunkCase struct {
	MsgIndex int        `json:"msg_index"`
	Message  string     `json:"message"`
	Chunks   []chunkVec `json:"chunks"`
}

type spqrChunkVectors struct {
	Domain    string      `json:"domain"`
	Cases     []chunkCase `json:"cases"`
	GFTriples []gfTriple  `json:"gf_triples"`
}

func loadSPQRChunkVectors(t *testing.T) *spqrChunkVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/spqr_chunks.json")
	if err != nil {
		t.Fatalf("read spqr-chunks vectors: %v", err)
	}
	var v spqrChunkVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode spqr-chunks vectors: %v", err)
	}
	if v.Domain != "spqr-chunks" {
		t.Fatalf("unexpected domain %q", v.Domain)
	}
	if len(v.Cases) == 0 || len(v.GFTriples) == 0 {
		t.Fatal("empty spqr-chunks vectors")
	}
	return &v
}

func unhexB(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// TestGF16OracleTriples pins gfMul/gfDiv to the genuine SPQR GF16 arithmetic.
func TestGF16OracleTriples(t *testing.T) {
	v := loadSPQRChunkVectors(t)
	for i, tr := range v.GFTriples {
		if got := gfMul(tr.A, tr.B); got != tr.Product {
			t.Fatalf("triple %d: gfMul(%#x,%#x)=%#x, crate=%#x", i, tr.A, tr.B, got, tr.Product)
		}
		if tr.Quotient != nil {
			if got := gfDiv(tr.A, tr.B); got != *tr.Quotient {
				t.Fatalf("triple %d: gfDiv(%#x,%#x)=%#x, crate=%#x", i, tr.A, tr.B, got, *tr.Quotient)
			}
		}
	}
	t.Logf("GF16: %d mul/div triples match SPQR v1.5.1 byte-for-byte", len(v.GFTriples))
}

// TestChunkOracleBytes pins Encoder.ChunkAt output to the crate's big-endian
// chunk wire bytes, across the literal-data range and the interpolated range.
func TestChunkOracleBytes(t *testing.T) {
	v := loadSPQRChunkVectors(t)
	totalChunks := 0
	for ci, c := range v.Cases {
		enc, err := NewEncoder(unhexB(t, c.Message))
		if err != nil {
			t.Fatalf("case %d: NewEncoder: %v", ci, err)
		}
		for _, cv := range c.Chunks {
			got := enc.ChunkAt(cv.Index)
			if got.Index != cv.Index {
				t.Fatalf("case %d idx %d: index field mismatch", ci, cv.Index)
			}
			want := unhexB(t, cv.Data)
			if !bytes.Equal(got.Data[:], want) {
				t.Fatalf("case %d idx %d: chunk bytes mismatch vs SPQR\n got=%x\nwant=%x",
					ci, cv.Index, got.Data[:], want)
			}
			totalChunks++
		}
	}
	t.Logf("chunks: %d chunk_at vectors across %d messages match SPQR v1.5.1 byte-for-byte (BE-u16 wire)",
		totalChunks, len(v.Cases))
}

// TestChunkOracleRoundTrip decodes each golden message back from its golden
// chunks through the Go decoder, confirming the full encode→wire→decode path
// agrees with the crate's encoder output (not just the encoder side).
func TestChunkOracleRoundTrip(t *testing.T) {
	v := loadSPQRChunkVectors(t)
	for ci, c := range v.Cases {
		msg := unhexB(t, c.Message)
		dec, err := NewDecoder(len(msg))
		if err != nil {
			t.Fatalf("case %d: NewDecoder: %v", ci, err)
		}
		var got []byte
		for _, cv := range c.Chunks {
			var chunk Chunk
			chunk.Index = cv.Index
			copy(chunk.Data[:], unhexB(t, cv.Data))
			dec.AddChunk(&chunk)
			if got = dec.DecodedMessage(); got != nil {
				break
			}
		}
		if got == nil {
			t.Fatalf("case %d: never decoded from golden chunks", ci)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("case %d: decoded golden chunks != message", ci)
		}
	}
}
