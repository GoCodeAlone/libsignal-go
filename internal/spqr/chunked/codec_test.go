// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package chunked

import (
	"bytes"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/proto"
)

// makeMsg builds a deterministic even-length test message.
func makeMsg(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return b
}

// TestEncoderProtoRoundTripPoints round-trips an encoder still in the Points
// state (no out-of-range index drawn yet) and checks subsequent chunks match.
func TestEncoderProtoRoundTripPoints(t *testing.T) {
	enc, err := NewEncoder(makeMsg(1152))
	if err != nil {
		t.Fatal(err)
	}
	// Draw a few in-range chunks; stays in Points state.
	for i := 0; i < 3; i++ {
		enc.NextChunk()
	}
	if enc.switched {
		t.Fatal("encoder unexpectedly switched to Polys state")
	}

	pb := EncoderToProto(enc)
	if len(pb.GetPolys()) != 0 || len(pb.GetPts()) != NumPolys {
		t.Fatalf("Points state: pts=%d polys=%d", len(pb.GetPts()), len(pb.GetPolys()))
	}
	got, err := EncoderFromProto(pb)
	if err != nil {
		t.Fatal(err)
	}
	// Both encoders must yield identical chunk bytes from here on, including
	// after the Points→Polys switch (which an out-of-range index forces).
	for idx := 0; idx < 200; idx++ {
		a := enc.ChunkAt(uint16(idx))
		b := got.ChunkAt(uint16(idx))
		if a.Index != b.Index || a.Data != b.Data {
			t.Fatalf("chunk %d mismatch after round-trip", idx)
		}
	}
}

// TestEncoderProtoRoundTripPolys round-trips an encoder already switched to the
// Polys state (forced by drawing an out-of-range index).
func TestEncoderProtoRoundTripPolys(t *testing.T) {
	enc, err := NewEncoder(makeMsg(64))
	if err != nil {
		t.Fatal(err)
	}
	// 64 bytes = 32 values over 16 polys = 2 points each; index 5 is out of range.
	enc.ChunkAt(5)
	if !enc.switched {
		t.Fatal("encoder did not switch to Polys state")
	}

	pb := EncoderToProto(enc)
	if len(pb.GetPts()) != 0 || len(pb.GetPolys()) != NumPolys {
		t.Fatalf("Polys state: pts=%d polys=%d", len(pb.GetPts()), len(pb.GetPolys()))
	}
	got, err := EncoderFromProto(pb)
	if err != nil {
		t.Fatal(err)
	}
	for idx := 0; idx < 100; idx++ {
		a := enc.ChunkAt(uint16(idx))
		b := got.ChunkAt(uint16(idx))
		if a.Index != b.Index || a.Data != b.Data {
			t.Fatalf("chunk %d mismatch after Polys round-trip", idx)
		}
	}
}

// TestDecoderProtoRoundTrip round-trips a partially-filled decoder and checks it
// reconstructs the original message.
func TestDecoderProtoRoundTrip(t *testing.T) {
	msg := makeMsg(1152)
	enc, err := NewEncoder(msg)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewDecoder(len(msg))
	if err != nil {
		t.Fatal(err)
	}
	// Feed half the needed chunks, round-trip, then feed the rest.
	for i := 0; i < 20; i++ {
		c := enc.NextChunk()
		dec.AddChunk(&c)
	}

	pb := DecoderToProto(dec)
	if pb.GetPtsNeeded() != uint32(len(msg)/2) || pb.GetPolys() != NumPolys || len(pb.GetPts()) != NumPolys {
		t.Fatalf("decoder pb shape: ptsNeeded=%d polys=%d pts=%d", pb.GetPtsNeeded(), pb.GetPolys(), len(pb.GetPts()))
	}
	got, err := DecoderFromProto(pb)
	if err != nil {
		t.Fatal(err)
	}
	for i := 20; i < 60; i++ {
		c := enc.NextChunk()
		dec.AddChunk(&c)
		got.AddChunk(&c)
	}
	want := dec.DecodedMessage()
	have := got.DecodedMessage()
	if want == nil || have == nil {
		t.Fatalf("decode incomplete: want=%v have=%v", want != nil, have != nil)
	}
	if !bytes.Equal(want, have) || !bytes.Equal(have, msg) {
		t.Fatal("round-tripped decoder reconstructed a different message")
	}
}

// TestEncoderFromProtoRejectsBadShapes covers the from_pb error branches.
func TestEncoderFromProtoRejectsBadShapes(t *testing.T) {
	// Both pts and polys populated → invalid.
	bad := &proto.PolynomialEncoder{
		Pts:   make([][]byte, NumPolys),
		Polys: make([][]byte, NumPolys),
	}
	if _, err := EncoderFromProto(bad); err == nil {
		t.Fatal("expected error for pts+polys both set")
	}
	// Wrong pts count → invalid.
	if _, err := EncoderFromProto(&proto.PolynomialEncoder{Pts: make([][]byte, 3)}); err == nil {
		t.Fatal("expected error for wrong pts count")
	}
	// Decoder with wrong pts count → invalid.
	if _, err := DecoderFromProto(&proto.PolynomialDecoder{Pts: make([][]byte, 3)}); err == nil {
		t.Fatal("expected error for decoder wrong pts count")
	}
}

// sixteen returns a 16-entry [][]byte with one entry replaced by bad.
func sixteen(idx int, bad []byte) [][]byte {
	out := make([][]byte, NumPolys)
	if idx >= 0 {
		out[idx] = bad
	}
	return out
}

// TestEncoderFromProtoRejectsMalformedEntries asserts the per-entry decode
// guards on the Points and Polys branches reject malformed (attacker-influenced)
// serialized state, not just wrong outer cardinality. These parse untrusted
// bytes, so the repo norm is a direct negative test on each reject path.
func TestEncoderFromProtoRejectsMalformedEntries(t *testing.T) {
	// Points branch: an odd-length pts entry (not a whole number of BE16 values).
	odd := &proto.PolynomialEncoder{Pts: sixteen(0, []byte{0x01})}
	if _, err := EncoderFromProto(odd); err == nil {
		t.Fatal("expected error for odd-length pts entry")
	}
	// Polys branch: an empty-coefficient polynomial.
	emptyPoly := &proto.PolynomialEncoder{Polys: sixteen(0, []byte{})}
	if _, err := EncoderFromProto(emptyPoly); err == nil {
		t.Fatal("expected error for empty polynomial in Polys branch")
	}
	// Polys branch: an odd-length poly entry (not a whole number of BE16 coeffs).
	oddPoly := &proto.PolynomialEncoder{Polys: sixteen(0, []byte{0x01, 0x02, 0x03})}
	if _, err := EncoderFromProto(oddPoly); err == nil {
		t.Fatal("expected error for odd-length poly entry")
	}
}

// TestDecoderFromProtoRejectsMalformedEntries asserts the decoder's per-entry
// guard: a pts entry whose length is not a multiple of 4 (one serialized point
// is BE16 x ‖ BE16 y) must be rejected.
func TestDecoderFromProtoRejectsMalformedEntries(t *testing.T) {
	notMul4 := &proto.PolynomialDecoder{Pts: sixteen(0, []byte{0x01, 0x02, 0x03})}
	if _, err := DecoderFromProto(notMul4); err == nil {
		t.Fatal("expected error for pts entry length not a multiple of 4")
	}
}
