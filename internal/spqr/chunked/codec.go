// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// Proto codec for the chunked Encoder / Decoder, ported from
// SparsePostQuantumRatchet v1.5.1 src/encoding/polynomial.rs (PolyEncoder /
// PolyDecoder into_pb / from_pb). The SPQR v1 state machine serializes its
// in-flight chunk streams into the PqRatchetState proto between every send/recv
// step, so these conversions are on the hot path of the lockstep oracle.
//
// Wire shapes (proto signal.proto.pq_ratchet):
//
//	PolynomialEncoder { idx, pts [][]byte, polys [][]byte }
//	  - Points state (not yet switched to polynomial evaluation): pts has 16
//	    entries, each the concatenated big-endian u16 y-values of one polynomial's
//	    stored data points (x is implicit = the value's slot index). polys empty.
//	  - Polys state (switched): polys has 16 entries, each the concatenated
//	    big-endian u16 coefficients of one interpolated polynomial. pts empty.
//	PolynomialDecoder { pts_needed, polys=16, pts [][]byte, is_complete }
//	  - pts has 16 entries, each the concatenated 4-byte points (BE16 x ‖ BE16 y)
//	    received for one polynomial. is_complete is a latch the reference never
//	    sets true (so it is always false here); decoded_message short-circuits on
//	    it, matching our point-driven DecodedMessage.
//
// All multi-byte integers are big-endian, the OPPOSITE of the KEM EncapsState
// i16 serialization — see the package doc.

package chunked

import (
	"github.com/GoCodeAlone/libsignal-go/proto"
)

// ptSize is the serialized size of one decoder point: BE16 x ‖ BE16 y.
const ptSize = 4

// EncoderToProto serializes an Encoder to its PolynomialEncoder proto. It mirrors
// PolyEncoder::into_pb: a not-yet-switched encoder emits its stored data points
// (Points state) in pts; a switched encoder emits its interpolated polynomial
// coefficients (Polys state) in polys. Exactly one of pts/polys is populated,
// each with NumPolys (16) entries.
func EncoderToProto(e *Encoder) *proto.PolynomialEncoder {
	out := &proto.PolynomialEncoder{Idx: uint32(e.idx)}
	if e.switched {
		out.Polys = make([][]byte, NumPolys)
		for p := 0; p < NumPolys; p++ {
			out.Polys[p] = serializeGF16s(e.polys[p].coeffs)
		}
	} else {
		out.Pts = make([][]byte, NumPolys)
		for p := 0; p < NumPolys; p++ {
			out.Pts[p] = serializeGF16s(e.values[p])
		}
	}
	return out
}

// EncoderFromProto reconstructs an Encoder from a PolynomialEncoder proto,
// mirroring PolyEncoder::from_pb. A non-empty pts decodes to the Points state
// (and polys must be empty); otherwise polys (which must have 16 entries)
// decodes to the Polys state. Any other shape is a serialization error.
func EncoderFromProto(pb *proto.PolynomialEncoder) (*Encoder, error) {
	e := &Encoder{idx: uint16(pb.GetIdx())}
	pts, polys := pb.GetPts(), pb.GetPolys()
	switch {
	case len(pts) != 0:
		if len(polys) != 0 || len(pts) != NumPolys {
			return nil, ErrSerializationInvalid
		}
		for p := 0; p < NumPolys; p++ {
			vs, err := deserializeGF16s(pts[p])
			if err != nil {
				return nil, err
			}
			e.values[p] = vs
		}
	case len(polys) == NumPolys:
		e.switched = true
		for p := 0; p < NumPolys; p++ {
			cs, err := deserializeGF16s(polys[p])
			if err != nil || len(cs) == 0 {
				return nil, ErrSerializationInvalid
			}
			e.polys[p] = &poly{coeffs: cs}
		}
	default:
		return nil, ErrSerializationInvalid
	}
	return e, nil
}

// DecoderToProto serializes a Decoder to its PolynomialDecoder proto, mirroring
// PolyDecoder::into_pb. It always emits NumPolys (16) point lists, polys=16, and
// is_complete=false (the latch the reference never sets).
func DecoderToProto(d *Decoder) *proto.PolynomialDecoder {
	out := &proto.PolynomialDecoder{
		PtsNeeded:  uint32(d.pointsNeeded),
		Polys:      NumPolys,
		IsComplete: false,
	}
	out.Pts = make([][]byte, NumPolys)
	for p := 0; p < NumPolys; p++ {
		buf := make([]byte, 0, len(d.pts[p])*ptSize)
		for _, point := range d.pts[p] {
			buf = append(buf,
				byte(point.x.Value>>8), byte(point.x.Value),
				byte(point.y.Value>>8), byte(point.y.Value))
		}
		out.Pts[p] = buf
	}
	return out
}

// DecoderFromProto reconstructs a Decoder from a PolynomialDecoder proto,
// mirroring PolyDecoder::from_pb. pts must have exactly NumPolys (16) entries,
// each a whole number of 4-byte points.
func DecoderFromProto(pb *proto.PolynomialDecoder) (*Decoder, error) {
	pts := pb.GetPts()
	if len(pts) != NumPolys {
		return nil, ErrSerializationInvalid
	}
	d := &Decoder{pointsNeeded: int(pb.GetPtsNeeded())}
	for p := 0; p < NumPolys; p++ {
		raw := pts[p]
		if len(raw)%ptSize != 0 {
			return nil, ErrSerializationInvalid
		}
		n := len(raw) / ptSize
		d.pts[p] = make([]pt, 0, n)
		for i := 0; i < n; i++ {
			off := i * ptSize
			d.pts[p] = append(d.pts[p], pt{
				x: GF16{Value: uint16(raw[off])<<8 | uint16(raw[off+1])},
				y: GF16{Value: uint16(raw[off+2])<<8 | uint16(raw[off+3])},
			})
		}
	}
	return d, nil
}

// serializeGF16s concatenates a slice of GF(2^16) values as big-endian u16,
// matching Point::value / Poly::serialize.
func serializeGF16s(vs []GF16) []byte {
	out := make([]byte, 0, len(vs)*2)
	for _, v := range vs {
		out = append(out, byte(v.Value>>8), byte(v.Value))
	}
	return out
}

// deserializeGF16s parses concatenated big-endian u16 values. The input length
// must be even.
func deserializeGF16s(b []byte) ([]GF16, error) {
	if len(b)%2 != 0 {
		return nil, ErrSerializationInvalid
	}
	out := make([]GF16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, GF16{Value: uint16(b[i])<<8 | uint16(b[i+1])})
	}
	return out, nil
}
