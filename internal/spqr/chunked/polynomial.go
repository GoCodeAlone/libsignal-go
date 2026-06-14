// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// SPQR chunked-transport erasure code, ported from SparsePostQuantumRatchet
// v1.5.1 src/encoding/polynomial.rs. A message (e.g. the 1152-byte incremental
// ML-KEM encapsulation key) is transported as a stream of fixed 32-byte Chunks;
// any sufficient subset of chunks reconstructs the message, so chunks can be
// dropped or reordered in transit.
//
// Scheme: the message is split into 16-bit values (big-endian u16 — note this is
// the OPPOSITE endianness of the KEM's EncapsState i16 serialization), and those
// values are distributed round-robin across NumPolys = 16 polynomials over
// GF(2^16). Value j of polynomial p is the data point (x = j, y = value). Chunk
// idx carries one point from each of the 16 polynomials at x = idx: slot i =
// poly i evaluated at x = idx, packed big-endian. The decoder collects points
// per polynomial; once a polynomial has enough points it is recovered by
// Lagrange interpolation and the message values are read back (again big-endian).
//
// We implement a straightforward Lagrange interpolation and Horner evaluation;
// the interpolating polynomial through a point set is unique, so the recovered
// polynomial — and therefore every chunk byte — matches the upstream crate's
// (heavily optimized) implementation. The golden chunk_at byte vectors in
// polynomial_oracle_test.go pin this byte-for-byte against the crate, and the
// big-endian point/coefficient serialization in particular.

package chunked

import "errors"

const (
	// ChunkSize is the fixed byte length of an encoded chunk payload.
	ChunkSize = 32
	// NumPolys is the number of GF(2^16) polynomials the message is spread
	// across (= ChunkSize / 2, one big-endian u16 per polynomial per chunk).
	NumPolys = ChunkSize / 2 // 16
)

// ErrOddLength is returned when a message or declared length is not a multiple
// of 2 (the byte width of a GF(2^16) value). The upstream encoder/decoder
// require even lengths.
var ErrOddLength = errors.New("spqr/encoding: message length must be even")

// ErrSerializationInvalid is returned when an Encoder/Decoder proto has a shape
// the codec cannot parse (wrong number of polynomial entries, a point list that
// is not a whole number of points, or both pts and polys populated). Mirrors the
// reference PolynomialError::SerializationInvalid.
var ErrSerializationInvalid = errors.New("spqr/encoding: invalid serialized encoder/decoder")

// Chunk is one encoded fragment: a 16-bit index and a fixed 32-byte payload of
// 16 big-endian GF(2^16) values.
type Chunk struct {
	Index uint16
	Data  [ChunkSize]byte
}

// poly is a polynomial over GF(2^16) in little-endian coefficient order:
// coeffs[0] is the constant term, coeffs[d] the degree-d coefficient.
type poly struct {
	coeffs []GF16
}

// evalAt evaluates the polynomial at x by Horner's method.
func (p poly) evalAt(x GF16) GF16 {
	var acc GF16 // zero
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		acc = acc.Mul(x).Add(p.coeffs[i])
	}
	return acc
}

// pt is an (x, y) data point. Points are identified and de-duplicated by their x
// value (matching the upstream Pt equality/ordering).
type pt struct {
	x GF16
	y GF16
}

// lagrangeInterpolate returns the unique polynomial of degree < len(pts) passing
// through every point (pts must have distinct x values). Standard Lagrange
// interpolation: f(x) = Σ_i y_i · Π_{j≠i} (x − x_j)/(x_i − x_j). The result is
// mathematically identical to the upstream crate's optimized interpolation, so
// evaluations (and thus chunk bytes) match.
func lagrangeInterpolate(pts []pt) poly {
	if len(pts) == 0 {
		return poly{coeffs: nil}
	}
	// Accumulate the sum of basis polynomials, each scaled by y_i.
	acc := poly{coeffs: []GF16{gfZero}}
	for i := range pts {
		// numerator = Π_{j≠i} (x − x_j); denominator = Π_{j≠i} (x_i − x_j).
		num := poly{coeffs: []GF16{gfOne}}
		denom := gfOne
		for j := range pts {
			if j == i {
				continue
			}
			num = polyMulLinear(num, pts[j].x) // multiply by (x − x_j)
			denom = denom.Mul(pts[i].x.Sub(pts[j].x))
		}
		scale := pts[i].y.Div(denom)
		acc = polyAddScaled(acc, num, scale)
	}
	return acc
}

// polyMulLinear returns p(x) · (x − root). In GF(2^16), (x − root) = (x + root)
// since subtraction is XOR.
func polyMulLinear(p poly, root GF16) poly {
	out := make([]GF16, len(p.coeffs)+1)
	for i, c := range p.coeffs {
		// Contribution to degree i+1 (the x·p term).
		out[i+1] = out[i+1].Add(c)
		// Contribution to degree i (the −root·p term).
		out[i] = out[i].Add(c.Mul(root))
	}
	return poly{coeffs: out}
}

// polyAddScaled returns dst + scale·src.
func polyAddScaled(dst, src poly, scale GF16) poly {
	if len(src.coeffs) > len(dst.coeffs) {
		grown := make([]GF16, len(src.coeffs))
		copy(grown, dst.coeffs)
		dst.coeffs = grown
	}
	for i, c := range src.coeffs {
		dst.coeffs[i] = dst.coeffs[i].Add(c.Mul(scale))
	}
	return dst
}

// --- Encoder ---

// Encoder produces a stream of Chunks from a message. It lazily switches from
// returning stored data points (for indices within the original data) to
// evaluating interpolated polynomials (for indices beyond it), matching the
// upstream PolyEncoder.
type Encoder struct {
	// values[p] holds the input GF(2^16) data points for polynomial p, where
	// values[p][j] is the point (x = j, y = values[p][j]).
	values [NumPolys][]GF16
	// polys[p] is the interpolated polynomial for p, computed lazily the first
	// time an index beyond the stored data is requested.
	polys    [NumPolys]*poly
	idx      uint16 // next index for NextChunk
	switched bool   // whether we've switched to polynomial evaluation
}

// NewEncoder builds an encoder for msg. msg length must be even.
func NewEncoder(msg []byte) (*Encoder, error) {
	if len(msg)%2 != 0 {
		return nil, ErrOddLength
	}
	e := &Encoder{}
	// Distribute big-endian u16 values round-robin across the 16 polynomials.
	for i := 0; i*2 < len(msg); i++ {
		v := (uint16(msg[i*2]) << 8) | uint16(msg[i*2+1])
		p := i % NumPolys
		e.values[p] = append(e.values[p], GF16{Value: v})
	}
	return e, nil
}

// pointAt returns the value of polynomial p at x = idx. For idx within the
// stored data it returns the literal value; beyond that it evaluates the
// (lazily interpolated) polynomial. Once any out-of-range index is requested we
// interpolate every polynomial and serve all subsequent points by evaluation —
// matching the upstream EncoderState Points→Polys transition.
func (e *Encoder) pointAt(p int, idx int) GF16 {
	if !e.switched && idx < len(e.values[p]) {
		return e.values[p][idx]
	}
	if !e.switched {
		for q := 0; q < NumPolys; q++ {
			pts := make([]pt, len(e.values[q]))
			for j, y := range e.values[q] {
				pts[j] = pt{x: GF16{Value: uint16(j)}, y: y}
			}
			pp := lagrangeInterpolate(pts)
			e.polys[q] = &pp
		}
		e.switched = true
	}
	return e.polys[p].evalAt(GF16{Value: uint16(idx)})
}

// ChunkAt returns the chunk at the given index: 16 big-endian GF(2^16) values,
// one from each polynomial, evaluated at x = idx.
func (e *Encoder) ChunkAt(idx uint16) Chunk {
	var c Chunk
	c.Index = idx
	for i := 0; i < NumPolys; i++ {
		v := e.pointAt(i, int(idx)).Value
		c.Data[i*2] = byte(v >> 8)
		c.Data[i*2+1] = byte(v)
	}
	return c
}

// NextChunk returns the next chunk in sequence (index 0, 1, 2, …).
func (e *Encoder) NextChunk() Chunk {
	c := e.ChunkAt(e.idx)
	e.idx++ // wraps at 2^16, matching the upstream wrapping_add
	return c
}

// --- Decoder ---

// Decoder reassembles a message from received Chunks. It needs pointsNeeded
// total points (= messageLen/2), distributed across the 16 polynomials.
type Decoder struct {
	pointsNeeded int
	// pts[p] holds received points for polynomial p, kept de-duplicated by x.
	pts [NumPolys][]pt
}

// NewDecoder builds a decoder for a message of msgLen bytes (must be even).
func NewDecoder(msgLen int) (*Decoder, error) {
	if msgLen%2 != 0 {
		return nil, ErrOddLength
	}
	return &Decoder{pointsNeeded: msgLen / 2}, nil
}

// necessaryPoints is how many points polynomial p needs for reconstruction:
// pointsNeeded spread across 16 polynomials, with the first (pointsNeeded%16)
// polynomials taking one extra.
func (d *Decoder) necessaryPoints(p int) int {
	per := d.pointsNeeded / NumPolys
	rem := d.pointsNeeded % NumPolys
	if p < rem {
		return per + 1
	}
	return per
}

// pushPoint adds a point to polynomial p's set unless an equal-x point is
// already present (de-duplication by x, matching the upstream SortedSet).
func (d *Decoder) pushPoint(p int, point pt) {
	for _, existing := range d.pts[p] {
		if existing.x.Value == point.x.Value {
			return
		}
	}
	d.pts[p] = append(d.pts[p], point)
}

// AddChunk folds a received chunk's 16 points into the decoder state. A point is
// kept only if its index is small enough to help decode without interpolation,
// or if the polynomial does not yet have enough points — matching the upstream
// add_chunk retention rule.
func (d *Decoder) AddChunk(c *Chunk) {
	for i := 0; i < NumPolys; i++ {
		totalIdx := int(c.Index)*NumPolys + i
		p := totalIdx % NumPolys
		polyIdx := totalIdx / NumPolys
		x := GF16{Value: uint16(polyIdx)}
		y := GF16{Value: (uint16(c.Data[i*2]) << 8) | uint16(c.Data[i*2+1])}
		if polyIdx < d.necessaryPoints(i) || len(d.pts[p]) < d.necessaryPoints(i) {
			d.pushPoint(p, pt{x: x, y: y})
		}
	}
}

// DecodedMessage attempts to reconstruct the message. It returns nil if not yet
// enough points have been received. The returned slice is pointsNeeded*2 bytes,
// each value big-endian.
func (d *Decoder) DecodedMessage() []byte {
	for i := 0; i < NumPolys; i++ {
		if len(d.pts[i]) < d.necessaryPoints(i) {
			return nil
		}
	}
	// Per-polynomial recovered polynomials, interpolated lazily.
	var polys [NumPolys]*poly
	out := make([]byte, 0, d.pointsNeeded*2)
	for i := 0; i < d.pointsNeeded; i++ {
		p := i % NumPolys
		polyIdx := i / NumPolys
		x := GF16{Value: uint16(polyIdx)}
		y, ok := d.directPoint(p, x)
		if !ok {
			if polys[p] == nil {
				need := d.necessaryPoints(p)
				pp := lagrangeInterpolate(d.pts[p][:need])
				polys[p] = &pp
			}
			y = polys[p].evalAt(x)
		}
		out = append(out, byte(y.Value>>8), byte(y.Value))
	}
	return out
}

// directPoint returns the received y at x for polynomial p if one was received,
// avoiding interpolation for points already in hand.
func (d *Decoder) directPoint(p int, x GF16) (GF16, bool) {
	for _, point := range d.pts[p] {
		if point.x.Value == x.Value {
			return point.y, true
		}
	}
	return GF16{}, false
}
