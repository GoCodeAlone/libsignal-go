// Package spqr implements Signal's Sparse Post-Quantum Ratchet (SPQR), the
// Stage-2 post-quantum layer that augments the Double Ratchet with chunked
// ML-KEM-768 key agreement. It is a pure-Go port of the SPQR reference crate
// (sparsepostquantumratchet v1.5.1) layered on the incremental ML-KEM-768 KEM
// in internal/mlkem768incr.
//
// This file is Slice A: the ratchet-state codec. A SPQR ratchet state is
// serialized as the signal.proto.pq_ratchet.PqRatchetState protobuf — version
// negotiation, the Double-Ratchet-style epoch Chain, and a V1State holding the
// in-flight incremental-KEM artifacts (header, encaps key, encaps state,
// ciphertexts) plus the chunk-transport encoder/decoder state. The codec is a
// transparent byte round-trip over that proto: it stores and returns the exact
// bytes, performing no normalization (the libcrux issue-1275 endianness fix
// lives in the encapsulate2 path, not here). The chunked transport (Slice B)
// and the send/recv state machine (Slice C) build on this codec.
package spqr

import (
	"errors"
	"fmt"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/GoCodeAlone/libsignal-go/proto"
)

// DefaultMaxJump is the SPQR Chain's default cap on how far ahead of the current
// counter a message key may be requested; a stored ChainParams.max_jump of 0
// resolves to this. It matches the protocol-wide forward-jump cap (the same
// 25000 value as the Double Ratchet / sender-key bound, groups.MaxForwardJumps);
// SPQR carries it as its own ChainParams field (proto pq_ratchet ChainParams),
// so it is named here rather than imported across the domain boundary.
const DefaultMaxJump uint32 = 25000

// Errors returned by the state codec, %w-wrappable and errors.Is-matchable.
var (
	// ErrInvalidState is returned when a serialized state cannot be decoded as a
	// PqRatchetState protobuf.
	ErrInvalidState = errors.New("spqr: invalid serialized state")
)

// SerializedState is a SPQR ratchet state in its wire/storage form: the
// PqRatchetState protobuf bytes. The empty slice is the initial "no SPQR yet"
// state (libcrux empty_state()).
type SerializedState = []byte

// EmptyState returns the initial serialized state: empty bytes. Decoding it
// yields a PqRatchetState with no inner version (V0 / SPQR disabled), matching
// the reference empty_state().
func EmptyState() SerializedState { return []byte{} }

// DecodeState parses a serialized state into the generated PqRatchetState
// proto. An empty input decodes to a zero PqRatchetState (V0). Malformed input
// returns ErrInvalidState and never panics.
func DecodeState(b SerializedState) (*proto.PqRatchetState, error) {
	var st proto.PqRatchetState
	if err := googleproto.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	return &st, nil
}

// EncodeState serializes a PqRatchetState back to its wire bytes. For a state
// obtained from DecodeState and left unmodified, this reproduces the input
// bytes exactly (the codec is a transparent byte round-trip — see the package
// doc and the fixture round-trip test).
func EncodeState(st *proto.PqRatchetState) (SerializedState, error) {
	out, err := googleproto.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("spqr: encoding state: %w", err)
	}
	return out, nil
}

// CurrentVersion reports the SPQR version a serialized state is operating at.
// A state with no inner is V0 (SPQR disabled); a V1State inner is V1. Mirrors
// the reference current_version (the version-negotiation detail — whether
// negotiation is still in progress — is a Slice C concern and not decoded here).
func CurrentVersion(b SerializedState) (proto.Version, error) {
	st, err := DecodeState(b)
	if err != nil {
		return proto.Version_V_0, err
	}
	if st.GetV1() != nil {
		return proto.Version_V_1, nil
	}
	return proto.Version_V_0, nil
}

// ResolveMaxJump returns the effective max-jump cap for a ChainParams: the
// stored value, or DefaultMaxJump when it is zero (the proto default). Mirrors
// the reference "if zero, defaults to 25,000".
func ResolveMaxJump(p *proto.ChainParams) uint32 {
	if p == nil || p.GetMaxJump() == 0 {
		return DefaultMaxJump
	}
	return p.GetMaxJump()
}

// EmbeddedEncapsState returns the incremental-KEM EncapsState (es) bytes carried
// by the state's current V1State variant, or (nil, false) when the variant holds
// no es. The send_ct side stores an es between encapsulate1 and encapsulate2; it
// lives in the Ct1Sent / Ct1SentEkReceived unchunked states (reached via the
// Ct1Sampled, Ct1Acknowledged, and EkReceivedCt1Sampled chunked variants).
//
// The bytes are returned verbatim, exactly as stored — possibly carrying the
// libcrux issue-1275 swapped endianness. The codec never normalizes them; the
// encapsulate2 path (mlkem768incr.FixEncapsStateEndianness) does, just before
// use. This accessor lets that path (Slice C) and the codec's own round-trip
// test reach the embedded es.
func EmbeddedEncapsState(st *proto.PqRatchetState) ([]byte, bool) {
	v1 := st.GetV1()
	if v1 == nil {
		return nil, false
	}
	switch {
	case v1.GetCt1Sampled() != nil:
		return nonEmpty(v1.GetCt1Sampled().GetUc().GetEs())
	case v1.GetCt1Acknowledged() != nil:
		return nonEmpty(v1.GetCt1Acknowledged().GetUc().GetEs())
	case v1.GetEkReceivedCt1Sampled() != nil:
		return nonEmpty(v1.GetEkReceivedCt1Sampled().GetUc().GetEs())
	default:
		return nil, false
	}
}

// nonEmpty reports an es slice as present only when it is non-empty.
func nonEmpty(b []byte) ([]byte, bool) {
	if len(b) == 0 {
		return nil, false
	}
	return b, true
}
