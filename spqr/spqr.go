// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// Top-level SPQR orchestration, ported from SparsePostQuantumRatchet v1.5.1
// src/lib.rs. This is the public surface the Double Ratchet layer calls: it
// decodes the serialized PqRatchetState, drives the v1 chunked state machine one
// step (v1.go), folds the per-epoch SCKA secret into the epoch Chain (chain.go),
// derives the message key, and re-encodes the state — performing protocol
// version negotiation along the way.
//
// Version negotiation: a state initialized at version V1 with min_version V0 may
// be negotiated DOWN to V0 by a peer that only speaks V0 (it sends an empty/V0
// message). Receiving a lower version than ours triggers the downgrade (unless
// it is below our min_version, which is an error). Once we negotiate or once we
// receive any message, negotiation is closed.
//
// The chain-epoch bridge: the v1 machine numbers epochs from 1 (the first KEM
// exchange completes epoch 1), but the Chain folds epoch secrets starting at
// epoch 1 and keys a message at chain epoch = v1_epoch - 1. So a message emitted
// while the v1 state is at epoch E draws its message key from chain epoch E-1
// (the chain epoch whose secret has already been agreed). send_key(msg.epoch-1)
// / recv_key(msg.epoch-1, index) encode this bridge.

package spqr

import (
	"errors"
	"io"

	"github.com/GoCodeAlone/libsignal-go/proto"
)

// SerializedMessage is a SPQR message in wire form (the v1 message codec bytes;
// empty for V0).
type SerializedMessage = []byte

// EpochSecret is a per-epoch shared secret the Double Ratchet should mix into its
// key schedule. (Exposed at the package boundary; internally the v1 machine and
// Chain pass the unexported epochSecret.)
type EpochSecret struct {
	Epoch  uint64
	Secret []byte
}

// Params configures a fresh SPQR state. Mirrors lib.rs Params.
type Params struct {
	Direction   proto.Direction
	Version     proto.Version
	MinVersion  proto.Version
	AuthKey     []byte
	ChainParams *proto.ChainParams
}

// SendResult is the output of Send: the new serialized state, the message to
// transmit, and an optional message key produced this step.
type SendResult struct {
	State SerializedState
	Msg   SerializedMessage
	Key   []byte // nil when no message key was produced
}

// RecvResult is the output of Recv: the new serialized state and an optional
// message key.
type RecvResult struct {
	State SerializedState
	Key   []byte // nil when no message key was produced
}

// VersionStatus reports a state's negotiation status. Mirrors lib.rs
// CurrentVersion: either still negotiating (with the proposed and minimum
// versions) or negotiation complete (at a fixed version).
type VersionStatus struct {
	Negotiating bool
	Version     proto.Version // the active/proposed version
	MinVersion  proto.Version // valid only while Negotiating
}

// Orchestration errors, mirroring the relevant lib.rs Error variants.
var (
	// ErrVersionMismatch is returned when a peer presents a lower version than
	// ours and we are not allowed to negotiate. Mirrors Error::VersionMismatch.
	ErrVersionMismatch = errors.New("spqr: version mismatch after negotiation")
	// ErrMinimumVersion is returned when a peer's version is below our configured
	// minimum. Mirrors Error::MinimumVersion.
	ErrMinimumVersion = errors.New("spqr: peer version below minimum")
	// ErrChainNotAvailable is returned when a V1 state needs its Chain but none is
	// present and no version-negotiation block can build one. Mirrors
	// Error::ChainNotAvailable.
	ErrChainNotAvailable = errors.New("spqr: chain not available")
)

// InitialState builds the initial serialized state for the given params. V0
// yields the empty state; V1 yields a PqRatchetState with the role's initial v1
// inner state and a version-negotiation block. Mirrors lib.rs initial_state.
func InitialState(p Params) (SerializedState, error) {
	if p.Version == proto.Version_V_0 {
		return EmptyState(), nil
	}
	st := &proto.PqRatchetState{
		VersionNegotiation: &proto.PqRatchetState_VersionNegotiation{
			AuthKey:     append([]byte(nil), p.AuthKey...),
			Direction:   p.Direction,
			MinVersion:  p.MinVersion,
			ChainParams: p.ChainParams,
		},
	}
	if inner := initInner(p.Version, p.Direction, p.AuthKey); inner != nil {
		st.Inner = inner
	}
	return EncodeState(st)
}

// initInner builds the v1 inner-state oneof wrapper for a version+direction, or
// nil for V0. Returns the concrete *PqRatchetState_V1 so callers can assign it
// only when non-nil (assigning a typed-nil to the interface field would make a
// non-nil interface value). Mirrors lib.rs init_inner.
func initInner(v proto.Version, d proto.Direction, authKey []byte) *proto.PqRatchetState_V1 {
	if v == proto.Version_V_0 {
		return nil
	}
	var s *v1State
	if d == proto.Direction_A_2_B {
		s = newSendEkState(authKey)
	} else {
		s = newSendCtState(authKey)
	}
	return &proto.PqRatchetState_V1{V1: v1StateToProto(s)}
}

// stateVersion reports the version implied by a decoded state's inner.
func stateVersion(st *proto.PqRatchetState) proto.Version {
	if st.GetV1() != nil {
		return proto.Version_V_1
	}
	return proto.Version_V_0
}

// Negotiation reports the negotiation status of a serialized state. Mirrors
// lib.rs current_version.
func Negotiation(b SerializedState) (VersionStatus, error) {
	st, err := DecodeState(b)
	if err != nil {
		return VersionStatus{}, err
	}
	v := stateVersion(st)
	vn := st.GetVersionNegotiation()
	if vn == nil {
		return VersionStatus{Negotiating: false, Version: v}, nil
	}
	return VersionStatus{Negotiating: true, Version: v, MinVersion: vn.GetMinVersion()}, nil
}

// Send produces the next outbound SPQR message and the updated state. For a V0
// state it returns empty state/msg and no key. Mirrors lib.rs send.
func Send(state SerializedState, rng io.Reader) (*SendResult, error) {
	st, err := DecodeState(state)
	if err != nil {
		return nil, err
	}
	if st.GetV1() == nil {
		return &SendResult{State: nil, Msg: nil, Key: nil}, nil
	}

	v1s, err := v1StateFromProto(st.GetV1())
	if err != nil {
		return nil, err
	}
	step, err := v1s.send(rng)
	if err != nil {
		return nil, err
	}

	ch, err := resolveSendChain(st)
	if err != nil {
		return nil, err
	}

	var (
		index   uint32
		msgKey  []byte
		chainPB *proto.Chain
	)
	if ch == nil {
		// No chain yet (version negotiation with min_version V0 still open): the
		// v1 machine must not have produced a key.
		if step.key != nil {
			return nil, ErrChainNotAvailable
		}
	} else {
		if step.key != nil {
			if err := ch.addEpoch(*step.key); err != nil {
				return nil, err
			}
		}
		idx, mk, kerr := ch.sendKey(step.msg.epoch - 1)
		if kerr != nil {
			return nil, kerr
		}
		index, msgKey = idx, mk
		chainPB = ch.toProto()
	}

	out := &proto.PqRatchetState{
		Inner:              &proto.PqRatchetState_V1{V1: v1StateToProto(step.state)},
		VersionNegotiation: st.GetVersionNegotiation(), // sending never changes negotiation
		Chain:              chainPB,
	}
	enc, err := EncodeState(out)
	if err != nil {
		return nil, err
	}
	return &SendResult{State: enc, Msg: serializeMessage(&step.msg, index), Key: nonEmptyKey(msgKey)}, nil
}

// Recv folds an inbound SPQR message into the state. It first performs version
// negotiation (a lower-version message may downgrade us, or be rejected), then
// drives the v1 recv step, folds any epoch secret into the Chain, and derives the
// message key. Mirrors lib.rs recv.
func Recv(state SerializedState, msg SerializedMessage) (*RecvResult, error) {
	prest, err := DecodeState(state)
	if err != nil {
		return nil, err
	}

	st, err := negotiateRecv(prest, msg)
	if err != nil {
		return nil, err
	}
	if st == nil {
		// Their version is too high for us; ignore the message, keep our state.
		return &RecvResult{State: append([]byte(nil), state...), Key: nil}, nil
	}

	if st.GetV1() == nil {
		return &RecvResult{State: nil, Key: nil}, nil
	}

	sckaMsg, index, _, derr := deserializeMessage(msg)
	if derr != nil {
		return nil, derr
	}

	v1s, err := v1StateFromProto(st.GetV1())
	if err != nil {
		return nil, err
	}
	step, err := v1s.recv(&sckaMsg)
	if err != nil {
		return nil, err
	}

	ch, err := chainFrom(st.GetChain(), st.GetVersionNegotiation())
	if err != nil {
		return nil, err
	}
	if step.key != nil {
		if err := ch.addEpoch(*step.key); err != nil {
			return nil, err
		}
	}

	keyEpoch := sckaMsg.epoch - 1
	var msgKey []byte
	if keyEpoch == 0 && index == 0 {
		msgKey = nil
	} else {
		mk, kerr := ch.recvKey(keyEpoch, index)
		if kerr != nil {
			return nil, kerr
		}
		msgKey = mk
	}

	out := &proto.PqRatchetState{
		Inner:              &proto.PqRatchetState_V1{V1: v1StateToProto(step.state)},
		VersionNegotiation: nil, // receiving clears negotiation
		Chain:              ch.toProto(),
	}
	enc, err := EncodeState(out)
	if err != nil {
		return nil, err
	}
	return &RecvResult{State: enc, Key: nonEmptyKey(msgKey)}, nil
}

// negotiateRecv performs version negotiation for an inbound message and returns
// the state to process the message against. A nil state means the message's
// version is higher than ours and should be ignored. Mirrors the negotiation
// block at the top of lib.rs recv.
func negotiateRecv(prest *proto.PqRatchetState, msg SerializedMessage) (*proto.PqRatchetState, error) {
	mv, ok := msgVersion(msg)
	if !ok {
		return nil, nil // their version is too high for us; ignore
	}
	ourV := stateVersion(prest)
	if mv >= ourV {
		return prest, nil // equal or higher-than-ours-but-recognized: proceed as-is
	}
	// Their version is lower than ours: negotiate down if allowed.
	vn := prest.GetVersionNegotiation()
	if vn == nil {
		return nil, ErrVersionMismatch
	}
	if mv < vn.GetMinVersion() {
		return nil, ErrMinimumVersion
	}
	ch, err := chainFrom(prest.GetChain(), vn)
	if err != nil {
		return nil, err
	}
	out := &proto.PqRatchetState{
		VersionNegotiation: nil, // our negotiation; disallow further
		Chain:              ch.toProto(),
	}
	if inner := initInner(mv, vn.GetDirection(), vn.GetAuthKey()); inner != nil {
		out.Inner = inner
	}
	return out, nil
}

// msgVersion returns the version byte of a serialized message (V0 for empty), or
// ok=false when the version is unrecognized (too high for us). Mirrors msg_version.
func msgVersion(msg SerializedMessage) (proto.Version, bool) {
	if len(msg) == 0 {
		return proto.Version_V_0, true
	}
	switch msg[0] {
	case byte(proto.Version_V_0):
		return proto.Version_V_0, true
	case byte(proto.Version_V_1):
		return proto.Version_V_1, true
	default:
		return 0, false
	}
}

// resolveSendChain resolves the Chain for a Send: the stored chain, or one built
// from the version-negotiation block when min_version > V0, or nil (no chain yet)
// when negotiation is still open at min_version V0. Mirrors the chain resolution
// in lib.rs send.
func resolveSendChain(st *proto.PqRatchetState) (*chain, error) {
	if pb := st.GetChain(); pb != nil {
		return chainFromProto(pb)
	}
	vn := st.GetVersionNegotiation()
	if vn == nil {
		return nil, ErrChainNotAvailable
	}
	if vn.GetMinVersion() > proto.Version_V_0 {
		return chainFromVersionNegotiation(vn)
	}
	return nil, nil
}

// chainFrom resolves a Chain from a stored chain proto, falling back to building
// one from the version-negotiation block. Mirrors lib.rs chain_from.
func chainFrom(pb *proto.Chain, vn *proto.PqRatchetState_VersionNegotiation) (*chain, error) {
	if pb != nil {
		return chainFromProto(pb)
	}
	if vn == nil {
		return nil, ErrChainNotAvailable
	}
	return chainFromVersionNegotiation(vn)
}

// chainFromVersionNegotiation builds a fresh Chain from a version-negotiation
// block. Mirrors lib.rs chain_from_version_negotiation.
func chainFromVersionNegotiation(vn *proto.PqRatchetState_VersionNegotiation) (*chain, error) {
	if vn.GetChainParams() == nil {
		return nil, ErrChainNotAvailable
	}
	return newChain(vn.GetAuthKey(), vn.GetDirection(), vn.GetChainParams()), nil
}

// nonEmptyKey maps an empty message key to nil (the "no key" sentinel),
// matching the reference's Option<Vec<u8>> filter.
func nonEmptyKey(k []byte) []byte {
	if len(k) == 0 {
		return nil
	}
	return k
}
