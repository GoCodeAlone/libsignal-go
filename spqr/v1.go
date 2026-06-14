// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// The SPQR v1 two-role chunked state machine, ported from
// SparsePostQuantumRatchet v1.5.1 src/v1/chunked/{states,send_ek,send_ct}.rs and
// src/v1/unchunked/{send_ek,send_ct}.rs. This is the heart of Slice C: it wires
// the incremental ML-KEM-768 KEM (internal/mlkem768incr), the GF(2^16) chunk
// transport (internal/spqr/chunked), the authenticator (authenticator.go), and
// — at the lib.rs send/recv layer — the epoch Chain (chain.go).
//
// Roles: one party starts as send_ek (init_a — generates the KEM keypair and
// chunk-sends the header then the encapsulation key, eventually Decapsulating);
// the other starts as send_ct (init_b — receives the header, Encapsulate1s to
// emit ct1, receives the ek, Encapsulate2s to emit ct2). When a KEM exchange
// completes, the epoch advances and the two roles SWAP. Each epoch derives one
// EpochSecret (the SCKA key) that the Chain folds in.
//
// WIP (T27 Slice C, 3/N): this file is the v1 machine; the lib.rs send/recv
// orchestration (chain wiring + version negotiation) and the lockstep oracle
// follow. Committed incrementally.

package spqr

import (
	"errors"
	"fmt"
	"io"

	"github.com/GoCodeAlone/libsignal-go/internal/mlkem768incr"
	"github.com/GoCodeAlone/libsignal-go/internal/spqr/chunked"
)

// SCKA key-derivation: the raw KEM shared secret is run through HKDF with this
// info (‖ BE64(epoch)) to produce the per-epoch EpochSecret. Mirrors the
// "Signal_PQCKA_V1_MLKEM768:SCKA Key" derivation in unchunked send_ct1/recv_ct2.
var sckaKeyInfo = []byte("Signal_PQCKA_V1_MLKEM768:SCKA Key")

// v1 errors mirroring the relevant reference Error variants.
var (
	// ErrEpochOutOfRangeV1 is returned when a received message's epoch is ahead
	// of the state's. Mirrors Error::EpochOutOfRange in the v1 dispatch.
	ErrEpochOutOfRangeV1 = errors.New("spqr: v1 message epoch out of range")
	// ErrErroneousData is returned when a received ek does not match the header
	// it should correspond to. Mirrors Error::ErroneousDataReceived.
	ErrErroneousData = errors.New("spqr: erroneous data received")
)

// messageKind tags a v1 message payload (the V1Msg oneof). None carries no
// chunk (a pure no-op turn); Ct1Ack carries a bool.
type messageKind uint8

const (
	payloadNone messageKind = iota
	payloadHdr
	payloadEk
	payloadEkCt1Ack
	payloadCt1Ack
	payloadCt1
	payloadCt2
)

// v1Message is one SPQR v1 message: the negotiating epoch, the payload kind, and
// (for chunk kinds) the chunk, or (for Ct1Ack) the ack bool. Mirrors
// states.rs Message { epoch, payload }.
type v1Message struct {
	epoch  uint64
	kind   messageKind
	chunk  chunked.Chunk // valid when kind is a chunk kind
	ct1Ack bool          // valid when kind == payloadCt1Ack
}

// v1Send is the result of a v1 send step: the new state, the message to send,
// and (when an epoch completed) the EpochSecret to fold into the Chain. Mirrors
// states.rs Send.
type v1Send struct {
	state *v1State
	msg   v1Message
	key   *epochSecret // nil unless an epoch secret was produced this step
}

// v1Recv is the result of a v1 recv step. Mirrors states.rs Recv.
type v1Recv struct {
	state *v1State
	key   *epochSecret
}

// stateTag identifies which of the 11 v1 states a v1State holds.
type stateTag uint8

const (
	// send_ek role.
	tagKeysUnsampled stateTag = iota
	tagKeysSampled
	tagHeaderSent
	tagCt1Received
	tagEkSentCt1Received
	// send_ct role.
	tagNoHeaderReceived
	tagHeaderReceived
	tagCt1Sampled
	tagEkReceivedCt1Sampled
	tagCt1Acknowledged
	tagCt2Sampled
)

// v1State is the SPQR v1 chunked state: a tag plus the union of fields the 11
// states use (Go has no sum types; the tag selects which fields are live). It
// holds the per-epoch authenticator, the KEM artifacts in flight, and the
// chunk-transport encoder/decoder(s) for the current message stream(s).
//
// Field liveness by tag follows the reference state structs (send_ek.rs /
// send_ct.rs); see each transition for which fields it reads/writes.
type v1State struct {
	tag   stateTag
	epoch uint64
	auth  *authenticator

	// KEM artifacts (subset live per tag).
	hdr []byte // 64  (send_ct: HeaderReceived/Ct1Sent)
	ek  []byte // 1152 (send_ek: HeaderSent/...; send_ct: Ct1SentEkReceived)
	dk  []byte // 2400 (send_ek: HeaderSent/EkSent/...)
	es  []byte // 2080 (send_ct: Ct1Sent/Ct1SentEkReceived) — the issue-1275 site
	ct1 []byte // 960  (send_ek/ send_ct after ct1 known)

	// Chunk transport (subset live per tag).
	sendingHdr *chunked.Encoder
	sendingEk  *chunked.Encoder
	sendingCt1 *chunked.Encoder
	sendingCt2 *chunked.Encoder
	recvingHdr *chunked.Decoder
	recvingEk  *chunked.Decoder
	recvingCt1 *chunked.Decoder
	recvingCt2 *chunked.Decoder
}

// newSendEkState returns the initial send_ek state (init_a): KeysUnsampled at
// epoch 1 with the authenticator seeded from authKey.
func newSendEkState(authKey []byte) *v1State {
	return &v1State{tag: tagKeysUnsampled, epoch: 1, auth: newAuthenticator(authKey, 1)}
}

// newSendCtState returns the initial send_ct state (init_b): NoHeaderReceived at
// epoch 1, authenticator seeded from authKey, with an hdr decoder ready.
func newSendCtState(authKey []byte) *v1State {
	dec, _ := chunked.NewDecoder(mlkem768incr.PublicKey1Size + authMACSize)
	return &v1State{
		tag:        tagNoHeaderReceived,
		epoch:      1,
		auth:       newAuthenticator(authKey, 1),
		recvingHdr: dec,
	}
}

// sckaKey derives the per-epoch EpochSecret from a raw KEM shared secret:
// HKDF(salt=zeros32, ikm=ss, info="…SCKA Key"‖BE64(epoch), 32). Mirrors the
// SCKA-key step in send_ct1 / recv_ct2.
func sckaKey(ss []byte, epoch uint64) []byte {
	info := append(append([]byte(nil), sckaKeyInfo...), be64(epoch)...)
	return chainHKDF(zeroSalt32, ss, info, 32)
}

// --- send_ek role transitions (the unchunked KEM/MAC steps inlined with the
// chunked encoder/decoder lifecycle from send_ek.rs). ---

// sendHdrChunk (KeysUnsampled): generate the KEM keypair, MAC the header, encode
// hdr‖mac into the hdr PolyEncoder, and emit the first chunk. → KeysSampled.
func (s *v1State) sendHdrChunk(rng io.Reader) (*v1State, chunked.Chunk, error) {
	keys, err := generateIncrementalKey(rng)
	if err != nil {
		return nil, chunked.Chunk{}, err
	}
	mac := s.auth.macHdr(s.epoch, keys.PK1)
	enc, err := chunked.NewEncoder(append(append([]byte(nil), keys.PK1...), mac...))
	if err != nil {
		return nil, chunked.Chunk{}, err
	}
	chunk := enc.NextChunk()
	ns := &v1State{
		tag: tagKeysSampled, epoch: s.epoch, auth: s.auth,
		ek: keys.PK2, dk: keys.DK, sendingHdr: enc,
	}
	return ns, chunk, nil
}

// generateIncrementalKey draws a 64-byte seed from rng and expands the
// incremental KEM keypair. Production helper around mlkem768incr.
func generateIncrementalKey(rng io.Reader) (*mlkem768incr.IncrementalKey, error) {
	seed := make([]byte, mlkem768incr.SeedSize)
	if _, err := io.ReadFull(rng, seed); err != nil {
		return nil, fmt.Errorf("spqr: reading keygen seed: %w", err)
	}
	return mlkem768incr.GenerateIncrementalKey(seed)
}

// (Remaining send_ek + send_ct transitions and the send/recv dispatch follow in
// subsequent WIP commits — this is the in-progress v1 machine, 3/N.)
