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

// sendHdrChunkAgain (KeysSampled): emit the next hdr chunk (still sending the
// header). Stays KeysSampled.
func (s *v1State) sendHdrChunkAgain() (*v1State, chunked.Chunk) {
	chunk := s.sendingHdr.NextChunk()
	return s, chunk
}

// recvCt1ChunkKeysSampled (KeysSampled): on the first ct1 chunk, start the ct1
// decoder, switch from sending hdr to sending ek (the ek is already generated),
// and fold the chunk. → HeaderSent.
func (s *v1State) recvCt1ChunkKeysSampled(chunk *chunked.Chunk) (*v1State, error) {
	dec, err := chunked.NewDecoder(mlkem768incr.Ciphertext1Size)
	if err != nil {
		return nil, err
	}
	dec.AddChunk(chunk)
	enc, err := chunked.NewEncoder(s.ek)
	if err != nil {
		return nil, err
	}
	return &v1State{
		tag: tagHeaderSent, epoch: s.epoch, auth: s.auth,
		ek: s.ek, dk: s.dk, sendingEk: enc, recvingCt1: dec,
	}, nil
}

// sendEkChunk (HeaderSent / Ct1Received): emit the next ek chunk. Stays in the
// same tag.
func (s *v1State) sendEkChunk() (*v1State, chunked.Chunk) {
	chunk := s.sendingEk.NextChunk()
	return s, chunk
}

// recvCt1ChunkHeaderSent (HeaderSent): fold a ct1 chunk; when ct1 fully decodes,
// store it → Ct1Received; else stay HeaderSent.
func (s *v1State) recvCt1ChunkHeaderSent(chunk *chunked.Chunk) *v1State {
	s.recvingCt1.AddChunk(chunk)
	ct1 := s.recvingCt1.DecodedMessage()
	if ct1 == nil {
		return s
	}
	return &v1State{
		tag: tagCt1Received, epoch: s.epoch, auth: s.auth,
		ek: s.ek, dk: s.dk, sendingEk: s.sendingEk, ct1: ct1,
	}
}

// recvCt2ChunkCt1Received (Ct1Received): on the first ct2 chunk, start the
// ct2+mac decoder and fold the chunk. → EkSentCt1Received.
func (s *v1State) recvCt2ChunkCt1Received(chunk *chunked.Chunk) (*v1State, error) {
	dec, err := chunked.NewDecoder(mlkem768incr.Ciphertext2Size + authMACSize)
	if err != nil {
		return nil, err
	}
	dec.AddChunk(chunk)
	return &v1State{
		tag: tagEkSentCt1Received, epoch: s.epoch, auth: s.auth,
		dk: s.dk, ct1: s.ct1, recvingCt2: dec,
	}, nil
}

// recvCt2ChunkEkSent (EkSentCt1Received): fold a ct2 chunk; when ct2+mac fully
// decodes, Decapsulate(dk, ct1, ct2) → raw ss, derive the SCKA epoch secret,
// authenticator.update(epoch, secret), verify the ct MAC over ct1‖ct2, advance
// the epoch and FLIP to the send_ct role (NoHeaderReceived at epoch+1). Returns
// the EpochSecret to fold into the Chain. Mirrors unchunked recv_ct2 +
// EkSentCt1Received.recv_ct2_chunk. ok=false while still receiving.
func (s *v1State) recvCt2ChunkEkSent(chunk *chunked.Chunk) (ns *v1State, key *epochSecret, ok bool, err error) {
	s.recvingCt2.AddChunk(chunk)
	decoded := s.recvingCt2.DecodedMessage()
	if decoded == nil {
		return s, nil, false, nil
	}
	ct2 := decoded[:mlkem768incr.Ciphertext2Size]
	mac := decoded[mlkem768incr.Ciphertext2Size:]

	ss, err := mlkem768incr.DecapsulateCompressedKey(s.dk, s.ct1, ct2)
	if err != nil {
		return nil, nil, false, fmt.Errorf("spqr: decapsulate: %w", err)
	}
	secret := sckaKey(ss, s.epoch)
	s.auth.update(s.epoch, secret)
	// The ct MAC covers ct1‖ct2.
	if err := s.auth.verifyCt(s.epoch, concat(s.ct1, ct2), mac); err != nil {
		return nil, nil, false, err
	}
	// Flip to send_ct at the next epoch.
	dec, err := chunked.NewDecoder(mlkem768incr.PublicKey1Size + authMACSize)
	if err != nil {
		return nil, nil, false, err
	}
	ns = &v1State{
		tag: tagNoHeaderReceived, epoch: s.epoch + 1, auth: s.auth, recvingHdr: dec,
	}
	return ns, &epochSecret{epoch: s.epoch, secret: secret}, true, nil
}

// --- send_ct role transitions (send_ct.rs port). The send_ct side receives the
// header, Encapsulate1s to emit ct1, receives the ek, Encapsulate2s to emit
// ct2; the ek-received vs ct1-acknowledged events can complete in either order.

// recvHdrChunk (NoHeaderReceived): fold an hdr chunk; when hdr‖mac fully
// decodes, verify the hdr MAC, store the hdr → HeaderReceived; else stay.
// ok=false while still receiving. Mirrors recv_hdr_chunk + unchunked recv_header.
func (s *v1State) recvHdrChunk(chunk *chunked.Chunk) (ns *v1State, ok bool, err error) {
	s.recvingHdr.AddChunk(chunk)
	decoded := s.recvingHdr.DecodedMessage()
	if decoded == nil {
		return s, false, nil
	}
	hdr := decoded[:mlkem768incr.PublicKey1Size]
	mac := decoded[mlkem768incr.PublicKey1Size:]
	if err := s.auth.verifyHdr(s.epoch, hdr, mac); err != nil {
		return nil, false, err
	}
	// Set up the ek receiver now (HeaderReceived carries it); the send_ek peer
	// won't actually send ek chunks until it gets our first ct1, but the decoder
	// must exist so the state serializes/round-trips. Mirrors recv_hdr_chunk
	// building receiving_ek for HeaderReceived.
	dec, err := chunked.NewDecoder(mlkem768incr.PublicKey2Size)
	if err != nil {
		return nil, false, err
	}
	return &v1State{
		tag: tagHeaderReceived, epoch: s.epoch, auth: s.auth, hdr: hdr, recvingEk: dec,
	}, true, nil
}

// sendCt1 (HeaderReceived): Encapsulate1(hdr) → (ct1, es, raw ss); derive the
// SCKA epoch secret, auth.update(epoch, secret); start the ct1 encoder; → Ct1Sampled.
// Returns the EpochSecret for the Chain. Mirrors HeaderReceived.send_ct1.
func (s *v1State) sendCt1(rng io.Reader) (*v1State, chunked.Chunk, *epochSecret, error) {
	res, err := encapsulate1(s.hdr, rng)
	if err != nil {
		return nil, chunked.Chunk{}, nil, err
	}
	secret := sckaKey(res.SharedSecret, s.epoch)
	s.auth.update(s.epoch, secret)
	enc, err := chunked.NewEncoder(res.Ciphertext1)
	if err != nil {
		return nil, chunked.Chunk{}, nil, err
	}
	chunk := enc.NextChunk()
	// The ek receiver was created when the header was received (HeaderReceived
	// carries it); pass it through. Mirrors HeaderReceived.send_ct1_chunk.
	ns := &v1State{
		tag: tagCt1Sampled, epoch: s.epoch, auth: s.auth,
		hdr: s.hdr, es: res.EncapsState, ct1: res.Ciphertext1,
		sendingCt1: enc, recvingEk: s.recvingEk,
	}
	return ns, chunk, &epochSecret{epoch: s.epoch, secret: secret}, nil
}

// encapsulate1 draws a 32-byte message from rng and runs phase-1 encapsulation.
// Production wrapper around mlkem768incr.Encapsulate1Internal.
func encapsulate1(hdr []byte, rng io.Reader) (*mlkem768incr.EncapsulationResult, error) {
	var m [32]byte
	if _, err := io.ReadFull(rng, m[:]); err != nil {
		return nil, fmt.Errorf("spqr: reading encaps message: %w", err)
	}
	return mlkem768incr.Encapsulate1Internal(hdr, &m)
}

// sendCt1Chunk (Ct1Sampled): emit the next ct1 chunk. Stays Ct1Sampled.
func (s *v1State) sendCt1Chunk() (*v1State, chunked.Chunk) {
	return s, s.sendingCt1.NextChunk()
}

// recvEkChunkCt1Sampled (Ct1Sampled): fold an ek chunk; `ack` is true when the
// chunk also acknowledged ct1 (EkCt1Ack). Branches on whether the ek finished
// decoding and whether ct1 is acked — ek-done and ct1-acked can arrive in either
// order. Mirrors Ct1Sampled.recv_ek_chunk + the Ct1SampledRecvChunk variants:
//   - ek not done, not acked → StillReceivingStillSending → Ct1Sampled
//   - ek not done, acked     → StillReceiving           → Ct1Acknowledged (keeps
//                              the ek decoder; ek may still arrive out of order)
//   - ek done, not acked     → StillSending → EkReceivedCt1Sampled (stores the
//                              validated ek in the uc; still sending ct1, no decoder)
//   - ek done, acked         → Done → Ct2Sampled (Encapsulate2 immediately)
func (s *v1State) recvEkChunkCt1Sampled(chunk *chunked.Chunk, ack bool) (*v1State, error) {
	s.recvingEk.AddChunk(chunk)
	ek := s.recvingEk.DecodedMessage()
	ekDone := ek != nil

	switch {
	case !ekDone && !ack:
		return s, nil // StillReceivingStillSending
	case !ekDone && ack:
		// acked, ek not done → Ct1Acknowledged keeps the ek decoder live (uc=Ct1Sent).
		return &v1State{
			tag: tagCt1Acknowledged, epoch: s.epoch, auth: s.auth,
			hdr: s.hdr, es: s.es, ct1: s.ct1, recvingEk: s.recvingEk,
		}, nil
	case ekDone && !ack:
		// ek done, ct1 not yet acked → EkReceivedCt1Sampled stores the validated
		// ek (uc=Ct1SentEkReceived) and keeps sending ct1; no decoder remains.
		if err := s.validateEk(ek); err != nil {
			return nil, err
		}
		return &v1State{
			tag: tagEkReceivedCt1Sampled, epoch: s.epoch, auth: s.auth,
			es: s.es, ek: ek, ct1: s.ct1, sendingCt1: s.sendingCt1,
		}, nil
	default: // ekDone && ack → ready to Encapsulate2 (Ct2Sampled).
		if err := s.validateEk(ek); err != nil {
			return nil, err
		}
		return s.toCt2Sampled(ek)
	}
}

// validateEk checks the received ek matches the header (the ek_matches_header
// guard). Mirrors Ct1Sent.recv_ek's ek_matches_header check.
func (s *v1State) validateEk(ek []byte) error {
	if err := mlkem768incr.ValidatePublicKeyParts(s.hdr, ek); err != nil {
		return fmt.Errorf("%w: %v", ErrErroneousData, err)
	}
	return nil
}

// toCt2Sampled runs Encapsulate2 (which internally applies the libcrux issue-1275
// EncapsState endianness fix before the KEM encapsulate2 — the fix lives in
// mlkem768incr.Encapsulate2, NOT here), MACs ct1‖ct2, and starts the ct2+mac
// encoder. → Ct2Sampled. Mirrors Ct1SentEkReceived.send_ct2.
func (s *v1State) toCt2Sampled(ek []byte) (*v1State, error) {
	ct2, err := mlkem768incr.Encapsulate2(s.es, ek)
	if err != nil {
		return nil, fmt.Errorf("spqr: encapsulate2: %w", err)
	}
	mac := s.auth.macCt(s.epoch, concat(s.ct1, ct2))
	enc, err := chunked.NewEncoder(concat(ct2, mac))
	if err != nil {
		return nil, err
	}
	return &v1State{
		tag: tagCt2Sampled, epoch: s.epoch, auth: s.auth, sendingCt2: enc,
	}, nil
}

// recvCt1Ack (EkReceivedCt1Sampled): the ek is already decoded and stored in the
// uc; a Ct1Ack(true) or EkCt1Ack now means ct1 is acknowledged, so Encapsulate2
// and advance to Ct2Sampled. Mirrors EkReceivedCt1Sampled.recv_ct1_ack
// (uc.send_ct2). No decoder is involved.
func (s *v1State) recvCt1Ack() (*v1State, error) {
	return s.toCt2Sampled(s.ek)
}

// recvEkChunkCt1Acknowledged (Ct1Acknowledged): ct1 was acked but the ek is still
// being received (the decoder is live). Fold the chunk; once the ek decodes,
// validate it and Encapsulate2 → Ct2Sampled, else stay. Mirrors
// Ct1Acknowledged.recv_ek_chunk (uc.recv_ek then uc.send_ct2).
func (s *v1State) recvEkChunkCt1Acknowledged(chunk *chunked.Chunk) (*v1State, error) {
	s.recvingEk.AddChunk(chunk)
	ek := s.recvingEk.DecodedMessage()
	if ek == nil {
		return s, nil
	}
	if err := s.validateEk(ek); err != nil {
		return nil, err
	}
	return s.toCt2Sampled(ek)
}

// sendCt2Chunk (Ct2Sampled): emit the next ct2 chunk. Stays Ct2Sampled.
func (s *v1State) sendCt2Chunk() (*v1State, chunked.Chunk) {
	return s, s.sendingCt2.NextChunk()
}

// recvNextEpoch (Ct2Sampled): on a message for epoch+1, advance and FLIP to the
// send_ek role (KeysUnsampled at epoch+1). Mirrors Ct2Sent.recv_next_epoch.
func (s *v1State) recvNextEpoch(nextEpoch uint64) *v1State {
	return &v1State{tag: tagKeysUnsampled, epoch: nextEpoch, auth: s.auth}
}

// --- send / recv dispatch (states.rs send/recv) ---

// send advances the state by one outbound step, returning the new state, the
// message to send, and (when this step completed a KEM exchange) the EpochSecret
// for the Chain. Mirrors States::send.
func (s *v1State) send(rng io.Reader) (*v1Send, error) {
	switch s.tag {
	// --- send_ek ---
	case tagKeysUnsampled:
		ns, chunk, err := s.sendHdrChunk(rng)
		if err != nil {
			return nil, err
		}
		return &v1Send{state: ns, msg: v1Message{epoch: s.epoch, kind: payloadHdr, chunk: chunk}}, nil
	case tagKeysSampled:
		ns, chunk := s.sendHdrChunkAgain()
		return &v1Send{state: ns, msg: v1Message{epoch: s.epoch, kind: payloadHdr, chunk: chunk}}, nil
	case tagHeaderSent:
		ns, chunk := s.sendEkChunk()
		return &v1Send{state: ns, msg: v1Message{epoch: s.epoch, kind: payloadEk, chunk: chunk}}, nil
	case tagCt1Received:
		// Ct1Received sends ek chunks that ALSO acknowledge ct1 → EkCt1Ack.
		ns, chunk := s.sendEkChunk()
		return &v1Send{state: ns, msg: v1Message{epoch: s.epoch, kind: payloadEkCt1Ack, chunk: chunk}}, nil
	case tagEkSentCt1Received:
		// Done sending ek; just acknowledge ct1 (no chunk).
		return &v1Send{state: s, msg: v1Message{epoch: s.epoch, kind: payloadCt1Ack, ct1Ack: true}}, nil

	// --- send_ct ---
	case tagNoHeaderReceived:
		return &v1Send{state: s, msg: v1Message{epoch: s.epoch, kind: payloadNone}}, nil
	case tagHeaderReceived:
		ns, chunk, sec, err := s.sendCt1(rng)
		if err != nil {
			return nil, err
		}
		return &v1Send{state: ns, msg: v1Message{epoch: s.epoch, kind: payloadCt1, chunk: chunk}, key: sec}, nil
	case tagCt1Sampled:
		ns, chunk := s.sendCt1Chunk()
		return &v1Send{state: ns, msg: v1Message{epoch: s.epoch, kind: payloadCt1, chunk: chunk}}, nil
	case tagEkReceivedCt1Sampled:
		ns, chunk := s.sendCt1Chunk()
		return &v1Send{state: ns, msg: v1Message{epoch: s.epoch, kind: payloadCt1, chunk: chunk}}, nil
	case tagCt1Acknowledged:
		return &v1Send{state: s, msg: v1Message{epoch: s.epoch, kind: payloadNone}}, nil
	case tagCt2Sampled:
		ns, chunk := s.sendCt2Chunk()
		return &v1Send{state: ns, msg: v1Message{epoch: s.epoch, kind: payloadCt2, chunk: chunk}}, nil
	default:
		return nil, fmt.Errorf("spqr: invalid v1 state tag %d", s.tag)
	}
}

// recv folds an inbound message, returning the new state and (when an epoch
// completed) the EpochSecret. Out-of-range epoch is an error except the
// Ct2Sampled→next-epoch advance; a stale (older-epoch) message is a no-op; an
// equal-epoch message is processed by payload kind. Mirrors States::recv.
func (s *v1State) recv(msg *v1Message) (*v1Recv, error) {
	switch s.tag {
	// --- send_ek ---
	case tagKeysUnsampled:
		if msg.epoch > s.epoch {
			return nil, fmt.Errorf("%w: %d", ErrEpochOutOfRangeV1, msg.epoch)
		}
		return &v1Recv{state: s}, nil // no-op (Less or Equal)
	case tagKeysSampled:
		if msg.epoch > s.epoch {
			return nil, fmt.Errorf("%w: %d", ErrEpochOutOfRangeV1, msg.epoch)
		}
		if msg.epoch == s.epoch && msg.kind == payloadCt1 {
			ns, err := s.recvCt1ChunkKeysSampled(&msg.chunk)
			if err != nil {
				return nil, err
			}
			return &v1Recv{state: ns}, nil
		}
		return &v1Recv{state: s}, nil
	case tagHeaderSent:
		if msg.epoch > s.epoch {
			return nil, fmt.Errorf("%w: %d", ErrEpochOutOfRangeV1, msg.epoch)
		}
		if msg.epoch == s.epoch && msg.kind == payloadCt1 {
			return &v1Recv{state: s.recvCt1ChunkHeaderSent(&msg.chunk)}, nil
		}
		return &v1Recv{state: s}, nil
	case tagCt1Received:
		if msg.epoch > s.epoch {
			return nil, fmt.Errorf("%w: %d", ErrEpochOutOfRangeV1, msg.epoch)
		}
		if msg.epoch == s.epoch && msg.kind == payloadCt2 {
			ns, err := s.recvCt2ChunkCt1Received(&msg.chunk)
			if err != nil {
				return nil, err
			}
			return &v1Recv{state: ns}, nil
		}
		return &v1Recv{state: s}, nil
	case tagEkSentCt1Received:
		if msg.epoch > s.epoch {
			return nil, fmt.Errorf("%w: %d", ErrEpochOutOfRangeV1, msg.epoch)
		}
		if msg.epoch == s.epoch && msg.kind == payloadCt2 {
			ns, key, _, err := s.recvCt2ChunkEkSent(&msg.chunk)
			if err != nil {
				return nil, err
			}
			return &v1Recv{state: ns, key: key}, nil
		}
		return &v1Recv{state: s}, nil

	// --- send_ct ---
	case tagNoHeaderReceived:
		if msg.epoch > s.epoch {
			return nil, fmt.Errorf("%w: %d", ErrEpochOutOfRangeV1, msg.epoch)
		}
		if msg.epoch == s.epoch && msg.kind == payloadHdr {
			ns, _, err := s.recvHdrChunk(&msg.chunk)
			if err != nil {
				return nil, err
			}
			return &v1Recv{state: ns}, nil
		}
		return &v1Recv{state: s}, nil
	case tagHeaderReceived:
		if msg.epoch > s.epoch {
			return nil, fmt.Errorf("%w: %d", ErrEpochOutOfRangeV1, msg.epoch)
		}
		return &v1Recv{state: s}, nil // no inbound transition; advances only via send
	case tagCt1Sampled:
		if msg.epoch > s.epoch {
			return nil, fmt.Errorf("%w: %d", ErrEpochOutOfRangeV1, msg.epoch)
		}
		if msg.epoch == s.epoch {
			var (
				chunk *chunked.Chunk
				ack   bool
			)
			switch msg.kind {
			case payloadEk:
				chunk, ack = &msg.chunk, false
			case payloadEkCt1Ack:
				chunk, ack = &msg.chunk, true
			}
			if chunk != nil {
				ns, err := s.recvEkChunkCt1Sampled(chunk, ack)
				if err != nil {
					return nil, err
				}
				return &v1Recv{state: ns}, nil
			}
		}
		return &v1Recv{state: s}, nil
	case tagEkReceivedCt1Sampled:
		if msg.epoch > s.epoch {
			return nil, fmt.Errorf("%w: %d", ErrEpochOutOfRangeV1, msg.epoch)
		}
		// ek is already decoded+stored; a ct1 acknowledgement (Ct1Ack(true) or
		// EkCt1Ack) means Encapsulate2 and advance. Any EkCt1Ack chunk is ignored
		// (the ek is already in hand). Mirrors EkReceivedCt1Sampled.recv_ct1_ack.
		if msg.epoch == s.epoch &&
			(msg.kind == payloadEkCt1Ack || (msg.kind == payloadCt1Ack && msg.ct1Ack)) {
			ns, err := s.recvCt1Ack()
			if err != nil {
				return nil, err
			}
			return &v1Recv{state: ns}, nil
		}
		return &v1Recv{state: s}, nil
	case tagCt1Acknowledged:
		if msg.epoch > s.epoch {
			return nil, fmt.Errorf("%w: %d", ErrEpochOutOfRangeV1, msg.epoch)
		}
		// ct1 already acked but the ek is still arriving; fold any Ek/EkCt1Ack
		// chunk and advance once the ek decodes. Mirrors Ct1Acknowledged.recv_ek_chunk.
		if msg.epoch == s.epoch && (msg.kind == payloadEk || msg.kind == payloadEkCt1Ack) {
			ns, err := s.recvEkChunkCt1Acknowledged(&msg.chunk)
			if err != nil {
				return nil, err
			}
			return &v1Recv{state: ns}, nil
		}
		return &v1Recv{state: s}, nil
	case tagCt2Sampled:
		if msg.epoch > s.epoch {
			if msg.epoch == s.epoch+1 {
				return &v1Recv{state: s.recvNextEpoch(msg.epoch)}, nil
			}
			return nil, fmt.Errorf("%w: %d", ErrEpochOutOfRangeV1, msg.epoch)
		}
		return &v1Recv{state: s}, nil
	default:
		return nil, fmt.Errorf("spqr: invalid v1 state tag %d", s.tag)
	}
}

// (lib.rs orchestration — chain wiring + version negotiation — and the lockstep
// oracle follow in subsequent WIP commits.)
