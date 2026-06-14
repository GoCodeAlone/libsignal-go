// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package spqr

import (
	"crypto/rand"
	"testing"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/GoCodeAlone/libsignal-go/internal/mlkem768incr"
	"github.com/GoCodeAlone/libsignal-go/internal/spqr/chunked"
	"github.com/GoCodeAlone/libsignal-go/proto"
)

// rtV1 round-trips a v1State through proto and asserts the proto bytes are stable
// (toProto∘fromProto∘toProto == toProto), which is the invariant the per-step
// state serialization in the orchestration depends on.
func rtV1(t *testing.T, s *v1State) *v1State {
	t.Helper()
	pb1 := v1StateToProto(s)
	b1, err := googleproto.Marshal(pb1)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := v1StateFromProto(pb1)
	if err != nil {
		t.Fatalf("fromProto (tag %d): %v", s.tag, err)
	}
	if got.tag != s.tag {
		t.Fatalf("tag changed: %d -> %d", s.tag, got.tag)
	}
	b2, err := googleproto.Marshal(v1StateToProto(got))
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("v1State proto round-trip not stable for tag %d", s.tag)
	}
	return got
}

// TestV1StateCodecRoundTripDrivenStates drives a lockstep A<->B exchange and
// round-trips both states through the proto codec at every step, covering all
// states the protocol traverses (and asserting the machine still completes
// epochs afterward).
func TestV1StateCodecRoundTripDrivenStates(t *testing.T) {
	authKey := make([]byte, 32)
	for i := range authKey {
		authKey[i] = 0x29
	}
	a := newSendEkState(authKey)
	b := newSendCtState(authKey)

	// Round-trip the two initial states.
	a = rtV1(t, a)
	b = rtV1(t, b)

	seenTags := map[stateTag]bool{}
	step := func(sender, receiver *v1State) (*v1State, *v1State) {
		t.Helper()
		sr, err := sender.send(rand.Reader)
		if err != nil {
			t.Fatalf("send (tag %d): %v", sender.tag, err)
		}
		ns := rtV1(t, sr.state)
		seenTags[ns.tag] = true
		rr, err := receiver.recv(&sr.msg)
		if err != nil {
			t.Fatalf("recv (tag %d): %v", receiver.tag, err)
		}
		nr := rtV1(t, rr.state)
		seenTags[nr.tag] = true
		return ns, nr
	}

	// Run enough lockstep rounds to advance several epochs (so the roles flip and
	// every state variant is exercised on at least one side).
	for i := 0; i < 60; i++ {
		a, b = step(a, b)
		b, a = step(b, a)
	}

	// We should have observed states from both roles, including the terminal
	// Ct2Sampled / EkSentCt1Received variants that complete an epoch.
	if len(seenTags) < 6 {
		t.Fatalf("expected to traverse many states, saw only %d distinct tags", len(seenTags))
	}
}

// TestV1StateFromProtoRejectsEmpty checks the error paths.
func TestV1StateFromProtoRejectsEmpty(t *testing.T) {
	if _, err := v1StateFromProto(nil); err == nil {
		t.Fatal("expected error for nil V1State")
	}
	if _, err := v1StateFromProto(&proto.V1State{}); err == nil {
		t.Fatal("expected error for V1State with no inner variant")
	}
	// A state variant present but missing its uc.
	bad := &proto.V1State{InnerState: &proto.V1State_KeysUnsampled{
		KeysUnsampled: &proto.V1State_Chunked_KeysUnsampled{},
	}}
	if _, err := v1StateFromProto(bad); err == nil {
		t.Fatal("expected error for missing uc")
	}
}

// newTestEncoder builds a valid Encoder over a zero message of the given byte
// length (must be even) for codec round-trip coverage.
func newTestEncoder(t *testing.T, n int) *chunked.Encoder {
	t.Helper()
	e, err := chunked.NewEncoder(make([]byte, n))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// newTestDecoder builds a valid Decoder for a message of the given byte length.
func newTestDecoder(t *testing.T, n int) *chunked.Decoder {
	t.Helper()
	d, err := chunked.NewDecoder(n)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestV1StateCodecAllTags exhaustively round-trips a constructed v1State for
// every one of the 11 state tags through the proto codec, asserting tag
// preservation and proto-byte stability. The byte/encoder/decoder field set per
// tag matches v1StateToProto's per-state mapping; sizes follow the KEM artifact
// sizes (header 64, ek 1152, dk 2400, es 2080, ct1 960, ct2 128). This closes
// the coverage gap left by the driven test (which only guarantees >=6 tags).
func TestV1StateCodecAllTags(t *testing.T) {
	authKey := make([]byte, 32)
	for i := range authKey {
		authKey[i] = 0x29
	}
	mkAuth := func() *authenticator { return newAuthenticator(authKey, 1) }

	const (
		hdrMACLen = mlkem768incr.PublicKey1Size + authMACSize
		ekLen     = mlkem768incr.PublicKey2Size
		ct1Len    = mlkem768incr.Ciphertext1Size
		ct2MACLen = mlkem768incr.Ciphertext2Size + authMACSize
	)
	hdr := make([]byte, mlkem768incr.PublicKey1Size)
	ek := make([]byte, mlkem768incr.PublicKey2Size)
	dk := make([]byte, mlkem768incr.DecapsulationKeySize)
	es := make([]byte, mlkem768incr.EncapsStateSize)
	ct1 := make([]byte, mlkem768incr.Ciphertext1Size)

	build := func(tag stateTag) *v1State {
		s := &v1State{tag: tag, epoch: 1, auth: mkAuth()}
		switch tag {
		case tagKeysUnsampled:
			// just tag/epoch/auth
		case tagKeysSampled:
			s.ek, s.dk = ek, dk
			s.sendingHdr = newTestEncoder(t, hdrMACLen)
		case tagHeaderSent:
			s.dk = dk
			s.sendingEk = newTestEncoder(t, ekLen)
			s.recvingCt1 = newTestDecoder(t, ct1Len)
		case tagCt1Received:
			s.dk, s.ct1 = dk, ct1
			s.sendingEk = newTestEncoder(t, ekLen)
		case tagEkSentCt1Received:
			s.dk, s.ct1 = dk, ct1
			s.recvingCt2 = newTestDecoder(t, ct2MACLen)
		case tagNoHeaderReceived:
			s.recvingHdr = newTestDecoder(t, hdrMACLen)
		case tagHeaderReceived:
			s.hdr = hdr
			s.recvingEk = newTestDecoder(t, ekLen)
		case tagCt1Sampled:
			s.hdr, s.es, s.ct1 = hdr, es, ct1
			s.sendingCt1 = newTestEncoder(t, ct1Len)
			s.recvingEk = newTestDecoder(t, ekLen)
		case tagEkReceivedCt1Sampled:
			s.es, s.ek, s.ct1 = es, ek, ct1
			s.sendingCt1 = newTestEncoder(t, ct1Len)
		case tagCt1Acknowledged:
			s.hdr, s.es, s.ct1 = hdr, es, ct1
			s.recvingEk = newTestDecoder(t, ekLen)
		case tagCt2Sampled:
			s.sendingCt2 = newTestEncoder(t, ct2MACLen)
		}
		return s
	}

	allTags := []stateTag{
		tagKeysUnsampled, tagKeysSampled, tagHeaderSent, tagCt1Received, tagEkSentCt1Received,
		tagNoHeaderReceived, tagHeaderReceived, tagCt1Sampled, tagEkReceivedCt1Sampled,
		tagCt1Acknowledged, tagCt2Sampled,
	}
	for _, tag := range allTags {
		got := rtV1(t, build(tag))
		if got.tag != tag {
			t.Fatalf("tag %d not preserved", tag)
		}
	}
	if len(allTags) != 11 {
		t.Fatalf("expected 11 tags, listed %d", len(allTags))
	}
}
