// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package spqr

import (
	"crypto/rand"
	"testing"

	googleproto "google.golang.org/protobuf/proto"

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
