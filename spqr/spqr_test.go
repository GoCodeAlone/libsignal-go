// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package spqr

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strconv"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/internal/spqr/chunked"
	"github.com/GoCodeAlone/libsignal-go/proto"
	gproto "google.golang.org/protobuf/proto"
)

func testAuthKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = 0x29
	}
	return k
}

func v1Params(dir proto.Direction, version, minVersion proto.Version) Params {
	return Params{
		Direction:   dir,
		Version:     version,
		MinVersion:  minVersion,
		AuthKey:     testAuthKey(),
		ChainParams: &proto.ChainParams{},
	}
}

// TestMessageCodecRoundTrip exercises the v1 message wire codec for every payload
// kind, including a chunk-carrying message and the chunk-less None/Ct1Ack.
func TestMessageCodecRoundTrip(t *testing.T) {
	var data [chunked.ChunkSize]byte
	for i := range data {
		data[i] = byte(i)
	}
	chunk := chunked.Chunk{Index: 1234, Data: data}

	cases := []struct {
		name  string
		msg   v1Message
		index uint32
	}{
		{"hdr", v1Message{epoch: 1, kind: payloadHdr, chunk: chunk}, 0},
		{"ek", v1Message{epoch: 2, kind: payloadEk, chunk: chunk}, 5},
		{"ekct1ack", v1Message{epoch: 3, kind: payloadEkCt1Ack, chunk: chunk}, 65535},
		{"ct1", v1Message{epoch: 7, kind: payloadCt1, chunk: chunk}, 7},
		{"ct2", v1Message{epoch: 9, kind: payloadCt2, chunk: chunk}, 300000},
		{"none", v1Message{epoch: 4, kind: payloadNone}, 0},
		{"ct1ack", v1Message{epoch: 5, kind: payloadCt1Ack, ct1Ack: true}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc := serializeMessage(&tc.msg, tc.index)
			if enc[0] != versionByteV1 {
				t.Fatalf("missing V1 version byte, got %d", enc[0])
			}
			got, idx, at, err := deserializeMessage(enc)
			if err != nil {
				t.Fatal(err)
			}
			if idx != tc.index {
				t.Fatalf("index: got %d want %d", idx, tc.index)
			}
			if at != len(enc) {
				t.Fatalf("consumed %d of %d bytes", at, len(enc))
			}
			if got.epoch != tc.msg.epoch || got.kind != tc.msg.kind || got.ct1Ack != tc.msg.ct1Ack {
				t.Fatalf("header mismatch: %+v vs %+v", got, tc.msg)
			}
			if kindHasChunk(tc.msg.kind) && (got.chunk.Index != chunk.Index || got.chunk.Data != chunk.Data) {
				t.Fatal("chunk mismatch")
			}
		})
	}
}

func TestMessageCodecRejectsMalformed(t *testing.T) {
	if _, _, _, err := deserializeMessage(nil); err == nil {
		t.Fatal("expected error for empty message")
	}
	if _, _, _, err := deserializeMessage([]byte{0x02}); err == nil {
		t.Fatal("expected error for wrong version byte")
	}
	// V1, epoch=0 → invalid.
	if _, _, _, err := deserializeMessage([]byte{versionByteV1, 0x00, 0x00, msgTypeNone}); err == nil {
		t.Fatal("expected error for zero epoch")
	}
	// V1, epoch=1, index=0, Ct1 type but truncated chunk.
	if _, _, _, err := deserializeMessage([]byte{versionByteV1, 0x01, 0x00, msgTypeCt1}); err == nil {
		t.Fatal("expected error for truncated chunk")
	}
}

// TestOrchestrationLockstep mirrors lib.rs lockstep_run_with_logging: 30 rounds
// of A->B then B->A, asserting both sides derive the same message key each step
// and the post-negotiation key is eventually non-nil (a real PQ secret).
func TestOrchestrationLockstep(t *testing.T) {
	alex, err := InitialState(v1Params(proto.Direction_A_2_B, proto.Version_V_1, proto.Version_V_1))
	if err != nil {
		t.Fatal(err)
	}
	blake, err := InitialState(v1Params(proto.Direction_B_2_A, proto.Version_V_1, proto.Version_V_1))
	if err != nil {
		t.Fatal(err)
	}

	sawKey := false
	for i := 0; i < 30; i++ {
		// A -> B
		sr, err := Send(alex, rand.Reader)
		if err != nil {
			t.Fatalf("step %d alex send: %v", i, err)
		}
		alex = sr.State
		rr, err := Recv(blake, sr.Msg)
		if err != nil {
			t.Fatalf("step %d blake recv: %v", i, err)
		}
		blake = rr.State
		if !bytes.Equal(sr.Key, rr.Key) {
			t.Fatalf("step %d A->B key mismatch: %x vs %x", i, sr.Key, rr.Key)
		}
		if sr.Key != nil {
			sawKey = true
		}

		// B -> A
		sr, err = Send(blake, rand.Reader)
		if err != nil {
			t.Fatalf("step %d blake send: %v", i, err)
		}
		blake = sr.State
		rr, err = Recv(alex, sr.Msg)
		if err != nil {
			t.Fatalf("step %d alex recv: %v", i, err)
		}
		alex = rr.State
		if !bytes.Equal(sr.Key, rr.Key) {
			t.Fatalf("step %d B->A key mismatch: %x vs %x", i, sr.Key, rr.Key)
		}
		if sr.Key != nil {
			sawKey = true
		}
	}
	if !sawKey {
		t.Fatal("no PQ message key was ever produced over 30 rounds")
	}
}

// TestNegotiateToV0 mirrors lib.rs negotiate_to_v0_a2b: a V1 peer with
// min_version V0 talking to a V0 peer negotiates down to V0.
func TestNegotiateToV0(t *testing.T) {
	alex, err := InitialState(v1Params(proto.Direction_A_2_B, proto.Version_V_1, proto.Version_V_0))
	if err != nil {
		t.Fatal(err)
	}
	blake, err := InitialState(v1Params(proto.Direction_B_2_A, proto.Version_V_0, proto.Version_V_0))
	if err != nil {
		t.Fatal(err)
	}

	ns, err := Negotiation(alex)
	if err != nil {
		t.Fatal(err)
	}
	if !ns.Negotiating || ns.Version != proto.Version_V_1 || ns.MinVersion != proto.Version_V_0 {
		t.Fatalf("alex negotiation: %+v", ns)
	}
	ns, err = Negotiation(blake)
	if err != nil {
		t.Fatal(err)
	}
	if ns.Negotiating || ns.Version != proto.Version_V_0 {
		t.Fatalf("blake negotiation: %+v", ns)
	}

	sr, err := Send(alex, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alex = sr.State
	rr, err := Recv(blake, sr.Msg)
	if err != nil {
		t.Fatal(err)
	}
	blake = rr.State
	sr, err = Send(blake, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rr, err = Recv(alex, sr.Msg)
	if err != nil {
		t.Fatal(err)
	}
	alex = rr.State

	ns, err = Negotiation(alex)
	if err != nil {
		t.Fatal(err)
	}
	if ns.Negotiating || ns.Version != proto.Version_V_0 {
		t.Fatalf("alex did not negotiate to V0: %+v", ns)
	}
}

// TestNegotiationRefused mirrors lib.rs negotiation_refused_a2b: a V1 peer with
// min_version V1 talking to a V0 peer must reject the V0 message.
func TestNegotiationRefused(t *testing.T) {
	alex, err := InitialState(v1Params(proto.Direction_A_2_B, proto.Version_V_1, proto.Version_V_1))
	if err != nil {
		t.Fatal(err)
	}
	blake, err := InitialState(v1Params(proto.Direction_B_2_A, proto.Version_V_0, proto.Version_V_0))
	if err != nil {
		t.Fatal(err)
	}
	sr, err := Send(alex, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alex = sr.State
	if _, err := Recv(blake, sr.Msg); err != nil {
		t.Fatal(err)
	}
	bs, err := Send(blake, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// blake (V0) sends an empty message; alex (min V1) must refuse to negotiate down.
	if _, err := Recv(alex, bs.Msg); err != ErrMinimumVersion {
		t.Fatalf("expected ErrMinimumVersion, got %v", err)
	}
}

func TestV16HigherVersionNegotiation(t *testing.T) {
	for _, version := range []byte{2, 255} {
		t.Run(strconv.Itoa(int(version)), func(t *testing.T) {
			a, _ := InitialState(v1Params(proto.Direction_A_2_B, proto.Version_V_1, proto.Version_V_1))
			b, _ := InitialState(v1Params(proto.Direction_B_2_A, proto.Version_V_1, proto.Version_V_1))
			sent, err := Send(b, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			sent.Msg[0] = version
			got, err := Recv(a, sent.Msg)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Key, sent.Key) || got.Key == nil {
				t.Fatalf("higher-version key: got %x want %x", got.Key, sent.Key)
			}
			before, _ := DecodeState(a)
			after, _ := DecodeState(got.State)
			if after.GetChain() == nil || after.GetVersionNegotiation() == nil {
				t.Fatal("higher-version receive must advance the chain and keep negotiation open")
			}
			if !gproto.Equal(before.GetV1(), after.GetV1()) {
				t.Fatal("higher-version payload must not advance the v1 state machine")
			}
			// Replaying the same index must exercise the retained receive chain.
			if _, err := Recv(got.State, sent.Msg); !errors.Is(err, ErrKeyAlreadyRequested) {
				t.Fatalf("replay: got %v want ErrKeyAlreadyRequested", err)
			}
		})
	}
}

func TestV16VersionErrors(t *testing.T) {
	initial, _ := InitialState(v1Params(proto.Direction_A_2_B, proto.Version_V_1, proto.Version_V_0))
	st, _ := DecodeState(initial)
	st.Chain = newChain(testAuthKey(), proto.Direction_A_2_B, &proto.ChainParams{}).toProto()
	st.VersionNegotiation = nil
	closed, _ := EncodeState(st)
	for _, tc := range []struct {
		name  string
		state []byte
		msg   []byte
		want  error
	}{
		{"closed_higher", closed, []byte{2, 1, 1, msgTypeNone}, ErrVersionMismatch},
		{"closed_highest", closed, []byte{255, 1, 1, msgTypeNone}, ErrVersionMismatch},
		{"closed_below_minimum", closed, nil, ErrMinimumVersion},
		{"closed_malformed_higher", closed, []byte{2}, ErrMsgDecode},
		{"disabled_malformed", nil, []byte{2}, ErrMsgDecode},
		{"open_zero_epoch", initial, []byte{2, 0, 1}, ErrMsgDecode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Recv(tc.state, tc.msg); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestV16HigherVersionZeroIndex(t *testing.T) {
	initial, _ := InitialState(v1Params(proto.Direction_A_2_B, proto.Version_V_1, proto.Version_V_0))
	got, err := Recv(initial, []byte{2, 1, 0, msgTypeNone})
	if err != nil {
		t.Fatal(err)
	}
	if got.Key == nil || len(got.Key) != 0 {
		t.Fatalf("expected present empty key, got %#v", got.Key)
	}
	st, _ := DecodeState(got.State)
	if st.GetChain() == nil || st.GetVersionNegotiation() == nil {
		t.Fatal("expected chain and open negotiation")
	}
}

func TestV16StoredMinimumWraps(t *testing.T) {
	for _, tc := range []struct {
		stored int32
		floor  byte
	}{
		{-1, 255},
		{256, 0},
		{257, 1},
	} {
		for _, version := range []byte{0, 1, 255} {
			t.Run(strconv.FormatInt(int64(tc.stored), 10)+"/"+strconv.Itoa(int(version)), func(t *testing.T) {
				initial, err := InitialState(v1Params(proto.Direction_A_2_B, proto.Version_V_1, proto.Version_V_1))
				if err != nil {
					t.Fatal(err)
				}
				st, err := DecodeState(initial)
				if err != nil {
					t.Fatal(err)
				}
				st.VersionNegotiation.MinVersion = proto.Version(tc.stored)
				initial, err = EncodeState(st)
				if err != nil {
					t.Fatal(err)
				}
				var message []byte
				if version != 0 {
					message = []byte{version, 1, 1, msgTypeNone}
				}
				got, err := Recv(initial, message)
				if version < tc.floor {
					if !errors.Is(err, ErrMinimumVersion) || got != nil {
						t.Fatalf("got result=%v err=%v; want ErrMinimumVersion", got, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if version == 0 {
					if len(got.State) != 0 || got.Key != nil {
						t.Fatal("wrapped minimum zero must allow downgrade to v0")
					}
				} else if len(got.Key) != chainKeyLen {
					t.Fatalf("got key length %d want %d", len(got.Key), chainKeyLen)
				}
			})
		}
	}
}
