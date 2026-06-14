// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/proto"
	"github.com/GoCodeAlone/libsignal-go/spqr"
)

// seedPQRState builds an initialized SessionState carrying a fresh SPQR state
// for the given direction (the auth_key is shared so the two sides agree).
func seedPQRState(t *testing.T, dir proto.Direction, authKey []byte) *SessionState {
	t.Helper()
	st, err := spqr.InitialState(spqr.Params{
		Direction:   dir,
		Version:     proto.Version_V_1,
		MinVersion:  proto.Version_V_0,
		AuthKey:     authKey,
		ChainParams: &proto.ChainParams{MaxJump: MaxForwardJumps, MaxOooKeys: MaxMessageKeys},
	})
	if err != nil {
		t.Fatalf("spqr.InitialState(%v): %v", dir, err)
	}
	s := NewEmptySessionState()
	s.SetPQRatchetState(st)
	return s
}

// TestPQRatchetSendRecvLockstep drives PQRatchetSend / PQRatchetRecv across two
// session states seeded with matching A2B/B2A SPQR initial states, asserting
// the SPQR keys agree both directions over many rounds and that the stored
// state advances each step (mirrors the spqr lockstep, but through the session
// wrappers).
func TestPQRatchetSendRecvLockstep(t *testing.T) {
	authKey := bytes.Repeat([]byte{0x29}, 32)
	alice := seedPQRState(t, proto.Direction_A_2_B, authKey)
	bob := seedPQRState(t, proto.Direction_B_2_A, authKey)

	sawKey := false
	for i := 0; i < 30; i++ {
		// A -> B
		prevA := append([]byte(nil), alice.PQRatchetState()...)
		msg, sk, err := alice.PQRatchetSend(rand.Reader)
		if err != nil {
			t.Fatalf("step %d alice send: %v", i, err)
		}
		if bytes.Equal(prevA, alice.PQRatchetState()) {
			t.Fatalf("step %d: alice SPQR state did not advance on send", i)
		}
		rk, err := bob.PQRatchetRecv(msg)
		if err != nil {
			t.Fatalf("step %d bob recv: %v", i, err)
		}
		if !bytes.Equal(sk, rk) {
			t.Fatalf("step %d A->B SPQR key mismatch: %x vs %x", i, sk, rk)
		}
		if sk != nil {
			sawKey = true
		}

		// B -> A
		msg, sk, err = bob.PQRatchetSend(rand.Reader)
		if err != nil {
			t.Fatalf("step %d bob send: %v", i, err)
		}
		rk, err = alice.PQRatchetRecv(msg)
		if err != nil {
			t.Fatalf("step %d alice recv: %v", i, err)
		}
		if !bytes.Equal(sk, rk) {
			t.Fatalf("step %d B->A SPQR key mismatch: %x vs %x", i, sk, rk)
		}
		if sk != nil {
			sawKey = true
		}
	}
	if !sawKey {
		t.Fatal("no SPQR key was ever produced over 30 rounds")
	}
}

// TestPQRatchetEmptyStateNoKey confirms an empty SPQR state (a V0 / SPQR-off
// session) drives without error and contributes no key, leaving the message-key
// derivation unchanged.
func TestPQRatchetEmptyStateNoKey(t *testing.T) {
	s := NewEmptySessionState() // no SPQR state set → empty
	msg, key, err := s.PQRatchetSend(rand.Reader)
	if err != nil {
		t.Fatalf("send on empty SPQR state: %v", err)
	}
	if key != nil {
		t.Fatalf("empty SPQR state produced a key: %x", key)
	}
	if len(msg) != 0 {
		t.Fatalf("empty SPQR state produced a non-empty message: %x", msg)
	}
	rkey, err := s.PQRatchetRecv(nil)
	if err != nil {
		t.Fatalf("recv on empty SPQR state: %v", err)
	}
	if rkey != nil {
		t.Fatalf("empty SPQR recv produced a key: %x", rkey)
	}
}
