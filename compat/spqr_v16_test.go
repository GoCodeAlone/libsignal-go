// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package compat

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/spqr"
)

func TestSPQRV16Oracle(t *testing.T) {
	data, err := os.ReadFile("vectors/spqr-v16.json")
	if err != nil {
		t.Fatal(err)
	}
	var batch struct {
		Domain string `json:"domain"`
		Cases  []struct {
			Label   string `json:"label"`
			State   string `json:"state"`
			Message string `json:"message"`
			Error   string `json:"error"`
			Result  *struct {
				State string  `json:"state"`
				Key   *string `json:"key"`
			} `json:"result"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &batch); err != nil {
		t.Fatal(err)
	}
	if batch.Domain != "spqr-v16" || len(batch.Cases) != 36 {
		t.Fatalf("unexpected fixture domain=%q cases=%d", batch.Domain, len(batch.Cases))
	}
	decode := func(t *testing.T, value string) []byte {
		t.Helper()
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	errorMap := map[string]error{
		"VersionMismatch":        spqr.ErrVersionMismatch,
		"MinimumVersion":         spqr.ErrMinimumVersion,
		"MsgDecode":              spqr.ErrMsgDecode,
		"StateDecode":            spqr.ErrChainDecode,
		"KeyAlreadyRequested(1)": spqr.ErrKeyAlreadyRequested,
	}
	for _, tc := range batch.Cases {
		t.Run(tc.Label, func(t *testing.T) {
			state, message := decode(t, tc.State), decode(t, tc.Message)
			beforeState, beforeMessage := bytes.Clone(state), bytes.Clone(message)
			got, err := spqr.Recv(state, message)
			if !bytes.Equal(state, beforeState) || !bytes.Equal(message, beforeMessage) {
				t.Fatal("Recv mutated its inputs")
			}
			if tc.Error != "" {
				want, ok := errorMap[tc.Error]
				if !ok || !errors.Is(err, want) || got != nil || tc.Result != nil {
					t.Fatalf("got result=%v error=%v; want %q", got, err, tc.Error)
				}
				return
			}
			if err != nil || got == nil || tc.Result == nil {
				t.Fatalf("got result=%v error=%v; want success", got, err)
			}
			if !bytes.Equal(got.State, decode(t, tc.Result.State)) {
				t.Fatalf("state: got %x want %s", got.State, tc.Result.State)
			}
			if tc.Result.Key == nil {
				if got.Key != nil {
					t.Fatalf("got key %x want absent", got.Key)
				}
			} else if got.Key == nil || !bytes.Equal(got.Key, decode(t, *tc.Result.Key)) {
				t.Fatalf("key: got %#v want %s", got.Key, *tc.Result.Key)
			}
		})
	}
}
