// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Consumes the committed sealedsender decrypt vectors (compat/vectors/
// sealedsender.json, upstream-generated) and checks the pure-Go sealedsender
// package decrypts and validates them — no Rust toolchain needed at test time.
// This complements the live sealed interop (sealed_interop_test.go), which
// proves both directions but requires the harness binary.
package compat

import (
	"bytes"
	"testing"
	"time"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/sealedsender"
)

// TestSealedSenderVectors decrypts each committed sealed v1 message with the
// recorded recipient identity private key, validates the recovered sender
// certificate against the recorded trust root, and confirms the recovered
// content and sender uuid match. validationTime is well before the cases'
// far-future expirations.
func TestSealedSenderVectors(t *testing.T) {
	var batch struct {
		Cases []struct {
			Version                  string `json:"version"`
			RecipientIdentityPrivate string `json:"recipient_identity_private"`
			RecipientIdentityPublic  string `json:"recipient_identity_public"`
			TrustRoot                string `json:"trust_root"`
			ExpectedContent          string `json:"expected_content"`
			ExpectedSenderUUID       string `json:"expected_sender_uuid"`
			Sealed                   string `json:"sealed"`
		} `json:"cases"`
	}
	loadVectors(t, "sealedsender", &batch)

	const minCases = 8
	if len(batch.Cases) < minCases {
		t.Fatalf("sealedsender: %d cases, want >= %d", len(batch.Cases), minCases)
	}

	validationTime := time.UnixMilli(1_500_000_000_000).UTC()
	for i, c := range batch.Cases {
		if c.Version != "v1" {
			t.Fatalf("case %d: unexpected version %q", i, c.Version)
		}
		recipientPriv, err := curve.DeserializePrivateKey(mustHex(t, c.RecipientIdentityPrivate))
		if err != nil {
			t.Fatalf("case %d: recipient private key: %v", i, err)
		}
		recipient, err := curve.KeyPairFromPrivateKey(recipientPriv)
		if err != nil {
			t.Fatalf("case %d: recipient key pair: %v", i, err)
		}
		trustRoot, err := curve.DeserializePublicKey(mustHex(t, c.TrustRoot))
		if err != nil {
			t.Fatalf("case %d: trust root: %v", i, err)
		}

		usmc, err := sealedsender.DecryptToUSMCAndValidate(mustHex(t, c.Sealed), recipient, trustRoot, validationTime)
		if err != nil {
			t.Fatalf("case %d: DecryptToUSMCAndValidate: %v", i, err)
		}
		if !bytes.Equal(usmc.Contents(), mustHex(t, c.ExpectedContent)) {
			t.Fatalf("case %d: content mismatch", i)
		}
		if usmc.Sender().SenderUUID() != c.ExpectedSenderUUID {
			t.Fatalf("case %d: sender uuid = %q, want %q", i, usmc.Sender().SenderUUID(), c.ExpectedSenderUUID)
		}
	}

	t.Logf("sealedsender: %d v1 decrypt vectors validated against upstream", len(batch.Cases))
}
