// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package sealedsender

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/GoCodeAlone/libsignal-go/protocol"
)

// usmcSenderCert builds a valid embedded-signer sender certificate for USMC tests.
func usmcSenderCert(t *testing.T) *SenderCertificate {
	t.Helper()
	trustRoot := genKey(t, 50)
	serverKey := genKey(t, 51)
	senderIdentity := genKey(t, 52)
	server, err := NewServerCertificate(1, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("NewServerCertificate: %v", err)
	}
	sender, err := NewSenderCertificate("u-1", nil, senderIdentity.PublicKey, 4,
		time.UnixMilli(2_000_000_000_000).UTC(), server, serverKey.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("NewSenderCertificate: %v", err)
	}
	return sender
}

func TestUSMCRoundTrip(t *testing.T) {
	sender := usmcSenderCert(t)

	cases := []struct {
		name        string
		msgType     uint8
		contentHint ContentHint
		groupID     []byte
	}{
		{"whisper_default_no_group", protocol.MessageTypeWhisper, ContentHintDefault, nil},
		{"prekey_resendable_group", protocol.MessageTypePreKey, ContentHintResendable, []byte("group-abc")},
		{"senderkey_implicit_group", protocol.MessageTypeSenderKey, ContentHintImplicit, []byte{0x01, 0x02, 0x03}},
		{"plaintext_default_empty_group", protocol.MessageTypePlaintext, ContentHintDefault, []byte{}},
		{"whisper_unknown_hint", protocol.MessageTypeWhisper, ContentHint(42), []byte("g")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			contents := []byte("ciphertext for " + tc.name)
			usmc, err := NewUnidentifiedSenderMessageContent(tc.msgType, sender, contents, tc.contentHint, tc.groupID)
			if err != nil {
				t.Fatalf("New USMC: %v", err)
			}

			got, err := DeserializeUnidentifiedSenderMessageContent(usmc.Serialized())
			if err != nil {
				t.Fatalf("Deserialize USMC: %v", err)
			}

			if got.MessageType() != tc.msgType {
				t.Fatalf("msg type = %d, want %d", got.MessageType(), tc.msgType)
			}
			if got.ContentHint() != tc.contentHint {
				t.Fatalf("content hint = %v, want %v", got.ContentHint(), tc.contentHint)
			}
			if !bytes.Equal(got.Contents(), contents) {
				t.Fatalf("contents = %q, want %q", got.Contents(), contents)
			}
			// An empty/nil group id round-trips as absent.
			gid, present := got.GroupID()
			wantPresent := len(tc.groupID) != 0
			if present != wantPresent {
				t.Fatalf("group present = %v, want %v", present, wantPresent)
			}
			if wantPresent && !bytes.Equal(gid, tc.groupID) {
				t.Fatalf("group id = %x, want %x", gid, tc.groupID)
			}
			// Sender certificate round-trips byte-for-byte.
			if !bytes.Equal(got.Sender().Serialized(), sender.Serialized()) {
				t.Fatal("sender certificate did not round-trip")
			}
			// Re-serializing the deserialized form is byte-stable.
			if !bytes.Equal(got.Serialized(), usmc.Serialized()) {
				t.Fatal("USMC serialized form not stable across round-trip")
			}
		})
	}
}

func TestUSMCDefaultHintOmittedOnWire(t *testing.T) {
	sender := usmcSenderCert(t)
	def, err := NewUnidentifiedSenderMessageContent(protocol.MessageTypeWhisper, sender, []byte("x"), ContentHintDefault, nil)
	if err != nil {
		t.Fatalf("New USMC default: %v", err)
	}
	res, err := NewUnidentifiedSenderMessageContent(protocol.MessageTypeWhisper, sender, []byte("x"), ContentHintResendable, nil)
	if err != nil {
		t.Fatalf("New USMC resendable: %v", err)
	}
	// The Default-hint serialized form must be strictly shorter (the contentHint
	// field is omitted), proving Default maps to an absent field, not 0-on-wire.
	if len(def.Serialized()) >= len(res.Serialized()) {
		t.Fatalf("default-hint USMC (%d B) not shorter than resendable (%d B); contentHint not omitted",
			len(def.Serialized()), len(res.Serialized()))
	}
	// And a deserialized Default reads back as Default.
	got, err := DeserializeUnidentifiedSenderMessageContent(def.Serialized())
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.ContentHint() != ContentHintDefault {
		t.Fatalf("content hint = %v, want Default", got.ContentHint())
	}
}

func TestUSMCRejectsBadMessageType(t *testing.T) {
	sender := usmcSenderCert(t)
	if _, err := NewUnidentifiedSenderMessageContent(99, sender, []byte("x"), ContentHintDefault, nil); !errors.Is(err, ErrInvalidUSMC) {
		t.Fatalf("bad msg type: err = %v, want ErrInvalidUSMC", err)
	}
}

func TestUSMCRejectsNilSender(t *testing.T) {
	if _, err := NewUnidentifiedSenderMessageContent(protocol.MessageTypeWhisper, nil, []byte("x"), ContentHintDefault, nil); !errors.Is(err, ErrInvalidUSMC) {
		t.Fatalf("nil sender: err = %v, want ErrInvalidUSMC", err)
	}
}

func TestUSMCDeserializeRejectsMalformed(t *testing.T) {
	if _, err := DeserializeUnidentifiedSenderMessageContent([]byte{0xFF, 0xFF}); !errors.Is(err, ErrInvalidUSMC) {
		t.Fatalf("garbage: err = %v, want ErrInvalidUSMC", err)
	}
}

func TestContentHintString(t *testing.T) {
	for _, tc := range []struct {
		h    ContentHint
		want string
	}{
		{ContentHintDefault, "Default"},
		{ContentHintResendable, "Resendable"},
		{ContentHintImplicit, "Implicit"},
		{ContentHint(7), "Unknown(7)"},
	} {
		if got := tc.h.String(); got != tc.want {
			t.Fatalf("ContentHint(%d).String() = %q, want %q", uint32(tc.h), got, tc.want)
		}
	}
}

// FuzzDeserializeUSMC confirms parsing arbitrary bytes never panics.
func FuzzDeserializeUSMC(f *testing.F) {
	if sender, err := buildUSMCSeedSender(); err == nil {
		if usmc, err := NewUnidentifiedSenderMessageContent(protocol.MessageTypeWhisper, sender, []byte("seed"), ContentHintResendable, []byte("g")); err == nil {
			f.Add(usmc.Serialized())
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x08, 0x02}) // a lone type field
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = DeserializeUnidentifiedSenderMessageContent(data)
	})
}

// buildUSMCSeedSender builds a sender certificate for the USMC fuzz seed without
// a *testing.T.
func buildUSMCSeedSender() (*SenderCertificate, error) {
	trustRoot, err := seedKey(60)
	if err != nil {
		return nil, err
	}
	serverKey, err := seedKey(61)
	if err != nil {
		return nil, err
	}
	senderIdentity, err := seedKey(62)
	if err != nil {
		return nil, err
	}
	server, err := NewServerCertificate(1, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewSenderCertificate("u", nil, senderIdentity.PublicKey, 1,
		time.UnixMilli(2_000_000_000_000).UTC(), server, serverKey.PrivateKey, rand.Reader)
}
