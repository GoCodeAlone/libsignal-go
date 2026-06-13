// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package sealedsender

import (
	"errors"
	"fmt"

	"github.com/GoCodeAlone/libsignal-go/proto"
	"github.com/GoCodeAlone/libsignal-go/protocol"
	googleproto "google.golang.org/protobuf/proto"
)

// ErrInvalidUSMC is returned when UnidentifiedSenderMessageContent bytes are
// structurally invalid (bad protobuf, missing required field, unknown message
// type, or an unparseable embedded sender certificate).
var ErrInvalidUSMC = errors.New("sealedsender: invalid unidentified sender message content")

// ContentHint advises the recipient how to handle a decryption failure for a
// sealed-sender message. It mirrors the ContentHint enum in sealed_sender.rs.
// The zero value is ContentHintDefault, which is omitted on the wire (a sealed
// sender will not resend; an error should be shown immediately).
type ContentHint uint32

const (
	// ContentHintDefault is the wire-absent default: do not resend; show an
	// error immediately. It encodes to a missing contentHint field.
	ContentHintDefault ContentHint = 0
	// ContentHintResendable means the sender will try to resend; the recipient
	// should delay error UI if possible. Proto value 1.
	ContentHintResendable ContentHint = 1
	// ContentHintImplicit means do not show any error UI; the message was sent
	// implicitly (e.g. a typing indicator or receipt). Proto value 2.
	ContentHintImplicit ContentHint = 2
)

// String renders the known hints by name and any other value as Unknown(n),
// matching upstream's Default/Resendable/Implicit/Unknown(value) variants.
func (h ContentHint) String() string {
	switch h {
	case ContentHintDefault:
		return "Default"
	case ContentHintResendable:
		return "Resendable"
	case ContentHintImplicit:
		return "Implicit"
	default:
		return fmt.Sprintf("Unknown(%d)", uint32(h))
	}
}

// contentHintToProto returns the value to put in the proto's optional
// contentHint field: nil for Default (so it is omitted), else a pointer to the
// raw value. Mirrors ContentHint::to_proto, where Default maps to None.
func contentHintToProto(h ContentHint) *uint32 {
	if h == ContentHintDefault {
		return nil
	}
	v := uint32(h)
	return &v
}

// usmcTypeToProto maps a protocol ciphertext-message type tag (Whisper/PreKey/
// SenderKey/Plaintext) to the sealed-sender proto Type enum. It mirrors the
// CiphertextMessageType -> ProtoMessageType conversion in sealed_sender.rs.
func usmcTypeToProto(msgType uint8) (proto.UnidentifiedSenderMessage_Message_Type, error) {
	switch msgType {
	case protocol.MessageTypeWhisper:
		return proto.UnidentifiedSenderMessage_Message_MESSAGE, nil
	case protocol.MessageTypePreKey:
		return proto.UnidentifiedSenderMessage_Message_PREKEY_MESSAGE, nil
	case protocol.MessageTypeSenderKey:
		return proto.UnidentifiedSenderMessage_Message_SENDERKEY_MESSAGE, nil
	case protocol.MessageTypePlaintext:
		return proto.UnidentifiedSenderMessage_Message_PLAINTEXT_CONTENT, nil
	default:
		return 0, fmt.Errorf("%w: unknown message type %d", ErrInvalidUSMC, msgType)
	}
}

// usmcTypeFromProto maps the sealed-sender proto Type enum back to a protocol
// ciphertext-message type tag, mirroring the ProtoMessageType ->
// CiphertextMessageType conversion in sealed_sender.rs.
func usmcTypeFromProto(t proto.UnidentifiedSenderMessage_Message_Type) (uint8, error) {
	switch t {
	case proto.UnidentifiedSenderMessage_Message_MESSAGE:
		return protocol.MessageTypeWhisper, nil
	case proto.UnidentifiedSenderMessage_Message_PREKEY_MESSAGE:
		return protocol.MessageTypePreKey, nil
	case proto.UnidentifiedSenderMessage_Message_SENDERKEY_MESSAGE:
		return protocol.MessageTypeSenderKey, nil
	case proto.UnidentifiedSenderMessage_Message_PLAINTEXT_CONTENT:
		return protocol.MessageTypePlaintext, nil
	default:
		return 0, fmt.Errorf("%w: unknown proto message type %d", ErrInvalidUSMC, int32(t))
	}
}

// UnidentifiedSenderMessageContent (USMC) is the inner payload of a sealed
// sender message: the wrapped ciphertext (contents) plus the metadata needed to
// route and handle it — the message type, the sender's certificate, a content
// hint, and an optional group id. Mirrors UnidentifiedSenderMessageContent in
// sealed_sender.rs. The sealed-sender encryption that wraps this (v1/v2) is a
// later task; this type is the serialize/deserialize boundary.
type UnidentifiedSenderMessageContent struct {
	msgType     uint8 // protocol.MessageType* tag
	sender      *SenderCertificate
	contents    []byte
	contentHint ContentHint
	groupID     []byte // nil/empty when absent
	serialized  []byte
}

// NewUnidentifiedSenderMessageContent assembles a USMC and serializes it. An
// empty (or nil) groupID is omitted from the wire form, matching upstream (a
// zero-length group id encodes to a missing field). msgType must be one of the
// protocol.MessageType* tags.
func NewUnidentifiedSenderMessageContent(
	msgType uint8,
	sender *SenderCertificate,
	contents []byte,
	contentHint ContentHint,
	groupID []byte,
) (*UnidentifiedSenderMessageContent, error) {
	if sender == nil {
		return nil, fmt.Errorf("%w: nil sender certificate", ErrInvalidUSMC)
	}
	protoType, err := usmcTypeToProto(msgType)
	if err != nil {
		return nil, err
	}

	msg := &proto.UnidentifiedSenderMessage_Message{
		Type:              &protoType,
		SenderCertificate: sender.Serialized(),
		Content:           cloneBytes(contents),
		ContentHint:       contentHintToProtoEnum(contentHint),
	}
	// An empty group id is omitted (upstream maps an empty buffer to None).
	if len(groupID) != 0 {
		msg.GroupId = cloneBytes(groupID)
	}

	serialized, err := googleproto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("sealedsender: marshal USMC: %w", err)
	}

	return &UnidentifiedSenderMessageContent{
		msgType:     msgType,
		sender:      sender,
		contents:    cloneBytes(contents),
		contentHint: contentHint,
		groupID:     nonEmptyClone(groupID),
		serialized:  serialized,
	}, nil
}

// DeserializeUnidentifiedSenderMessageContent parses a serialized USMC: it
// decodes the proto, resolves the message type, parses the embedded sender
// certificate, and reads the content hint (absent => Default) and optional group
// id. Fails with ErrInvalidUSMC on a missing required field or unknown type, and
// surfaces certificate-parse failures. No signature/expiry validation is done
// here — validate the returned Sender() against a trust root separately.
func DeserializeUnidentifiedSenderMessageContent(data []byte) (*UnidentifiedSenderMessageContent, error) {
	var pb proto.UnidentifiedSenderMessage_Message
	if err := googleproto.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("%w: protobuf: %v", ErrInvalidUSMC, err)
	}

	if pb.Type == nil {
		return nil, fmt.Errorf("%w: missing message type", ErrInvalidUSMC)
	}
	msgType, err := usmcTypeFromProto(pb.GetType())
	if err != nil {
		return nil, err
	}
	if pb.SenderCertificate == nil {
		return nil, fmt.Errorf("%w: missing sender certificate", ErrInvalidUSMC)
	}
	if pb.Content == nil {
		return nil, fmt.Errorf("%w: missing content", ErrInvalidUSMC)
	}
	sender, err := DeserializeSenderCertificate(pb.GetSenderCertificate())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUSMC, err)
	}

	contentHint := ContentHintDefault
	if pb.ContentHint != nil {
		//nolint:gosec // G115: the proto enum is non-negative; ContentHint keeps
		// any unrecognized value verbatim (matching upstream's Unknown(value)).
		contentHint = ContentHint(pb.GetContentHint())
	}

	return &UnidentifiedSenderMessageContent{
		msgType:     msgType,
		sender:      sender,
		contents:    cloneBytes(pb.GetContent()),
		contentHint: contentHint,
		groupID:     nonEmptyClone(pb.GetGroupId()),
		serialized:  cloneBytes(data),
	}, nil
}

// MessageType returns the wrapped ciphertext's protocol.MessageType* tag.
func (u *UnidentifiedSenderMessageContent) MessageType() uint8 { return u.msgType }

// Sender returns the sender's certificate.
func (u *UnidentifiedSenderMessageContent) Sender() *SenderCertificate { return u.sender }

// Contents returns the wrapped ciphertext bytes.
func (u *UnidentifiedSenderMessageContent) Contents() []byte { return cloneBytes(u.contents) }

// ContentHint returns the content hint (ContentHintDefault when none was set).
func (u *UnidentifiedSenderMessageContent) ContentHint() ContentHint { return u.contentHint }

// GroupID returns the optional group id and whether one is present (an empty
// group id is treated as absent).
func (u *UnidentifiedSenderMessageContent) GroupID() ([]byte, bool) {
	if len(u.groupID) == 0 {
		return nil, false
	}
	return cloneBytes(u.groupID), true
}

// Serialized returns the full serialized USMC wire form.
func (u *UnidentifiedSenderMessageContent) Serialized() []byte { return cloneBytes(u.serialized) }

// contentHintToProtoEnum returns the proto enum pointer for the optional
// contentHint field: nil for Default (omitted), else the enum value. It bridges
// contentHintToProto's raw u32 to the generated enum type.
func contentHintToProtoEnum(h ContentHint) *proto.UnidentifiedSenderMessage_Message_ContentHint {
	raw := contentHintToProto(h)
	if raw == nil {
		return nil
	}
	//nolint:gosec // G115: round-trips the hint's own u32 value into the proto
	// enum; the value originated from a ContentHint and is preserved verbatim.
	v := proto.UnidentifiedSenderMessage_Message_ContentHint(*raw)
	return &v
}

// nonEmptyClone returns a defensive copy of b, or nil when b is empty, so an
// empty group id is stored as nil (absent) consistently.
func nonEmptyClone(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return cloneBytes(b)
}
