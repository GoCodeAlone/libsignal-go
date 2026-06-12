// Package protocol implements the Signal wire message types: the versioned,
// length-checked binary encodings of SignalMessage, PreKeySignalMessage, and
// the group/plaintext message forms. It is a pure-Go port of
// rust/protocol/src/protocol.rs and is wire-compatible with upstream libsignal.
package protocol

import (
	"errors"
	"fmt"
)

// Ciphertext message version constants, from rust/protocol/src/protocol.rs.
const (
	// CurrentVersion is the current ciphertext message version (PQXDH / v4).
	CurrentVersion uint8 = 4
	// PreKyberVersion is the last version without Kyber keys (v3). Messages at
	// this version are still accepted on deserialize for backward compatibility.
	PreKyberVersion uint8 = 3
	// SenderKeyCurrentVersion is the current SenderKeyMessage version
	// (SENDERKEY_MESSAGE_CURRENT_VERSION in protocol.rs). The sender-key message
	// family versions independently of the Double Ratchet messages.
	SenderKeyCurrentVersion uint8 = 3
)

// Ciphertext message type tags, from CiphertextMessageType in protocol.rs.
const (
	// MessageTypeWhisper tags a SignalMessage.
	MessageTypeWhisper uint8 = 2
	// MessageTypePreKey tags a PreKeySignalMessage.
	MessageTypePreKey uint8 = 3
	// MessageTypeSenderKey tags a SenderKeyMessage.
	MessageTypeSenderKey uint8 = 7
	// MessageTypePlaintext tags a PlaintextContent message.
	MessageTypePlaintext uint8 = 8
)

// Errors returned by this package. All are sentinel errors matchable with
// errors.Is; call sites return them either directly or %w-wrapped with context.
var (
	// ErrCiphertextTooShort is returned when a serialized message is shorter
	// than its minimum framing (version byte, and for SignalMessage the MAC).
	ErrCiphertextTooShort = errors.New("protocol: ciphertext message too short")
	// ErrLegacyVersion is returned when a message declares a version below the
	// minimum supported version (PreKyberVersion).
	ErrLegacyVersion = errors.New("protocol: legacy ciphertext version")
	// ErrUnrecognizedVersion is returned when a message declares a version
	// above CurrentVersion.
	ErrUnrecognizedVersion = errors.New("protocol: unrecognized ciphertext version")
	// ErrInvalidProtobuf is returned when the protobuf body fails to decode or
	// is missing a required field.
	ErrInvalidProtobuf = errors.New("protocol: invalid protobuf encoding")
	// ErrInvalidMACKeyLength is returned when a MAC key is not 32 bytes.
	ErrInvalidMACKeyLength = errors.New("protocol: invalid MAC key length")
	// ErrInvalidMessage is returned when a message is structurally valid but
	// semantically rejected (e.g. a v4 PreKeySignalMessage missing its Kyber
	// payload).
	ErrInvalidMessage = errors.New("protocol: invalid message")
)

// encodeVersionByte builds the leading version byte of a serialized message:
// the high nibble carries the message version, the low nibble carries the
// message family's current version, matching protocol.rs:
//
//	((message_version & 0xF) << 4) | <family>_CURRENT_VERSION
//
// SignalMessage and PreKeySignalMessage pass CurrentVersion (4);
// SenderKeyMessage passes SenderKeyCurrentVersion (3), since upstream keys the
// low nibble to SENDERKEY_MESSAGE_CURRENT_VERSION for that family.
func encodeVersionByte(messageVersion, currentVersion uint8) byte {
	return byte(((messageVersion & 0x0F) << 4) | (currentVersion & 0x0F))
}

// decodeVersion extracts the message version from a serialized message's
// leading byte (the high nibble) and validates it against the supported range
// [PreKyberVersion, CurrentVersion]. Mirrors the version checks in the
// TryFrom<&[u8]> impls in protocol.rs.
func decodeVersion(versionByte byte) (uint8, error) {
	v := uint8(versionByte) >> 4
	if v < PreKyberVersion {
		return 0, fmt.Errorf("%w: %d", ErrLegacyVersion, v)
	}
	if v > CurrentVersion {
		return 0, fmt.Errorf("%w: %d", ErrUnrecognizedVersion, v)
	}
	return v, nil
}
