// Package protocol implements the Signal protocol ciphertext message types and
// their wire encodings. It is a pure-Go port of rust/protocol/src/protocol.rs;
// wire encodings are byte-compatible with upstream libsignal.
//
// Task 9 (SignalMessage, PreKeySignalMessage) and Task 10 (SenderKeyMessage,
// SenderKeyDistributionMessage, PlaintextContent, DecryptionErrorMessage) are
// developed on separate branches and merged before the PR. The shared version
// constants, version-byte helpers, and ciphertext error types below live in
// this file by agreement (Task 9 owns version.go); both task sets reference
// them and neither redeclares them.
package protocol

import (
	"errors"
	"fmt"
)

// Ciphertext message version constants, mirroring protocol.rs.
const (
	// CiphertextMessageCurrentVersion is the current 1:1 ciphertext message
	// version (post-Kyber).
	CiphertextMessageCurrentVersion uint8 = 4
	// CiphertextMessagePreKyberVersion is the pre-Kyber 1:1 ciphertext message
	// version, the minimum still accepted.
	CiphertextMessagePreKyberVersion uint8 = 3
	// SenderKeyMessageCurrentVersion is the current sender-key message version.
	SenderKeyMessageCurrentVersion uint8 = 3
)

// versionByte encodes a message version into the leading wire byte:
// (messageVersion & 0xF) << 4 | currentVersion, matching protocol.rs.
func versionByte(msgVersion, currentVersion uint8) byte {
	return byte((msgVersion&0xF)<<4 | currentVersion)
}

// messageVersion extracts the message version from a leading wire byte
// (the high nibble).
func messageVersion(b byte) uint8 {
	return b >> 4
}

// ErrInvalidProtobufEncoding is returned when a message body fails protobuf
// decoding or omits a required field.
var ErrInvalidProtobufEncoding = errors.New("invalid protobuf encoding")

// CiphertextMessageTooShortError is returned when a serialized message is too
// short to contain its required fixed-size components.
type CiphertextMessageTooShortError struct {
	Length int
}

func (e CiphertextMessageTooShortError) Error() string {
	return fmt.Sprintf("ciphertext message too short: %d bytes", e.Length)
}

// LegacyCiphertextVersionError is returned when a message carries a version
// below the minimum still supported.
type LegacyCiphertextVersionError struct {
	Version uint8
}

func (e LegacyCiphertextVersionError) Error() string {
	return fmt.Sprintf("legacy ciphertext version: %d", e.Version)
}

// UnrecognizedCiphertextVersionError is returned when a message carries a
// version above the current supported version.
type UnrecognizedCiphertextVersionError struct {
	Version uint8
}

func (e UnrecognizedCiphertextVersionError) Error() string {
	return fmt.Sprintf("unrecognized ciphertext version: %d", e.Version)
}

// UnrecognizedMessageVersionError is returned when a message's leading
// identifier byte is not recognized.
type UnrecognizedMessageVersionError struct {
	Version uint32
}

func (e UnrecognizedMessageVersionError) Error() string {
	return fmt.Sprintf("unrecognized message version: %d", e.Version)
}
