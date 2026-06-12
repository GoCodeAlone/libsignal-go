package protocol

import (
	"fmt"

	"github.com/GoCodeAlone/libsignal-go/proto"
	googleproto "google.golang.org/protobuf/proto"
)

const (
	// plaintextContentIdentifierByte identifies a serialized PlaintextContent.
	// It ensures an arbitrary Content message is not interpreted as
	// PlaintextContent; only messages safe to send as plaintext carry it.
	plaintextContentIdentifierByte = 0xC0
	// paddingBoundaryByte marks the end of the message and the start of any
	// padding. PlaintextContent messages are fixed-length, so no padding
	// follows in practice.
	paddingBoundaryByte = 0x80
)

// PlaintextContent is a message that may be sent without encryption. Its wire
// form is the identifier byte (0xC0), a Content protobuf body, and a trailing
// padding-boundary byte (0x80).
type PlaintextContent struct {
	serialized []byte
}

// NewPlaintextContentFromDecryptionError wraps a DecryptionErrorMessage as
// PlaintextContent, matching the upstream From<DecryptionErrorMessage>
// conversion.
func NewPlaintextContentFromDecryptionError(message *DecryptionErrorMessage) (*PlaintextContent, error) {
	content := &proto.Content{
		DecryptionErrorMessage: message.Serialized(),
	}
	body, err := googleproto.Marshal(content)
	if err != nil {
		return nil, err
	}
	serialized := make([]byte, 0, 1+len(body)+1)
	serialized = append(serialized, plaintextContentIdentifierByte)
	serialized = append(serialized, body...)
	serialized = append(serialized, paddingBoundaryByte)
	return &PlaintextContent{serialized: serialized}, nil
}

// DeserializePlaintextContent parses the wire form, requiring the leading
// identifier byte. The body is not further decoded here (it mirrors upstream,
// which stores the serialized form and exposes the body via Body).
func DeserializePlaintextContent(value []byte) (*PlaintextContent, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("%w: empty plaintext content", ErrCiphertextTooShort)
	}
	if value[0] != plaintextContentIdentifierByte {
		return nil, fmt.Errorf("%w: bad plaintext identifier byte 0x%02x", ErrUnrecognizedVersion, value[0])
	}
	serialized := make([]byte, len(value))
	copy(serialized, value)
	return &PlaintextContent{serialized: serialized}, nil
}

// Body returns the message contents after the identifier byte.
func (m *PlaintextContent) Body() []byte {
	return m.serialized[1:]
}

// Serialized returns the full wire encoding.
func (m *PlaintextContent) Serialized() []byte {
	return m.serialized
}
