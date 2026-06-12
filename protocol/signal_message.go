package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/GoCodeAlone/libsignal-go/curve"
	pb "github.com/GoCodeAlone/libsignal-go/proto"
)

// macLength is the truncated HMAC-SHA256 length appended to a SignalMessage,
// from SignalMessage::MAC_LENGTH in protocol.rs.
const macLength = 8

// macKeyLength is the required MAC key length.
const macKeyLength = 32

// SignalMessage is the Double Ratchet ciphertext message ("Whisper" message).
// Its wire form is: version byte ‖ protobuf body ‖ HMAC-SHA256 tag[:8].
type SignalMessage struct {
	messageVersion  uint8
	senderRatchet   curve.PublicKey
	counter         uint32
	previousCounter uint32
	ciphertext      []byte
	pqRatchet       []byte // opaque SPQR state; passed through, empty pre-P10
	addresses       []byte // optional, opaque
	serialized      []byte
}

// NewSignalMessage builds and serializes a SignalMessage, computing the MAC
// over the sender/receiver identity public keys and the versioned body, exactly
// as SignalMessage::new in protocol.rs. macKey must be 32 bytes. pqRatchet may
// be nil/empty (it is then omitted from the proto, matching upstream). addresses
// may be nil.
func NewSignalMessage(
	messageVersion uint8,
	macKey []byte,
	senderRatchetKey curve.PublicKey,
	counter uint32,
	previousCounter uint32,
	ciphertext []byte,
	senderIdentityKey curve.PublicKey,
	receiverIdentityKey curve.PublicKey,
	pqRatchet []byte,
	addresses []byte,
) (*SignalMessage, error) {
	if len(macKey) != macKeyLength {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidMACKeyLength, len(macKey), macKeyLength)
	}

	body := &pb.SignalMessage{
		RatchetKey:      senderRatchetKey.Serialize(),
		Counter:         proto.Uint32(counter),
		PreviousCounter: proto.Uint32(previousCounter),
		Ciphertext:      append([]byte(nil), ciphertext...),
	}
	if len(pqRatchet) > 0 {
		body.PqRatchet = append([]byte(nil), pqRatchet...)
	}
	if len(addresses) > 0 {
		body.Addresses = append([]byte(nil), addresses...)
	}

	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("protocol: marshaling SignalMessage: %w", err)
	}

	serialized := make([]byte, 0, 1+len(bodyBytes)+macLength)
	serialized = append(serialized, encodeVersionByte(messageVersion))
	serialized = append(serialized, bodyBytes...)

	mac, err := computeSignalMessageMAC(senderIdentityKey, receiverIdentityKey, macKey, serialized)
	if err != nil {
		return nil, err
	}
	serialized = append(serialized, mac...)

	return &SignalMessage{
		messageVersion:  messageVersion,
		senderRatchet:   senderRatchetKey,
		counter:         counter,
		previousCounter: previousCounter,
		ciphertext:      append([]byte(nil), ciphertext...),
		pqRatchet:       append([]byte(nil), pqRatchet...),
		addresses:       append([]byte(nil), addresses...),
		serialized:      serialized,
	}, nil
}

// DeserializeSignalMessage parses and validates the wire form of a
// SignalMessage. It checks the minimum length, the version range, and decodes
// the protobuf body, requiring the ratchet key, counter, and ciphertext fields.
// It does not verify the MAC; call VerifyMAC for that.
func DeserializeSignalMessage(value []byte) (*SignalMessage, error) {
	if len(value) < macLength+1 {
		return nil, fmt.Errorf("%w: %d bytes", ErrCiphertextTooShort, len(value))
	}
	version, err := decodeVersion(value[0])
	if err != nil {
		return nil, err
	}

	bodyBytes := value[1 : len(value)-macLength]
	var body pb.SignalMessage
	if err := proto.Unmarshal(bodyBytes, &body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProtobuf, err)
	}
	if body.RatchetKey == nil || body.Counter == nil || body.Ciphertext == nil {
		return nil, fmt.Errorf("%w: missing required SignalMessage field", ErrInvalidProtobuf)
	}
	ratchet, err := curve.DeserializePublicKey(body.RatchetKey)
	if err != nil {
		return nil, fmt.Errorf("%w: ratchet key: %v", ErrInvalidProtobuf, err)
	}

	return &SignalMessage{
		messageVersion:  version,
		senderRatchet:   ratchet,
		counter:         body.GetCounter(),
		previousCounter: body.GetPreviousCounter(), // defaults to 0 if absent
		ciphertext:      body.GetCiphertext(),
		pqRatchet:       body.GetPqRatchet(), // nil/empty if absent
		addresses:       body.GetAddresses(),
		serialized:      append([]byte(nil), value...),
	}, nil
}

// VerifyMAC recomputes the message's MAC from the identity keys and mac key and
// compares it (in constant time) against the trailing tag. It returns false on
// mismatch and an error only for a malformed mac key. Mirrors
// SignalMessage::verify_mac.
func (m *SignalMessage) VerifyMAC(senderIdentityKey, receiverIdentityKey curve.PublicKey, macKey []byte) (bool, error) {
	if len(m.serialized) < macLength {
		return false, fmt.Errorf("%w: %d bytes", ErrCiphertextTooShort, len(m.serialized))
	}
	content := m.serialized[:len(m.serialized)-macLength]
	theirMAC := m.serialized[len(m.serialized)-macLength:]
	ourMAC, err := computeSignalMessageMAC(senderIdentityKey, receiverIdentityKey, macKey, content)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(ourMAC, theirMAC) == 1, nil
}

// computeSignalMessageMAC computes HMAC-SHA256(macKey, senderIdentityPub ‖
// receiverIdentityPub ‖ message)[:8], where the identity public keys are in
// their 33-byte serialized form. Mirrors SignalMessage::compute_mac.
func computeSignalMessageMAC(senderIdentityKey, receiverIdentityKey curve.PublicKey, macKey, message []byte) ([]byte, error) {
	if len(macKey) != macKeyLength {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidMACKeyLength, len(macKey), macKeyLength)
	}
	mac := hmac.New(sha256.New, macKey)
	mac.Write(senderIdentityKey.Serialize())
	mac.Write(receiverIdentityKey.Serialize())
	mac.Write(message)
	return mac.Sum(nil)[:macLength], nil
}

// MessageVersion returns the message's protocol version.
func (m *SignalMessage) MessageVersion() uint8 { return m.messageVersion }

// SenderRatchetKey returns the sender's ratchet public key.
func (m *SignalMessage) SenderRatchetKey() curve.PublicKey { return m.senderRatchet }

// Counter returns the message counter.
func (m *SignalMessage) Counter() uint32 { return m.counter }

// PreviousCounter returns the previous-chain counter.
func (m *SignalMessage) PreviousCounter() uint32 { return m.previousCounter }

// Body returns the inner ciphertext.
func (m *SignalMessage) Body() []byte { return m.ciphertext }

// PQRatchet returns the opaque SPQR state bytes (empty when absent).
func (m *SignalMessage) PQRatchet() []byte { return m.pqRatchet }

// Serialize returns the full wire form (version byte ‖ body ‖ MAC).
func (m *SignalMessage) Serialize() []byte { return m.serialized }
