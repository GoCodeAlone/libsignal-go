package protocol

import (
	"io"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/proto"
	googleproto "google.golang.org/protobuf/proto"
)

// senderKeySignatureLen is the length of the XEdDSA signature appended to a
// serialized SenderKeyMessage.
const senderKeySignatureLen = 64

// uuidLen is the length of the raw distribution UUID.
const uuidLen = 16

// SenderKeyMessage is a group (sender-key) ciphertext message. Its wire form is
// a version byte, the protobuf body, and a trailing 64-byte XEdDSA signature
// computed over the version byte and body.
type SenderKeyMessage struct {
	messageVersion uint8
	distributionID [uuidLen]byte
	chainID        uint32
	iteration      uint32
	ciphertext     []byte
	serialized     []byte
}

// NewSenderKeyMessage builds and signs a SenderKeyMessage. The signature is an
// XEdDSA signature over the version byte and protobuf body, using signatureKey;
// rng supplies the signature nonce (use crypto/rand.Reader in production).
func NewSenderKeyMessage(
	distributionID [uuidLen]byte,
	chainID uint32,
	iteration uint32,
	ciphertext []byte,
	rng io.Reader,
	signatureKey curve.PrivateKey,
) (*SenderKeyMessage, error) {
	protoMessage := &proto.SenderKeyMessage{
		DistributionUuid: distributionID[:],
		ChainId:          googleproto.Uint32(chainID),
		Iteration:        googleproto.Uint32(iteration),
		Ciphertext:       ciphertext,
	}
	body, err := googleproto.Marshal(protoMessage)
	if err != nil {
		return nil, err
	}

	serialized := make([]byte, 0, 1+len(body)+senderKeySignatureLen)
	serialized = append(serialized, versionByte(SenderKeyMessageCurrentVersion, SenderKeyMessageCurrentVersion))
	serialized = append(serialized, body...)

	signature, err := signatureKey.CalculateSignature(rng, serialized)
	if err != nil {
		return nil, err
	}
	serialized = append(serialized, signature...)

	return &SenderKeyMessage{
		messageVersion: SenderKeyMessageCurrentVersion,
		distributionID: distributionID,
		chainID:        chainID,
		iteration:      iteration,
		ciphertext:     ciphertext,
		serialized:     serialized,
	}, nil
}

// DeserializeSenderKeyMessage parses the wire form of a SenderKeyMessage,
// validating the version and protobuf body. It does not verify the signature;
// call VerifySignature for that.
func DeserializeSenderKeyMessage(value []byte) (*SenderKeyMessage, error) {
	if len(value) < 1+senderKeySignatureLen {
		return nil, CiphertextMessageTooShortError{Length: len(value)}
	}
	version := messageVersion(value[0])
	if version < SenderKeyMessageCurrentVersion {
		return nil, LegacyCiphertextVersionError{Version: version}
	}
	if version > SenderKeyMessageCurrentVersion {
		return nil, UnrecognizedCiphertextVersionError{Version: version}
	}

	body := value[1 : len(value)-senderKeySignatureLen]
	var protoMessage proto.SenderKeyMessage
	if err := googleproto.Unmarshal(body, &protoMessage); err != nil {
		return nil, ErrInvalidProtobufEncoding
	}

	rawUUID := protoMessage.GetDistributionUuid()
	if len(rawUUID) != uuidLen {
		return nil, ErrInvalidProtobufEncoding
	}
	if protoMessage.ChainId == nil || protoMessage.Iteration == nil || protoMessage.Ciphertext == nil {
		return nil, ErrInvalidProtobufEncoding
	}

	var distributionID [uuidLen]byte
	copy(distributionID[:], rawUUID)

	return &SenderKeyMessage{
		messageVersion: version,
		distributionID: distributionID,
		chainID:        protoMessage.GetChainId(),
		iteration:      protoMessage.GetIteration(),
		ciphertext:     protoMessage.GetCiphertext(),
		serialized:     value,
	}, nil
}

// VerifySignature reports whether the message's trailing signature is valid
// under signatureKey, computed over the version byte and protobuf body.
func (m *SenderKeyMessage) VerifySignature(signatureKey curve.PublicKey) bool {
	if len(m.serialized) < senderKeySignatureLen {
		return false
	}
	split := len(m.serialized) - senderKeySignatureLen
	content := m.serialized[:split]
	signature := m.serialized[split:]
	return signatureKey.VerifySignature(signature, content)
}

// MessageVersion returns the message version.
func (m *SenderKeyMessage) MessageVersion() uint8 { return m.messageVersion }

// DistributionID returns the raw 16-byte distribution UUID.
func (m *SenderKeyMessage) DistributionID() [uuidLen]byte { return m.distributionID }

// ChainID returns the chain ID.
func (m *SenderKeyMessage) ChainID() uint32 { return m.chainID }

// Iteration returns the iteration.
func (m *SenderKeyMessage) Iteration() uint32 { return m.iteration }

// Ciphertext returns the ciphertext body.
func (m *SenderKeyMessage) Ciphertext() []byte { return m.ciphertext }

// Serialized returns the full wire encoding.
func (m *SenderKeyMessage) Serialized() []byte { return m.serialized }
