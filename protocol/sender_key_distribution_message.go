package protocol

import (
	"fmt"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/proto"
	googleproto "google.golang.org/protobuf/proto"
)

const (
	// chainKeyLen is the required length of a sender-key chain key.
	chainKeyLen = 32
	// serializedPublicKeyLen is the length of a type-tagged Curve25519 public
	// key (1 type byte + 32 raw bytes).
	serializedPublicKeyLen = 33
)

// SenderKeyDistributionMessage announces a sender-key chain to group members.
// Its wire form is a version byte followed by the protobuf body; it carries no
// signature.
type SenderKeyDistributionMessage struct {
	messageVersion uint8
	distributionID [uuidLen]byte
	chainID        uint32
	iteration      uint32
	chainKey       []byte
	signingKey     curve.PublicKey
	serialized     []byte
}

// NewSenderKeyDistributionMessage builds a SenderKeyDistributionMessage.
func NewSenderKeyDistributionMessage(
	distributionID [uuidLen]byte,
	chainID uint32,
	iteration uint32,
	chainKey []byte,
	signingKey curve.PublicKey,
) (*SenderKeyDistributionMessage, error) {
	protoMessage := &proto.SenderKeyDistributionMessage{
		DistributionUuid: distributionID[:],
		ChainId:          googleproto.Uint32(chainID),
		Iteration:        googleproto.Uint32(iteration),
		ChainKey:         chainKey,
		SigningKey:       signingKey.Serialize(),
	}
	body, err := googleproto.Marshal(protoMessage)
	if err != nil {
		return nil, err
	}

	serialized := make([]byte, 0, 1+len(body))
	serialized = append(serialized, encodeVersionByte(SenderKeyCurrentVersion, SenderKeyCurrentVersion))
	serialized = append(serialized, body...)

	return &SenderKeyDistributionMessage{
		messageVersion: SenderKeyCurrentVersion,
		distributionID: distributionID,
		chainID:        chainID,
		iteration:      iteration,
		chainKey:       chainKey,
		signingKey:     signingKey,
		serialized:     serialized,
	}, nil
}

// DeserializeSenderKeyDistributionMessage parses the wire form of a
// SenderKeyDistributionMessage.
func DeserializeSenderKeyDistributionMessage(value []byte) (*SenderKeyDistributionMessage, error) {
	// The message contains at least a X25519 key and a chain key.
	if len(value) < 1+chainKeyLen+chainKeyLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrCiphertextTooShort, len(value))
	}
	version, err := senderKeyVersion(value[0])
	if err != nil {
		return nil, err
	}

	var protoMessage proto.SenderKeyDistributionMessage
	if err := googleproto.Unmarshal(value[1:], &protoMessage); err != nil {
		return nil, ErrInvalidProtobuf
	}

	rawUUID := protoMessage.GetDistributionUuid()
	if len(rawUUID) != uuidLen {
		return nil, ErrInvalidProtobuf
	}
	if protoMessage.ChainId == nil || protoMessage.Iteration == nil ||
		protoMessage.ChainKey == nil || protoMessage.SigningKey == nil {
		return nil, ErrInvalidProtobuf
	}

	chainKey := protoMessage.GetChainKey()
	signingKeyBytes := protoMessage.GetSigningKey()
	if len(chainKey) != chainKeyLen || len(signingKeyBytes) != serializedPublicKeyLen {
		return nil, ErrInvalidProtobuf
	}
	signingKey, err := curve.DeserializePublicKey(signingKeyBytes)
	if err != nil {
		return nil, err
	}

	var distributionID [uuidLen]byte
	copy(distributionID[:], rawUUID)

	return &SenderKeyDistributionMessage{
		messageVersion: version,
		distributionID: distributionID,
		chainID:        protoMessage.GetChainId(),
		iteration:      protoMessage.GetIteration(),
		chainKey:       chainKey,
		signingKey:     signingKey,
		serialized:     value,
	}, nil
}

// MessageVersion returns the message version.
func (m *SenderKeyDistributionMessage) MessageVersion() uint8 { return m.messageVersion }

// DistributionID returns the raw 16-byte distribution UUID.
func (m *SenderKeyDistributionMessage) DistributionID() [uuidLen]byte { return m.distributionID }

// ChainID returns the chain ID.
func (m *SenderKeyDistributionMessage) ChainID() uint32 { return m.chainID }

// Iteration returns the iteration.
func (m *SenderKeyDistributionMessage) Iteration() uint32 { return m.iteration }

// ChainKey returns the chain key.
func (m *SenderKeyDistributionMessage) ChainKey() []byte { return m.chainKey }

// SigningKey returns the signing public key.
func (m *SenderKeyDistributionMessage) SigningKey() curve.PublicKey { return m.signingKey }

// Serialized returns the full wire encoding.
func (m *SenderKeyDistributionMessage) Serialized() []byte { return m.serialized }
