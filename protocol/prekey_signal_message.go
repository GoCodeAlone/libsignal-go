package protocol

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/GoCodeAlone/libsignal-go/curve"
	pb "github.com/GoCodeAlone/libsignal-go/proto"
)

// PreKeySignalMessage is the initial message of a session, carrying the prekey
// identifiers and the keys needed to establish the ratchet, wrapping an inner
// SignalMessage. Its wire form is: version byte ‖ protobuf body (no MAC; the
// inner SignalMessage carries its own MAC).
type PreKeySignalMessage struct {
	messageVersion  uint8
	registrationID  uint32
	preKeyID        *uint32 // optional: a one-time prekey id, absent if none
	signedPreKeyID  uint32
	kyberPreKeyID   *uint32 // present iff a Kyber payload is present
	kyberCiphertext []byte  // present iff a Kyber payload is present
	baseKey         curve.PublicKey
	identityKey     curve.PublicKey
	message         *SignalMessage
	serialized      []byte
}

// NewPreKeySignalMessage builds and serializes a PreKeySignalMessage. A Kyber
// payload (kyberPreKeyID + kyberCiphertext) is required for v4 sessions; pass a
// nil preKeyID when there is no one-time prekey. The message is the inner
// SignalMessage. Mirrors PreKeySignalMessage::new.
func NewPreKeySignalMessage(
	messageVersion uint8,
	registrationID uint32,
	preKeyID *uint32,
	signedPreKeyID uint32,
	kyberPreKeyID *uint32,
	kyberCiphertext []byte,
	baseKey curve.PublicKey,
	identityKey curve.PublicKey,
	message *SignalMessage,
) (*PreKeySignalMessage, error) {
	if message == nil {
		return nil, fmt.Errorf("%w: inner SignalMessage is required", ErrInvalidProtobuf)
	}

	body := &pb.PreKeySignalMessage{
		RegistrationId: proto.Uint32(registrationID),
		PreKeyId:       preKeyID,
		SignedPreKeyId: proto.Uint32(signedPreKeyID),
		KyberPreKeyId:  kyberPreKeyID,
		BaseKey:        baseKey.Serialize(),
		IdentityKey:    identityKey.Serialize(),
		Message:        message.Serialize(),
	}
	if len(kyberCiphertext) > 0 {
		body.KyberCiphertext = append([]byte(nil), kyberCiphertext...)
	}

	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("protocol: marshaling PreKeySignalMessage: %w", err)
	}

	serialized := []byte{encodeVersionByte(messageVersion, CurrentVersion)}
	serialized = append(serialized, bodyBytes...)

	return &PreKeySignalMessage{
		messageVersion:  messageVersion,
		registrationID:  registrationID,
		preKeyID:        cloneU32Ptr(preKeyID),
		signedPreKeyID:  signedPreKeyID,
		kyberPreKeyID:   cloneU32Ptr(kyberPreKeyID),
		kyberCiphertext: append([]byte(nil), kyberCiphertext...),
		baseKey:         baseKey,
		identityKey:     identityKey,
		message:         message,
		serialized:      serialized,
	}, nil
}

// DeserializePreKeySignalMessage parses and validates the wire form. It checks
// the version range, decodes the body (requiring base key, identity key, inner
// message, and signed-prekey id), enforces the Kyber-payload rule (required for
// versions above PreKyberVersion; both-or-neither otherwise), and recursively
// parses the inner SignalMessage. Mirrors PreKeySignalMessage::try_from.
func DeserializePreKeySignalMessage(value []byte) (*PreKeySignalMessage, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrCiphertextTooShort)
	}
	version, err := decodeVersion(value[0])
	if err != nil {
		return nil, err
	}

	var body pb.PreKeySignalMessage
	if err := proto.Unmarshal(value[1:], &body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProtobuf, err)
	}
	if body.BaseKey == nil || body.IdentityKey == nil || body.Message == nil || body.SignedPreKeyId == nil {
		return nil, fmt.Errorf("%w: missing required PreKeySignalMessage field", ErrInvalidProtobuf)
	}

	baseKey, err := curve.DeserializePublicKey(body.BaseKey)
	if err != nil {
		return nil, fmt.Errorf("%w: base key: %v", ErrInvalidProtobuf, err)
	}
	identityKey, err := curve.DeserializePublicKey(body.IdentityKey)
	if err != nil {
		return nil, fmt.Errorf("%w: identity key: %v", ErrInvalidProtobuf, err)
	}

	// Kyber payload rule (protocol.rs): both present, or — only for versions at
	// or below PreKyberVersion — both absent. Any other combination is rejected.
	kyberID := body.KyberPreKeyId
	kyberCT := body.KyberCiphertext
	switch {
	case kyberID != nil && kyberCT != nil:
		// payload present
	case kyberID == nil && kyberCT == nil:
		if version > PreKyberVersion {
			return nil, fmt.Errorf("%w: Kyber pre key must be present for this session version", ErrInvalidMessage)
		}
	default:
		return nil, fmt.Errorf("%w: both or neither kyber pre_key_id and kyber_ciphertext must be present", ErrInvalidMessage)
	}

	inner, err := DeserializeSignalMessage(body.Message)
	if err != nil {
		return nil, err
	}

	return &PreKeySignalMessage{
		messageVersion:  version,
		registrationID:  body.GetRegistrationId(), // defaults to 0 if absent
		preKeyID:        cloneU32Ptr(body.PreKeyId),
		signedPreKeyID:  body.GetSignedPreKeyId(),
		kyberPreKeyID:   cloneU32Ptr(kyberID),
		kyberCiphertext: kyberCT,
		baseKey:         baseKey,
		identityKey:     identityKey,
		message:         inner,
		serialized:      append([]byte(nil), value...),
	}, nil
}

// MessageVersion returns the message's protocol version.
func (m *PreKeySignalMessage) MessageVersion() uint8 { return m.messageVersion }

// RegistrationID returns the sender's registration id.
func (m *PreKeySignalMessage) RegistrationID() uint32 { return m.registrationID }

// PreKeyID returns the one-time prekey id, or nil if the message used none.
func (m *PreKeySignalMessage) PreKeyID() *uint32 { return cloneU32Ptr(m.preKeyID) }

// SignedPreKeyID returns the signed prekey id.
func (m *PreKeySignalMessage) SignedPreKeyID() uint32 { return m.signedPreKeyID }

// KyberPreKeyID returns the Kyber prekey id, or nil if no Kyber payload.
func (m *PreKeySignalMessage) KyberPreKeyID() *uint32 { return cloneU32Ptr(m.kyberPreKeyID) }

// KyberCiphertext returns the Kyber ciphertext, or nil if no Kyber payload.
func (m *PreKeySignalMessage) KyberCiphertext() []byte { return m.kyberCiphertext }

// BaseKey returns the sender's base public key.
func (m *PreKeySignalMessage) BaseKey() curve.PublicKey { return m.baseKey }

// IdentityKey returns the sender's identity public key.
func (m *PreKeySignalMessage) IdentityKey() curve.PublicKey { return m.identityKey }

// Message returns the inner SignalMessage.
func (m *PreKeySignalMessage) Message() *SignalMessage { return m.message }

// Serialize returns the full wire form (version byte ‖ body).
func (m *PreKeySignalMessage) Serialize() []byte { return m.serialized }

// cloneU32Ptr returns an independent copy of a *uint32 (nil-safe), so getters
// and stored fields do not alias caller-provided pointers.
func cloneU32Ptr(p *uint32) *uint32 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
