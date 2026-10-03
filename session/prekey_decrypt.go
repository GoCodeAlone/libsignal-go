package session

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/kem"
	pb "github.com/GoCodeAlone/libsignal-go/proto"
	"github.com/GoCodeAlone/libsignal-go/protocol"
	"github.com/GoCodeAlone/libsignal-go/stores"
	googleproto "google.golang.org/protobuf/proto"
)

// PreKeyDecryptStores provides the recipient's identity, sessions and pre-keys.
type PreKeyDecryptStores struct {
	Sessions     Store
	Identities   stores.IdentityKeyStore
	PreKeys      stores.PreKeyStore
	SignedKeys   stores.SignedPreKeyStore
	KyberPreKeys stores.KyberPreKeyStore
}

// DecryptPreKey establishes or resumes the recipient's PQXDH session and
// decrypts the embedded SignalMessage. Authentication failures leave all stores
// unchanged, including archived sessions and one-time pre-keys.
//
// Successful decryption saves the identity, marks Kyber use against the signed
// EC pre-key, removes the optional one-time pre-key, then saves the session, in
// upstream order. Store-write failures may leave earlier writes committed;
// hosts must serialize operations per peer and provide a transaction boundary
// across these stores if they require atomic durable writes.
func DecryptPreKey(ctx context.Context, ciphertext *protocol.PreKeySignalMessage, remote address.ProtocolAddress, storage PreKeyDecryptStores, rng io.Reader) ([]byte, error) {
	if ciphertext == nil || ciphertext.Message() == nil || rng == nil {
		return nil, fmt.Errorf("%w: missing pre-key message or random source", ErrInvalidMessage)
	}
	if storage.Sessions == nil || storage.Identities == nil || storage.PreKeys == nil || storage.SignedKeys == nil || storage.KyberPreKeys == nil {
		return nil, fmt.Errorf("%w: missing recipient store", ErrInvalidMessage)
	}
	theirIdentity := ciphertext.IdentityKey()
	trusted, err := storage.Identities.IsTrustedIdentity(ctx, remote, theirIdentity, stores.Receiving)
	if err != nil {
		return nil, fmt.Errorf("session: trust check: %w", err)
	}
	if !trusted {
		return nil, fmt.Errorf("%w: %s", ErrUntrustedIdentity, remote.String())
	}
	stored, err := storage.Sessions.LoadSession(ctx, remote)
	if err != nil {
		return nil, fmt.Errorf("session: load session: %w", err)
	}
	working := NewFreshSessionRecord()
	if stored != nil {
		// A host store may return an alias: clone the entire record before
		// promoting an archive, not only the state used by the cipher.
		raw, err := stored.Serialize()
		if err != nil {
			return nil, err
		}
		working, err = DeserializeSessionRecord(raw)
		clear(raw)
		if err != nil {
			return nil, err
		}
	}
	matched, err := promoteMatchingPreKeySession(working, ciphertext)
	if err != nil {
		return nil, err
	}
	if matched {
		identity, err := curve.DeserializePublicKey(working.CurrentState().RemoteIdentityPublic())
		if err != nil || !identity.Equal(theirIdentity) {
			return nil, fmt.Errorf("%w: identity inconsistent with established session", ErrInvalidMessage)
		}
	} else {
		state, err := recipientPreKeyState(ctx, ciphertext, storage)
		if err != nil {
			return nil, err
		}
		if err := working.PromoteState(state); err != nil {
			return nil, err
		}
	}
	plaintext, err := decryptWithState(working.CurrentState(), ciphertext.Message(), rng)
	if err != nil {
		return nil, err
	}
	commit := func() error {
		if _, err := storage.Identities.SaveIdentity(ctx, remote, theirIdentity); err != nil {
			return fmt.Errorf("session: save identity: %w", err)
		}
		if !matched {
			if err := storage.KyberPreKeys.MarkKyberPreKeyUsed(ctx, *ciphertext.KyberPreKeyID(), ciphertext.SignedPreKeyID(), ciphertext.BaseKey()); err != nil {
				return fmt.Errorf("session: mark Kyber pre-key used: %w", err)
			}
			if id := ciphertext.PreKeyID(); id != nil {
				if err := storage.PreKeys.RemovePreKey(ctx, *id); err != nil {
					return fmt.Errorf("session: remove pre-key: %w", err)
				}
			}
		}
		if err := storage.Sessions.StoreSession(ctx, remote, working); err != nil {
			return fmt.Errorf("session: store session: %w", err)
		}
		return nil
	}
	if err := commit(); err != nil {
		clear(plaintext)
		return nil, err
	}
	return plaintext, nil
}

func promoteMatchingPreKeySession(record *SessionRecord, message *protocol.PreKeySignalMessage) (bool, error) {
	base := message.BaseKey().Serialize()
	matches := func(state *SessionState) bool {
		return state != nil && state.SessionVersion() == uint32(message.MessageVersion()) && subtle.ConstantTimeCompare(state.AliceBaseKey(), base) == 1
	}
	if matches(record.CurrentState()) {
		return true, nil
	}
	for i, raw := range record.previousSessions {
		var state pb.SessionStructure
		if err := googleproto.Unmarshal(raw, &state); err != nil {
			return false, fmt.Errorf("%w: malformed archived session", ErrInvalidMessage)
		}
		if matches(NewSessionState(&state)) {
			return true, record.PromoteOldSession(i)
		}
	}
	return false, nil
}

func recipientPreKeyState(ctx context.Context, message *protocol.PreKeySignalMessage, storage PreKeyDecryptStores) (*SessionState, error) {
	if message.MessageVersion() != signalMessageCurrentVersion {
		return nil, fmt.Errorf("%w: new sessions require PQXDH", ErrInvalidMessage)
	}
	kyberID := message.KyberPreKeyID()
	if kyberID == nil || len(message.KyberCiphertext()) == 0 {
		return nil, ErrNoKyberPreKey
	}
	signedRaw, err := storage.SignedKeys.GetSignedPreKey(ctx, message.SignedPreKeyID())
	if err != nil {
		return nil, fmt.Errorf("session: load signed pre-key: %w", err)
	}
	var signed pb.SignedPreKeyRecordStructure
	if err := googleproto.Unmarshal(signedRaw, &signed); err != nil {
		return nil, fmt.Errorf("%w: malformed signed pre-key record", ErrInvalidKey)
	}
	defer clear(signed.PrivateKey)
	signedPair, err := recipientCurveKeyPair(signed.PublicKey, signed.PrivateKey)
	if err != nil {
		return nil, err
	}
	kyberRaw, err := storage.KyberPreKeys.GetKyberPreKey(ctx, *kyberID)
	if err != nil {
		return nil, fmt.Errorf("session: load Kyber pre-key: %w", err)
	}
	var kyber pb.SignedPreKeyRecordStructure
	if err := googleproto.Unmarshal(kyberRaw, &kyber); err != nil {
		return nil, fmt.Errorf("%w: malformed Kyber pre-key record", ErrInvalidKey)
	}
	defer clear(kyber.PrivateKey)
	kyberPair, err := kem.KeyPairFromPublicAndSecret(kyber.PublicKey, kyber.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: unusable Kyber pre-key record", ErrInvalidKey)
	}
	var oneTime *curve.KeyPair
	if id := message.PreKeyID(); id != nil {
		raw, err := storage.PreKeys.GetPreKey(ctx, *id)
		if err != nil {
			return nil, fmt.Errorf("session: load one-time pre-key: %w", err)
		}
		var pre pb.PreKeyRecordStructure
		if err := googleproto.Unmarshal(raw, &pre); err != nil {
			return nil, fmt.Errorf("%w: malformed one-time pre-key record", ErrInvalidKey)
		}
		defer clear(pre.PrivateKey)
		pair, err := recipientCurveKeyPair(pre.PublicKey, pre.PrivateKey)
		if err != nil {
			return nil, err
		}
		oneTime = &pair
	}
	identity, err := storage.Identities.GetIdentityKeyPair(ctx)
	if err != nil {
		return nil, fmt.Errorf("session: identity key pair: %w", err)
	}
	registration, err := storage.Identities.GetLocalRegistrationID(ctx)
	if err != nil {
		return nil, fmt.Errorf("session: local registration id: %w", err)
	}
	state, err := InitializeBobSession(BobParams{OurIdentity: identity, OurSignedPre: signedPair, OurOneTime: oneTime, OurKyber: kyberPair, TheirIdentity: message.IdentityKey(), TheirBaseKey: message.BaseKey(), KyberCipher: message.KyberCiphertext()})
	if err != nil {
		return nil, err
	}
	state.SetLocalRegistrationID(registration)
	state.SetRemoteRegistrationID(message.RegistrationID())
	return state, nil
}

func recipientCurveKeyPair(public, private []byte) (curve.KeyPair, error) {
	pub, err := curve.DeserializePublicKey(public)
	if err != nil {
		return curve.KeyPair{}, fmt.Errorf("%w: unusable pre-key public key", ErrInvalidKey)
	}
	priv, err := curve.DeserializePrivateKey(private)
	if err != nil {
		return curve.KeyPair{}, fmt.Errorf("%w: unusable pre-key private key", ErrInvalidKey)
	}
	return curve.KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}
