package groups

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/internal/crypto"
	"github.com/GoCodeAlone/libsignal-go/protocol"
	"github.com/GoCodeAlone/libsignal-go/stores"
)

// Error sentinels returned by Encrypt/Decrypt, wrapped with %w so callers can
// match them with errors.Is. They mirror the relevant SignalProtocolError
// variants from rust/protocol/src/group_cipher.rs.
var (
	// ErrNoSenderKeyState is returned when no record exists for the (sender,
	// distribution) pair, or the message's chain id is not in the record.
	// Mirrors SignalProtocolError::NoSenderKeyState.
	ErrNoSenderKeyState = errors.New("groups: no sender key state for distribution")

	// ErrInvalidSenderKeySession is returned when the stored state is corrupt or
	// incomplete (missing chain key, missing/invalid signing key, or AES key/IV
	// rejected). Mirrors SignalProtocolError::InvalidSenderKeySession.
	ErrInvalidSenderKeySession = errors.New("groups: invalid sender key session")

	// ErrUnrecognizedMessageVersion is returned when a message's version does not
	// match the chain's. Mirrors SignalProtocolError::UnrecognizedMessageVersion.
	ErrUnrecognizedMessageVersion = errors.New("groups: unrecognized sender key message version")

	// ErrSignatureInvalid is returned when the message signature does not verify
	// under the chain's signing key. Mirrors
	// SignalProtocolError::SignatureValidationFailed.
	ErrSignatureInvalid = errors.New("groups: sender key signature validation failed")

	// ErrDuplicateMessage is returned when a message's iteration is in the past
	// and its message key is not cached (already consumed). Mirrors
	// SignalProtocolError::DuplicatedMessage.
	ErrDuplicateMessage = errors.New("groups: duplicate sender key message")

	// ErrInvalidMessage is returned when a message is structurally valid but
	// cannot be processed: too far into the future (beyond MaxForwardJumps) or a
	// decryption (padding) failure. Wraps protocol.ErrInvalidMessage so callers
	// matching on the shared protocol sentinel also catch it. Mirrors
	// SignalProtocolError::InvalidMessage(SenderKey, ...).
	ErrInvalidMessage = fmt.Errorf("groups: %w", protocol.ErrInvalidMessage)
)

// Encrypt produces a signed SenderKeyMessage for plaintext on sender's
// sender-key chain for distributionID, advancing the chain by one and
// persisting it. The chain must already exist in store (created by
// CreateSenderKeyDistributionMessage). Mirrors group_cipher.rs group_encrypt.
//
// rng supplies the XEdDSA signing nonce (use crypto/rand.Reader in production).
func Encrypt(
	ctx context.Context,
	sender address.ProtocolAddress,
	distributionID [16]byte,
	plaintext []byte,
	store stores.SenderKeyStore,
	rng io.Reader,
) (*protocol.SenderKeyMessage, error) {
	record, err := loadSenderKeyRecord(ctx, store, sender, distributionID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("%w %x", ErrNoSenderKeyState, distributionID)
	}

	state, ok := record.SenderKeyState()
	if !ok {
		return nil, fmt.Errorf("%w for distribution %x: empty state", ErrInvalidSenderKeySession, distributionID)
	}
	chainKey, ok := state.ChainKey()
	if !ok {
		return nil, fmt.Errorf("%w for distribution %x: missing chain key", ErrInvalidSenderKeySession, distributionID)
	}
	signingKey, ok := state.SigningKeyPrivate()
	if !ok {
		return nil, fmt.Errorf("%w for distribution %x: missing private signing key", ErrInvalidSenderKeySession, distributionID)
	}

	messageKey, err := chainKey.senderMessageKey()
	if err != nil {
		return nil, err
	}

	ciphertext, err := crypto.EncryptCBC(plaintext, messageKey.CipherKey(), messageKey.IV())
	if err != nil {
		return nil, fmt.Errorf("%w for distribution %x: %v", ErrInvalidSenderKeySession, distributionID, err)
	}

	skm, err := protocol.NewSenderKeyMessage(
		distributionID,
		state.ChainID(),
		messageKey.Iteration(),
		ciphertext,
		rng,
		signingKey,
	)
	if err != nil {
		return nil, fmt.Errorf("groups: building sender key message: %w", err)
	}

	// Advance the chain past the message we just emitted, then persist.
	nextChainKey, err := chainKey.next()
	if err != nil {
		return nil, err
	}
	state.setSenderChainKey(nextChainKey)

	if err := storeSenderKeyRecord(ctx, store, sender, distributionID, record); err != nil {
		return nil, err
	}
	return skm, nil
}

// Decrypt parses, authenticates, and decrypts a serialized SenderKeyMessage
// from sender, returning the plaintext. It handles out-of-order delivery via
// the per-state skipped-message-key cache (bounded by MaxForwardJumps ahead and
// maxMessageKeys retained), rejects replays and signature failures, and
// persists the advanced state. Mirrors group_cipher.rs group_decrypt.
func Decrypt(
	ctx context.Context,
	sender address.ProtocolAddress,
	skmBytes []byte,
	store stores.SenderKeyStore,
) ([]byte, error) {
	skm, err := protocol.DeserializeSenderKeyMessage(skmBytes)
	if err != nil {
		return nil, err
	}
	distributionID := skm.DistributionID()
	chainID := skm.ChainID()

	record, err := loadSenderKeyRecord(ctx, store, sender, distributionID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("%w %x", ErrNoSenderKeyState, distributionID)
	}

	state := record.SenderKeyStateForChainID(chainID)
	if state == nil {
		return nil, fmt.Errorf("%w %x: unknown chain id %d", ErrNoSenderKeyState, distributionID, chainID)
	}

	if uint32(skm.MessageVersion()) != state.MessageVersion() {
		return nil, fmt.Errorf("%w: message %d, chain %d", ErrUnrecognizedMessageVersion, skm.MessageVersion(), state.MessageVersion())
	}

	signingKey, ok := state.SigningKeyPublic()
	if !ok {
		return nil, fmt.Errorf("%w for distribution %x: missing signing key", ErrInvalidSenderKeySession, distributionID)
	}
	if !skm.VerifySignature(signingKey) {
		return nil, ErrSignatureInvalid
	}

	messageKey, err := senderKeyForIteration(state, skm.Iteration(), distributionID)
	if err != nil {
		return nil, err
	}

	plaintext, err := crypto.DecryptCBC(skm.Ciphertext(), messageKey.CipherKey(), messageKey.IV())
	if err != nil {
		// A bad key/IV (wrong-length, structurally impossible here but mirrored)
		// is a corrupt session; a padding/length failure is a corrupt message.
		// Upstream distinguishes BadKeyOrIv (InvalidSenderKeySession) from
		// BadCiphertext (InvalidMessage); both are surfaced as distinct sentinels.
		if errors.Is(err, crypto.ErrInvalidKeySize) || errors.Is(err, crypto.ErrInvalidNonceSize) {
			return nil, fmt.Errorf("%w for distribution %x: %v", ErrInvalidSenderKeySession, distributionID, err)
		}
		return nil, fmt.Errorf("%w: sender key decryption failed: %v", ErrInvalidMessage, err)
	}

	if err := storeSenderKeyRecord(ctx, store, sender, distributionID, record); err != nil {
		return nil, err
	}
	return plaintext, nil
}

// senderKeyForIteration resolves the message key for iteration on state,
// advancing and caching as needed. Mirrors group_cipher.rs get_sender_key:
//   - if the chain is already past iteration, the key must be in the skipped
//     cache (pop it) or the message is a duplicate;
//   - a jump beyond MaxForwardJumps is rejected;
//   - otherwise the chain ratchets forward to iteration, caching each skipped
//     message key, and the state's chain key is advanced one past iteration.
func senderKeyForIteration(state *SenderKeyState, iteration uint32, distributionID [16]byte) (senderMessageKey, error) {
	chainKey, ok := state.ChainKey()
	if !ok {
		return senderMessageKey{}, fmt.Errorf("%w for distribution %x: missing chain key", ErrInvalidSenderKeySession, distributionID)
	}
	current := chainKey.Iteration()

	if current > iteration {
		// The message is from the past: its key must be cached, else it is a
		// replay of an already-consumed (or never-skipped) iteration.
		if smk, ok := state.removeSenderMessageKey(iteration); ok {
			return smk, nil
		}
		return senderMessageKey{}, fmt.Errorf("%w: distribution %x iteration %d (current %d)", ErrDuplicateMessage, distributionID, iteration, current)
	}

	if iteration-current > MaxForwardJumps {
		return senderMessageKey{}, fmt.Errorf("%w: sender key message %d too far past current %d (cap %d)", ErrInvalidMessage, iteration, current, MaxForwardJumps)
	}

	// Ratchet forward to `iteration`, caching the skipped keys along the way.
	for chainKey.Iteration() < iteration {
		skipped, err := chainKey.senderMessageKey()
		if err != nil {
			return senderMessageKey{}, err
		}
		state.addSenderMessageKey(skipped)
		chainKey, err = chainKey.next()
		if err != nil {
			return senderMessageKey{}, err
		}
	}

	messageKey, err := chainKey.senderMessageKey()
	if err != nil {
		return senderMessageKey{}, err
	}
	nextChainKey, err := chainKey.next()
	if err != nil {
		return senderMessageKey{}, err
	}
	state.setSenderChainKey(nextChainKey)
	return messageKey, nil
}
