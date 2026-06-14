package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/internal/crypto"
	"github.com/GoCodeAlone/libsignal-go/protocol"
	"github.com/GoCodeAlone/libsignal-go/ratchet"
	"github.com/GoCodeAlone/libsignal-go/stores"
)

// MaxForwardJumps caps how many message keys a receive may skip ahead in one
// chain before rejecting the message (MAX_FORWARD_JUMPS in consts.rs). It
// bounds work and the skipped-key cache growth from a forged far-future counter.
const MaxForwardJumps = 25000

// Cipher errors. All are %w-wrappable and errors.Is-matchable.
var (
	// ErrSessionNotFound is returned when no usable session exists for the
	// address (none stored, or the unacknowledged session is stale).
	ErrSessionNotFound = errors.New("session: no session for address")
	// ErrDuplicateMessage is returned when a message's counter has already been
	// decrypted (its message keys are no longer cached).
	ErrDuplicateMessage = errors.New("session: duplicate message")
	// ErrInvalidMessage is returned for a structurally valid but undecryptable
	// message (MAC failure, too-far-future counter, corrupt body).
	ErrInvalidMessage = errors.New("session: invalid message")
)

// Clock returns the current time; injectable so tests can drive the
// stale-unacknowledged-session check deterministically.
type Clock func() time.Time

// Encrypt encrypts plaintext for remoteAddress using the stored session,
// advancing the sending chain by one step and persisting the mutated session.
// While the session's pre-key message is unacknowledged it returns a
// PreKeySignalMessage (wrapping the SignalMessage); afterward a plain
// SignalMessage. A stale unacknowledged session (older than
// MaxUnacknowledgedSessionAge) yields ErrSessionNotFound.
//
// Mirrors message_encrypt: derive message keys from the sender chain, AES-256-
// CBC encrypt, build the (pre-key) signal message MAC'd over the identities and
// versioned body, then advance the sender chain key and store.
func Encrypt(
	ctx context.Context,
	plaintext []byte,
	remoteAddress address.ProtocolAddress,
	sessionStore Store,
	identityStore stores.IdentityKeyStore,
	clock Clock,
) (*protocol.SignalMessage, *protocol.PreKeySignalMessage, error) {
	record, err := sessionStore.LoadSession(ctx, remoteAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("session: load session: %w", err)
	}
	if record == nil || !record.HasCurrentState() {
		return nil, nil, fmt.Errorf("%w: %s", ErrSessionNotFound, remoteAddress.String())
	}
	state := record.CurrentState()

	localID := state.LocalIdentityPublic()
	remoteID := state.RemoteIdentityPublic()
	senderID, err := curve.DeserializePublicKey(localID)
	if err != nil {
		return nil, nil, fmt.Errorf("session: local identity: %w", err)
	}
	receiverID, err := curve.DeserializePublicKey(remoteID)
	if err != nil {
		return nil, nil, fmt.Errorf("session: remote identity: %w", err)
	}

	chainKey, err := state.SenderChainKey()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSessionNotFound, err)
	}
	mk, err := chainKey.MessageKeys().GenerateKeys(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("session: deriving message keys: %w", err)
	}
	ratchetKey, err := state.SenderRatchetKey()
	if err != nil {
		return nil, nil, fmt.Errorf("session: sender ratchet key: %w", err)
	}

	ctext, err := crypto.EncryptCBC(plaintext, mk.CipherKey(), mk.IV())
	if err != nil {
		return nil, nil, fmt.Errorf("session: AES-CBC encrypt: %w", err)
	}

	version := uint8(state.SessionVersion())
	signal, err := protocol.NewSignalMessage(
		version,
		mk.MACKey(),
		ratchetKey,
		chainKey.Index(),
		state.PreviousCounter(),
		ctext,
		senderID,
		receiverID,
		nil, // pq_ratchet absent (Stage 1, no SPQR)
		nil, // addresses (sealed-sender binding) unused here
	)
	if err != nil {
		return nil, nil, fmt.Errorf("session: building SignalMessage: %w", err)
	}

	// Pre-key wrapping while the handshake is unacknowledged.
	var preKey *protocol.PreKeySignalMessage
	out := signal
	if pending, ok := state.PendingPreKeyMessage(); ok {
		if isStaleUnacked(pending.UnixSeconds, clock) {
			return nil, nil, fmt.Errorf("%w: stale unacknowledged session", ErrSessionNotFound)
		}
		base, err := curve.DeserializePublicKey(pending.BaseKey)
		if err != nil {
			return nil, nil, fmt.Errorf("session: pending base key: %w", err)
		}
		preKey, err = protocol.NewPreKeySignalMessage(
			version,
			state.LocalRegistrationID(),
			pending.PreKeyID, // optional one-time pre-key id
			pending.SignedPreKeyID,
			pending.KyberPreKeyID,
			pending.KyberCiphertext,
			base,
			senderID,
			signal,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("session: building PreKeySignalMessage: %w", err)
		}
		out = nil // pre-key form supersedes the plain form
	}

	// Trust-check the recipient identity (Sending) and record it, mirroring
	// message_encrypt's post-build check + save_identity.
	trusted, err := identityStore.IsTrustedIdentity(ctx, remoteAddress, receiverID, stores.Sending)
	if err != nil {
		return nil, nil, fmt.Errorf("session: trust check: %w", err)
	}
	if !trusted {
		return nil, nil, fmt.Errorf("%w: %s", ErrUntrustedIdentity, remoteAddress.String())
	}
	if _, err := identityStore.SaveIdentity(ctx, remoteAddress, receiverID); err != nil {
		return nil, nil, fmt.Errorf("session: save identity: %w", err)
	}

	// Advance the sending chain and persist.
	if err := state.SetSenderChainKey(chainKey.Next()); err != nil {
		return nil, nil, fmt.Errorf("session: advancing sender chain: %w", err)
	}
	if err := sessionStore.StoreSession(ctx, remoteAddress, record); err != nil {
		return nil, nil, fmt.Errorf("session: store session: %w", err)
	}
	return out, preKey, nil
}

// Decrypt decrypts a SignalMessage from remoteAddress against the stored
// session, using the clone-then-commit discipline: the session state is mutated
// on a clone and only persisted if decryption succeeds, so a failed decrypt
// leaves the stored record byte-identical. Mirrors message_decrypt_signal +
// try_decrypt_from_record (current state only — previous-session fallback is a
// later refinement; PreKey messages always target the current state).
func Decrypt(
	ctx context.Context,
	ciphertext *protocol.SignalMessage,
	remoteAddress address.ProtocolAddress,
	sessionStore Store,
	rng io.Reader,
) ([]byte, error) {
	record, err := sessionStore.LoadSession(ctx, remoteAddress)
	if err != nil {
		return nil, fmt.Errorf("session: load session: %w", err)
	}
	if record == nil || !record.HasCurrentState() {
		return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, remoteAddress.String())
	}

	// Clone-then-commit: work on a copy of the current state.
	working := record.CurrentState().Clone()
	ptext, err := decryptWithState(working, ciphertext, rng)
	if err != nil {
		return nil, err // stored record untouched
	}

	// Commit the mutated state and persist.
	record.SetCurrentState(working)
	if err := sessionStore.StoreSession(ctx, remoteAddress, record); err != nil {
		return nil, fmt.Errorf("session: store session: %w", err)
	}
	return ptext, nil
}

// decryptWithState runs the Double Ratchet receive on state (a clone the caller
// owns): version check, DH ratchet step if the sender ratchet key is new,
// skipped-key handling / duplicate detection / forward-jump cap, MAC verify,
// AES-256-CBC decrypt. Mirrors decrypt_message_with_state +
// get_or_create_chain_key + get_or_create_message_key in session_cipher_legacy.
func decryptWithState(state *SessionState, ciphertext *protocol.SignalMessage, rng io.Reader) ([]byte, error) {
	if len(state.RootKey()) == 0 {
		return nil, fmt.Errorf("%w: no session to decrypt with", ErrInvalidMessage)
	}
	if uint32(ciphertext.MessageVersion()) != state.SessionVersion() {
		return nil, fmt.Errorf("%w: version %d != session %d", ErrInvalidMessage, ciphertext.MessageVersion(), state.SessionVersion())
	}

	theirRatchet := ciphertext.SenderRatchetKey()
	counter := ciphertext.Counter()

	chainKey, err := getOrCreateChainKey(state, theirRatchet, rng)
	if err != nil {
		return nil, err
	}
	mk, err := getOrCreateMessageKeys(state, theirRatchet, chainKey, counter)
	if err != nil {
		return nil, err
	}

	senderID, err := curve.DeserializePublicKey(state.RemoteIdentityPublic())
	if err != nil {
		return nil, fmt.Errorf("session: remote identity: %w", err)
	}
	receiverID, err := curve.DeserializePublicKey(state.LocalIdentityPublic())
	if err != nil {
		return nil, fmt.Errorf("session: local identity: %w", err)
	}
	ok, err := ciphertext.VerifyMAC(senderID, receiverID, mk.MacKey)
	if err != nil {
		return nil, fmt.Errorf("session: MAC check: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: MAC verification failed", ErrInvalidMessage)
	}

	ptext, err := crypto.DecryptCBC(ciphertext.Body(), mk.CipherKey, mk.IV)
	if err != nil {
		return nil, fmt.Errorf("%w: AES-CBC decrypt: %v", ErrInvalidMessage, err)
	}
	state.ClearUnacknowledgedPreKeyMessage()
	return ptext, nil
}

// getOrCreateChainKey returns the receiver chain key for theirRatchet, creating
// a new pair of chains (a DH ratchet step) if this ratchet key is unseen.
func getOrCreateChainKey(state *SessionState, theirRatchet curve.PublicKey, rng io.Reader) (ratchet.ChainKey, error) {
	if ck, ok, err := state.ReceiverChainKey(theirRatchet); err != nil {
		return ratchet.ChainKey{}, err
	} else if ok {
		return ck, nil
	}

	// DH ratchet step.
	rk, err := ratchet.NewRootKey(state.RootKey())
	if err != nil {
		return ratchet.ChainKey{}, fmt.Errorf("session: root key: %w", err)
	}
	ourCurrent, err := state.SenderRatchetKeyPair()
	if err != nil {
		return ratchet.ChainKey{}, err
	}
	receiverRoot, receiverChain, err := rk.CreateChain(theirRatchet, ourCurrent.PrivateKey)
	if err != nil {
		return ratchet.ChainKey{}, fmt.Errorf("session: receiver DH ratchet: %w", err)
	}
	ourNew, err := curve.GenerateKeyPair(rng)
	if err != nil {
		return ratchet.ChainKey{}, fmt.Errorf("session: new ratchet key: %w", err)
	}
	senderRoot, senderChain, err := receiverRoot.CreateChain(theirRatchet, ourNew.PrivateKey)
	if err != nil {
		return ratchet.ChainKey{}, fmt.Errorf("session: sender DH ratchet: %w", err)
	}

	state.SetRootKey(senderRoot)
	state.AddReceiverChain(theirRatchet, receiverChain)
	if cur, err := state.SenderChainKey(); err == nil {
		if idx := cur.Index(); idx > 0 {
			state.SetPreviousCounter(idx - 1)
		} else {
			state.SetPreviousCounter(0)
		}
	}
	state.SetSenderChain(ourNew, senderChain)
	return receiverChain, nil
}

// getOrCreateMessageKeys returns the message keys for counter on theirRatchet's
// chain. If the chain has already advanced past counter, it returns the cached
// skipped keys (or ErrDuplicateMessage if none). Otherwise it steps the chain
// to counter, caching each skipped key, capped by MaxForwardJumps.
func getOrCreateMessageKeys(state *SessionState, theirRatchet curve.PublicKey, chainKey ratchet.ChainKey, counter uint32) (MessageKeyAt, error) {
	chainIndex := chainKey.Index()

	if chainIndex > counter {
		mk, ok, err := state.TakeMessageKeys(theirRatchet, counter)
		if err != nil {
			return MessageKeyAt{}, err
		}
		if !ok {
			return MessageKeyAt{}, fmt.Errorf("%w: counter %d", ErrDuplicateMessage, counter)
		}
		return mk, nil
	}

	if counter-chainIndex > MaxForwardJumps {
		return MessageKeyAt{}, fmt.Errorf("%w: message too far in the future (jump %d > %d)", ErrInvalidMessage, counter-chainIndex, MaxForwardJumps)
	}

	// Step the chain to counter, caching each skipped message's keys.
	ck := chainKey
	for ck.Index() < counter {
		skipped, err := ck.MessageKeys().GenerateKeys(nil)
		if err != nil {
			return MessageKeyAt{}, fmt.Errorf("session: skipped message keys: %w", err)
		}
		if err := state.CacheMessageKeys(theirRatchet, messageKeysToAt(skipped)); err != nil {
			return MessageKeyAt{}, err
		}
		ck = ck.Next()
	}
	if err := state.SetReceiverChainKey(theirRatchet, ck.Next()); err != nil {
		return MessageKeyAt{}, err
	}
	mk, err := ck.MessageKeys().GenerateKeys(nil)
	if err != nil {
		return MessageKeyAt{}, fmt.Errorf("session: message keys: %w", err)
	}
	return messageKeysToAt(mk), nil
}

// messageKeysToAt converts a ratchet.MessageKeys into the storage-facing
// MessageKeyAt (carrying the same cipher/mac/iv and the chain index).
func messageKeysToAt(mk ratchet.MessageKeys) MessageKeyAt {
	return MessageKeyAt{
		Index:     mk.Index(),
		CipherKey: mk.CipherKey(),
		MacKey:    mk.MACKey(),
		IV:        mk.IV(),
	}
}

// isStaleUnacked reports whether an unacknowledged session created at
// unixSeconds is older than MaxUnacknowledgedSessionAge as of the clock.
func isStaleUnacked(unixSeconds uint64, clock Clock) bool {
	now := time.Now()
	if clock != nil {
		now = clock()
	}
	created := time.Unix(int64(unixSeconds), 0)
	return created.Add(MaxUnacknowledgedSessionAge).Before(now)
}
