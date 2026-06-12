package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/kem"
	"github.com/GoCodeAlone/libsignal-go/ratchet"
	"github.com/GoCodeAlone/libsignal-go/stores"
)

// Store is the session store interface. It lives here rather than in stores/
// because it is the only store that references *SessionRecord — keeping it in
// stores/ would make stores/ import session/ and cycle. The remaining store
// interfaces (identity, pre-key, etc.) stay in stores/, which is now a leaf;
// stores/inmem provides an InMemSessionStore that satisfies this interface.
type Store interface {
	// LoadSession returns the session record for address, or (nil, nil) when no
	// session is stored — mirroring upstream's Option<SessionRecord> return,
	// where a nil record means "absent" rather than an error.
	LoadSession(ctx context.Context, address address.ProtocolAddress) (*SessionRecord, error)

	// StoreSession sets the session record for address, overwriting any existing
	// entry.
	StoreSession(ctx context.Context, address address.ProtocolAddress, record *SessionRecord) error
}

// Errors returned by session establishment. All are %w-wrappable and
// errors.Is-matchable.
var (
	// ErrUntrustedIdentity is returned when the remote identity key is not
	// trusted for the address per the IdentityKeyStore.
	ErrUntrustedIdentity = errors.New("session: untrusted identity")
	// ErrInvalidSignature is returned when a signed pre-key or Kyber pre-key
	// signature fails to verify under the remote identity key.
	ErrInvalidSignature = errors.New("session: pre-key signature verification failed")
	// ErrNoKyberPreKey is returned when a bundle or pre-key message lacks the
	// Kyber pre-key material required at the v4 protocol surface.
	ErrNoKyberPreKey = errors.New("session: missing Kyber pre-key")
	// ErrInvalidPreKeyBundle is returned for a structurally invalid bundle
	// (e.g. a one-time pre-key id without its key, or vice versa).
	ErrInvalidPreKeyBundle = errors.New("session: invalid pre-key bundle")
	// ErrInvalidKey is returned when supplied key material fails to deserialize
	// or is otherwise unusable.
	ErrInvalidKey = errors.New("session: invalid key material")
)

// signalMessageCurrentVersion is the v4 ciphertext message / session version
// (CIPHERTEXT_MESSAGE_CURRENT_VERSION in protocol.rs). PQXDH sessions are v4.
const signalMessageCurrentVersion = 4

// nowUnixSeconds returns the current time as whole seconds since the Unix
// epoch, matching upstream's pending-pre-key timestamp granularity. It is a
// package var so tests can pin it.
var nowUnixSeconds = func() uint64 {
	return uint64(time.Now().Unix())
}

// ProcessPreKeyBundle performs the initiator (Alice) side of session
// establishment from a recipient's PreKeyBundle, mirroring
// session::process_prekey_bundle. On success it stores a fresh alice session
// (with the unacknowledged pre-key message + Kyber ciphertext recorded) under
// remoteAddress and saves the recipient's identity.
//
// Steps (in upstream order): trust-check the identity, verify the signed
// pre-key and Kyber pre-key signatures under that identity, run the PQXDH
// initiator agreement (4 DH + Kyber encapsulation), initialize the Double
// Ratchet alice session, record the pending pre-key state + registration ids,
// save the identity, and store the session.
func ProcessPreKeyBundle(
	ctx context.Context,
	rng io.Reader,
	remoteAddress address.ProtocolAddress,
	bundle *PreKeyBundle,
	sessionStore Store,
	identityStore stores.IdentityKeyStore,
) error {
	theirIdentity := bundle.IdentityKey()

	// 1. Identity trust check (Sending direction).
	trusted, err := identityStore.IsTrustedIdentity(ctx, remoteAddress, theirIdentity, stores.Sending)
	if err != nil {
		return fmt.Errorf("session: trust check: %w", err)
	}
	if !trusted {
		return fmt.Errorf("%w: %s", ErrUntrustedIdentity, remoteAddress.String())
	}

	// 2. Verify the signed pre-key signature over the serialized signed pre-key.
	if !theirIdentity.VerifySignature(bundle.SignedPreKeySignature(), bundle.SignedPreKey().Serialize()) {
		return fmt.Errorf("%w: signed pre-key", ErrInvalidSignature)
	}

	// 3. Verify the Kyber pre-key signature over the serialized Kyber pre-key.
	if !theirIdentity.VerifySignature(bundle.KyberPreKeySignature(), bundle.KyberPreKey().Serialize()) {
		return fmt.Errorf("%w: Kyber pre-key", ErrInvalidSignature)
	}

	// Load or start the session record.
	record, err := sessionStore.LoadSession(ctx, remoteAddress)
	if err != nil {
		return fmt.Errorf("session: load session: %w", err)
	}
	if record == nil {
		record = NewFreshSessionRecord()
	}

	ourIdentity, err := identityStore.GetIdentityKeyPair(ctx)
	if err != nil {
		return fmt.Errorf("session: identity key pair: %w", err)
	}
	localRegistrationID, err := identityStore.GetLocalRegistrationID(ctx)
	if err != nil {
		return fmt.Errorf("session: local registration id: %w", err)
	}

	// 4. Fresh ephemeral (base) key for this handshake.
	baseKeyPair, err := curve.GenerateKeyPair(rng)
	if err != nil {
		return fmt.Errorf("session: generating base key: %w", err)
	}

	var oneTime *curve.PublicKey
	var oneTimeID *uint32
	if id, pk, ok := bundle.PreKey(); ok {
		oneTime = &pk
		oneTimeID = &id
	}

	// 5. PQXDH initiator agreement + alice ratchet init.
	state, err := initializeAliceSession(rng, aliceParams{
		ourIdentity:    ourIdentity,
		ourBase:        baseKeyPair,
		theirIdentity:  theirIdentity,
		theirSignedPre: bundle.SignedPreKey(),
		theirOneTime:   oneTime,
		theirKyber:     bundle.KyberPreKey(),
	})
	if err != nil {
		return err
	}

	// 6. Record the unacknowledged pre-key message + Kyber id + registration ids.
	state.SetUnacknowledgedPreKeyMessage(oneTimeID, bundle.SignedPreKeyID(), baseKeyPair.PublicKey, nowUnixSeconds())
	if err := state.SetUnacknowledgedKyberPreKeyID(bundle.KyberPreKeyID()); err != nil {
		return err
	}
	state.SetLocalRegistrationID(localRegistrationID)
	state.SetRemoteRegistrationID(bundle.RegistrationID())

	// 7. Save identity and store the promoted session.
	if _, err := identityStore.SaveIdentity(ctx, remoteAddress, theirIdentity); err != nil {
		return fmt.Errorf("session: save identity: %w", err)
	}
	if err := record.PromoteState(state); err != nil {
		return err
	}
	if err := sessionStore.StoreSession(ctx, remoteAddress, record); err != nil {
		return fmt.Errorf("session: store session: %w", err)
	}
	return nil
}

// aliceParams carries the resolved key material for the initiator agreement.
type aliceParams struct {
	ourIdentity    curve.KeyPair
	ourBase        curve.KeyPair
	theirIdentity  curve.PublicKey
	theirSignedPre curve.PublicKey
	theirOneTime   *curve.PublicKey // optional
	theirKyber     kem.PublicKey
}

// initializeAliceSession runs the PQXDH initiator agreement and Double Ratchet
// alice init (ratchet::initialize_alice_session, minus SPQR per ADR 0001 Stage
// 1 — pq_ratchet_state is left empty). The recipient's signed pre-key is the
// initiator's "their ratchet key" for the first DH ratchet step.
func initializeAliceSession(rng io.Reader, p aliceParams) (*SessionState, error) {
	// DH agreements in upstream order (pqxdh_initiate):
	//   DH1 = our_identity.priv x their_signed_pre
	//   DH2 = our_base.priv     x their_identity
	//   DH3 = our_base.priv     x their_signed_pre
	//   DH4 = our_base.priv     x their_one_time   (optional)
	dh1, err := p.ourIdentity.PrivateKey.CalculateAgreement(p.theirSignedPre)
	if err != nil {
		return nil, fmt.Errorf("%w: DH1: %v", ErrInvalidKey, err)
	}
	dh2, err := p.ourBase.PrivateKey.CalculateAgreement(p.theirIdentity)
	if err != nil {
		return nil, fmt.Errorf("%w: DH2: %v", ErrInvalidKey, err)
	}
	dh3, err := p.ourBase.PrivateKey.CalculateAgreement(p.theirSignedPre)
	if err != nil {
		return nil, fmt.Errorf("%w: DH3: %v", ErrInvalidKey, err)
	}
	var dh4 []byte
	if p.theirOneTime != nil {
		dh4, err = p.ourBase.PrivateKey.CalculateAgreement(*p.theirOneTime)
		if err != nil {
			return nil, fmt.Errorf("%w: DH4: %v", ErrInvalidKey, err)
		}
	}

	// Kyber encapsulation to the recipient's Kyber pre-key.
	kyberSS, kyberCT, err := p.theirKyber.Encapsulate()
	if err != nil {
		return nil, fmt.Errorf("%w: Kyber encapsulate: %v", ErrInvalidKey, err)
	}

	initial, err := ratchet.DeriveInitialKeys(dh1, dh2, dh3, dh4, kyberSS)
	if err != nil {
		return nil, fmt.Errorf("session: deriving initial keys: %w", err)
	}

	// First DH ratchet step: a fresh sending ratchet key against the
	// recipient's signed pre-key, off the derived root key.
	sendingRatchet, err := curve.GenerateKeyPair(rng)
	if err != nil {
		return nil, fmt.Errorf("session: generating sending ratchet key: %w", err)
	}
	sendingRoot, sendingChain, err := initial.RootKey.CreateChain(p.theirSignedPre, sendingRatchet.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("session: alice DH ratchet step: %w", err)
	}

	st := NewEmptySessionState()
	st.SetSessionVersion(signalMessageCurrentVersion)
	st.SetLocalIdentityPublic(p.ourIdentity.PublicKey)
	st.SetRemoteIdentityPublic(p.theirIdentity)
	st.SetRootKey(sendingRoot)
	// alice_base_key is the initiator's ephemeral public key (used to match
	// sessions, per ratchet.rs SessionState::new base-key argument).
	st.SetAliceBaseKey(p.ourBase.PublicKey.Serialize())
	// Receiver chain keyed by the recipient's signed pre-key, with the
	// PQXDH-derived chain key; sender chain off the DH ratchet step.
	st.AddReceiverChain(p.theirSignedPre, initial.ChainKey)
	st.SetSenderChain(sendingRatchet, sendingChain)
	// The Kyber ciphertext to relay in the PreKeySignalMessage.
	st.SetKyberCiphertext(kyberCT)
	return st, nil
}

// BobParams carries the resolved key material for the recipient agreement. The
// session cipher (T18) supplies these from the recipient's stores plus the
// incoming PreKeySignalMessage's base key and Kyber ciphertext.
type BobParams struct {
	OurIdentity   curve.KeyPair
	OurSignedPre  curve.KeyPair
	OurOneTime    *curve.KeyPair // optional; present iff the message used a one-time pre-key
	OurKyber      kem.KeyPair
	TheirIdentity curve.PublicKey
	TheirBaseKey  curve.PublicKey
	KyberCipher   []byte
}

// InitializeBobSession performs the recipient (Bob) side of the PQXDH agreement
// and Double Ratchet bob init (ratchet::initialize_bob_session, minus SPQR per
// ADR 0001 Stage 1). It is the seam the decrypt path (T18) calls once it has
// resolved the recipient's pre-keys from its stores and the initiator's base
// key + Kyber ciphertext from the PreKeySignalMessage. The returned state has
// no receiver chain (the first incoming message establishes it) and a sender
// chain off the recipient's signed pre-key.
func InitializeBobSession(p BobParams) (*SessionState, error) {
	if len(p.KyberCipher) == 0 {
		return nil, ErrNoKyberPreKey
	}
	// Mirror of the initiator agreement (pqxdh_accept), same secret:
	//   DH1 = our_signed_pre.priv x their_identity
	//   DH2 = our_identity.priv   x their_base
	//   DH3 = our_signed_pre.priv x their_base
	//   DH4 = our_one_time.priv   x their_base   (optional)
	dh1, err := p.OurSignedPre.PrivateKey.CalculateAgreement(p.TheirIdentity)
	if err != nil {
		return nil, fmt.Errorf("%w: DH1: %v", ErrInvalidKey, err)
	}
	dh2, err := p.OurIdentity.PrivateKey.CalculateAgreement(p.TheirBaseKey)
	if err != nil {
		return nil, fmt.Errorf("%w: DH2: %v", ErrInvalidKey, err)
	}
	dh3, err := p.OurSignedPre.PrivateKey.CalculateAgreement(p.TheirBaseKey)
	if err != nil {
		return nil, fmt.Errorf("%w: DH3: %v", ErrInvalidKey, err)
	}
	var dh4 []byte
	if p.OurOneTime != nil {
		dh4, err = p.OurOneTime.PrivateKey.CalculateAgreement(p.TheirBaseKey)
		if err != nil {
			return nil, fmt.Errorf("%w: DH4: %v", ErrInvalidKey, err)
		}
	}

	kyberSS, err := p.OurKyber.SecretKey.Decapsulate(p.KyberCipher)
	if err != nil {
		return nil, fmt.Errorf("%w: Kyber decapsulate: %v", ErrInvalidKey, err)
	}

	initial, err := ratchet.DeriveInitialKeys(dh1, dh2, dh3, dh4, kyberSS)
	if err != nil {
		return nil, fmt.Errorf("session: deriving initial keys: %w", err)
	}

	st := NewEmptySessionState()
	st.SetSessionVersion(signalMessageCurrentVersion)
	st.SetLocalIdentityPublic(p.OurIdentity.PublicKey)
	st.SetRemoteIdentityPublic(p.TheirIdentity)
	st.SetRootKey(initial.RootKey)
	// alice_base_key is the initiator's base key (so both sides record the same
	// matching key), per ratchet.rs initialize_recipient_session.
	st.SetAliceBaseKey(p.TheirBaseKey.Serialize())
	// Bob's sending chain is keyed by his own signed pre-key off the PQXDH chain
	// key; no receiver chain yet (set when Bob first receives from Alice).
	st.SetSenderChain(p.OurSignedPre, initial.ChainKey)
	return st, nil
}
