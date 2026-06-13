package session_test

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/kem"
	"github.com/GoCodeAlone/libsignal-go/session"
	"github.com/GoCodeAlone/libsignal-go/stores/inmem"
)

// Example_sessionRoundTrip shows a PQXDH handshake and the first message.
// Bob publishes a pre-key bundle; Alice processes it and encrypts an initial
// message (a PreKeySignalMessage carrying the inner SignalMessage); Bob
// establishes his side from the same handshake material and decrypts.
//
// Bob's session is established here via InitializeBobSession, the recipient
// seam: it consumes Alice's base key and the Kyber ciphertext (recovered from
// Alice's pending pre-key message) together with Bob's own pre-key private keys.
func Example_sessionRoundTrip() {
	ctx := context.Background()
	dev, _ := address.NewDeviceID(1)
	aliceAddr := address.NewProtocolAddress("+15551230001", dev)
	bobAddr := address.NewProtocolAddress("+15551230002", dev)

	// --- Bob's long-lived + pre-key material ---
	bobIdentity, _ := curve.GenerateKeyPair(rand.Reader)
	bobSignedPre, _ := curve.GenerateKeyPair(rand.Reader)
	bobOneTime, _ := curve.GenerateKeyPair(rand.Reader)
	bobKyber, _ := kem.GenerateKeyPair(kem.KeyTypeKyber1024, rand.Reader)

	// Bob signs his signed-pre-key and Kyber pre-key with his identity key.
	signedSig, _ := bobIdentity.PrivateKey.CalculateSignature(rand.Reader, bobSignedPre.PublicKey.Serialize())
	kyberSig, _ := bobIdentity.PrivateKey.CalculateSignature(rand.Reader, bobKyber.PublicKey.Serialize())

	oneTimeID := uint32(31)
	oneTimePub := bobOneTime.PublicKey
	bundle, err := session.NewPreKeyBundle(session.PreKeyBundleParams{
		RegistrationID:  4242,
		DeviceID:        1,
		PreKeyID:        &oneTimeID,
		PreKey:          &oneTimePub,
		SignedPreKeyID:  55,
		SignedPreKey:    bobSignedPre.PublicKey,
		SignedPreKeySig: signedSig,
		KyberPreKeyID:   66,
		KyberPreKey:     bobKyber.PublicKey,
		KyberPreKeySig:  kyberSig,
		IdentityKey:     bobIdentity.PublicKey,
	})
	if err != nil {
		panic(err)
	}

	// --- Alice establishes a session from Bob's bundle and encrypts ---
	aliceIdentity, _ := curve.GenerateKeyPair(rand.Reader)
	aliceID := inmem.NewIdentityKeyStore(aliceIdentity, 1001)
	aliceSess := inmem.NewSessionStore()

	if err := session.ProcessPreKeyBundle(ctx, rand.Reader, bobAddr, bundle, aliceSess, aliceID); err != nil {
		panic(err)
	}

	plaintext := []byte("hello, bob")
	// On the first (unacknowledged) message Alice wraps the SignalMessage in a
	// PreKeySignalMessage; the inner SignalMessage is what Bob's session decrypts.
	signalMsg, preKeyMsg, err := session.Encrypt(ctx, plaintext, bobAddr, aliceSess, aliceID, nil)
	if err != nil {
		panic(err)
	}
	if preKeyMsg != nil {
		signalMsg = preKeyMsg.Message()
	}

	// --- Bob establishes his side from the handshake material and decrypts ---
	// Recover Alice's base key + Kyber ciphertext from her pending pre-key state.
	aliceRec, _ := aliceSess.LoadSession(ctx, bobAddr)
	pending, ok := aliceRec.CurrentState().PendingPreKeyMessage()
	if !ok {
		panic("alice has no pending pre-key message")
	}
	aliceBaseKey, err := curve.DeserializePublicKey(pending.BaseKey)
	if err != nil {
		panic(err)
	}

	bobState, err := session.InitializeBobSession(session.BobParams{
		OurIdentity:   bobIdentity,
		OurSignedPre:  bobSignedPre,
		OurOneTime:    &bobOneTime,
		OurKyber:      bobKyber,
		TheirIdentity: aliceIdentity.PublicKey,
		TheirBaseKey:  aliceBaseKey,
		KyberCipher:   pending.KyberCiphertext,
	})
	if err != nil {
		panic(err)
	}
	bobSess := inmem.NewSessionStore()
	if err := bobSess.StoreSession(ctx, aliceAddr, session.NewSessionRecord(bobState)); err != nil {
		panic(err)
	}

	got, err := session.Decrypt(ctx, signalMsg, aliceAddr, bobSess, rand.Reader)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(got))
	// Output: hello, bob
}
