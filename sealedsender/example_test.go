package sealedsender_test

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/protocol"
	"github.com/GoCodeAlone/libsignal-go/sealedsender"
)

// Example_sealedSender shows the sealed-sender v1 flow: a sender holding a
// certificate chain (sender cert signed by a server cert, which is signed by the
// trust root) wraps a message so only the recipient learns who sent it, then the
// recipient decrypts and validates the sender's certificate against the trust
// root.
func Example_sealedSender() {
	// Long-lived identities. In production these come from key stores; here they
	// are generated for the example. genKey panics on a key-generation error so
	// the example handles every error rather than discarding it.
	genKey := func() curve.KeyPair {
		kp, err := curve.GenerateKeyPair(rand.Reader)
		if err != nil {
			panic(err)
		}
		return kp
	}
	trustRoot := genKey()
	serverKey := genKey()
	senderIdentity := genKey()
	recipientIdentity := genKey()

	// The server certificate is signed by the trust root; the sender certificate
	// is signed by the server, binding the sender's identity + UUID + device.
	server, err := sealedsender.NewServerCertificate(1, serverKey.PublicKey, trustRoot.PrivateKey, rand.Reader)
	if err != nil {
		panic(err)
	}
	expires := time.UnixMilli(2_000_000_000_000).UTC()
	senderCert, err := sealedsender.NewSenderCertificate(
		"sender-uuid", nil, senderIdentity.PublicKey, 1, expires, server, serverKey.PrivateKey, rand.Reader)
	if err != nil {
		panic(err)
	}

	// The unidentified sender message content wraps the actual ciphertext plus
	// routing metadata (message type, sender cert, content hint, optional group).
	usmc, err := sealedsender.NewUnidentifiedSenderMessageContent(
		protocol.MessageTypeWhisper, senderCert, []byte("sealed hello"), sealedsender.ContentHintDefault, nil)
	if err != nil {
		panic(err)
	}

	// The sender seals to the recipient's identity public key.
	sealed, err := sealedsender.SealV1(usmc, senderIdentity, recipientIdentity.PublicKey, rand.Reader)
	if err != nil {
		panic(err)
	}

	// The recipient decrypts with its own identity and validates the sender's
	// certificate chain against the trust root at the current time.
	got, err := sealedsender.DecryptToUSMCAndValidate(sealed, recipientIdentity, trustRoot.PublicKey, expires.Add(-time.Hour))
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s from %s\n", got.Contents(), got.Sender().SenderUUID())
	// Output: sealed hello from sender-uuid
}
