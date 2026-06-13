package groups_test

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/groups"
	"github.com/GoCodeAlone/libsignal-go/stores/inmem"
)

// Example_groupMessaging shows the sender-key group flow: a sender distributes
// its sender key to a group member, then encrypts a message the member decrypts.
// Each party keeps its own SenderKeyStore keyed by (sender, distributionID).
func Example_groupMessaging() {
	ctx := context.Background()

	// The sender's address and a shared 16-byte distribution id for this group.
	dev, err := address.NewDeviceID(1)
	if err != nil {
		panic(err)
	}
	sender := address.NewProtocolAddress("+15551230001", dev)
	var distributionID [16]byte
	copy(distributionID[:], []byte("example-dist-001"))

	senderStore := inmem.NewSenderKeyStore()
	memberStore := inmem.NewSenderKeyStore()

	// The sender provisions its chain and produces a distribution message.
	skdm, err := groups.CreateSenderKeyDistributionMessage(ctx, sender, distributionID, senderStore, rand.Reader)
	if err != nil {
		panic(err)
	}

	// The group member processes the distribution message into its own store.
	if err := groups.ProcessSenderKeyDistributionMessage(ctx, sender, skdm, memberStore); err != nil {
		panic(err)
	}

	// The sender encrypts; the member decrypts to the identical plaintext.
	plaintext := []byte("hello, group")
	skm, err := groups.Encrypt(ctx, sender, distributionID, plaintext, senderStore, rand.Reader)
	if err != nil {
		panic(err)
	}
	got, err := groups.Decrypt(ctx, sender, skm.Serialized(), memberStore)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(got))
	// Output: hello, group
}
