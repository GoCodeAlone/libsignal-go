package groups

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/protocol"
	"github.com/GoCodeAlone/libsignal-go/stores/inmem"
)

// FuzzDeserializeSenderKeyRecord checks that decoding arbitrary bytes as a
// SenderKeyRecord never panics, and that any successful parse re-serializes
// without error.
func FuzzDeserializeSenderKeyRecord(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	// A valid single-state record, as a realistic seed.
	if seed := validRecordBytes(f); seed != nil {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := DeserializeSenderKeyRecord(data)
		if err != nil {
			return
		}
		// A successful parse must re-serialize without panicking or erroring, and
		// state accessors must not panic on the decoded (possibly empty) states.
		if _, err := rec.Serialize(); err != nil {
			t.Fatalf("re-serialize after successful parse: %v", err)
		}
		for _, s := range rec.states {
			_ = s.MessageVersion()
			_, _ = s.ChainKey()
			_, _ = s.SigningKeyPublic()
			_, _ = s.SigningKeyPrivate()
		}
	})
}

// FuzzDeserializeSenderKeyDistributionMessage checks that decoding arbitrary
// bytes as an SKDM never panics, and that a successful parse can be processed
// into a store without panicking. It exercises the deserialize path the group
// builder consumes.
func FuzzDeserializeSenderKeyDistributionMessage(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{byte((protocol.SenderKeyCurrentVersion << 4) | protocol.SenderKeyCurrentVersion)})
	if seed := validSKDMBytes(f); seed != nil {
		f.Add(seed)
	}

	ctx := context.Background()
	sender := fuzzAddress(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		skdm, err := protocol.DeserializeSenderKeyDistributionMessage(data)
		if err != nil {
			return
		}
		// A successful parse must round-trip its own bytes and be processable.
		_ = skdm.Serialized()
		store := inmem.NewSenderKeyStore()
		if err := ProcessSenderKeyDistributionMessage(ctx, sender, skdm, store); err != nil {
			t.Fatalf("process valid SKDM: %v", err)
		}
	})
}

// validRecordBytes produces the serialized bytes of a single-state record for
// use as a fuzz seed; returns nil on setup failure (seeds are best-effort).
func validRecordBytes(f *testing.F) []byte {
	f.Helper()
	kp, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil
	}
	rec := NewSenderKeyRecord()
	priv := kp.PrivateKey
	rec.AddSenderKeyState(senderKeyMessageVersion, 7, 0, make([]byte, chainKeyLen), kp.PublicKey, &priv)
	b, err := rec.Serialize()
	if err != nil {
		return nil
	}
	return b
}

// validSKDMBytes produces the serialized bytes of a valid SKDM for use as a
// fuzz seed; returns nil on setup failure.
func validSKDMBytes(f *testing.F) []byte {
	f.Helper()
	ctx := context.Background()
	store := inmem.NewSenderKeyStore()
	skdm, err := CreateSenderKeyDistributionMessage(ctx, fuzzAddress(f), distributionID(), store, rand.Reader)
	if err != nil {
		return nil
	}
	return skdm.Serialized()
}

// fuzzAddress builds a fixed test address for fuzz seeds/harnesses.
func fuzzAddress(f *testing.F) address.ProtocolAddress {
	f.Helper()
	dev, err := address.NewDeviceID(1)
	if err != nil {
		f.Fatalf("device id: %v", err)
	}
	return address.NewProtocolAddress("+14155550100", dev)
}
