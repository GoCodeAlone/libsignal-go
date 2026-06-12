package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/curve"
)

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestSenderKeyDistributionMessageRoundTrip(t *testing.T) {
	signKP, err := curve.GenerateKeyPair(&fixedReader{b: 3})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	chainKey := repeatByte(0xCD, chainKeyLen)
	msg, err := NewSenderKeyDistributionMessage(testDistributionID(), 9, 3, chainKey, signKP.PublicKey)
	if err != nil {
		t.Fatalf("NewSenderKeyDistributionMessage: %v", err)
	}

	got, err := DeserializeSenderKeyDistributionMessage(msg.Serialized())
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.MessageVersion() != SenderKeyCurrentVersion {
		t.Fatalf("version = %d", got.MessageVersion())
	}
	if got.DistributionID() != testDistributionID() {
		t.Fatalf("distribution id mismatch")
	}
	if got.ChainID() != 9 || got.Iteration() != 3 {
		t.Fatalf("chainID/iteration = %d/%d", got.ChainID(), got.Iteration())
	}
	if !bytes.Equal(got.ChainKey(), chainKey) {
		t.Fatalf("chain key mismatch")
	}
	if !got.SigningKey().Equal(signKP.PublicKey) {
		t.Fatal("signing key mismatch")
	}
	if !bytes.Equal(got.Serialized(), msg.Serialized()) {
		t.Fatal("serialized round-trip mismatch")
	}
}

func TestSenderKeyDistributionMessageRejectsBadInput(t *testing.T) {
	if _, err := DeserializeSenderKeyDistributionMessage(make([]byte, 10)); err == nil {
		t.Fatal("short message accepted")
	} else if !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("short error = %v, want ErrCiphertextTooShort", err)
	}

	signKP, _ := curve.GenerateKeyPair(&fixedReader{b: 3})
	msg, _ := NewSenderKeyDistributionMessage(testDistributionID(), 1, 1, repeatByte(0x01, chainKeyLen), signKP.PublicKey)

	legacy := append([]byte(nil), msg.Serialized()...)
	legacy[0] = (2 << 4) | SenderKeyCurrentVersion
	if _, err := DeserializeSenderKeyDistributionMessage(legacy); err == nil {
		t.Fatal("legacy accepted")
	} else if !errors.Is(err, ErrLegacyVersion) {
		t.Fatalf("legacy error = %v, want ErrLegacyVersion", err)
	}

	future := append([]byte(nil), msg.Serialized()...)
	future[0] = (5 << 4) | SenderKeyCurrentVersion
	if _, err := DeserializeSenderKeyDistributionMessage(future); err == nil {
		t.Fatal("future accepted")
	} else if !errors.Is(err, ErrUnrecognizedVersion) {
		t.Fatalf("future error = %v, want ErrUnrecognizedVersion", err)
	}
}

func TestSenderKeyDistributionMessageGolden(t *testing.T) {
	signKP, err := curve.GenerateKeyPair(&fixedReader{b: 0x20})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	msg, err := NewSenderKeyDistributionMessage(testDistributionID(), 0x01020304, 0x05060708, repeatByte(0xAB, chainKeyLen), signKP.PublicKey)
	if err != nil {
		t.Fatalf("NewSenderKeyDistributionMessage: %v", err)
	}
	if got := hex.EncodeToString(msg.Serialized()); got != goldenSenderKeyDistributionMessageHex {
		t.Fatalf("golden mismatch:\n got %s\nwant %s", got, goldenSenderKeyDistributionMessageHex)
	}
}
