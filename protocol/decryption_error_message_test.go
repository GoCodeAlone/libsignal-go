package protocol

import (
	"encoding/hex"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/curve"
)

func TestDecryptionErrorMessageRoundTripWithRatchetKey(t *testing.T) {
	rkKP, err := curve.GenerateKeyPair(&fixedReader{b: 7})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	msg, err := NewDecryptionErrorMessage(&rkKP.PublicKey, 1234567890, 2)
	if err != nil {
		t.Fatalf("NewDecryptionErrorMessage: %v", err)
	}
	got, err := DeserializeDecryptionErrorMessage(msg.Serialized())
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.Timestamp() != 1234567890 {
		t.Fatalf("timestamp = %d", got.Timestamp())
	}
	if got.DeviceID() != 2 {
		t.Fatalf("deviceID = %d", got.DeviceID())
	}
	if got.RatchetKey() == nil || !got.RatchetKey().Equal(rkKP.PublicKey) {
		t.Fatal("ratchet key mismatch")
	}
}

func TestDecryptionErrorMessageRoundTripWithoutRatchetKey(t *testing.T) {
	msg, err := NewDecryptionErrorMessage(nil, 999, 0)
	if err != nil {
		t.Fatalf("NewDecryptionErrorMessage: %v", err)
	}
	got, err := DeserializeDecryptionErrorMessage(msg.Serialized())
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.RatchetKey() != nil {
		t.Fatal("expected nil ratchet key")
	}
	if got.Timestamp() != 999 {
		t.Fatalf("timestamp = %d", got.Timestamp())
	}
}

func TestDecryptionErrorMessageRejectsMissingTimestamp(t *testing.T) {
	// An empty protobuf has no timestamp field -> required-field error.
	if _, err := DeserializeDecryptionErrorMessage([]byte{}); err == nil {
		t.Fatal("empty message accepted")
	} else if err != ErrInvalidProtobufEncoding {
		t.Fatalf("error = %v, want ErrInvalidProtobufEncoding", err)
	}
}

func TestDecryptionErrorMessageRejectsBadRatchetKey(t *testing.T) {
	// timestamp set, ratchet_key present but not a valid public key (bad type
	// byte). Field 1 (ratchet_key) len-delimited; field 2 (timestamp) varint.
	bad := []byte{
		0x0a, 0x02, 0x00, 0x00, // ratchet_key = {0x00,0x00} (too short / bad)
		0x10, 0x01, // timestamp = 1
	}
	if _, err := DeserializeDecryptionErrorMessage(bad); err == nil {
		t.Fatal("bad ratchet key accepted")
	}
}

func TestDecryptionErrorMessageGolden(t *testing.T) {
	rkKP, err := curve.GenerateKeyPair(&fixedReader{b: 0x30})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	msg, err := NewDecryptionErrorMessage(&rkKP.PublicKey, 0x1122334455667788, 0x09)
	if err != nil {
		t.Fatalf("NewDecryptionErrorMessage: %v", err)
	}
	if got := hex.EncodeToString(msg.Serialized()); got != goldenDecryptionErrorMessageHex {
		t.Fatalf("golden mismatch:\n got %s\nwant %s", got, goldenDecryptionErrorMessageHex)
	}
}
