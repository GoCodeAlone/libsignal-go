package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/curve"
)

func TestPlaintextContentFromDecryptionError(t *testing.T) {
	rkKP, err := curve.GenerateKeyPair(&fixedReader{b: 4})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dem, err := NewDecryptionErrorMessage(&rkKP.PublicKey, 42, 1)
	if err != nil {
		t.Fatalf("NewDecryptionErrorMessage: %v", err)
	}
	pc, err := NewPlaintextContentFromDecryptionError(dem)
	if err != nil {
		t.Fatalf("NewPlaintextContentFromDecryptionError: %v", err)
	}

	ser := pc.Serialized()
	if ser[0] != plaintextContentIdentifierByte {
		t.Fatalf("identifier byte = 0x%02x, want 0xC0", ser[0])
	}
	if ser[len(ser)-1] != paddingBoundaryByte {
		t.Fatalf("padding byte = 0x%02x, want 0x80", ser[len(ser)-1])
	}

	got, err := DeserializePlaintextContent(ser)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if !bytes.Equal(got.Serialized(), ser) {
		t.Fatal("serialized round-trip mismatch")
	}
	if !bytes.Equal(got.Body(), ser[1:]) {
		t.Fatal("body mismatch")
	}
}

func TestPlaintextContentRejectsBadInput(t *testing.T) {
	if _, err := DeserializePlaintextContent(nil); err == nil {
		t.Fatal("empty accepted")
	} else if !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("empty error = %v, want ErrCiphertextTooShort", err)
	}

	// Wrong identifier byte.
	if _, err := DeserializePlaintextContent([]byte{0x05, 0x01, 0x02}); err == nil {
		t.Fatal("wrong identifier accepted")
	} else if !errors.Is(err, ErrUnrecognizedVersion) {
		t.Fatalf("wrong identifier error = %v, want ErrUnrecognizedVersion", err)
	}
}

func TestPlaintextContentGolden(t *testing.T) {
	rkKP, err := curve.GenerateKeyPair(&fixedReader{b: 0x30})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dem, err := NewDecryptionErrorMessage(&rkKP.PublicKey, 0x1122334455667788, 0x09)
	if err != nil {
		t.Fatalf("NewDecryptionErrorMessage: %v", err)
	}
	pc, err := NewPlaintextContentFromDecryptionError(dem)
	if err != nil {
		t.Fatalf("NewPlaintextContentFromDecryptionError: %v", err)
	}
	if got := hex.EncodeToString(pc.Serialized()); got != goldenPlaintextContentHex {
		t.Fatalf("golden mismatch:\n got %s\nwant %s", got, goldenPlaintextContentHex)
	}
}

// --- Fuzz targets: every Deserialize entry point must never panic. ---

func FuzzDeserializeSenderKeyMessage(f *testing.F) {
	signKP, _ := curve.GenerateKeyPair(&fixedReader{b: 1})
	msg, _ := NewSenderKeyMessage(testDistributionID(), 1, 2, []byte("x"), &fixedReader{b: 2}, signKP.PrivateKey)
	f.Add(msg.Serialized())
	f.Add([]byte{})
	f.Add(make([]byte, 65))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := DeserializeSenderKeyMessage(b)
		if err == nil {
			_ = m.VerifySignature(signKP.PublicKey)
			if !bytes.Equal(m.Serialized(), b) {
				t.Fatal("serialized not preserved")
			}
		}
	})
}

func FuzzDeserializeSenderKeyDistributionMessage(f *testing.F) {
	signKP, _ := curve.GenerateKeyPair(&fixedReader{b: 3})
	msg, _ := NewSenderKeyDistributionMessage(testDistributionID(), 1, 2, repeatByte(0x01, chainKeyLen), signKP.PublicKey)
	f.Add(msg.Serialized())
	f.Add([]byte{})
	f.Add(make([]byte, 65))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = DeserializeSenderKeyDistributionMessage(b)
	})
}

func FuzzDeserializeDecryptionErrorMessage(f *testing.F) {
	rkKP, _ := curve.GenerateKeyPair(&fixedReader{b: 7})
	msg, _ := NewDecryptionErrorMessage(&rkKP.PublicKey, 1, 2)
	f.Add(msg.Serialized())
	f.Add([]byte{})
	f.Add([]byte{0x10, 0x01})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = DeserializeDecryptionErrorMessage(b)
	})
}

func FuzzDeserializePlaintextContent(f *testing.F) {
	f.Add([]byte{plaintextContentIdentifierByte, 0x42, 0x00, paddingBoundaryByte})
	f.Add([]byte{})
	f.Add([]byte{0xC0})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := DeserializePlaintextContent(b)
		if err == nil && !bytes.Equal(m.Serialized(), b) {
			t.Fatal("serialized not preserved")
		}
	})
}
