package accountkeys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"math"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestMFAMetadataRoundTripAndTampering(t *testing.T) {
	key := NewSVRKey([32]byte(bytes.Repeat([]byte{42}, 32)))
	for _, name := range []string{"", "laptop", strings.Repeat("x", MFAKeyNameMaxLen), strings.Repeat("\U0001f511", 24) + "xy"} {
		for _, millis := range []uint64{0, 999, 1000, 1721234567890, math.MaxUint64} {
			metadata, err := NewMFAMetadata(name, millis)
			if err != nil {
				t.Fatal(err)
			}
			iv := bytes.Repeat([]byte{7}, aes.BlockSize)
			encrypted, err := metadata.Encrypt(key, bytes.NewReader(iv))
			if err != nil {
				t.Fatal(err)
			}
			raw := encrypted.Bytes()
			if len(raw) != 160 || !bytes.Equal(raw[:aes.BlockSize], iv) {
				t.Fatal("MFA ciphertext changed fixed size or supplied IV")
			}
			parsed, err := ParseEncryptedMFAMetadata(raw[:])
			if err != nil {
				t.Fatal(err)
			}
			raw[0] ^= 1
			if parsed != encrypted {
				t.Fatal("parsed ciphertext aliases caller memory")
			}
			decoded, err := parsed.Decrypt(key)
			if err != nil || decoded.Name() != name || decoded.CreatedAtEpochMillis() != millis/1000*1000 {
				t.Fatalf("MFA round trip failed: %v", err)
			}
			for i := range encrypted {
				mutated := encrypted
				mutated[i] ^= 1
				got, err := mutated.Decrypt(key)
				if err == nil || got != (MFAMetadata{}) {
					t.Fatalf("tampered byte %d returned metadata or no error", i)
				}
			}
			if got, err := encrypted.Decrypt(NewSVRKey([32]byte{})); err == nil || got != (MFAMetadata{}) {
				t.Fatal("wrong SVR key returned metadata or no error")
			}
		}
	}
}

func TestMFAMetadataRejectsInvalidNamesAndRandomness(t *testing.T) {
	for _, name := range []string{"\xff", "contains\x00nul", strings.Repeat("x", 99), strings.Repeat("\U0001f511", 25)} {
		got, err := NewMFAMetadata(name, 0)
		if err == nil || got != (MFAMetadata{}) || strings.Contains(err.Error(), name) {
			t.Fatal("invalid MFA name was accepted, returned metadata, or leaked into its error")
		}
	}
	metadata, err := NewMFAMetadata("key", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, reader := range []io.Reader{nil, bytes.NewReader(nil), bytes.NewReader(make([]byte, 15))} {
		got, err := metadata.Encrypt(NewSVRKey([32]byte{}), reader)
		if err == nil || got != (EncryptedMFAMetadata{}) {
			t.Fatal("failed randomness returned a partial ciphertext or no error")
		}
	}
	for _, length := range []int{0, 159, 161, 320} {
		got, err := ParseEncryptedMFAMetadata(make([]byte, length))
		if err == nil || got != (EncryptedMFAMetadata{}) {
			t.Fatalf("accepted invalid ciphertext length %d", length)
		}
	}
}

// Seal hostile, authenticated plaintext independently of the production encoder.
func sealMFATestPlaintext(t *testing.T, padded []byte) EncryptedMFAMetadata {
	t.Helper()
	if len(padded) != 112 {
		t.Fatal("test plaintext must be exactly 112 bytes")
	}
	cipherKey := mustHex32(t, "3ac203547d12b86aedc2c0ed76f4d80b2d504fa8859a85153378b2694af67116")
	authKey := mustHex32(t, "8f89663ca56515705125d2208be3a5828147fa7326e0796edc26871dfe7c8aa0")
	block, err := aes.NewCipher(cipherKey[:])
	if err != nil {
		t.Fatal(err)
	}
	var out EncryptedMFAMetadata
	cipher.NewCBCEncrypter(block, out[:16]).CryptBlocks(out[16:128], padded)
	mac := hmac.New(sha256.New, authKey[:])
	_, _ = mac.Write(out[:128])
	copy(out[128:], mac.Sum(nil))
	return out
}

func padMFATestPlaintext(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	if len(plaintext) >= 112 {
		t.Fatal("test plaintext leaves no room for padding")
	}
	padding := byte(112 - len(plaintext)) // #nosec G115 -- the test guard bounds padding to 1..112.
	return append(bytes.Clone(plaintext), bytes.Repeat([]byte{padding}, 112-len(plaintext))...)
}

func TestMFAMetadataRejectsAuthenticatedMalformedPlaintext(t *testing.T) {
	nameProto := func(name string) []byte {
		return protowire.AppendString(protowire.AppendTag(nil, 2, protowire.BytesType), name)
	}
	overflow := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), math.MaxUint64/1000+1)
	badPadding := bytes.Repeat([]byte{2}, 112)
	badPadding[110] = 1
	cases := map[string][]byte{
		"zero padding":        make([]byte, 112),
		"oversize padding":    bytes.Repeat([]byte{113}, 112),
		"unequal padding":     badPadding,
		"invalid protobuf":    padMFATestPlaintext(t, []byte{0xff}),
		"oversize tag":        padMFATestPlaintext(t, []byte{0x88, 0x80, 0x80, 0x80, 0x80, 0x00, 0x00}),
		"oversize length":     padMFATestPlaintext(t, []byte{0x12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}),
		"group tag bounds":    padMFATestPlaintext(t, []byte{0x1b, 0x88, 0x80, 0x80, 0x80, 0x80, 0x00, 0x00, 0x1c}),
		"unterminated group":  padMFATestPlaintext(t, []byte{0x1b}),
		"top-level end group": padMFATestPlaintext(t, []byte{0x1c}),
		"invalid UTF-8":       padMFATestPlaintext(t, nameProto("\xff")),
		"NUL name":            padMFATestPlaintext(t, nameProto("key\x00name")),
		"oversize name":       padMFATestPlaintext(t, nameProto(strings.Repeat("x", 99))),
		"time overflow":       padMFATestPlaintext(t, overflow),
	}
	key := NewSVRKey([32]byte(bytes.Repeat([]byte{42}, 32)))
	for name, padded := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := sealMFATestPlaintext(t, padded).Decrypt(key)
			if err == nil || got != (MFAMetadata{}) {
				t.Fatal("authenticated malformed plaintext returned metadata or no error")
			}
		})
	}
	// Upstream accepts unknown protobuf fields for forward compatibility.
	unknown := protowire.AppendVarint(protowire.AppendTag(nameProto("key"), 3, protowire.VarintType), 42)
	got, err := sealMFATestPlaintext(t, padMFATestPlaintext(t, unknown)).Decrypt(key)
	if err != nil || got.Name() != "key" {
		t.Fatalf("unknown protobuf field rejected: %v", err)
	}
	for _, plaintext := range [][]byte{
		{0x88, 0x80, 0x80, 0x80, 0x00, 0x00}, // Non-minimal, five-byte tag.
		{0x12, 0x80, 0x80, 0x80, 0x80, 0x00}, // Non-minimal, five-byte length.
		{0x1b, 0x24},                         // Upstream skips groups even with mismatched end-field numbers.
		{0x1b, 0x12, 0x01, 0xff, 0x1c},       // Known fields inside unknown groups are not interpreted.
	} {
		got, err := sealMFATestPlaintext(t, padMFATestPlaintext(t, plaintext)).Decrypt(key)
		if err != nil || got != (MFAMetadata{}) {
			t.Fatalf("upstream-compatible non-minimal/group encoding rejected: %v", err)
		}
	}
}

func FuzzMFAMetadataRoundTrip(f *testing.F) {
	f.Add("key", uint64(1721234567890), bytes.Repeat([]byte{42}, 32))
	f.Add("", uint64(0), make([]byte, 32))
	f.Fuzz(func(t *testing.T, name string, millis uint64, raw []byte) {
		if len(raw) != 32 {
			return
		}
		metadata, err := NewMFAMetadata(name, millis)
		if err != nil {
			return
		}
		key := NewSVRKey([32]byte(raw))
		encrypted, err := metadata.Encrypt(key, bytes.NewReader(make([]byte, 16)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := encrypted.Decrypt(key)
		if err != nil || got.Name() != name || got.CreatedAtEpochMillis() != millis/1000*1000 {
			t.Fatal("MFA round trip failed")
		}
	})
}

func FuzzMFAMetadataDecrypt(f *testing.F) {
	f.Add(make([]byte, 160))
	f.Fuzz(func(t *testing.T, raw []byte) {
		encrypted, err := ParseEncryptedMFAMetadata(raw)
		if err != nil {
			return
		}
		got, err := encrypted.Decrypt(NewSVRKey([32]byte{}))
		if err != nil && got != (MFAMetadata{}) {
			t.Fatal("failed decryption returned metadata")
		}
	})
}

func FuzzMFAMetadataAuthenticatedPlaintext(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x12, 0x03, 'k', 'e', 'y'})
	f.Add([]byte{0x88, 0x80, 0x80, 0x80, 0x80, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 112 {
			return
		}
		padded := raw
		if len(raw) < 112 {
			padded = padMFATestPlaintext(t, raw)
		}
		key := NewSVRKey([32]byte(bytes.Repeat([]byte{42}, 32)))
		metadata, err := sealMFATestPlaintext(t, padded).Decrypt(key)
		if err != nil {
			if metadata != (MFAMetadata{}) {
				t.Fatal("malformed authenticated plaintext returned metadata")
			}
			return
		}
		if _, err := NewMFAMetadata(metadata.Name(), metadata.CreatedAtEpochMillis()); err != nil || metadata.CreatedAtEpochMillis()%1000 != 0 {
			t.Fatal("authenticated parser returned invalid metadata")
		}
		encrypted, err := metadata.Encrypt(key, bytes.NewReader(make([]byte, 16)))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := encrypted.Decrypt(key)
		if err != nil || decoded != metadata {
			t.Fatal("authenticated parsed metadata failed canonical round trip")
		}
	})
}
