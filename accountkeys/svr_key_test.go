package accountkeys

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"testing"
)

func TestPinHashMasterKeySIV(t *testing.T) {
	type masterKeyCodec interface {
		EncodeMasterKey([32]byte) [48]byte
		DecodeMasterKey([48]byte) ([32]byte, error)
	}
	hash := CreatePinHash([]byte("password"), mustHex32(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	codec, ok := any(hash).(masterKeyCodec)
	if !ok {
		t.Fatal("PinHash is missing upstream master-key SIV encoding and decoding")
	}
	master := mustHex32(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	ciphertext := codec.EncodeMasterKey(master)
	const want = "3f33ce58eb25b40436592a30eae2a8fabab1899095f4e2fba6e2d0dc43b4a2d9cac5a3931748522393951e0e54dec769"
	if hex.EncodeToString(ciphertext[:]) != want {
		t.Fatalf("master-key SIV = %x, want %s", ciphertext, want)
	}
	decoded, err := codec.DecodeMasterKey(ciphertext)
	if err != nil || decoded != master {
		t.Fatalf("master-key round trip failed: %v", err)
	}
	for i := range ciphertext {
		mutated := ciphertext
		mutated[i] ^= 1
		got, err := codec.DecodeMasterKey(mutated)
		if err == nil || got != ([32]byte{}) {
			t.Fatalf("tampered byte %d returned plaintext or no error", i)
		}
	}
	wrong := hash
	wrong.EncryptionKey[0] ^= 1
	if got, err := any(wrong).(masterKeyCodec).DecodeMasterKey(ciphertext); err == nil || got != ([32]byte{}) {
		t.Fatal("wrong PIN encryption key returned plaintext or no error")
	}
}

func TestSVRDerivationsAndRedaction(t *testing.T) {
	key := NewSVRKey([32]byte(bytes.Repeat([]byte{42}, 32)))
	cases := []struct {
		name string
		got  [32]byte
		want string
	}{
		{"registration lock", key.DeriveRegistrationLock(), "3a40e25812e6c20cca76a602451dd2bc7484553514438cade320c2aef54e10d1"},
		{"recovery password", key.DeriveRegistrationRecoveryPassword(), "91f959cfee39676dedd028bc8bbbd1e91ffa6a42c57754d095fe8abe7f0d4f56"},
		{"storage service", key.DeriveStorageServiceKey(), "3f31b618172a9f8ad45e290788e6176736e6161d4ea0e8050f8553521f59c200"},
		{"logging", key.DeriveLoggingKey(), "cd2a39f4857de4df3fe793d1de061bfa3dd63533c0a4ef79b3fa3eba2bf96e62"},
	}
	for _, tc := range cases {
		if tc.got != mustHex32(t, tc.want) {
			t.Errorf("%s derivation = %x, want %s", tc.name, tc.got, tc.want)
		}
	}
	pool, err := ParseAccountEntropyPool(strings.Repeat("m", 64))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pool.SVRKey().DeriveRegistrationLock(), NewSVRKey(pool.DeriveSVRKey()).DeriveRegistrationLock(); got != want {
		t.Fatal("typed SVR key changed legacy entropy derivation")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%x", "%s", "%q", "%100x", "%.4s"} {
		for _, value := range []any{key, &key} {
			if got := fmt.Sprintf(format, value); got != "[REDACTED SVRKey]" {
				t.Errorf("format %q = %q, want unconditional redaction", format, got)
			}
		}
	}
	var out bytes.Buffer
	log.New(&out, "", 0).Print(key)
	slog.New(slog.NewTextHandler(&out, nil)).Info("key", "svr", key)
	fmt.Fprint(&out, fmt.Errorf("operation failed: %w", fmt.Errorf("key=%#v", key)))
	if strings.Contains(out.String(), strings.Repeat("2a", 32)) || strings.Contains(out.String(), "42 42") {
		t.Fatal("logging or wrapped errors leaked SVR key bytes")
	}
	if strings.Count(out.String(), "REDACTED SVRKey") != 3 {
		t.Fatalf("expected redaction in log, slog and wrapped errors: %s", out.String())
	}
}

func FuzzPinHashMasterKeySIV(f *testing.F) {
	f.Add(bytes.Repeat([]byte{42}, 32), bytes.Repeat([]byte{1}, 32))
	f.Fuzz(func(t *testing.T, key, master []byte) {
		if len(key) != 32 || len(master) != 32 {
			return
		}
		hash := PinHash{EncryptionKey: [32]byte(key)}
		ciphertext := hash.EncodeMasterKey([32]byte(master))
		decoded, err := hash.DecodeMasterKey(ciphertext)
		if err != nil || decoded != [32]byte(master) {
			t.Fatal("SIV round trip failed")
		}
		ciphertext[0] ^= 1
		if got, err := hash.DecodeMasterKey(ciphertext); err == nil || got != ([32]byte{}) {
			t.Fatal("unauthenticated SIV returned plaintext")
		}
	})
}
