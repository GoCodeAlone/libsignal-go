package accountkeys_test

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/accountkeys"
)

// Compile the additive public contract as a downstream consumer, without internals.
var (
	_ func([32]byte) accountkeys.SVRKey                      = accountkeys.NewSVRKey
	_ func(string, uint64) (accountkeys.MFAMetadata, error)  = accountkeys.NewMFAMetadata
	_ func([]byte) (accountkeys.EncryptedMFAMetadata, error) = accountkeys.ParseEncryptedMFAMetadata
	_ interface {
		fmt.Stringer
		fmt.GoStringer
		fmt.Formatter
		DeriveRegistrationLock() [32]byte
		DeriveRegistrationRecoveryPassword() [32]byte
		DeriveStorageServiceKey() [32]byte
		DeriveLoggingKey() [32]byte
	} = accountkeys.SVRKey{}
	_ interface {
		SVRKey() accountkeys.SVRKey
		DeriveSVRKey() [32]byte
	} = accountkeys.AccountEntropyPool{}
	_ interface {
		EncodeMasterKey([32]byte) [48]byte
		DecodeMasterKey([48]byte) ([32]byte, error)
	} = accountkeys.PinHash{}
	_ interface {
		Name() string
		CreatedAtEpochMillis() uint64
		Encrypt(accountkeys.SVRKey, io.Reader) (accountkeys.EncryptedMFAMetadata, error)
	} = accountkeys.MFAMetadata{}
	_ interface {
		Bytes() [160]byte
		Decrypt(accountkeys.SVRKey) (accountkeys.MFAMetadata, error)
	} = accountkeys.EncryptedMFAMetadata{}
)

func TestPublicAccountKeyAPI(t *testing.T) {
	keyType := reflect.TypeFor[accountkeys.SVRKey]()
	for i := range keyType.NumField() {
		field := keyType.Field(i)
		if field.IsExported() {
			t.Fatal("SVR master key has an exported raw field")
		}
	}
	if keyType.NumMethod() != 7 {
		t.Fatalf("SVR key has %d methods, want only the approved seven", keyType.NumMethod())
	}
	metadata, err := accountkeys.NewMFAMetadata("security key", 1234567)
	if err != nil {
		t.Fatal(err)
	}
	key := accountkeys.NewSVRKey([32]byte{42})
	encrypted, err := metadata.Encrypt(key, bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := encrypted.Decrypt(key)
	if err != nil || decrypted.Name() != metadata.Name() || decrypted.CreatedAtEpochMillis() != 1234000 {
		t.Fatalf("downstream consumer round trip failed: %v", err)
	}
	if accountkeys.MediaEncryptionAESKeyLen+accountkeys.MediaEncryptionHMACKeyLen != accountkeys.MediaEncryptionKeyLen {
		t.Fatal("media encryption key split changed")
	}
}
