package session_test

import (
	"context"
	"io"
	"reflect"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/protocol"
	"github.com/GoCodeAlone/libsignal-go/session"
)

var _ func(context.Context, *protocol.PreKeySignalMessage, address.ProtocolAddress, session.PreKeyDecryptStores, io.Reader) ([]byte, error) = session.DecryptPreKey

func TestPreKeyDecryptStoresPublicContract(t *testing.T) {
	typeOf := reflect.TypeFor[session.PreKeyDecryptStores]()
	want := []string{"Sessions", "Identities", "PreKeys", "SignedKeys", "KyberPreKeys"}
	if typeOf.NumField() != len(want) {
		t.Fatal("recipient store bundle deviated from the approved public contract")
	}
	for i, name := range want {
		if typeOf.Field(i).Name != name || !typeOf.Field(i).IsExported() {
			t.Fatalf("recipient store field %d must remain %s", i, name)
		}
	}
}
