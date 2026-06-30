package accountkeys

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/address"
)

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Fatalf("decoded %d bytes, want 32", len(raw))
	}
	return array32(raw)
}

func TestAccountEntropyPoolParse(t *testing.T) {
	pool, err := ParseAccountEntropyPool(strings.Repeat("m", 64))
	if err != nil {
		t.Fatalf("ParseAccountEntropyPool: %v", err)
	}
	if got := pool.String(); got != strings.Repeat("m", 64) {
		t.Fatalf("String() = %q", got)
	}
	if _, err := ParseAccountEntropyPool("abc"); !errors.Is(err, ErrInvalidAccountEntropyPool) {
		t.Fatalf("short parse error = %v, want ErrInvalidAccountEntropyPool", err)
	}
	if _, err := ParseAccountEntropyPool(strings.Repeat(" ", 64)); !errors.Is(err, ErrInvalidAccountEntropyPool) {
		t.Fatalf("invalid char parse error = %v, want ErrInvalidAccountEntropyPool", err)
	}
}

func TestBackupKeyKnownFromAccountEntropy(t *testing.T) {
	pool, err := ParseAccountEntropyPool("dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l")
	if err != nil {
		t.Fatal(err)
	}
	wantSVR := mustHex32(t, "cdfecb856b148ca1c7f7557904f1ec698d0ccc4d4d68ed4c58c74a21e5c1c6c1")
	if got := pool.DeriveSVRKey(); got != wantSVR {
		t.Fatalf("DeriveSVRKey = %x, want %x", got, wantSVR)
	}
	got := DeriveBackupKey(pool)
	want := BackupKey(mustHex32(t, "ea26a2ddb5dba5ef9e34e1b8dea1f5ae7f255306a6d2d883e542306eaa9fe985"))
	if got != want {
		t.Fatalf("DeriveBackupKey = %x, want %x", got, want)
	}
}

func TestBackupIDKnownFromAccountEntropy(t *testing.T) {
	pool, err := ParseAccountEntropyPool("dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l")
	if err != nil {
		t.Fatal(err)
	}
	aciUUID, err := hex.DecodeString("659aa5f4a28dfcc11ea1b997537a3d95")
	if err != nil {
		t.Fatal(err)
	}
	var uuid [16]byte
	copy(uuid[:], aciUUID)
	got := DeriveBackupKey(pool).DeriveBackupID(address.NewACI(uuid))
	wantRaw, err := hex.DecodeString("8a624fbc45379043f39f1391cddc5fe8")
	if err != nil {
		t.Fatal(err)
	}
	var want BackupID
	copy(want[:], wantRaw)
	if got != want {
		t.Fatalf("DeriveBackupID = %x, want %x", got, want)
	}
}

func TestPinHashKnownSalt(t *testing.T) {
	got := MakePINSalt("username", 3862621253427332054)
	want := mustHex32(t, "d6159ba30f90b6eb6ccf1ec844427f052baaf0705da849767471744cdb3f8a5e")
	if got != want {
		t.Fatalf("MakePINSalt = %x, want %x", got, want)
	}
}

func TestPinHashKnownHash(t *testing.T) {
	salt := mustHex32(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	got := CreatePinHash([]byte("password"), salt)
	wantAccess := mustHex32(t, "ab7e8499d21f80a6600b3b9ee349ac6d72c07e3359fe885a934ba7aa844429f8")
	if got.AccessKey != wantAccess {
		t.Fatalf("AccessKey = %x, want %x", got.AccessKey, wantAccess)
	}
}

func TestLocalPINHashKnownPHCString(t *testing.T) {
	var salt [16]byte
	rawSalt, err := hex.DecodeString("202122232425262728292A2B2C2D2E2F")
	if err != nil {
		t.Fatal(err)
	}
	copy(salt[:], rawSalt)
	const want = "$argon2i$v=19$m=512,t=64,p=1$ICEiIyQlJicoKSorLC0uLw$NeZzhiNv4cRmRMct9scf7d838bzmHJvrZtU/0BH0v/U"
	if got := LocalPINHashWithSalt([]byte("apassword"), salt); got != want {
		t.Fatalf("LocalPINHashWithSalt = %q, want %q", got, want)
	}
	ok, err := VerifyLocalPINHash(want, []byte("apassword"))
	if err != nil {
		t.Fatalf("VerifyLocalPINHash: %v", err)
	}
	if !ok {
		t.Fatal("VerifyLocalPINHash returned false for correct PIN")
	}
	ok, err = VerifyLocalPINHash(want, []byte("wrongpin"))
	if err != nil {
		t.Fatalf("VerifyLocalPINHash wrong pin: %v", err)
	}
	if ok {
		t.Fatal("VerifyLocalPINHash returned true for wrong PIN")
	}
}
