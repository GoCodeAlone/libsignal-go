package fingerprint

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/curve"
)

// The hard-coded KATs from rust/protocol/src/fingerprint.rs (testVectorsVersion1
// / testVectorsVersion2 in Java). These pin display + scannable byte-for-byte
// against upstream without needing the harness, complementing the committed
// fingerprint.json consumer in compat/vectors_test.go.
const (
	aliceIdentityHex = "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868"
	bobIdentityHex   = "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b"

	displayableV1 = "300354477692869396892869876765458257569162576843440918079131"

	aliceScannableV1 = "080112220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d"
	bobScannableV1   = "080112220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df"

	aliceScannableV2 = "080212220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d"
	bobScannableV2   = "080212220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df"

	aliceStableID = "+14152222222"
	bobStableID   = "+14153333333"

	stdIterations = 5200
)

func mustKey(t *testing.T, h string) curve.PublicKey {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("bad hex %q: %v", h, err)
	}
	k, err := curve.DeserializePublicKey(b)
	if err != nil {
		t.Fatalf("deserialize key %q: %v", h, err)
	}
	return k
}

// TestFingerprintKAT_V1 pins display + both scannable serializations against the
// upstream v1 test vectors.
func TestFingerprintKAT_V1(t *testing.T) {
	aKey, bKey := mustKey(t, aliceIdentityHex), mustKey(t, bobIdentityHex)

	a, err := New(1, stdIterations, []byte(aliceStableID), aKey, []byte(bobStableID), bKey)
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	b, err := New(1, stdIterations, []byte(bobStableID), bKey, []byte(aliceStableID), aKey)
	if err != nil {
		t.Fatalf("New(bob): %v", err)
	}

	if got := a.DisplayString(); got != displayableV1 {
		t.Fatalf("alice display = %q, want %q", got, displayableV1)
	}
	if got := b.DisplayString(); got != displayableV1 {
		t.Fatalf("bob display = %q, want %q", got, displayableV1)
	}
	if got := hexScannable(t, a); got != aliceScannableV1 {
		t.Fatalf("alice scannable v1 = %s, want %s", got, aliceScannableV1)
	}
	if got := hexScannable(t, b); got != bobScannableV1 {
		t.Fatalf("bob scannable v1 = %s, want %s", got, bobScannableV1)
	}
}

// TestFingerprintKAT_V2 pins the v2 scannable (version byte differs) and that
// the display string is unchanged from v1.
func TestFingerprintKAT_V2(t *testing.T) {
	aKey, bKey := mustKey(t, aliceIdentityHex), mustKey(t, bobIdentityHex)

	a, err := New(2, stdIterations, []byte(aliceStableID), aKey, []byte(bobStableID), bKey)
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	b, err := New(2, stdIterations, []byte(bobStableID), bKey, []byte(aliceStableID), aKey)
	if err != nil {
		t.Fatalf("New(bob): %v", err)
	}

	if got := hexScannable(t, a); got != aliceScannableV2 {
		t.Fatalf("alice scannable v2 = %s, want %s", got, aliceScannableV2)
	}
	if got := hexScannable(t, b); got != bobScannableV2 {
		t.Fatalf("bob scannable v2 = %s, want %s", got, bobScannableV2)
	}
	if got := a.DisplayString(); got != displayableV1 {
		t.Fatalf("v2 display = %q, want (unchanged) %q", got, displayableV1)
	}
}

// TestScannableEncoding pins the protobuf wire shape for a known content pair,
// mirroring the Rust fingerprint_encodings test.
func TestScannableEncoding(t *testing.T) {
	l := bytes.Repeat([]byte{0x12}, 32)
	r := bytes.Repeat([]byte{0xBA}, 32)
	sf := newScannableFingerprint(2, l, r)
	got, err := sf.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want := "080212220a20" + hex.EncodeToString(bytes.Repeat([]byte{0x12}, 32)) +
		"1a220a20" + hex.EncodeToString(bytes.Repeat([]byte{0xBA}, 32))
	if hex.EncodeToString(got) != want {
		t.Fatalf("scannable encoding = %s, want %s", hex.EncodeToString(got), want)
	}
}

// TestMatchingFingerprints checks a matching pair compares true both ways, a
// self-compare is false, and the display is 60 chars, mirroring the Rust
// testMatchingFingerprints.
func TestMatchingFingerprints(t *testing.T) {
	aKey := genKey(t)
	bKey := genKey(t)

	a, err := New(1, 1024, []byte(aliceStableID), aKey, []byte(bobStableID), bKey)
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	b, err := New(1, 1024, []byte(bobStableID), bKey, []byte(aliceStableID), aKey)
	if err != nil {
		t.Fatalf("New(bob): %v", err)
	}

	if a.DisplayString() != b.DisplayString() {
		t.Fatal("matching identifiers must yield equal display strings")
	}
	if len(a.DisplayString()) != 60 {
		t.Fatalf("display length = %d, want 60", len(a.DisplayString()))
	}

	bSer := mustSerialize(t, b)
	aSer := mustSerialize(t, a)
	if ok, err := a.Scannable.Compare(bSer); err != nil || !ok {
		t.Fatalf("a.Compare(b) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := b.Scannable.Compare(aSer); err != nil || !ok {
		t.Fatalf("b.Compare(a) = %v, %v; want true, nil", ok, err)
	}
	// A self-compare must be false (local != remote).
	if ok, err := a.Scannable.Compare(aSer); err != nil || ok {
		t.Fatalf("a.Compare(a) = %v, %v; want false, nil", ok, err)
	}
}

// TestMismatchingFingerprints checks a MITM'd remote key makes the pair compare
// false, mirroring the Rust testMismatchingFingerprints.
func TestMismatchingFingerprints(t *testing.T) {
	aKey, bKey, mKey := genKey(t), genKey(t), genKey(t)

	// Alice computed her fingerprint against the MITM key, not Bob's.
	a, err := New(1, 1024, []byte(aliceStableID), aKey, []byte(bobStableID), mKey)
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	b, err := New(1, 1024, []byte(bobStableID), bKey, []byte(aliceStableID), aKey)
	if err != nil {
		t.Fatalf("New(bob): %v", err)
	}

	if a.DisplayString() == b.DisplayString() {
		t.Fatal("mismatched keys must yield different display strings")
	}
	if ok, _ := a.Scannable.Compare(mustSerialize(t, b)); ok {
		t.Fatal("mismatched fingerprints must not compare equal")
	}
	if ok, _ := b.Scannable.Compare(mustSerialize(t, a)); ok {
		t.Fatal("mismatched fingerprints must not compare equal")
	}
}

// TestMismatchingVersions checks that comparing across versions yields a typed
// version-mismatch error, mirroring the Rust testMismatchingVersions intent.
func TestMismatchingVersions(t *testing.T) {
	aKey, bKey := mustKey(t, aliceIdentityHex), mustKey(t, bobIdentityHex)

	v1, err := New(1, stdIterations, []byte(aliceStableID), aKey, []byte(bobStableID), bKey)
	if err != nil {
		t.Fatalf("New(v1): %v", err)
	}
	v2, err := New(2, stdIterations, []byte(bobStableID), bKey, []byte(aliceStableID), aKey)
	if err != nil {
		t.Fatalf("New(v2): %v", err)
	}

	// Display fingerprint is version-independent.
	if v1.DisplayString() != v2.DisplayString() {
		t.Fatal("display must not depend on version")
	}
	// Scannable does depend on version.
	if bytes.Equal(mustSerialize(t, v1), mustSerialize(t, v2)) {
		t.Fatal("scannable must differ across versions")
	}

	// Comparing a v1 scannable against a v2 serialized form is a version mismatch.
	_, err = v1.Scannable.Compare(mustSerialize(t, v2))
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("cross-version Compare error = %v, want ErrVersionMismatch", err)
	}
}

// TestDeserializeRoundTrip checks Serialize -> Deserialize preserves the
// version and fingerprints.
func TestDeserializeRoundTrip(t *testing.T) {
	aKey, bKey := mustKey(t, aliceIdentityHex), mustKey(t, bobIdentityHex)
	fp, err := New(1, stdIterations, []byte(aliceStableID), aKey, []byte(bobStableID), bKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ser := mustSerialize(t, fp)
	got, err := DeserializeScannableFingerprint(ser)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	reSer, err := got.Serialize()
	if err != nil {
		t.Fatalf("re-serialize: %v", err)
	}
	if !bytes.Equal(ser, reSer) {
		t.Fatal("round-trip serialization not stable")
	}
}

// TestInvalidIterationCount checks the iteration-count guard (1 < n <= 1_000_000).
func TestInvalidIterationCount(t *testing.T) {
	aKey, bKey := mustKey(t, aliceIdentityHex), mustKey(t, bobIdentityHex)
	for _, n := range []uint32{0, 1, 1_000_001} {
		_, err := New(1, n, []byte(aliceStableID), aKey, []byte(bobStableID), bKey)
		if !errors.Is(err, ErrInvalidIterationCount) {
			t.Fatalf("New(iterations=%d) err = %v, want ErrInvalidIterationCount", n, err)
		}
	}
}

func genKey(t *testing.T) curve.PublicKey {
	t.Helper()
	kp, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return kp.PublicKey
}

func hexScannable(t *testing.T, fp *Fingerprint) string {
	t.Helper()
	return hex.EncodeToString(mustSerialize(t, fp))
}

func mustSerialize(t *testing.T, fp *Fingerprint) []byte {
	t.Helper()
	b, err := fp.Scannable.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return b
}
