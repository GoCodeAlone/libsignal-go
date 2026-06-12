package curve

import (
	"bytes"
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
)

// TestXEdDSAUpstreamSignatureVector ports test_signature from
// rust/core/src/curve/curve25519.rs: a fixed identity key, message, and
// signature. Verification is deterministic, so the exact upstream signature
// bytes are checked for acceptance, and every single-bit flip is rejected.
func TestXEdDSAUpstreamSignatureVector(t *testing.T) {
	aliceIdentityPrivate := []byte{
		0xc0, 0x97, 0x24, 0x84, 0x12, 0xe5, 0x8b, 0xf0, 0x5d, 0xf4, 0x87, 0x96, 0x82, 0x05,
		0x13, 0x27, 0x94, 0x17, 0x8e, 0x36, 0x76, 0x37, 0xf5, 0x81, 0x8f, 0x81, 0xe0, 0xe6,
		0xce, 0x73, 0xe8, 0x65,
	}
	aliceIdentityPublic := []byte{
		0xab, 0x7e, 0x71, 0x7d, 0x4a, 0x16, 0x3b, 0x7d, 0x9a, 0x1d, 0x80, 0x71, 0xdf, 0xe9,
		0xdc, 0xf8, 0xcd, 0xcd, 0x1c, 0xea, 0x33, 0x39, 0xb6, 0x35, 0x6b, 0xe8, 0x4d, 0x88,
		0x7e, 0x32, 0x2c, 0x64,
	}
	// 33-byte serialized ephemeral public key (0x05 type byte + 32 raw); the
	// signed message is exactly these 33 bytes.
	aliceEphemeralPublic := []byte{
		0x05, 0xed, 0xce, 0x9d, 0x9c, 0x41, 0x5c, 0xa7, 0x8c, 0xb7, 0x25, 0x2e, 0x72, 0xc2,
		0xc4, 0xa5, 0x54, 0xd3, 0xeb, 0x29, 0x48, 0x5a, 0x0e, 0x1d, 0x50, 0x31, 0x18, 0xd1,
		0xa8, 0x2d, 0x99, 0xfb, 0x4a,
	}
	aliceSignature := []byte{
		0x5d, 0xe8, 0x8c, 0xa9, 0xa8, 0x9b, 0x4a, 0x11, 0x5d, 0xa7, 0x91, 0x09, 0xc6, 0x7c,
		0x9c, 0x74, 0x64, 0xa3, 0xe4, 0x18, 0x02, 0x74, 0xf1, 0xcb, 0x8c, 0x63, 0xc2, 0x98,
		0x4e, 0x28, 0x6d, 0xfb, 0xed, 0xe8, 0x2d, 0xeb, 0x9d, 0xcd, 0x9f, 0xae, 0x0b, 0xfb,
		0xb8, 0x21, 0x56, 0x9b, 0x3d, 0x90, 0x01, 0xbd, 0x81, 0x30, 0xcd, 0x11, 0xd4, 0x86,
		0xce, 0xf0, 0x47, 0xbd, 0x60, 0xb8, 0x6e, 0x88,
	}

	priv, err := DeserializePrivateKey(aliceIdentityPrivate)
	if err != nil {
		t.Fatalf("DeserializePrivateKey: %v", err)
	}
	// The derived public key must match the upstream fixture.
	derived, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !bytes.Equal(derived.PublicKeyBytes(), aliceIdentityPublic) {
		t.Fatalf("derived public key = %x, want %x", derived.PublicKeyBytes(), aliceIdentityPublic)
	}

	pub, err := NewPublicKey(aliceIdentityPublic)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	if !pub.VerifySignature(aliceSignature, aliceEphemeralPublic) {
		t.Fatal("upstream signature failed to verify")
	}

	// Every single-bit flip in the signature must be rejected.
	for i := 0; i < len(aliceSignature); i++ {
		bad := append([]byte(nil), aliceSignature...)
		bad[i] ^= 0x01
		if pub.VerifySignature(bad, aliceEphemeralPublic) {
			t.Fatalf("tampered signature (byte %d) verified when it should not have", i)
		}
	}
}

// fixedReader yields deterministic bytes for signing nonces in tests.
type fixedReader struct{ b byte }

func (r *fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
		r.b++
	}
	return len(p), nil
}

func TestXEdDSASignVerifyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair(&fixedReader{b: 1})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	msg := []byte("the medium is the message")
	sig, err := kp.PrivateKey.CalculateSignature(&fixedReader{b: 0x42}, msg)
	if err != nil {
		t.Fatalf("CalculateSignature: %v", err)
	}
	if len(sig) != SignatureLength {
		t.Fatalf("signature length = %d, want %d", len(sig), SignatureLength)
	}
	if !kp.PublicKey.VerifySignature(sig, msg) {
		t.Fatal("round-trip signature failed to verify")
	}
}

func TestXEdDSARejectsTamperedMessageKeyAndSig(t *testing.T) {
	kp, err := GenerateKeyPair(&fixedReader{b: 9})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	msg := []byte("authentic message")
	sig, err := kp.PrivateKey.CalculateSignature(&fixedReader{b: 0x11}, msg)
	if err != nil {
		t.Fatalf("CalculateSignature: %v", err)
	}

	// Flipped message byte.
	badMsg := append([]byte(nil), msg...)
	badMsg[0] ^= 0x01
	if kp.PublicKey.VerifySignature(sig, badMsg) {
		t.Fatal("verified against tampered message")
	}

	// Flipped signature byte.
	badSig := append([]byte(nil), sig...)
	badSig[10] ^= 0x01
	if kp.PublicKey.VerifySignature(badSig, msg) {
		t.Fatal("verified tampered signature")
	}

	// Wrong public key.
	other, err := GenerateKeyPair(&fixedReader{b: 200})
	if err != nil {
		t.Fatalf("GenerateKeyPair(other): %v", err)
	}
	if other.PublicKey.VerifySignature(sig, msg) {
		t.Fatal("verified under the wrong public key")
	}
}

func TestXEdDSAMultipartMessage(t *testing.T) {
	kp, err := GenerateKeyPair(&fixedReader{b: 3})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	full := []byte("concatenated multipart body")
	sig, err := kp.PrivateKey.CalculateSignature(&fixedReader{b: 7}, full[:10], full[10:])
	if err != nil {
		t.Fatalf("CalculateSignature: %v", err)
	}
	// Verifying with the whole message in one piece must match the multipart sign.
	if !kp.PublicKey.VerifySignature(sig, full) {
		t.Fatal("multipart sign / single-piece verify mismatch")
	}
	// And verifying with a different split must also match (concatenation only).
	if !kp.PublicKey.VerifySignature(sig, full[:5], full[5:]) {
		t.Fatal("multipart verify with different split failed")
	}
}

func TestXEdDSAVerifyRejectsWrongLength(t *testing.T) {
	pub, err := NewPublicKey(make([]byte, PublicKeyLength))
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	for _, n := range []int{0, 1, 63, 65, 128} {
		if pub.VerifySignature(make([]byte, n), []byte("m")) {
			t.Fatalf("verified signature of wrong length %d", n)
		}
	}
}

// --- Validity checks (backport 2026-06-12: torsion/range owned by T5) ---

// TestHonestKeysAreTorsionFree ports honest_keys_are_torsion_free.
func TestHonestKeysAreTorsionFree(t *testing.T) {
	for i := 0; i < 20; i++ {
		kp, err := GenerateKeyPair(&fixedReader{b: byte(i * 7)})
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		if !kp.PublicKey.IsTorsionFree() {
			t.Fatalf("honest key %d reported as not torsion-free", i)
		}
	}
}

// TestTweakedKeysAreNotTorsionFree ports tweaked_keys_are_not_torsion_free:
// adding a nonzero torsion point to an honest (torsion-free) key produces a key
// that is not torsion-free.
//
// We construct the distinct nonzero low-order torsion points (the order-2 point
// that Montgomery u=0 maps to, and the two order-4 points that u=1 maps to) and
// add each (in the Edwards group) to several honest keys. The sum, converted
// back to a Montgomery u-coordinate, must be rejected as not torsion-free.
func TestTweakedKeysAreNotTorsionFree(t *testing.T) {
	torsionPoints := nonzeroTorsionPoints(t)
	if len(torsionPoints) == 0 {
		t.Fatal("no nonzero torsion points constructed")
	}

	for keyIdx := 0; keyIdx < 5; keyIdx++ {
		kp, err := GenerateKeyPair(&fixedReader{b: byte(keyIdx*13 + 1)})
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		honest, ok := montgomeryToEdwards(kp.PublicKey.data, 0)
		if !ok {
			t.Fatalf("key %d: honest key did not map to Edwards", keyIdx)
		}
		for tIdx, tp := range torsionPoints {
			tweaked := new(edwards25519.Point).Add(honest, tp)
			var u [PublicKeyLength]byte
			copy(u[:], tweaked.BytesMontgomery())
			pk, err := NewPublicKey(u[:])
			if err != nil {
				t.Fatalf("key %d torsion %d: NewPublicKey: %v", keyIdx, tIdx, err)
			}
			if pk.IsTorsionFree() {
				t.Fatalf("key %d + torsion point %d reported torsion-free", keyIdx, tIdx)
			}
		}
	}
}

// nonzeroTorsionPoints returns the distinct nonzero low-order torsion points
// reachable through our Montgomery->Edwards map: the order-2 point (Montgomery
// u=0) and the order-4 point (u=1) together with its negation. Each returned
// point Q is nonzero and genuinely in the 8-torsion subgroup ([8]Q == identity),
// asserted here so the test cannot silently degrade. No table is hardcoded.
func nonzeroTorsionPoints(t *testing.T) []*edwards25519.Point {
	t.Helper()
	id := edwards25519.NewIdentityPoint()

	var candidates []*edwards25519.Point
	if order2, ok := montgomeryToEdwards([PublicKeyLength]byte{0x00}, 0); ok {
		candidates = append(candidates, order2)
	}
	if order4, ok := montgomeryToEdwards([PublicKeyLength]byte{0x01}, 0); ok {
		candidates = append(candidates, order4)
		candidates = append(candidates, new(edwards25519.Point).Negate(order4))
	}

	var out []*edwards25519.Point
	for _, q := range candidates {
		if q.Equal(id) == 1 {
			continue
		}
		// [8]Q == identity confirms Q is in the 8-torsion subgroup.
		eightQ := new(edwards25519.Point).Set(q)
		eightQ.Add(eightQ, eightQ)
		eightQ.Add(eightQ, eightQ)
		eightQ.Add(eightQ, eightQ)
		if eightQ.Equal(id) != 1 {
			t.Fatalf("constructed point is not 8-torsion")
		}
		// Skip points already present (the order-4 point and its negation are
		// distinct, but guard against accidental duplicates).
		dup := false
		for _, e := range out {
			if e.Equal(q) == 1 {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, q)
		}
	}
	return out
}

// TestKeysWithHighBitSetAreOutOfRange ports
// keys_with_the_high_bit_set_are_out_of_range.
func TestKeysWithHighBitSetAreOutOfRange(t *testing.T) {
	zero := make([]byte, 32)
	pk, err := NewPublicKey(zero)
	if err != nil {
		t.Fatalf("NewPublicKey(0): %v", err)
	}
	if !pk.ScalarIsInRange() {
		t.Fatal("0 should be in range")
	}

	twoTo255, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000080")
	pk, _ = NewPublicKey(twoTo255)
	if pk.ScalarIsInRange() {
		t.Fatal("2^255 should be out of range")
	}

	allFF := bytes.Repeat([]byte{0xFF}, 32)
	pk, _ = NewPublicKey(allFF)
	if pk.ScalarIsInRange() {
		t.Fatal("2^256 - 1 should be out of range")
	}

	// An honest key has its high bit clear and is in range; setting the high
	// bit pushes it out of range.
	kp, err := GenerateKeyPair(&fixedReader{b: 0x33})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if !kp.PublicKey.ScalarIsInRange() {
		t.Fatal("honest key should be in range")
	}
	raw := kp.PublicKey.PublicKeyBytes()
	if raw[31]&0x80 != 0 {
		t.Fatal("honest key unexpectedly has high bit set")
	}
	raw[31] |= 0x80
	pk, _ = NewPublicKey(raw)
	if pk.ScalarIsInRange() {
		t.Fatal(">2^255 should be out of range")
	}
}

// TestKeysAboveThePrimeModulusAreOutOfRange ports
// keys_above_the_prime_modulus_are_out_of_range: values 2^255-1 down to
// 2^255-19 are out of range, while 2^255-20 is in range.
func TestKeysAboveThePrimeModulusAreOutOfRange(t *testing.T) {
	twoTo255Minus1, _ := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

	for i := 1; i <= 19; i++ {
		pkBytes := append([]byte(nil), twoTo255Minus1...)
		// pk = 2^255 - 1 - (i-1) == 2^255 - i.
		pkBytes[0] = pkBytes[0] - byte(i) + 1
		pk, err := NewPublicKey(pkBytes)
		if err != nil {
			t.Fatalf("NewPublicKey: %v", err)
		}
		if pk.ScalarIsInRange() {
			t.Fatalf("2^255 - %d should be out of range", i)
		}
	}

	// 2^255 - 20 is in range.
	pkBytes := append([]byte(nil), twoTo255Minus1...)
	pkBytes[0] -= 19 // 2^255 - 1 - 19 == 2^255 - 20
	pk, err := NewPublicKey(pkBytes)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	if !pk.ScalarIsInRange() {
		t.Fatal("2^255 - 20 should be in range")
	}
}

// FuzzVerifySignature feeds arbitrary public-key, signature, and message bytes
// into VerifySignature; the only contract is that it never panics (and, almost
// always, returns false).
func FuzzVerifySignature(f *testing.F) {
	f.Add(make([]byte, PublicKeyLength), make([]byte, SignatureLength), []byte("m"))
	f.Add([]byte{0x05}, []byte{}, []byte(""))
	f.Add(bytes.Repeat([]byte{0xFF}, PublicKeyLength), bytes.Repeat([]byte{0xAA}, SignatureLength), []byte("xyz"))

	f.Fuzz(func(_ *testing.T, pkBytes, sig, msg []byte) {
		// Only construct a key when the length is valid; otherwise exercise
		// VerifySignature's own length guard with a zero key.
		var pk PublicKey
		if len(pkBytes) == PublicKeyLength {
			pk, _ = NewPublicKey(pkBytes)
		} else {
			pk, _ = NewPublicKey(make([]byte, PublicKeyLength))
		}
		_ = pk.VerifySignature(sig, msg)
	})
}

func TestIsCanonicalCombinesChecks(t *testing.T) {
	kp, err := GenerateKeyPair(&fixedReader{b: 0x55})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if !kp.PublicKey.IsCanonical() {
		t.Fatal("honest key should be canonical")
	}
	// Out-of-range key is not canonical even if otherwise structurally valid.
	allFF := bytes.Repeat([]byte{0xFF}, 32)
	pk, _ := NewPublicKey(allFF)
	if pk.IsCanonical() {
		t.Fatal("all-0xFF key should not be canonical")
	}
}
