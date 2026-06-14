package spqr

import (
	"bytes"
	"errors"
	"testing"
)

// TestAuthenticatorMacRoundTrip checks that a MAC produced by one authenticator
// verifies on an identically-seeded peer, and that hdr/ct domains are distinct.
func TestAuthenticatorMacRoundTrip(t *testing.T) {
	root := bytes.Repeat([]byte{0x07}, 32)
	a := newAuthenticator(root, 0)
	b := newAuthenticator(root, 0)

	const ep = uint64(0)
	ct := []byte("ciphertext bytes")
	hdr := []byte("header bytes")

	if err := b.verifyCt(ep, ct, a.macCt(ep, ct)); err != nil {
		t.Fatalf("verifyCt on genuine MAC: %v", err)
	}
	if err := b.verifyHdr(ep, hdr, a.macHdr(ep, hdr)); err != nil {
		t.Fatalf("verifyHdr on genuine MAC: %v", err)
	}
	// MAC length is 32 bytes.
	if got := len(a.macCt(ep, ct)); got != authMACSize {
		t.Fatalf("ct MAC length = %d, want %d", got, authMACSize)
	}
	// The ct and hdr MAC domains must differ for the same data + epoch.
	if bytes.Equal(a.macCt(ep, ct), a.macHdr(ep, ct)) {
		t.Fatal("ct and hdr MAC domains collide")
	}
}

// TestAuthenticatorRejectsTamper checks that a tampered MAC, a tampered message,
// and a wrong epoch all fail verification.
func TestAuthenticatorRejectsTamper(t *testing.T) {
	a := newAuthenticator(bytes.Repeat([]byte{0x11}, 32), 5)
	const ep = uint64(5)
	ct := []byte("payload")
	mac := a.macCt(ep, ct)

	tampered := append([]byte(nil), mac...)
	tampered[0] ^= 0x01
	if err := a.verifyCt(ep, ct, tampered); !errors.Is(err, ErrInvalidCtMac) {
		t.Fatalf("tampered MAC err = %v, want ErrInvalidCtMac", err)
	}
	if err := a.verifyCt(ep, append([]byte("x"), ct...), mac); !errors.Is(err, ErrInvalidCtMac) {
		t.Fatalf("tampered ct err = %v, want ErrInvalidCtMac", err)
	}
	if err := a.verifyCt(ep+1, ct, mac); !errors.Is(err, ErrInvalidCtMac) {
		t.Fatalf("wrong epoch err = %v, want ErrInvalidCtMac", err)
	}
	// A length-mismatched MAC must also reject (ctEqual is false on differing len).
	if err := a.verifyCt(ep, ct, mac[:16]); !errors.Is(err, ErrInvalidCtMac) {
		t.Fatalf("short MAC err = %v, want ErrInvalidCtMac", err)
	}
}

// TestAuthenticatorUpdateRatchets checks that update() advances the keys (so a
// stale MAC stops verifying) and that both sides stay in sync across an update.
func TestAuthenticatorUpdateRatchets(t *testing.T) {
	root := bytes.Repeat([]byte{0x22}, 32)
	a := newAuthenticator(root, 0)
	b := newAuthenticator(root, 0)

	beforeMac := a.macKey
	a.update(1, []byte("epoch-1 secret"))
	b.update(1, []byte("epoch-1 secret"))
	if bytes.Equal(a.macKey, beforeMac) {
		t.Fatal("update did not change the MAC key")
	}
	// After a synchronized update both sides still agree.
	ct := []byte("post-update ct")
	if err := b.verifyCt(1, ct, a.macCt(1, ct)); err != nil {
		t.Fatalf("post-update verifyCt: %v", err)
	}
	// A divergent update breaks agreement.
	c := newAuthenticator(root, 0)
	c.update(1, []byte("different secret"))
	if err := c.verifyCt(1, ct, a.macCt(1, ct)); !errors.Is(err, ErrInvalidCtMac) {
		t.Fatalf("divergent-update verify err = %v, want ErrInvalidCtMac", err)
	}
}

// TestAuthenticatorProtoRoundTrip checks serialize/parse preserves the keys.
func TestAuthenticatorProtoRoundTrip(t *testing.T) {
	a := newAuthenticator(bytes.Repeat([]byte{0x33}, 32), 9)
	got := authenticatorFromProto(a.toProto())
	if !bytes.Equal(got.rootKey, a.rootKey) || !bytes.Equal(got.macKey, a.macKey) {
		t.Fatal("authenticator keys not preserved across proto round-trip")
	}
	ct := []byte("rt")
	if err := got.verifyCt(9, ct, a.macCt(9, ct)); err != nil {
		t.Fatalf("round-tripped authenticator verifyCt: %v", err)
	}
}
