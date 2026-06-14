// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// The SPQR authenticator — the symmetric MAC chain that binds each transported
// encapsulation-key header and ciphertext to the agreed epoch, ported from
// SparsePostQuantumRatchet v1.5.1 src/authenticator.rs. Part of Slice C (the
// SPQR state machine): the version-negotiation handshake seeds it, and the
// send_ek / send_ct roles MAC/verify the hdr and ct chunks they exchange.

package spqr

import (
	"crypto/subtle"
	"errors"

	"github.com/GoCodeAlone/libsignal-go/internal/crypto"
	"github.com/GoCodeAlone/libsignal-go/proto"
)

// authMACSize is the authenticator MAC length (32 bytes). Mirrors
// Authenticator::MACSIZE.
const authMACSize = 32

// Authenticator info / MAC-domain strings, byte-exact from authenticator.rs.
var (
	authUpdateInfo = []byte("Signal_PQCKA_V1_MLKEM768:Authenticator Update")
	authCtDomain   = []byte("Signal_PQCKA_V1_MLKEM768:ciphertext")
	authHdrDomain  = []byte("Signal_PQCKA_V1_MLKEM768:ekheader")
)

// Authenticator MAC-verification errors, mirroring authenticator.rs Error.
var (
	// ErrInvalidCtMac is returned when a ciphertext MAC does not verify.
	// Mirrors Error::InvalidCtMac.
	ErrInvalidCtMac = errors.New("spqr: ciphertext MAC is invalid")
	// ErrInvalidHdrMac is returned when an encapsulation-key header MAC does not
	// verify. Mirrors Error::InvalidHdrMac.
	ErrInvalidHdrMac = errors.New("spqr: encapsulation-key header MAC is invalid")
)

// authenticator is the SPQR MAC chain: a root key (ratcheted each epoch) and the
// current epoch's MAC key. Mirrors authenticator.rs Authenticator.
type authenticator struct {
	rootKey []byte // 32 bytes
	macKey  []byte // 32 bytes
}

// newAuthenticator seeds the authenticator from an initial root key at epoch ep:
// zero-initialize, then update(ep, rootKey). Mirrors Authenticator::new.
func newAuthenticator(rootKey []byte, ep uint64) *authenticator {
	a := &authenticator{rootKey: make([]byte, 32), macKey: make([]byte, 32)}
	a.update(ep, rootKey)
	return a
}

// update ratchets the authenticator with a new epoch key k: HKDF(salt=zeros32,
// ikm=rootKey‖k, info="…Authenticator Update"‖BE64(ep), 64) → rootKey[:32],
// macKey[32:]. Mirrors Authenticator::update.
func (a *authenticator) update(ep uint64, k []byte) {
	ikm := append(append([]byte(nil), a.rootKey...), k...)
	info := append(append([]byte(nil), authUpdateInfo...), be64(ep)...)
	out := chainHKDF(zeroSalt32, ikm, info, 64)
	a.rootKey = append([]byte(nil), out[:32]...)
	a.macKey = append([]byte(nil), out[32:64]...)
}

// macCt computes the ciphertext MAC: HMAC-SHA256(macKey,
// "…:ciphertext"‖BE64(ep)‖ct). Mirrors Authenticator::mac_ct.
func (a *authenticator) macCt(ep uint64, ct []byte) []byte {
	data := concat(authCtDomain, be64(ep), ct)
	return crypto.HMACSHA256(a.macKey, data)
}

// macHdr computes the header MAC: HMAC-SHA256(macKey,
// "…:ekheader"‖BE64(ep)‖hdr). Mirrors Authenticator::mac_hdr.
func (a *authenticator) macHdr(ep uint64, hdr []byte) []byte {
	data := concat(authHdrDomain, be64(ep), hdr)
	return crypto.HMACSHA256(a.macKey, data)
}

// verifyCt checks a ciphertext MAC in constant time. Mirrors verify_ct.
func (a *authenticator) verifyCt(ep uint64, ct, expected []byte) error {
	if !ctEqual(expected, a.macCt(ep, ct)) {
		return ErrInvalidCtMac
	}
	return nil
}

// verifyHdr checks a header MAC in constant time. Mirrors verify_hdr.
func (a *authenticator) verifyHdr(ep uint64, hdr, expected []byte) error {
	if !ctEqual(expected, a.macHdr(ep, hdr)) {
		return ErrInvalidHdrMac
	}
	return nil
}

// toProto serializes the authenticator into the proto Authenticator message.
func (a *authenticator) toProto() *proto.Authenticator {
	return &proto.Authenticator{
		RootKey: append([]byte(nil), a.rootKey...),
		MacKey:  append([]byte(nil), a.macKey...),
	}
}

// authenticatorFromProto parses a proto Authenticator. A nil message yields a
// zero authenticator (the proto default), matching the reference's all-zeros
// default for an unset field.
func authenticatorFromProto(pb *proto.Authenticator) *authenticator {
	return &authenticator{
		rootKey: append([]byte(nil), pb.GetRootKey()...),
		macKey:  append([]byte(nil), pb.GetMacKey()...),
	}
}

// be64 returns the big-endian encoding of a u64 epoch (matching ep.to_be_bytes).
func be64(v uint64) []byte {
	return []byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

// concat joins byte slices (the MAC-input assembly).
func concat(parts ...[]byte) []byte {
	var n int
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ctEqual reports whether a and b are equal in constant time. Mirrors SPQR's
// util::compare (subtle.ConstantTimeCompare returns 0 — not equal — for a length
// mismatch, matching compare's nonzero-on-mismatch).
func ctEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
