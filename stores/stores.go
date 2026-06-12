// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package stores defines the storage interfaces the Signal protocol drives
// against — the identity, pre-key, signed-pre-key, Kyber-pre-key, session, and
// sender-key stores — and is a pure-Go port of
// rust/protocol/src/storage/traits.rs. Implementations may be in-memory (see the
// inmem subpackage), on-disk, or remote.
//
// All methods take a context.Context as their first parameter and return an
// error; none panic.
//
// Pre-key, signed-pre-key, Kyber-pre-key, and sender-key records are exchanged
// as opaque serialized bytes keyed by typed ids: the store neither parses nor
// validates a record, it only persists and returns it. Callers serialize a
// record before saving and deserialize the bytes they read back, so the store
// contract is stable across those record types' own evolution. Session records,
// whose Go type (session.SessionRecord) is available, are exchanged as that
// typed value instead.
package stores

import (
	"context"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/session"
)

// Direction is the role an identity is being checked for when deciding trust.
// It mirrors upstream's Direction enum. The reference in-memory identity store
// does not branch on it (trust is symmetric there), but it is part of the
// interface because other implementations may apply role-specific policy.
type Direction int

const (
	// Sending is the context of sending a message to the identity.
	Sending Direction = iota
	// Receiving is the context of receiving a message from the identity.
	Receiving
)

// IdentityChange reports whether saving an identity replaced a different
// existing identity for an address. It mirrors upstream's IdentityChange enum.
type IdentityChange int

const (
	// NewOrUnchanged means the address had no identity, or the same identity
	// was already recorded.
	NewOrUnchanged IdentityChange = iota
	// ReplacedExisting means a different identity was already recorded for the
	// address and has now been overwritten.
	ReplacedExisting
)

// IdentityChangeFromReplaced is the convenience constructor mirroring upstream's
// IdentityChange::from_changed: ReplacedExisting when an existing identity was
// replaced, NewOrUnchanged otherwise.
func IdentityChangeFromReplaced(replaced bool) IdentityChange {
	if replaced {
		return ReplacedExisting
	}
	return NewOrUnchanged
}

// IdentityKeyStore stores the local identity key pair and the identity public
// keys observed for remote addresses, and decides whether a remote identity is
// trusted. Signal clients usually use it in a trust-on-first-use manner, though
// that is policy, not a requirement of the interface.
//
// The local identity is a curve key pair; remote identities are curve public
// keys. (Upstream wraps these in IdentityKey/IdentityKeyPair newtypes; this port
// uses the underlying curve types directly until those wrappers exist, so the
// store's behavior is identical and a future newtype slots in transparently.)
type IdentityKeyStore interface {
	// GetIdentityKeyPair returns the single identity key pair this store
	// represents.
	GetIdentityKeyPair(ctx context.Context) (curve.KeyPair, error)

	// GetLocalRegistrationID returns the registration id specific to this store
	// instance. It is distinct from any per-device id and is stable across runs
	// for the same registration.
	GetLocalRegistrationID(ctx context.Context) (uint32, error)

	// SaveIdentity records identity as the known identity for address, marking
	// it trusted. It reports whether a different existing identity was replaced.
	SaveIdentity(ctx context.Context, address address.ProtocolAddress, identity curve.PublicKey) (IdentityChange, error)

	// IsTrustedIdentity reports whether identity is trusted for address in the
	// given direction. An address with no recorded identity is trusted (first
	// use); otherwise trust requires the recorded identity to equal identity.
	IsTrustedIdentity(ctx context.Context, address address.ProtocolAddress, identity curve.PublicKey, direction Direction) (bool, error)

	// GetIdentity returns the recorded identity for address and true, or the
	// zero value and false when none is recorded.
	GetIdentity(ctx context.Context, address address.ProtocolAddress) (curve.PublicKey, bool, error)
}

// PreKeyStore stores one-time pre-keys downloaded from a server, keyed by id.
// Records are opaque serialized bytes (a marshaled PreKeyRecordStructure).
type PreKeyStore interface {
	// GetPreKey returns the serialized record for id, or an error if id is not
	// present.
	GetPreKey(ctx context.Context, id uint32) ([]byte, error)

	// SavePreKey stores record under id, overwriting any existing entry.
	SavePreKey(ctx context.Context, id uint32, record []byte) error

	// RemovePreKey deletes the entry for id. Removing a missing id is not an
	// error.
	RemovePreKey(ctx context.Context, id uint32) error
}

// SignedPreKeyStore stores signed pre-keys downloaded from a server, keyed by
// id. Records are opaque serialized bytes (a marshaled
// SignedPreKeyRecordStructure). There is no removal: signed pre-keys are
// rotated, not deleted, matching upstream.
type SignedPreKeyStore interface {
	// GetSignedPreKey returns the serialized record for id, or an error if id is
	// not present.
	GetSignedPreKey(ctx context.Context, id uint32) ([]byte, error)

	// SaveSignedPreKey stores record under id, overwriting any existing entry.
	SaveSignedPreKey(ctx context.Context, id uint32, record []byte) error
}

// KyberPreKeyStore stores signed Kyber pre-keys downloaded from a server, keyed
// by id, and tracks base keys to reject pre-key reuse. Records are opaque
// serialized bytes. Upstream makes no distinction between one-time and
// last-resort Kyber pre-keys at this interface.
type KyberPreKeyStore interface {
	// GetKyberPreKey returns the serialized record for id, or an error if id is
	// not present.
	GetKyberPreKey(ctx context.Context, id uint32) ([]byte, error)

	// SaveKyberPreKey stores record under id, overwriting any existing entry.
	SaveKyberPreKey(ctx context.Context, id uint32, record []byte) error

	// MarkKyberPreKeyUsed records that the (kyberPreKeyID, ecPreKeyID, baseKey)
	// combination was used. It returns an error if the same baseKey was already
	// seen for that (kyberPreKeyID, ecPreKeyID) pair — a replayed pre-key
	// message — and otherwise records the base key. A one-time key would be
	// deleted by a real client after this; a last-resort key is retained, which
	// is why the reuse check exists.
	MarkKyberPreKeyUsed(ctx context.Context, kyberPreKeyID uint32, ecPreKeyID uint32, baseKey curve.PublicKey) error
}

// SessionStore stores the Double Ratchet session record for each remote
// address. It mirrors upstream's SessionStore trait.
type SessionStore interface {
	// LoadSession returns the session record for address, or (nil, nil) when no
	// session is stored — mirroring upstream's Option<SessionRecord> return,
	// where a nil record means "absent" rather than an error.
	LoadSession(ctx context.Context, address address.ProtocolAddress) (*session.SessionRecord, error)

	// StoreSession sets the session record for address, overwriting any existing
	// entry.
	StoreSession(ctx context.Context, address address.ProtocolAddress, record *session.SessionRecord) error
}

// SenderKeyStore stores sender-key records for group messaging, keyed by the
// (sender, distributionID) pair so a single sender may hold multiple keys. It
// mirrors upstream's SenderKeyStore trait.
//
// The sender-key record is exchanged as opaque serialized bytes: its Go type
// lands with the group messaging work (T20). Until then this matches the
// pre-key stores' convention; the typed record can replace []byte later without
// changing the keying or semantics.
type SenderKeyStore interface {
	// LoadSenderKey returns the serialized record for (sender, distributionID),
	// or (nil, nil) when none is stored.
	LoadSenderKey(ctx context.Context, sender address.ProtocolAddress, distributionID [16]byte) ([]byte, error)

	// StoreSenderKey sets the serialized record for (sender, distributionID),
	// overwriting any existing entry.
	StoreSenderKey(ctx context.Context, sender address.ProtocolAddress, distributionID [16]byte, record []byte) error
}
