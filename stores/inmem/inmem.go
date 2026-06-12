// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package inmem provides in-memory implementations of the storage interfaces in
// the stores package. They are a pure-Go port of
// rust/protocol/src/storage/inmem.rs and are intended primarily for tests and
// as the reference behavior other implementations must match.
//
// The stores are not safe for concurrent use; callers needing concurrency must
// serialize access. Serialized record bytes are defensively copied on save and
// on read, so a caller can reuse or mutate the buffers it passes in or gets
// back without disturbing stored state.
package inmem

import (
	"context"
	"errors"
	"fmt"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/stores"
)

// Errors returned when a record is not present, mirroring upstream's
// InvalidPreKeyId / InvalidSignedPreKeyId / InvalidKyberPreKeyId. They are
// sentinels matchable with errors.Is.
var (
	// ErrInvalidPreKeyID is returned by GetPreKey for an unknown id.
	ErrInvalidPreKeyID = errors.New("inmem: invalid pre-key id")
	// ErrInvalidSignedPreKeyID is returned by GetSignedPreKey for an unknown id.
	ErrInvalidSignedPreKeyID = errors.New("inmem: invalid signed pre-key id")
	// ErrInvalidKyberPreKeyID is returned by GetKyberPreKey for an unknown id.
	ErrInvalidKyberPreKeyID = errors.New("inmem: invalid kyber pre-key id")
	// ErrReusedBaseKey is returned by MarkKyberPreKeyUsed when the same base key
	// was already seen for a (kyber, ec) pre-key pair — a replayed pre-key
	// message.
	ErrReusedBaseKey = errors.New("inmem: reused base key for kyber pre-key")
)

// cloneBytes returns a copy of b (nil stays nil) so stored records do not alias
// caller buffers and returned records do not alias stored state.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

// IdentityKeyStore is the in-memory stores.IdentityKeyStore.
type IdentityKeyStore struct {
	keyPair        curve.KeyPair
	registrationID uint32
	knownKeys      map[address.ProtocolAddress]curve.PublicKey
}

var _ stores.IdentityKeyStore = (*IdentityKeyStore)(nil)

// NewIdentityKeyStore creates an identity store for the given local identity
// key pair and registration id, with no known remote identities.
func NewIdentityKeyStore(keyPair curve.KeyPair, registrationID uint32) *IdentityKeyStore {
	return &IdentityKeyStore{
		keyPair:        keyPair,
		registrationID: registrationID,
		knownKeys:      make(map[address.ProtocolAddress]curve.PublicKey),
	}
}

// Reset clears all known remote identities.
func (s *IdentityKeyStore) Reset() {
	clear(s.knownKeys)
}

// GetIdentityKeyPair returns the local identity key pair.
func (s *IdentityKeyStore) GetIdentityKeyPair(_ context.Context) (curve.KeyPair, error) {
	return s.keyPair, nil
}

// GetLocalRegistrationID returns the local registration id.
func (s *IdentityKeyStore) GetLocalRegistrationID(_ context.Context) (uint32, error) {
	return s.registrationID, nil
}

// SaveIdentity records identity for address and reports whether it replaced a
// different existing identity. Unknown address -> NewOrUnchanged (and stored);
// same identity -> NewOrUnchanged; different identity -> ReplacedExisting (and
// overwritten).
func (s *IdentityKeyStore) SaveIdentity(_ context.Context, addr address.ProtocolAddress, identity curve.PublicKey) (stores.IdentityChange, error) {
	existing, ok := s.knownKeys[addr]
	if ok && existing.Equal(identity) {
		return stores.NewOrUnchanged, nil
	}
	s.knownKeys[addr] = identity
	return stores.IdentityChangeFromReplaced(ok), nil
}

// IsTrustedIdentity reports whether identity is trusted for address. Unknown
// address is trusted (first use); a known address is trusted only if its
// recorded identity equals identity. Direction does not affect the decision in
// this reference store.
func (s *IdentityKeyStore) IsTrustedIdentity(_ context.Context, addr address.ProtocolAddress, identity curve.PublicKey, _ stores.Direction) (bool, error) {
	existing, ok := s.knownKeys[addr]
	if !ok {
		return true, nil
	}
	return existing.Equal(identity), nil
}

// GetIdentity returns the recorded identity for address and true, or the zero
// value and false when none is recorded.
func (s *IdentityKeyStore) GetIdentity(_ context.Context, addr address.ProtocolAddress) (curve.PublicKey, bool, error) {
	existing, ok := s.knownKeys[addr]
	return existing, ok, nil
}

// PreKeyStore is the in-memory stores.PreKeyStore.
type PreKeyStore struct {
	preKeys map[uint32][]byte
}

var _ stores.PreKeyStore = (*PreKeyStore)(nil)

// NewPreKeyStore creates an empty pre-key store.
func NewPreKeyStore() *PreKeyStore {
	return &PreKeyStore{preKeys: make(map[uint32][]byte)}
}

// GetPreKey returns the serialized record for id, or ErrInvalidPreKeyID.
func (s *PreKeyStore) GetPreKey(_ context.Context, id uint32) ([]byte, error) {
	record, ok := s.preKeys[id]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrInvalidPreKeyID, id)
	}
	return cloneBytes(record), nil
}

// SavePreKey stores record under id, overwriting any existing entry.
func (s *PreKeyStore) SavePreKey(_ context.Context, id uint32, record []byte) error {
	s.preKeys[id] = cloneBytes(record)
	return nil
}

// RemovePreKey deletes the entry for id; removing a missing id is a no-op.
func (s *PreKeyStore) RemovePreKey(_ context.Context, id uint32) error {
	delete(s.preKeys, id)
	return nil
}

// AllPreKeyIDs returns the ids of all stored pre-keys, in unspecified order.
func (s *PreKeyStore) AllPreKeyIDs() []uint32 {
	ids := make([]uint32, 0, len(s.preKeys))
	for id := range s.preKeys {
		ids = append(ids, id)
	}
	return ids
}

// SignedPreKeyStore is the in-memory stores.SignedPreKeyStore.
type SignedPreKeyStore struct {
	signedPreKeys map[uint32][]byte
}

var _ stores.SignedPreKeyStore = (*SignedPreKeyStore)(nil)

// NewSignedPreKeyStore creates an empty signed pre-key store.
func NewSignedPreKeyStore() *SignedPreKeyStore {
	return &SignedPreKeyStore{signedPreKeys: make(map[uint32][]byte)}
}

// GetSignedPreKey returns the serialized record for id, or
// ErrInvalidSignedPreKeyID.
func (s *SignedPreKeyStore) GetSignedPreKey(_ context.Context, id uint32) ([]byte, error) {
	record, ok := s.signedPreKeys[id]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrInvalidSignedPreKeyID, id)
	}
	return cloneBytes(record), nil
}

// SaveSignedPreKey stores record under id, overwriting any existing entry.
func (s *SignedPreKeyStore) SaveSignedPreKey(_ context.Context, id uint32, record []byte) error {
	s.signedPreKeys[id] = cloneBytes(record)
	return nil
}

// AllSignedPreKeyIDs returns the ids of all stored signed pre-keys, in
// unspecified order.
func (s *SignedPreKeyStore) AllSignedPreKeyIDs() []uint32 {
	ids := make([]uint32, 0, len(s.signedPreKeys))
	for id := range s.signedPreKeys {
		ids = append(ids, id)
	}
	return ids
}

// KyberPreKeyStore is the in-memory stores.KyberPreKeyStore. Like upstream's
// reference store it never clears keys on use (correct for last-resort keys),
// and it tracks the base keys seen per (kyber, ec) pre-key pair to reject reuse.
type KyberPreKeyStore struct {
	kyberPreKeys map[uint32][]byte
	baseKeysSeen map[kyberEcPair][]curve.PublicKey
}

// kyberEcPair keys the base-keys-seen map by the (kyber, ec) pre-key id pair.
type kyberEcPair struct {
	kyberPreKeyID uint32
	ecPreKeyID    uint32
}

var _ stores.KyberPreKeyStore = (*KyberPreKeyStore)(nil)

// NewKyberPreKeyStore creates an empty Kyber pre-key store.
func NewKyberPreKeyStore() *KyberPreKeyStore {
	return &KyberPreKeyStore{
		kyberPreKeys: make(map[uint32][]byte),
		baseKeysSeen: make(map[kyberEcPair][]curve.PublicKey),
	}
}

// GetKyberPreKey returns the serialized record for id, or
// ErrInvalidKyberPreKeyID.
func (s *KyberPreKeyStore) GetKyberPreKey(_ context.Context, id uint32) ([]byte, error) {
	record, ok := s.kyberPreKeys[id]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrInvalidKyberPreKeyID, id)
	}
	return cloneBytes(record), nil
}

// SaveKyberPreKey stores record under id, overwriting any existing entry.
func (s *KyberPreKeyStore) SaveKyberPreKey(_ context.Context, id uint32, record []byte) error {
	s.kyberPreKeys[id] = cloneBytes(record)
	return nil
}

// MarkKyberPreKeyUsed records the (kyberPreKeyID, ecPreKeyID, baseKey)
// combination, returning ErrReusedBaseKey if that base key was already seen for
// the (kyber, ec) pair.
func (s *KyberPreKeyStore) MarkKyberPreKeyUsed(_ context.Context, kyberPreKeyID uint32, ecPreKeyID uint32, baseKey curve.PublicKey) error {
	key := kyberEcPair{kyberPreKeyID: kyberPreKeyID, ecPreKeyID: ecPreKeyID}
	for _, seen := range s.baseKeysSeen[key] {
		if seen.Equal(baseKey) {
			return fmt.Errorf("%w: kyber %d, ec %d", ErrReusedBaseKey, kyberPreKeyID, ecPreKeyID)
		}
	}
	s.baseKeysSeen[key] = append(s.baseKeysSeen[key], baseKey)
	return nil
}

// AllKyberPreKeyIDs returns the ids of all stored Kyber pre-keys, in unspecified
// order.
func (s *KyberPreKeyStore) AllKyberPreKeyIDs() []uint32 {
	ids := make([]uint32, 0, len(s.kyberPreKeys))
	for id := range s.kyberPreKeys {
		ids = append(ids, id)
	}
	return ids
}
