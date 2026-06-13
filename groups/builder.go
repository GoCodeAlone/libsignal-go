package groups

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/protocol"
	"github.com/GoCodeAlone/libsignal-go/stores"
)

// CreateSenderKeyDistributionMessage builds the SKDM that announces sender's
// sender-key chain for distributionID to other group members. If the store has
// no record yet, it provisions a fresh chain (random 31-bit chain id, random
// 32-byte chain key at iteration 0, fresh signing key pair) and persists it
// before building the message; otherwise it reuses the existing head state.
// Mirrors group_cipher.rs create_sender_key_distribution_message.
//
// rng supplies the chain key and signing-key entropy (use crypto/rand.Reader in
// production); store holds the opaque serialized SenderKeyRecord.
func CreateSenderKeyDistributionMessage(
	ctx context.Context,
	sender address.ProtocolAddress,
	distributionID [16]byte,
	store stores.SenderKeyStore,
	rng io.Reader,
) (*protocol.SenderKeyDistributionMessage, error) {
	record, err := loadSenderKeyRecord(ctx, store, sender, distributionID)
	if err != nil {
		return nil, err
	}

	if record == nil {
		record, err = provisionSenderKeyChain(ctx, sender, distributionID, store, rng)
		if err != nil {
			return nil, err
		}
	}

	state, ok := record.SenderKeyState()
	if !ok {
		return nil, fmt.Errorf("groups: invalid sender key session for distribution %x: empty state", distributionID)
	}
	chainKey, ok := state.ChainKey()
	if !ok {
		return nil, fmt.Errorf("groups: invalid sender key session for distribution %x: missing chain key", distributionID)
	}
	signingKey, ok := state.SigningKeyPublic()
	if !ok {
		return nil, fmt.Errorf("groups: invalid sender key session for distribution %x: missing signing key", distributionID)
	}

	return protocol.NewSenderKeyDistributionMessage(
		distributionID,
		state.ChainID(),
		chainKey.Iteration(),
		chainKey.Seed(),
		signingKey,
	)
}

// provisionSenderKeyChain creates and persists a fresh sender-key chain for
// (sender, distributionID), returning the new record. Used only when the store
// holds no record yet.
func provisionSenderKeyChain(
	ctx context.Context,
	sender address.ProtocolAddress,
	distributionID [16]byte,
	store stores.SenderKeyStore,
	rng io.Reader,
) (*SenderKeyRecord, error) {
	chainID, err := randomChainID(rng)
	if err != nil {
		return nil, err
	}

	var chainKey [chainKeyLen]byte
	if _, err := io.ReadFull(rng, chainKey[:]); err != nil {
		return nil, fmt.Errorf("groups: reading sender chain key: %w", err)
	}

	signingKey, err := curve.GenerateKeyPair(rng)
	if err != nil {
		return nil, fmt.Errorf("groups: generating signing key: %w", err)
	}

	record := NewSenderKeyRecord()
	signingPrivate := signingKey.PrivateKey
	record.AddSenderKeyState(
		senderKeyMessageVersion,
		chainID,
		0, // iteration
		chainKey[:],
		signingKey.PublicKey,
		&signingPrivate,
	)
	if err := storeSenderKeyRecord(ctx, store, sender, distributionID, record); err != nil {
		return nil, err
	}
	return record, nil
}

// randomChainID draws a 31-bit chain id (top bit cleared). libsignal-protocol-java
// uses 31-bit integers for sender key chain IDs; matching it keeps cross-client
// compatibility. Mirrors `csprng.random::<u32>() >> 1` in upstream.
func randomChainID(rng io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(rng, buf[:]); err != nil {
		return 0, fmt.Errorf("groups: reading chain id: %w", err)
	}
	return binary.BigEndian.Uint32(buf[:]) >> 1, nil
}

// ProcessSenderKeyDistributionMessage records the sender-key chain announced by
// skdm into the store under (sender, skdm.DistributionID). The receiver stores
// only the public signing key (no private key). Mirrors group_cipher.rs
// process_sender_key_distribution_message.
func ProcessSenderKeyDistributionMessage(
	ctx context.Context,
	sender address.ProtocolAddress,
	skdm *protocol.SenderKeyDistributionMessage,
	store stores.SenderKeyStore,
) error {
	distributionID := skdm.DistributionID()

	record, err := loadSenderKeyRecord(ctx, store, sender, distributionID)
	if err != nil {
		return err
	}
	if record == nil {
		record = NewSenderKeyRecord()
	}

	record.AddSenderKeyState(
		skdm.MessageVersion(),
		skdm.ChainID(),
		skdm.Iteration(),
		skdm.ChainKey(),
		skdm.SigningKey(),
		nil, // receiver holds no private signing key
	)

	return storeSenderKeyRecord(ctx, store, sender, distributionID, record)
}

// loadSenderKeyRecord loads and decodes the SenderKeyRecord for (sender,
// distributionID), returning (nil, nil) when none is stored. The store holds
// the record as opaque serialized bytes.
func loadSenderKeyRecord(
	ctx context.Context,
	store stores.SenderKeyStore,
	sender address.ProtocolAddress,
	distributionID [16]byte,
) (*SenderKeyRecord, error) {
	raw, err := store.LoadSenderKey(ctx, sender, distributionID)
	if err != nil {
		return nil, fmt.Errorf("groups: loading sender key record: %w", err)
	}
	if raw == nil {
		return nil, nil
	}
	record, err := DeserializeSenderKeyRecord(raw)
	if err != nil {
		return nil, err
	}
	return record, nil
}

// storeSenderKeyRecord serializes record and stores it for (sender,
// distributionID).
func storeSenderKeyRecord(
	ctx context.Context,
	store stores.SenderKeyStore,
	sender address.ProtocolAddress,
	distributionID [16]byte,
	record *SenderKeyRecord,
) error {
	serialized, err := record.Serialize()
	if err != nil {
		return err
	}
	if err := store.StoreSenderKey(ctx, sender, distributionID, serialized); err != nil {
		return fmt.Errorf("groups: storing sender key record: %w", err)
	}
	return nil
}
