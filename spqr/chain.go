// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// The SPQR epoch key Chain — the Double-Ratchet-style symmetric key schedule
// that turns each KEM epoch secret into a stream of per-message keys. Ported
// from SparsePostQuantumRatchet v1.5.1 src/chain.rs. This is part of Slice C
// (the SPQR state machine): send/recv drive the Chain, feeding it each new KEM
// shared secret as an epoch secret and drawing send/recv message keys from it.

package spqr

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/GoCodeAlone/libsignal-go/internal/crypto"
	"github.com/GoCodeAlone/libsignal-go/proto"
)

// chainKeyLen is the byte length of a chain "next" key and a per-message key.
const chainKeyLen = 32

// defaultMaxOOOKeys is the default out-of-order key retention window: keys back
// to ctr-MaxOOOKeys are kept for late-arriving messages. Mirrors
// DEFAULT_CHAIN_PARAMS.max_ooo_keys.
const defaultMaxOOOKeys uint32 = 2000

// HKDF info strings, byte-exact from chain.rs (note the TWO spaces in the Start
// label — "Chain  Start" — which is load-bearing for interop).
var (
	chainNextInfo     = []byte("Signal PQ Ratchet V1 Chain Next")
	chainStartInfo    = []byte("Signal PQ Ratchet V1 Chain  Start")
	chainAddEpochInfo = []byte("Signal PQ Ratchet V1 Chain Add Epoch")
)

// zeroSalt32 is the 32-byte zero HKDF salt used for the chain-next and
// chain-start derivations (Chain::new / next_key use a zero salt; add_epoch uses
// next_root as the salt).
var zeroSalt32 = make([]byte, 32)

// Chain errors, mirroring the relevant chain.rs Error variants.
var (
	// ErrKeyJump is returned when a requested key index is more than max_jump
	// ahead of the current counter. Mirrors Error::KeyJump.
	ErrKeyJump = errors.New("spqr: requested key too far ahead (max jump)")
	// ErrKeyTrimmed is returned when a requested out-of-order key is older than
	// the retention window. Mirrors Error::KeyTrimmed.
	ErrKeyTrimmed = errors.New("spqr: requested key already trimmed (too old)")
	// ErrKeyAlreadyRequested is returned when a key index was already consumed.
	// Mirrors Error::KeyAlreadyRequested.
	ErrKeyAlreadyRequested = errors.New("spqr: key already requested")
	// ErrEpochOutOfRange is returned for an epoch not in the retained window.
	// Mirrors Error::EpochOutOfRange.
	ErrEpochOutOfRange = errors.New("spqr: epoch out of range")
	// ErrSendKeyEpochDecreased is returned when send_key is asked for an epoch
	// older than the current send epoch. Mirrors Error::SendKeyEpochDecreased.
	ErrSendKeyEpochDecreased = errors.New("spqr: send key epoch decreased")
	// ErrChainDecode is returned when a Chain proto is structurally invalid.
	// Mirrors Error::StateDecode in the chain context.
	ErrChainDecode = errors.New("spqr: invalid chain state")
)

// epochsToKeepPriorToSendEpoch bounds how many epochs before the current send
// epoch are retained. Mirrors EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH.
const epochsToKeepPriorToSendEpoch = 1

// keyHistory stores skipped/out-of-order keys as packed (BE32 index ‖ 32-byte
// key) records, mirroring chain.rs KeyHistory.
type keyHistory struct {
	data []byte // len multiple of keyHistoryEntry
}

const keyHistoryEntry = 4 + chainKeyLen // 36

func (h *keyHistory) add(idx uint32, key []byte) {
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], idx)
	h.data = append(h.data, be[:]...)
	h.data = append(h.data, key...)
}

func (h *keyHistory) clear() { h.data = h.data[:0] }

// trimSize is the history length (in entries) past which gc runs. Mirrors
// ChainParamsPB::trim_size = max_ooo*11/10 + 1.
func trimSize(maxOOO uint32) int { return int(maxOOO)*11/10 + 1 }

// remove deletes the entry at byte offset i by swapping the last entry into its
// place (matching chain.rs KeyHistory::remove copy_within+truncate).
func (h *keyHistory) remove(i int) {
	newEnd := len(h.data) - keyHistoryEntry
	if i+keyHistoryEntry < len(h.data) {
		copy(h.data[i:i+keyHistoryEntry], h.data[newEnd:])
	}
	h.data = h.data[:newEnd]
}

// gc drops keys older than currentKey-maxOOO, but only once the history exceeds
// trim_size entries. Mirrors KeyHistory::gc.
func (h *keyHistory) gc(currentKey, maxOOO uint32) {
	if len(h.data) < trimSize(maxOOO)*keyHistoryEntry {
		return
	}
	if currentKey < maxOOO {
		return // trim horizon underflows; nothing to trim (mirrors the assert guard)
	}
	horizon := currentKey - maxOOO
	var horizonBE [4]byte
	binary.BigEndian.PutUint32(horizonBE[:], horizon)
	i := 0
	for i < len(h.data) {
		if string(horizonBE[:]) > string(h.data[i:i+4]) { // horizon > stored index
			h.remove(i) // don't advance i: a swapped-in entry now occupies i
		} else {
			i += keyHistoryEntry
		}
	}
}

// get pops the key at index at, or errors if it was trimmed (too old) or never
// stored (already requested). Mirrors KeyHistory::get.
func (h *keyHistory) get(at, currentCtr, maxOOO uint32) ([]byte, error) {
	if at+maxOOO < currentCtr {
		return nil, fmt.Errorf("%w: index %d", ErrKeyTrimmed, at)
	}
	var wantBE [4]byte
	binary.BigEndian.PutUint32(wantBE[:], at)
	for i := 0; i < len(h.data); i += keyHistoryEntry {
		if string(h.data[i:i+4]) == string(wantBE[:]) {
			out := append([]byte(nil), h.data[i+4:i+keyHistoryEntry]...)
			h.remove(i)
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w: index %d", ErrKeyAlreadyRequested, at)
}

// chainEpochDirection is one half (send or recv) of an epoch's key chain.
// Mirrors chain.rs ChainEpochDirection.
type chainEpochDirection struct {
	ctr  uint32
	next []byte // 32 bytes; empty after clearNext
	prev keyHistory
}

func newChainEpochDirection(k []byte) chainEpochDirection {
	return chainEpochDirection{ctr: 0, next: append([]byte(nil), k...)}
}

// nextKeyInternal advances the chain one step: ctr++; HKDF(salt=zeros32,
// ikm=next, info=BE32(ctr)‖"…Chain Next", out=64); next=out[:32]; key=out[32:].
// Mirrors ChainEpochDirection::next_key_internal.
func (d *chainEpochDirection) nextKeyInternal() (uint32, []byte) {
	d.ctr++
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], d.ctr)
	info := append(append([]byte(nil), be[:]...), chainNextInfo...)
	okm, err := crypto.HKDFSHA256(d.next, zeroSalt32, info, 64)
	if err != nil {
		// HKDF over SHA-256 with these fixed lengths cannot fail.
		panic(fmt.Sprintf("spqr: chain next HKDF: %v", err))
	}
	d.next = append([]byte(nil), okm[:32]...)
	return d.ctr, append([]byte(nil), okm[32:64]...)
}

// nextKey returns the next sequential (index, key). Mirrors next_key.
func (d *chainEpochDirection) nextKey() (uint32, []byte) {
	return d.nextKeyInternal()
}

// key returns the key at index at, advancing/caching as needed. Mirrors
// ChainEpochDirection::key: future keys past max_jump are rejected; past keys
// come from the history (or are already-requested/trimmed); intermediate keys
// are derived and cached up to the retention window.
func (d *chainEpochDirection) key(at uint32, p *proto.ChainParams) ([]byte, error) {
	maxJump := ResolveMaxJump(p)
	maxOOO := resolveMaxOOO(p)
	switch {
	case at > d.ctr:
		if at-d.ctr > maxJump {
			return nil, fmt.Errorf("%w: ctr %d, at %d", ErrKeyJump, d.ctr, at)
		}
	case at < d.ctr:
		return d.prev.get(at, d.ctr, maxOOO)
	default: // at == d.ctr: already returned
		return nil, fmt.Errorf("%w: index %d", ErrKeyAlreadyRequested, at)
	}

	if at > d.ctr+maxOOO {
		d.prev.clear() // all currently-held keys become obsolete
	}
	for at > d.ctr+1 {
		idx, k := d.nextKeyInternal()
		if d.ctr+maxOOO >= at { // only retain keys we won't immediately gc
			d.prev.add(idx, k)
		}
	}
	d.prev.gc(d.ctr, maxOOO)
	_, k := d.nextKeyInternal()
	return k, nil
}

func (d *chainEpochDirection) clearNext() { d.next = d.next[:0] }

func (d chainEpochDirection) toProto() *proto.Chain_Epoch_EpochDirection {
	return &proto.Chain_Epoch_EpochDirection{
		Ctr:  d.ctr,
		Next: append([]byte(nil), d.next...),
		Prev: append([]byte(nil), d.prev.data...),
	}
}

func chainEpochDirectionFromProto(pb *proto.Chain_Epoch_EpochDirection) (chainEpochDirection, error) {
	if pb == nil {
		return chainEpochDirection{}, ErrChainDecode
	}
	return chainEpochDirection{
		ctr:  pb.GetCtr(),
		next: append([]byte(nil), pb.GetNext()...),
		prev: keyHistory{data: append([]byte(nil), pb.GetPrev()...)},
	}, nil
}

// resolveMaxOOO returns the effective out-of-order retention window (0→default).
func resolveMaxOOO(p *proto.ChainParams) uint32 {
	if p == nil || p.GetMaxOooKeys() == 0 {
		return defaultMaxOOOKeys
	}
	return p.GetMaxOooKeys()
}

// switchDirection flips A2B<->B2A. Mirrors Direction::switch.
func switchDirection(d proto.Direction) proto.Direction {
	if d == proto.Direction_A_2_B {
		return proto.Direction_B_2_A
	}
	return proto.Direction_A_2_B
}

// epochSecret is a new KEM-derived secret to fold into the chain at a given
// epoch. Mirrors EpochSecret.
type epochSecret struct {
	epoch  uint64
	secret []byte
}

// chainEpoch holds an epoch's send and recv key chains. Mirrors ChainEpoch.
type chainEpoch struct {
	send chainEpochDirection
	recv chainEpochDirection
}

// chain is the SPQR epoch key schedule. Mirrors chain.rs Chain.
type chain struct {
	dir          proto.Direction
	currentEpoch uint64
	sendEpoch    uint64
	links        []chainEpoch // links[0] is the oldest retained epoch
	nextRoot     []byte       // 32 bytes
	params       *proto.ChainParams
}

// cedForDirection picks the send/recv seed from a 96-byte KDF output by
// direction: A2B→[32:64], B2A→[64:96]. Mirrors Chain::ced_for_direction.
func cedForDirection(genr8r []byte, dir proto.Direction) chainEpochDirection {
	if dir == proto.Direction_A_2_B {
		return newChainEpochDirection(genr8r[32:64])
	}
	return newChainEpochDirection(genr8r[64:96])
}

// newChain creates a chain from an initial key + direction. Mirrors Chain::new:
// HKDF(salt=zeros32, ikm=initial_key, info="…Chain  Start", out=96); next_root =
// out[0:32]; the first epoch's send/recv CEDs from out by direction.
func newChain(initialKey []byte, dir proto.Direction, params *proto.ChainParams) *chain {
	genr8r := chainHKDF(zeroSalt32, initialKey, chainStartInfo, 96)
	return &chain{
		dir:          dir,
		currentEpoch: 0,
		sendEpoch:    0,
		links: []chainEpoch{{
			send: cedForDirection(genr8r, dir),
			recv: cedForDirection(genr8r, switchDirection(dir)),
		}},
		nextRoot: append([]byte(nil), genr8r[0:32]...),
		params:   params,
	}
}

// addEpoch folds a new epoch secret into the chain. Mirrors Chain::add_epoch:
// HKDF(salt=next_root, ikm=secret, info="…Chain Add Epoch", out=96).
func (c *chain) addEpoch(es epochSecret) error {
	if es.epoch != c.currentEpoch+1 {
		return fmt.Errorf("%w: add epoch %d, current %d", ErrChainDecode, es.epoch, c.currentEpoch)
	}
	genr8r := chainHKDF(c.nextRoot, es.secret, chainAddEpochInfo, 96)
	c.currentEpoch = es.epoch
	c.nextRoot = append([]byte(nil), genr8r[0:32]...)
	c.links = append(c.links, chainEpoch{
		send: cedForDirection(genr8r, c.dir),
		recv: cedForDirection(genr8r, switchDirection(c.dir)),
	})
	return nil
}

// epochIdx maps an epoch number to its index in links, or errors if out of the
// retained range. Mirrors Chain::epoch_idx.
func (c *chain) epochIdx(epoch uint64) (int, error) {
	if epoch > c.currentEpoch {
		return 0, fmt.Errorf("%w: %d", ErrEpochOutOfRange, epoch)
	}
	back := int(c.currentEpoch - epoch)
	if back >= len(c.links) {
		return 0, fmt.Errorf("%w: %d", ErrEpochOutOfRange, epoch)
	}
	return len(c.links) - 1 - back, nil
}

// sendKey returns the next (index, key) on the send chain for epoch, advancing
// the send epoch and trimming older epochs. Mirrors Chain::send_key.
func (c *chain) sendKey(epoch uint64) (uint32, []byte, error) {
	if epoch < c.sendEpoch {
		return 0, nil, fmt.Errorf("%w: send %d, asked %d", ErrSendKeyEpochDecreased, c.sendEpoch, epoch)
	}
	epochIndex, err := c.epochIdx(epoch)
	if err != nil {
		return 0, nil, err
	}
	if c.sendEpoch != epoch {
		c.sendEpoch = epoch
		for epochIndex > epochsToKeepPriorToSendEpoch {
			c.links = c.links[1:] // pop_front
			epochIndex--
		}
		for i := 0; i < epochIndex; i++ {
			c.links[i].send.clearNext()
		}
	}
	idx, key := c.links[epochIndex].send.nextKey()
	return idx, key, nil
}

// recvKey returns the recv-chain key at (epoch, index). Mirrors Chain::recv_key.
func (c *chain) recvKey(epoch uint64, index uint32) ([]byte, error) {
	epochIndex, err := c.epochIdx(epoch)
	if err != nil {
		return nil, err
	}
	return c.links[epochIndex].recv.key(index, c.params)
}

func (c *chain) toProto() *proto.Chain {
	links := make([]*proto.Chain_Epoch, len(c.links))
	for i, l := range c.links {
		links[i] = &proto.Chain_Epoch{Send: l.send.toProto(), Recv: l.recv.toProto()}
	}
	return &proto.Chain{
		Direction:    c.dir,
		CurrentEpoch: c.currentEpoch,
		SendEpoch:    c.sendEpoch,
		Links:        links,
		NextRoot:     append([]byte(nil), c.nextRoot...),
		Params:       c.params,
	}
}

func chainFromProto(pb *proto.Chain) (*chain, error) {
	if pb == nil || pb.GetParams() == nil {
		return nil, ErrChainDecode
	}
	links := make([]chainEpoch, len(pb.GetLinks()))
	for i, l := range pb.GetLinks() {
		send, err := chainEpochDirectionFromProto(l.GetSend())
		if err != nil {
			return nil, err
		}
		recv, err := chainEpochDirectionFromProto(l.GetRecv())
		if err != nil {
			return nil, err
		}
		links[i] = chainEpoch{send: send, recv: recv}
	}
	return &chain{
		dir:          pb.GetDirection(),
		currentEpoch: pb.GetCurrentEpoch(),
		sendEpoch:    pb.GetSendEpoch(),
		links:        links,
		nextRoot:     append([]byte(nil), pb.GetNextRoot()...),
		params:       pb.GetParams(),
	}, nil
}

// chainHKDF is the SPQR chain KDF: HKDF-SHA256(salt, ikm).expand(info, out).
// Mirrors kdf::hkdf_to_slice. Panics on the structurally-impossible HKDF error
// (fixed SHA-256 lengths).
func chainHKDF(salt, ikm, info []byte, outLen int) []byte {
	out, err := crypto.HKDFSHA256(ikm, salt, info, outLen)
	if err != nil {
		panic(fmt.Sprintf("spqr: chain HKDF: %v", err))
	}
	return out
}
