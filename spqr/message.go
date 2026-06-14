// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// The SPQR v1 message wire codec, ported from
// SparsePostQuantumRatchet v1.5.1 src/v1/chunked/states/serialize.rs
// (Message::serialize / deserialize). A serialized message is:
//
//	[version]      - 1 byte (always Version_V_1 for a v1 message)
//	[epoch]        - varint
//	[index]        - varint (the chain message-key index, threaded in by the
//	                 orchestration's chain.send_key / recv_key)
//	[message_type] - 1 byte (0..6)
//
// For the chunk-carrying types (Hdr, Ek, EkCt1Ack, Ct1, Ct2) a 32-byte data
// chunk is appended as:
//
//	[chunk_index]  - varint
//	[chunk_data]   - 32 bytes
//
// None and Ct1Ack carry no chunk. Trailing data after the message is permitted
// (for forward-compatible protocol upgrades), so deserialize returns the byte
// offset it consumed.

package spqr

import (
	"errors"

	"github.com/GoCodeAlone/libsignal-go/internal/spqr/chunked"
	"github.com/GoCodeAlone/libsignal-go/proto"
)

// ErrMsgDecode is returned when a serialized v1 message is malformed (wrong
// version byte, zero/absent epoch, truncated chunk, or an unknown message type).
// Mirrors the reference Error::MsgDecode.
var ErrMsgDecode = errors.New("spqr: invalid serialized message")

// versionByteV1 is the leading byte of every serialized v1 message.
const versionByteV1 = byte(proto.Version_V_1)

// message-type tags, matching serialize.rs MessageType.
const (
	msgTypeNone     = 0
	msgTypeHdr      = 1
	msgTypeEk       = 2
	msgTypeEkCt1Ack = 3
	msgTypeCt1Ack   = 4
	msgTypeCt1      = 5
	msgTypeCt2      = 6
)

// msgTypeFor returns the wire message-type byte for a payload kind.
func msgTypeFor(k messageKind) byte {
	switch k {
	case payloadHdr:
		return msgTypeHdr
	case payloadEk:
		return msgTypeEk
	case payloadEkCt1Ack:
		return msgTypeEkCt1Ack
	case payloadCt1Ack:
		return msgTypeCt1Ack
	case payloadCt1:
		return msgTypeCt1
	case payloadCt2:
		return msgTypeCt2
	default:
		return msgTypeNone
	}
}

// kindHasChunk reports whether a payload kind carries a data chunk.
func kindHasChunk(k messageKind) bool {
	switch k {
	case payloadHdr, payloadEk, payloadEkCt1Ack, payloadCt1, payloadCt2:
		return true
	default:
		return false
	}
}

// serializeMessage encodes a v1 message at the given chain message-key index.
// Mirrors Message::serialize(index).
func serializeMessage(m *v1Message, index uint32) []byte {
	out := make([]byte, 0, 48)
	out = append(out, versionByteV1)
	out = appendVarint(out, m.epoch)
	out = appendVarint(out, uint64(index))
	out = append(out, msgTypeFor(m.kind))
	if kindHasChunk(m.kind) {
		out = appendVarint(out, uint64(m.chunk.Index))
		out = append(out, m.chunk.Data[:]...)
	}
	return out
}

// deserializeMessage decodes a serialized v1 message, returning the message, the
// chain message-key index, and the number of bytes consumed (trailing data is
// allowed). Mirrors Message::deserialize.
func deserializeMessage(b []byte) (m v1Message, index uint32, at int, err error) {
	if len(b) == 0 || b[0] != versionByteV1 {
		return v1Message{}, 0, 0, ErrMsgDecode
	}
	at = 1
	epoch, n, ok := decodeVarint(b, at)
	if !ok || epoch == 0 {
		return v1Message{}, 0, 0, ErrMsgDecode
	}
	at = n
	idx64, n, ok := decodeVarint(b, at)
	if !ok || idx64 > 0xFFFFFFFF {
		return v1Message{}, 0, 0, ErrMsgDecode
	}
	at = n
	if at >= len(b) {
		return v1Message{}, 0, 0, ErrMsgDecode
	}
	mt := b[at]
	at++

	m = v1Message{epoch: epoch}
	switch mt {
	case msgTypeNone:
		m.kind = payloadNone
	case msgTypeCt1Ack:
		m.kind, m.ct1Ack = payloadCt1Ack, true
	case msgTypeHdr, msgTypeEk, msgTypeEkCt1Ack, msgTypeCt1, msgTypeCt2:
		chunk, n2, derr := decodeChunk(b, at)
		if derr != nil {
			return v1Message{}, 0, 0, derr
		}
		at = n2
		m.chunk = chunk
		switch mt {
		case msgTypeHdr:
			m.kind = payloadHdr
		case msgTypeEk:
			m.kind = payloadEk
		case msgTypeEkCt1Ack:
			m.kind = payloadEkCt1Ack
		case msgTypeCt1:
			m.kind = payloadCt1
		case msgTypeCt2:
			m.kind = payloadCt2
		}
	default:
		return v1Message{}, 0, 0, ErrMsgDecode
	}
	return m, uint32(idx64), at, nil
}

// decodeChunk reads a chunk: a varint index (must fit u16) followed by exactly 32
// bytes of data. Mirrors decode_chunk.
func decodeChunk(b []byte, at int) (chunked.Chunk, int, error) {
	idx64, n, ok := decodeVarint(b, at)
	if !ok || idx64 > 0xFFFF {
		return chunked.Chunk{}, 0, ErrMsgDecode
	}
	start := n
	end := start + chunked.ChunkSize
	if end > len(b) {
		return chunked.Chunk{}, 0, ErrMsgDecode
	}
	var c chunked.Chunk
	c.Index = uint16(idx64)
	copy(c.Data[:], b[start:end])
	return c, end, nil
}

// appendVarint appends a base-128 varint (LEB128), matching encode_varint.
func appendVarint(b []byte, v uint64) []byte {
	for {
		if v < 0x80 {
			return append(b, byte(v))
		}
		b = append(b, byte(v&0x7F)|0x80)
		v >>= 7
	}
}

// decodeVarint reads a base-128 varint starting at offset at, returning the
// value, the offset just past it, and ok. Reads at most 10 bytes. Mirrors
// decode_varint.
func decodeVarint(b []byte, at int) (val uint64, next int, ok bool) {
	if at >= len(b) {
		return 0, at, false
	}
	const maxVarintBytes = 10
	limit := maxVarintBytes
	if rem := len(b) - at; rem < limit {
		limit = rem
	}
	for i := 0; i < limit; i++ {
		c := b[at+i]
		val |= (uint64(c) & 0x7F) << (7 * uint(i))
		if c&0x80 == 0 {
			return val, at + i + 1, true
		}
	}
	return 0, at, false
}
