package crypto

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// NonceSizeCTR is the AES-256-CTR nonce size used by Signal: 12 bytes, leaving
// the trailing 4 bytes of the AES block as a 32-bit big-endian counter
// (rust/crypto/src/aes_ctr.rs: NONCE_SIZE = BlockSize - 4).
const NonceSizeCTR = blockSize - 4 // 12

// Aes256Ctr32 is AES-256 in counter mode with a 12-byte nonce and a 32-bit
// big-endian block counter, matching rust/crypto/src/aes_ctr.rs Aes256Ctr32.
//
// Unlike the standard library's CTR (which treats the whole 16-byte IV as a
// 128-bit counter), only the trailing 32 bits increment; the 12-byte nonce
// prefix is fixed. The two agree until the 32-bit counter would overflow into
// the nonce, which for Signal's message sizes never happens, but we implement
// the 32-bit behavior to remain faithful to the upstream contract.
type Aes256Ctr32 struct {
	block      cipher.Block
	nonce      [NonceSizeCTR]byte
	counter    uint32
	keystream  [blockSize]byte
	ksUsed     int // bytes of keystream already consumed in the current block
	ksHasBlock bool
}

// NewAES256CTR32 constructs a CTR stream for the given 32-byte key and 12-byte
// nonce, starting at block counter initCtr. It returns ErrInvalidKeySize or
// ErrInvalidNonceSize on bad input lengths.
func NewAES256CTR32(key, nonce []byte, initCtr uint32) (*Aes256Ctr32, error) {
	block, err := newAES256(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSizeCTR {
		return nil, fmt.Errorf("%w: CTR nonce must be %d bytes, got %d", ErrInvalidNonceSize, NonceSizeCTR, len(nonce))
	}
	c := &Aes256Ctr32{block: block, counter: initCtr}
	copy(c.nonce[:], nonce)
	return c, nil
}

// Process XORs the AES-CTR keystream into buf in place (encrypt and decrypt are
// the same operation). It may be called repeatedly to process a stream; the
// counter advances across calls.
func (c *Aes256Ctr32) Process(buf []byte) {
	for len(buf) > 0 {
		if !c.ksHasBlock || c.ksUsed == blockSize {
			c.fillKeystream()
		}
		n := subtle.ConstantTimeSelect(boolToInt(len(buf) < blockSize-c.ksUsed), len(buf), blockSize-c.ksUsed)
		for i := 0; i < n; i++ {
			buf[i] ^= c.keystream[c.ksUsed+i]
		}
		c.ksUsed += n
		buf = buf[n:]
	}
}

// fillKeystream encrypts the current counter block to produce a fresh keystream
// block and advances the 32-bit counter (wrapping, nonce untouched).
func (c *Aes256Ctr32) fillKeystream() {
	var ctrBlock [blockSize]byte
	copy(ctrBlock[:NonceSizeCTR], c.nonce[:])
	binary.BigEndian.PutUint32(ctrBlock[NonceSizeCTR:], c.counter)
	c.block.Encrypt(c.keystream[:], ctrBlock[:])
	c.counter++ // wraps mod 2^32, matching Ctr32BE
	c.ksUsed = 0
	c.ksHasBlock = true
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
