package spqr

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/internal/mlkem768incr"
	"github.com/GoCodeAlone/libsignal-go/proto"
)

// readFixture loads a committed SPQR state fixture. The two issue1275_*.in files
// are full serialized PqRatchetState blobs captured 30 steps into a lockstep
// A<->B run on a SIMD (NEON) libcrux host — so the send_ct side carries an
// EncapsState with the issue-1275 byte-swapped endianness, pre-encapsulate2.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// TestStateRoundTripByteExact is the Slice-A codec oracle: decoding a real
// serialized PqRatchetState and re-encoding it must reproduce the input bytes
// exactly. This pins that the Go proto codec agrees byte-for-byte with the
// reference (prost) encoder — the transparent-byte-round-trip property the later
// slices rely on (a stored state, incl. a swapped EncapsState, is returned
// verbatim; the codec never normalizes).
func TestStateRoundTripByteExact(t *testing.T) {
	for _, name := range []string{"issue1275_a_state.in", "issue1275_b_state.in"} {
		raw := readFixture(t, name)
		st, err := DecodeState(raw)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		re, err := EncodeState(st)
		if err != nil {
			t.Fatalf("%s: encode: %v", name, err)
		}
		if !bytes.Equal(raw, re) {
			n := len(raw)
			if len(re) < n {
				n = len(re)
			}
			diff := -1
			for i := 0; i < n; i++ {
				if raw[i] != re[i] {
					diff = i
					break
				}
			}
			t.Fatalf("%s: re-encode not byte-exact (raw=%d re=%d firstDiff@%d)", name, len(raw), len(re), diff)
		}
		// These fixtures are mid-handshake V1 states.
		if st.GetV1() == nil {
			t.Fatalf("%s: expected a V1 state", name)
		}
	}
}

// TestEmbeddedEncapsStateDetectorFires confirms that the embedded incremental-KEM
// EncapsState in a real swapped-endianness fixture (b's Ct1Sampled state) is
// reachable via EmbeddedEncapsState AND is detected as byte-swapped by the
// issue-1275 detector — i.e. the codec preserves the bad bytes verbatim (does
// NOT normalize them) and the detector genuinely fires on real libcrux SIMD
// output. (The fix itself runs in the encapsulate2 path, Slice C; here we only
// assert detection on the codec-preserved bytes.)
func TestEmbeddedEncapsStateDetectorFires(t *testing.T) {
	st, err := DecodeState(readFixture(t, "issue1275_b_state.in"))
	if err != nil {
		t.Fatalf("decode b: %v", err)
	}
	es, ok := EmbeddedEncapsState(st)
	if !ok {
		t.Fatal("b fixture: expected an embedded EncapsState (Ct1Sampled)")
	}
	if len(es) != mlkem768incr.EncapsStateSize {
		t.Fatalf("embedded es length = %d, want %d", len(es), mlkem768incr.EncapsStateSize)
	}
	fixed, err := mlkem768incr.FixEncapsStateEndianness(es)
	if err != nil {
		t.Fatalf("FixEncapsStateEndianness: %v", err)
	}
	if bytes.Equal(es, fixed) {
		t.Fatal("b fixture: the embedded es was already correct-endian; expected a swapped (SIMD-host) state the detector flips")
	}
}

// TestEmbeddedEncapsStateAbsent confirms the accessor reports no es for a state
// variant that does not carry one (the a fixture is the peer side of the
// lockstep, not in a Ct1Sent-bearing state).
func TestEmbeddedEncapsStateAbsent(t *testing.T) {
	st, err := DecodeState(readFixture(t, "issue1275_a_state.in"))
	if err != nil {
		t.Fatalf("decode a: %v", err)
	}
	if _, ok := EmbeddedEncapsState(st); ok {
		t.Fatal("a fixture: did not expect an embedded EncapsState")
	}
}

// TestEmptyStateIsV0 checks the initial state: empty bytes decode to a V0
// (SPQR-disabled) state with no inner.
func TestEmptyStateIsV0(t *testing.T) {
	v, err := CurrentVersion(EmptyState())
	if err != nil {
		t.Fatalf("CurrentVersion(empty): %v", err)
	}
	if v != proto.Version_V_0 {
		t.Fatalf("empty state version = %v, want V_0", v)
	}
}

// TestCurrentVersionV1 checks a real V1 fixture reports V1.
func TestCurrentVersionV1(t *testing.T) {
	v, err := CurrentVersion(readFixture(t, "issue1275_b_state.in"))
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if v != proto.Version_V_1 {
		t.Fatalf("fixture version = %v, want V_1", v)
	}
}

// TestResolveMaxJump checks the ChainParams max-jump default (0 -> 25000).
func TestResolveMaxJump(t *testing.T) {
	if got := ResolveMaxJump(nil); got != DefaultMaxJump {
		t.Fatalf("nil params max jump = %d, want %d", got, DefaultMaxJump)
	}
	if got := ResolveMaxJump(&proto.ChainParams{MaxJump: 0}); got != DefaultMaxJump {
		t.Fatalf("zero max jump = %d, want default %d", got, DefaultMaxJump)
	}
	if got := ResolveMaxJump(&proto.ChainParams{MaxJump: 100}); got != 100 {
		t.Fatalf("explicit max jump = %d, want 100", got)
	}
}

// TestDecodeInvalidState confirms malformed input is a typed error, not a panic.
func TestDecodeInvalidState(t *testing.T) {
	// A byte that starts a length-delimited field claiming more bytes than exist.
	if _, err := DecodeState([]byte{0x0a, 0xff}); err == nil {
		t.Fatal("expected ErrInvalidState for truncated input")
	}
}
