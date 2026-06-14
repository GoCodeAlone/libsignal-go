package spqr

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzDecodeState checks that decoding arbitrary bytes as a PqRatchetState never
// panics, and that any successful decode re-encodes and exposes its accessors
// without panicking. The two real fixtures seed the corpus.
func FuzzDecodeState(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	for _, name := range []string{"issue1275_a_state.in", "issue1275_b_state.in"} {
		if b, err := os.ReadFile(filepath.Join("testdata", name)); err == nil {
			f.Add(b)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		st, err := DecodeState(data)
		if err != nil {
			return
		}
		// A successful decode must re-encode and expose accessors without panic.
		if _, err := EncodeState(st); err != nil {
			t.Fatalf("re-encode after successful decode: %v", err)
		}
		_, _ = EmbeddedEncapsState(st)
		_ = ResolveMaxJump(st.GetChain().GetParams())
		_ = st.GetV1() != nil
	})
}
