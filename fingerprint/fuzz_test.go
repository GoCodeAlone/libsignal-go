package fingerprint

import (
	"bytes"
	"testing"
)

// FuzzDeserializeScannableFingerprint checks that decoding arbitrary bytes as a
// ScannableFingerprint never panics, and that any successful parse re-serializes
// without error. It also feeds the same bytes to Compare against a valid
// fingerprint, whose only contract is likewise that it never panics.
func FuzzDeserializeScannableFingerprint(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})

	// A valid serialized scannable as a realistic seed, plus a reference
	// fingerprint to drive Compare against the fuzzed bytes.
	var ref ScannableFingerprint
	if seed := validScannableSeed(f, &ref); seed != nil {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		sf, err := DeserializeScannableFingerprint(data)
		if err == nil {
			// A successful parse must re-serialize without panicking or erroring.
			if _, serr := sf.Serialize(); serr != nil {
				t.Fatalf("re-serialize after successful parse: %v", serr)
			}
			_ = sf.Version()
		}
		// Compare must never panic regardless of input shape; result/err ignored.
		_, _ = ref.Compare(data)
	})
}

// validScannableSeed builds a real scannable fingerprint, stores it in ref for
// the fuzz body's Compare calls, and returns its serialized bytes as a seed.
// Returns nil on setup failure (seeds are best-effort).
func validScannableSeed(f *testing.F, ref *ScannableFingerprint) []byte {
	f.Helper()
	local := bytes.Repeat([]byte{0x12}, scannableContentLen)
	remote := bytes.Repeat([]byte{0xBA}, scannableContentLen)
	sf := newScannableFingerprint(1, local, remote)
	*ref = sf
	b, err := sf.Serialize()
	if err != nil {
		return nil
	}
	return b
}
