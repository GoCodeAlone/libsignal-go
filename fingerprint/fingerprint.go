// Package fingerprint implements Signal's safety-number fingerprints: the
// numeric DisplayableFingerprint (a 60-digit human-comparable string) and the
// ScannableFingerprint (a protobuf for QR-code comparison). It mirrors
// rust/protocol/src/fingerprint.rs.
package fingerprint

import (
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/proto"
)

const (
	// fingerprintLen is the minimum hash-chain output length the display
	// encoder consumes (6 chunks of 5 bytes). SHA-512 yields 64 bytes, so there
	// is headroom; the first 30 bytes drive the 30-digit half.
	displayChunkBytes = 5
	displayChunks     = 6
	displayMinLen     = displayChunkBytes * displayChunks // 30

	// scannableContentLen is the per-side fingerprint length carried in the
	// scannable protobuf (the first 32 bytes of the hash-chain output).
	scannableContentLen = 32

	// minIterations/maxIterations bound the hash-chain length, mirroring
	// Fingerprint::get_fingerprint's guard (iterations must be > 1 and <= 1e6).
	minIterations = 1
	maxIterations = 1_000_000
)

// Error sentinels, wrapped with %w so callers can match with errors.Is. They
// mirror fingerprint.rs Error.
var (
	// ErrVersionMismatch is returned by Compare when the two fingerprints carry
	// different versions. Mirrors Error::VersionMismatch.
	ErrVersionMismatch = errors.New("fingerprint: version mismatch")
	// ErrParsing is returned when a scannable protobuf is malformed or a
	// fingerprint is too short to encode. Mirrors Error::ParsingError.
	ErrParsing = errors.New("fingerprint: parsing error")
	// ErrInvalidIterationCount is returned when the requested iteration count is
	// outside (1, 1_000_000]. Mirrors Error::InvalidIterationCount.
	ErrInvalidIterationCount = errors.New("fingerprint: invalid iteration count")
)

// DisplayableFingerprint is the numeric safety number: two 30-digit halves
// (local and remote), rendered in a stable order. Mirrors DisplayableFingerprint.
type DisplayableFingerprint struct {
	local  string
	remote string
}

// String renders the safety number as the concatenation of the two halves in
// ascending lexicographic order, so both parties compute the identical 60-digit
// string regardless of who is "local". Mirrors the Display impl.
func (d DisplayableFingerprint) String() string {
	if d.local < d.remote {
		return d.local + d.remote
	}
	return d.remote + d.local
}

// getEncodedString turns a hash-chain output into a 30-digit half: six chunks
// of five bytes, each folded big-endian into a u64 and reduced mod 100000, then
// zero-padded to five digits. Mirrors get_encoded_string.
func getEncodedString(fprint []byte) (string, error) {
	if len(fprint) < displayMinLen {
		return "", fmt.Errorf("%w: displayable fingerprint created with short encoding (%d bytes)", ErrParsing, len(fprint))
	}
	out := make([]byte, 0, displayMinLen)
	for i := 0; i < displayChunks; i++ {
		chunk := fprint[i*displayChunkBytes : i*displayChunkBytes+displayChunkBytes]
		var x uint64
		for _, b := range chunk {
			x = (x << 8) | uint64(b)
		}
		out = append(out, []byte(fmt.Sprintf("%05d", x%100_000))...)
	}
	return string(out), nil
}

// newDisplayableFingerprint encodes both halves. Mirrors DisplayableFingerprint::new.
func newDisplayableFingerprint(local, remote []byte) (DisplayableFingerprint, error) {
	l, err := getEncodedString(local)
	if err != nil {
		return DisplayableFingerprint{}, err
	}
	r, err := getEncodedString(remote)
	if err != nil {
		return DisplayableFingerprint{}, err
	}
	return DisplayableFingerprint{local: l, remote: r}, nil
}

// ScannableFingerprint is the QR-comparison form: a version plus the two 32-byte
// per-side fingerprints. Mirrors ScannableFingerprint.
type ScannableFingerprint struct {
	version          uint32
	localFingerprint []byte
	remoteFprint     []byte
}

// newScannableFingerprint takes the first 32 bytes of each hash-chain output.
// Mirrors ScannableFingerprint::new (which slices [..32]).
func newScannableFingerprint(version uint32, localFprint, remoteFprint []byte) ScannableFingerprint {
	return ScannableFingerprint{
		version:          version,
		localFingerprint: append([]byte(nil), localFprint[:scannableContentLen]...),
		remoteFprint:     append([]byte(nil), remoteFprint[:scannableContentLen]...),
	}
}

// Version returns the scannable fingerprint's version.
func (s ScannableFingerprint) Version() uint32 { return s.version }

// Serialize encodes the scannable fingerprint as a CombinedFingerprints
// protobuf. Mirrors ScannableFingerprint::serialize.
func (s ScannableFingerprint) Serialize() ([]byte, error) {
	combined := &proto.CombinedFingerprints{
		Version: googleproto.Uint32(s.version),
		LocalFingerprint: &proto.LogicalFingerprint{
			Content: append([]byte(nil), s.localFingerprint...),
		},
		RemoteFingerprint: &proto.LogicalFingerprint{
			Content: append([]byte(nil), s.remoteFprint...),
		},
	}
	out, err := googleproto.Marshal(combined)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: encoding scannable: %w", err)
	}
	return out, nil
}

// DeserializeScannableFingerprint decodes a CombinedFingerprints protobuf.
// Malformed input or a missing field returns an error and never panics. Mirrors
// ScannableFingerprint::deserialize.
func DeserializeScannableFingerprint(protobuf []byte) (ScannableFingerprint, error) {
	var combined proto.CombinedFingerprints
	if err := googleproto.Unmarshal(protobuf, &combined); err != nil {
		return ScannableFingerprint{}, fmt.Errorf("%w: failed to decode protobuf", ErrParsing)
	}
	if combined.Version == nil {
		return ScannableFingerprint{}, fmt.Errorf("%w: missing version", ErrParsing)
	}
	local := combined.GetLocalFingerprint().GetContent()
	if local == nil {
		return ScannableFingerprint{}, fmt.Errorf("%w: missing local fingerprint", ErrParsing)
	}
	remote := combined.GetRemoteFingerprint().GetContent()
	if remote == nil {
		return ScannableFingerprint{}, fmt.Errorf("%w: missing remote fingerprint", ErrParsing)
	}
	return ScannableFingerprint{
		version:          combined.GetVersion(),
		localFingerprint: append([]byte(nil), local...),
		remoteFprint:     append([]byte(nil), remote...),
	}, nil
}

// Compare reports whether the serialized CombinedFingerprints in combined match
// this fingerprint: their local must equal our remote and their remote must
// equal our local (the parties hold mirror-image views). A version mismatch is
// a typed error, not a false result. The content comparison is constant-time.
// Mirrors ScannableFingerprint::compare.
func (s ScannableFingerprint) Compare(combined []byte) (bool, error) {
	var theirs proto.CombinedFingerprints
	if err := googleproto.Unmarshal(combined, &theirs); err != nil {
		return false, fmt.Errorf("%w: failed to decode their protobuf", ErrParsing)
	}

	// A missing version decodes as 0 (upstream uses unwrap_or(0)).
	theirVersion := theirs.GetVersion()
	if theirVersion != s.version {
		return false, fmt.Errorf("%w: theirs %d, ours %d", ErrVersionMismatch, theirVersion, s.version)
	}

	theirLocal := theirs.GetLocalFingerprint().GetContent()
	if theirLocal == nil {
		return false, fmt.Errorf("%w: missing their local fingerprint", ErrParsing)
	}
	theirRemote := theirs.GetRemoteFingerprint().GetContent()
	if theirRemote == nil {
		return false, fmt.Errorf("%w: missing their remote fingerprint", ErrParsing)
	}

	same1 := subtle.ConstantTimeCompare(theirLocal, s.remoteFprint)
	same2 := subtle.ConstantTimeCompare(theirRemote, s.localFingerprint)
	return same1 == 1 && same2 == 1, nil
}

// Fingerprint bundles the numeric (Display) and scannable forms for a pair of
// identities. Mirrors Fingerprint.
type Fingerprint struct {
	Display   DisplayableFingerprint
	Scannable ScannableFingerprint
}

// getFingerprint runs the iterated SHA-512 hash chain for one side. Iteration 0
// hashes (0x0000 || key || id || key); each subsequent iteration hashes
// (previous || key). Mirrors Fingerprint::get_fingerprint.
func getFingerprint(iterations uint32, localID []byte, key curve.PublicKey) ([]byte, error) {
	if iterations <= minIterations || iterations > maxIterations {
		return nil, fmt.Errorf("%w: %d", ErrInvalidIterationCount, iterations)
	}

	keyBytes := key.Serialize()
	version := []byte{0x00, 0x00} // fingerprint version 0x0000

	h := sha512.New()
	h.Write(version)
	h.Write(keyBytes)
	h.Write(localID)
	h.Write(keyBytes)
	buf := h.Sum(nil)

	for i := uint32(1); i < iterations; i++ {
		h := sha512.New()
		h.Write(buf)
		h.Write(keyBytes)
		buf = h.Sum(nil)
	}
	return buf, nil
}

// New builds a Fingerprint for the (local, remote) identity pair at the given
// version and iteration count. The display string is identical for both parties
// (it sorts the halves); the scannable form is version-specific. Mirrors
// Fingerprint::new.
func New(
	version uint32,
	iterations uint32,
	localID []byte,
	localKey curve.PublicKey,
	remoteID []byte,
	remoteKey curve.PublicKey,
) (*Fingerprint, error) {
	localFprint, err := getFingerprint(iterations, localID, localKey)
	if err != nil {
		return nil, err
	}
	remoteFprint, err := getFingerprint(iterations, remoteID, remoteKey)
	if err != nil {
		return nil, err
	}

	display, err := newDisplayableFingerprint(localFprint, remoteFprint)
	if err != nil {
		return nil, err
	}
	return &Fingerprint{
		Display:   display,
		Scannable: newScannableFingerprint(version, localFprint, remoteFprint),
	}, nil
}

// DisplayString returns the 60-digit numeric safety number. Mirrors
// Fingerprint::display_string.
func (f *Fingerprint) DisplayString() string {
	return f.Display.String()
}
