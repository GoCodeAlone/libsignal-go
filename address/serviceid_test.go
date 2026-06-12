package address

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"testing"
)

// testUUID is the UUID used throughout the upstream address.rs unit tests:
// 8c78cd2a-16ff-427d-83dc-1a5e36ce713d.
var testUUID = [UUIDLen]byte{
	0x8c, 0x78, 0xcd, 0x2a, 0x16, 0xff, 0x42, 0x7d,
	0x83, 0xdc, 0x1a, 0x5e, 0x36, 0xce, 0x71, 0x3d,
}

const testUUIDString = "8c78cd2a-16ff-427d-83dc-1a5e36ce713d"

// arrayPrepend builds a 17-byte fixed-width buffer with the given tag byte
// followed by the UUID, mirroring the upstream array_prepend test helper.
func arrayPrepend(tag byte, uuid [UUIDLen]byte) [ServiceIDFixedWidthBinaryLen]byte {
	var out [ServiceIDFixedWidthBinaryLen]byte
	out[0] = tag
	copy(out[1:], uuid[:])
	return out
}

// Port of address.rs `conversions`.
func TestConversions(t *testing.T) {
	aci := NewACI(testUUID)
	if aci.RawUUID() != testUUID {
		t.Fatalf("ACI RawUUID = %x, want %x", aci.RawUUID(), testUUID)
	}
	if aci.Kind() != ServiceIDKindACI {
		t.Fatalf("ACI Kind = %v, want ACI", aci.Kind())
	}
	if got, err := aci.ACI(); err != nil || got != aci {
		t.Fatalf("aci.ACI() = (%v, %v), want (aci, nil)", got, err)
	}
	if _, err := aci.PNI(); err == nil {
		t.Fatal("aci.PNI() = nil error, want ErrWrongKindOfServiceID")
	} else {
		var wrong ErrWrongKindOfServiceID
		if !errors.As(err, &wrong) {
			t.Fatalf("aci.PNI() error = %v, want ErrWrongKindOfServiceID", err)
		}
		if wrong.Expected != ServiceIDKindPNI || wrong.Actual != ServiceIDKindACI {
			t.Fatalf("aci.PNI() wrong = %+v, want {PNI, ACI}", wrong)
		}
	}

	pni := NewPNI(testUUID)
	if pni.RawUUID() != testUUID {
		t.Fatalf("PNI RawUUID = %x, want %x", pni.RawUUID(), testUUID)
	}
	if pni.Kind() != ServiceIDKindPNI {
		t.Fatalf("PNI Kind = %v, want PNI", pni.Kind())
	}
	if got, err := pni.PNI(); err != nil || got != pni {
		t.Fatalf("pni.PNI() = (%v, %v), want (pni, nil)", got, err)
	}
	if _, err := pni.ACI(); err == nil {
		t.Fatal("pni.ACI() = nil error, want ErrWrongKindOfServiceID")
	} else {
		var wrong ErrWrongKindOfServiceID
		if !errors.As(err, &wrong) {
			t.Fatalf("pni.ACI() error = %v, want ErrWrongKindOfServiceID", err)
		}
		if wrong.Expected != ServiceIDKindACI || wrong.Actual != ServiceIDKindPNI {
			t.Fatalf("pni.ACI() wrong = %+v, want {ACI, PNI}", wrong)
		}
	}

	if aci == pni {
		t.Fatal("ACI and PNI with same UUID compared equal")
	}
}

// roundTripCase exercises the ACI and PNI serialize/parse round trips for one
// representation, mirroring the upstream round_trip_test helper.
func roundTripCase(
	t *testing.T,
	uuid [UUIDLen]byte,
	serialize func(ServiceID) []byte,
	parse func([]byte) (ServiceID, error),
	expectedACI, expectedPNI []byte,
) {
	t.Helper()

	aci := NewACI(uuid)
	serACI := serialize(aci)
	if !bytes.Equal(serACI, expectedACI) {
		t.Fatalf("serialize(ACI) = %x, want %x", serACI, expectedACI)
	}
	gotACI, err := parse(serACI)
	if err != nil {
		t.Fatalf("parse(serialize(ACI)) error = %v", err)
	}
	if gotACI.Kind() != ServiceIDKindACI {
		t.Fatalf("parsed ACI kind = %v, want ACI", gotACI.Kind())
	}
	if gotACI.RawUUID() != uuid {
		t.Fatalf("parsed ACI uuid = %x, want %x", gotACI.RawUUID(), uuid)
	}
	if _, err := gotACI.ACI(); err != nil {
		t.Fatalf("parsed ACI ACI() error = %v", err)
	}

	pni := NewPNI(uuid)
	serPNI := serialize(pni)
	if !bytes.Equal(serPNI, expectedPNI) {
		t.Fatalf("serialize(PNI) = %x, want %x", serPNI, expectedPNI)
	}
	gotPNI, err := parse(serPNI)
	if err != nil {
		t.Fatalf("parse(serialize(PNI)) error = %v", err)
	}
	if gotPNI.Kind() != ServiceIDKindPNI {
		t.Fatalf("parsed PNI kind = %v, want PNI", gotPNI.Kind())
	}
	if gotPNI.RawUUID() != uuid {
		t.Fatalf("parsed PNI uuid = %x, want %x", gotPNI.RawUUID(), uuid)
	}
	if _, err := gotPNI.PNI(); err != nil {
		t.Fatalf("parsed PNI PNI() error = %v", err)
	}
}

// splitmix64 is a small deterministic PRNG used to generate UUIDs for
// property-style round-trip coverage, standing in for the upstream proptest
// harness. It avoids math/rand so the tests stay lint-clean (no weak-RNG
// warning) while remaining fully reproducible from a seed.
type splitmix64 struct {
	state uint64
}

func (s *splitmix64) next() uint64 {
	s.state += 0x9e3779b97f4a7c15
	z := s.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// uuid produces the next deterministic UUID in the sequence.
func (s *splitmix64) uuid() [UUIDLen]byte {
	var u [UUIDLen]byte
	binary.LittleEndian.PutUint64(u[0:8], s.next())
	binary.LittleEndian.PutUint64(u[8:16], s.next())
	return u
}

// Port of address.rs `round_trip_service_id_binary`.
func TestRoundTripServiceIDBinary(t *testing.T) {
	gen := splitmix64{state: 1}
	check := func(uuid [UUIDLen]byte) {
		expectedPNI := arrayPrepend(0x01, uuid)
		roundTripCase(t, uuid,
			func(s ServiceID) []byte { return s.ServiceIDBinary() },
			ParseServiceIDBinary,
			uuid[:],
			expectedPNI[:],
		)
	}
	check(testUUID)
	for i := 0; i < 256; i++ {
		check(gen.uuid())
	}
}

// Port of address.rs `round_trip_service_id_fixed_width_binary`.
func TestRoundTripServiceIDFixedWidthBinary(t *testing.T) {
	parse := func(b []byte) (ServiceID, error) {
		var fixed [ServiceIDFixedWidthBinaryLen]byte
		copy(fixed[:], b)
		return ParseServiceIDFixedWidthBinary(fixed)
	}
	gen := splitmix64{state: 2}
	check := func(uuid [UUIDLen]byte) {
		expectedACI := arrayPrepend(0x00, uuid)
		expectedPNI := arrayPrepend(0x01, uuid)
		roundTripCase(t, uuid,
			func(s ServiceID) []byte {
				fixed := s.ServiceIDFixedWidthBinary()
				return fixed[:]
			},
			parse,
			expectedACI[:],
			expectedPNI[:],
		)
	}
	check(testUUID)
	for i := 0; i < 256; i++ {
		check(gen.uuid())
	}
}

// Port of address.rs `round_trip_service_id_string`.
func TestRoundTripServiceIDString(t *testing.T) {
	parse := func(b []byte) (ServiceID, error) {
		return ParseServiceIDString(string(b))
	}
	gen := splitmix64{state: 3}
	check := func(uuid [UUIDLen]byte) {
		expectedACI := []byte(formatUUID(uuid))
		expectedPNI := []byte("PNI:" + formatUUID(uuid))
		roundTripCase(t, uuid,
			func(s ServiceID) []byte { return []byte(s.ServiceIDString()) },
			parse,
			expectedACI,
			expectedPNI,
		)
	}
	check(testUUID)
	for i := 0; i < 256; i++ {
		check(gen.uuid())
	}
}

// Port of address.rs `logging`.
func TestLogging(t *testing.T) {
	want := "<ACI:" + testUUIDString + ">"
	aci := NewACI(testUUID)
	if got := aci.LogString(); got != want {
		t.Fatalf("aci.LogString() = %q, want %q", got, want)
	}

	wantPNI := "<PNI:" + testUUIDString + ">"
	pni := NewPNI(testUUID)
	if got := pni.LogString(); got != wantPNI {
		t.Fatalf("pni.LogString() = %q, want %q", got, wantPNI)
	}
}

// Port of address.rs `case_insensitive`.
func TestCaseInsensitive(t *testing.T) {
	upper := "8C78CD2A-16FF-427D-83DC-1A5E36CE713D"
	lower := testUUIDString

	for _, in := range []string{upper, lower} {
		s, err := ParseServiceIDString(in)
		if err != nil {
			t.Fatalf("ParseServiceIDString(%q) error = %v", in, err)
		}
		if s.RawUUID() != testUUID {
			t.Fatalf("ParseServiceIDString(%q) uuid = %x, want %x", in, s.RawUUID(), testUUID)
		}
	}

	for _, in := range []string{"PNI:" + upper, "PNI:" + lower} {
		s, err := ParseServiceIDString(in)
		if err != nil {
			t.Fatalf("ParseServiceIDString(%q) error = %v", in, err)
		}
		if s.RawUUID() != testUUID {
			t.Fatalf("ParseServiceIDString(%q) uuid = %x, want %x", in, s.RawUUID(), testUUID)
		}
		if s.Kind() != ServiceIDKindPNI {
			t.Fatalf("ParseServiceIDString(%q) kind = %v, want PNI", in, s.Kind())
		}
	}
}

// Port of address.rs `accepts_ios_system_story_aci`.
func TestAcceptsIOSSystemStoryACI(t *testing.T) {
	s, err := ParseServiceIDString("00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatalf("ParseServiceIDString error = %v", err)
	}
	want := [UUIDLen]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if s.RawUUID() != want {
		t.Fatalf("uuid = %x, want %x", s.RawUUID(), want)
	}
	if s.Kind() != ServiceIDKindACI {
		t.Fatalf("kind = %v, want ACI", s.Kind())
	}
}

// Port of address.rs `rejects_invalid_binary_lengths`.
func TestRejectsInvalidBinaryLengths(t *testing.T) {
	cases := [][]byte{
		{},
		{1},
		testUUID[1:], // 15 bytes
		bytes.Repeat([]byte{1}, 18),
	}
	for i, c := range cases {
		if _, err := ParseServiceIDBinary(c); err == nil {
			t.Fatalf("case %d: ParseServiceIDBinary(%x) = nil error, want error", i, c)
		}
	}
}

// Port of address.rs `rejects_invalid_uuid_strings`.
func TestRejectsInvalidUUIDStrings(t *testing.T) {
	cases := []string{
		"",
		"11",
		"8c78cd2a16ff427d83dc1a5e36ce713d",       // no hyphens
		"{8c78cd2a-16ff-427d-83dc-1a5e36ce713d}", // braces
		"PNI:",
		"PNI:11",
		"PNI:8c78cd2a16ff427d83dc1a5e36ce713d", // no hyphens
		"PNI:{8c78cd2a-16ff-427d-83dc-1a5e36ce713d}",
	}
	for _, c := range cases {
		if _, err := ParseServiceIDString(c); err == nil {
			t.Fatalf("ParseServiceIDString(%q) = nil error, want error", c)
		}
	}
}

// Port of address.rs `rejects_invalid_types`.
func TestRejectsInvalidTypes(t *testing.T) {
	badBinary := arrayPrepend(0xFF, testUUID)
	if _, err := ParseServiceIDBinary(badBinary[:]); err == nil {
		t.Fatal("ParseServiceIDBinary(0xFF tag) = nil error, want error")
	}
	if _, err := ParseServiceIDFixedWidthBinary(badBinary); err == nil {
		t.Fatal("ParseServiceIDFixedWidthBinary(0xFF tag) = nil error, want error")
	}

	for _, c := range []string{"BAD:{uuid}", "PNI{uuid}", "PNI {uuid}", "PNI{uuid} ", "ACI:" + testUUIDString} {
		if _, err := ParseServiceIDString(c); err == nil {
			t.Fatalf("ParseServiceIDString(%q) = nil error, want error", c)
		}
	}

	// ACIs are only prefixed in the fixed-width format: a 0x00-tagged
	// variable-width binary is invalid.
	aciTagged := arrayPrepend(0x00, testUUID)
	if _, err := ParseServiceIDBinary(aciTagged[:]); err == nil {
		t.Fatal("ParseServiceIDBinary(0x00-tagged ACI) = nil error, want error")
	}
}

// Port of address.rs `ordering`.
func TestOrdering(t *testing.T) {
	var nilUUID [UUIDLen]byte
	original := []ServiceID{
		NewACI(nilUUID),
		NewACI(testUUID),
		NewPNI(nilUUID),
		NewPNI(testUUID),
	}
	// Start from a fixed scrambled order; sorting must restore the canonical
	// order regardless of starting arrangement.
	shuffled := []ServiceID{original[2], original[0], original[3], original[1]}
	sort.Slice(shuffled, func(i, j int) bool { return shuffled[i].Compare(shuffled[j]) < 0 })
	for i := range original {
		if shuffled[i] != original[i] {
			t.Fatalf("sorted[%d] = %v, want %v", i, shuffled[i], original[i])
		}
	}
}

// Port of address.rs `ordering_consistency`: Compare must agree with the
// fixed-width binary ordering for all kind/UUID combinations.
func TestOrderingConsistency(t *testing.T) {
	gen := splitmix64{state: 5}
	ctor := func(kind uint64, uuid [UUIDLen]byte) ServiceID {
		if kind%2 == 0 {
			return NewACI(uuid)
		}
		return NewPNI(uuid)
	}
	for i := 0; i < 1024; i++ {
		left := ctor(gen.next(), gen.uuid())
		right := ctor(gen.next(), gen.uuid())
		got := left.Compare(right)
		lb := left.ServiceIDFixedWidthBinary()
		rb := right.ServiceIDFixedWidthBinary()
		want := bytes.Compare(lb[:], rb[:])
		if got != want {
			t.Fatalf("Compare(%v, %v) = %d, want %d (fixed-width ordering)", left, right, got, want)
		}
	}
}
