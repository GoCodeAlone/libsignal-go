package address

import (
	"errors"
	"testing"
)

// TestDeviceIDBounds covers the upstream DeviceId range invariant (1..=127).
func TestDeviceIDBounds(t *testing.T) {
	if _, err := NewDeviceID(0); !errors.Is(err, ErrInvalidDeviceID) {
		t.Fatalf("NewDeviceID(0) error = %v, want ErrInvalidDeviceID", err)
	}
	for _, v := range []uint32{1, 2, 127} {
		d, err := NewDeviceID(v)
		if err != nil {
			t.Fatalf("NewDeviceID(%d) error = %v", v, err)
		}
		if d.Value() != v {
			t.Fatalf("NewDeviceID(%d).Value() = %d", v, d.Value())
		}
	}
	for _, v := range []uint32{128, 255, 256, 1 << 20} {
		if _, err := NewDeviceID(v); !errors.Is(err, ErrInvalidDeviceID) {
			t.Fatalf("NewDeviceID(%d) error = %v, want ErrInvalidDeviceID", v, err)
		}
	}
}

func TestDeviceIDString(t *testing.T) {
	d, err := NewDeviceID(2)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.String(); got != "2" {
		t.Fatalf("DeviceID.String() = %q, want %q", got, "2")
	}
}

// TestProtocolAddress mirrors the upstream ProtocolAddress::new doc example.
func TestProtocolAddress(t *testing.T) {
	userID := "04899A85-4C9E-44CC-8428-A02AB69335F1"
	deviceID, err := NewDeviceID(2)
	if err != nil {
		t.Fatal(err)
	}
	addr := NewProtocolAddress(userID, deviceID)
	if addr.Name() != userID {
		t.Fatalf("Name() = %q, want %q", addr.Name(), userID)
	}
	if addr.DeviceID() != deviceID {
		t.Fatalf("DeviceID() = %v, want %v", addr.DeviceID(), deviceID)
	}
	if got, want := addr.String(), userID+".2"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestToProtocolAddress(t *testing.T) {
	deviceID, err := NewDeviceID(3)
	if err != nil {
		t.Fatal(err)
	}
	pni := NewPNI(testUUID)
	addr := pni.ToProtocolAddress(deviceID)
	if want := "PNI:" + testUUIDString; addr.Name() != want {
		t.Fatalf("Name() = %q, want %q", addr.Name(), want)
	}
	if addr.DeviceID() != deviceID {
		t.Fatalf("DeviceID() = %v, want %v", addr.DeviceID(), deviceID)
	}
}

// FuzzParseServiceIDBinary asserts the binary parser never panics on arbitrary
// input and that successful parses round-trip back to the same bytes.
func FuzzParseServiceIDBinary(f *testing.F) {
	f.Add(testUUID[:])
	fixed := NewPNI(testUUID).ServiceIDFixedWidthBinary()
	f.Add(fixed[:])
	f.Add([]byte{})
	f.Add([]byte{0xFF})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseServiceIDBinary(b)
		if err != nil {
			return
		}
		if got := s.ServiceIDBinary(); string(got) != string(b) {
			t.Fatalf("round-trip mismatch: parsed %x, re-serialized %x", b, got)
		}
	})
}

// FuzzParseServiceIDString asserts the string parser never panics on arbitrary
// input and that successful parses round-trip back to the same string.
func FuzzParseServiceIDString(f *testing.F) {
	f.Add(testUUIDString)
	f.Add("PNI:" + testUUIDString)
	f.Add("")
	f.Add("PNI:")
	f.Add("not-a-uuid")
	f.Fuzz(func(t *testing.T, s string) {
		parsed, err := ParseServiceIDString(s)
		if err != nil {
			return
		}
		// UUID parsing is case-insensitive, so re-serialization is the
		// lower-cased canonical form; reparsing it must be stable.
		canonical := parsed.ServiceIDString()
		reparsed, err := ParseServiceIDString(canonical)
		if err != nil {
			t.Fatalf("canonical form %q failed to reparse: %v", canonical, err)
		}
		if reparsed != parsed {
			t.Fatalf("round-trip mismatch: %q -> %v -> %v", s, parsed, reparsed)
		}
	})
}
