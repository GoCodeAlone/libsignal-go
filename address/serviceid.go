// Package address provides types identifying an individual Signal client
// instance: service IDs (ACI/PNI), device IDs, and protocol addresses.
//
// It is a pure-Go port of rust/core/src/address.rs; the binary and string
// encodings are wire-compatible with upstream libsignal.
package address

import (
	"bytes"
	"errors"
	"fmt"
)

// ServiceIDKind enumerates the known kinds of [ServiceID].
type ServiceIDKind uint8

const (
	// ServiceIDKindACI identifies an ACI ("ACcount Identifier").
	ServiceIDKindACI ServiceIDKind = 0
	// ServiceIDKindPNI identifies a PNI ("Phone Number Identifier").
	ServiceIDKindPNI ServiceIDKind = 1
)

// String returns the canonical short name of the kind ("ACI" or "PNI").
func (k ServiceIDKind) String() string {
	switch k {
	case ServiceIDKindACI:
		return "ACI"
	case ServiceIDKindPNI:
		return "PNI"
	default:
		return fmt.Sprintf("ServiceIDKind(%d)", uint8(k))
	}
}

// ErrWrongKindOfServiceID is returned when downcasting a [ServiceID] to a
// specific kind (via [ServiceID.ACI] or [ServiceID.PNI]) and the actual kind
// does not match the expected kind.
type ErrWrongKindOfServiceID struct {
	Expected ServiceIDKind
	Actual   ServiceIDKind
}

func (e ErrWrongKindOfServiceID) Error() string {
	return fmt.Sprintf("wrong kind of service ID: expected %s, got %s", e.Expected, e.Actual)
}

// ErrInvalidServiceID is returned when parsing fails for any of the standard
// service-ID representations.
var ErrInvalidServiceID = errors.New("invalid service ID")

// ServiceIDFixedWidthBinaryLen is the length of the fixed-width binary
// representation of a service ID: a one-byte kind tag followed by the 16-byte
// raw UUID.
const ServiceIDFixedWidthBinaryLen = 17

// UUIDLen is the length of the raw UUID inside a service ID.
const UUIDLen = 16

// ServiceID is a Signal service ID, which can be one of various kinds.
//
// Conceptually it is a UUID in a particular "namespace" representing a
// particular way to reach a user on the Signal service.
type ServiceID struct {
	kind ServiceIDKind
	uuid [UUIDLen]byte
}

// NewACI constructs an ACI service ID from a raw UUID.
func NewACI(uuid [UUIDLen]byte) ServiceID {
	return ServiceID{kind: ServiceIDKindACI, uuid: uuid}
}

// NewPNI constructs a PNI service ID from a raw UUID.
func NewPNI(uuid [UUIDLen]byte) ServiceID {
	return ServiceID{kind: ServiceIDKindPNI, uuid: uuid}
}

// Kind reports which kind of service ID this is.
func (s ServiceID) Kind() ServiceIDKind {
	return s.kind
}

// RawUUID returns the raw 16-byte UUID inside this service ID, discarding the
// kind.
func (s ServiceID) RawUUID() [UUIDLen]byte {
	return s.uuid
}

// ACI returns the service ID as an ACI, or an [ErrWrongKindOfServiceID] error
// if it is not an ACI.
func (s ServiceID) ACI() (ServiceID, error) {
	if s.kind != ServiceIDKindACI {
		return ServiceID{}, ErrWrongKindOfServiceID{Expected: ServiceIDKindACI, Actual: s.kind}
	}
	return s, nil
}

// PNI returns the service ID as a PNI, or an [ErrWrongKindOfServiceID] error if
// it is not a PNI.
func (s ServiceID) PNI() (ServiceID, error) {
	if s.kind != ServiceIDKindPNI {
		return ServiceID{}, ErrWrongKindOfServiceID{Expected: ServiceIDKindPNI, Actual: s.kind}
	}
	return s, nil
}

// ServiceIDBinary returns the standard variable-width binary representation.
//
// This format is not self-delimiting; the length is needed to decode it. An
// ACI is encoded as its raw 16-byte UUID; any other kind is encoded as the
// 17-byte fixed-width form.
func (s ServiceID) ServiceIDBinary() []byte {
	if s.kind == ServiceIDKindACI {
		out := make([]byte, UUIDLen)
		copy(out, s.uuid[:])
		return out
	}
	fixed := s.ServiceIDFixedWidthBinary()
	return fixed[:]
}

// ServiceIDFixedWidthBinary returns the standard fixed-width binary
// representation: a one-byte kind tag followed by the raw UUID.
func (s ServiceID) ServiceIDFixedWidthBinary() [ServiceIDFixedWidthBinaryLen]byte {
	var out [ServiceIDFixedWidthBinaryLen]byte
	out[0] = uint8(s.kind)
	copy(out[1:], s.uuid[:])
	return out
}

// ServiceIDString returns the standard string representation. An ACI is
// rendered as a bare hyphenated UUID; any other kind is prefixed with its kind
// and a colon (e.g. "PNI:...").
func (s ServiceID) ServiceIDString() string {
	if s.kind == ServiceIDKindACI {
		return formatUUID(s.uuid)
	}
	return fmt.Sprintf("%s:%s", s.kind, formatUUID(s.uuid))
}

// String implements fmt.Stringer using the standard string representation.
func (s ServiceID) String() string {
	return s.ServiceIDString()
}

// LogString returns the redacted-free debug form "<KIND:uuid>", matching the
// upstream Debug formatting used in logs.
func (s ServiceID) LogString() string {
	return fmt.Sprintf("<%s:%s>", s.kind, formatUUID(s.uuid))
}

// ToProtocolAddress constructs a [ProtocolAddress] from this service ID and a
// device ID.
func (s ServiceID) ToProtocolAddress(deviceID DeviceID) ProtocolAddress {
	return NewProtocolAddress(s.ServiceIDString(), deviceID)
}

// ParseServiceIDBinary parses the standard variable-width binary
// representation. A 16-byte input is an ACI; a 17-byte input is the fixed-width
// form, but it is an error for the fixed-width form to carry the ACI tag (ACIs
// are unmarked in the variable-width format).
func ParseServiceIDBinary(b []byte) (ServiceID, error) {
	switch len(b) {
	case UUIDLen:
		var uuid [UUIDLen]byte
		copy(uuid[:], b)
		return NewACI(uuid), nil
	case ServiceIDFixedWidthBinaryLen:
		var fixed [ServiceIDFixedWidthBinaryLen]byte
		copy(fixed[:], b)
		result, err := ParseServiceIDFixedWidthBinary(fixed)
		if err != nil {
			return ServiceID{}, err
		}
		if result.kind == ServiceIDKindACI {
			// The ACI is unmarked in the variable-width binary format, so a
			// tagged ACI in this position is invalid.
			return ServiceID{}, ErrInvalidServiceID
		}
		return result, nil
	default:
		return ServiceID{}, ErrInvalidServiceID
	}
}

// ParseServiceIDFixedWidthBinary parses the standard fixed-width binary
// representation, rejecting unknown kind tags.
func ParseServiceIDFixedWidthBinary(b [ServiceIDFixedWidthBinaryLen]byte) (ServiceID, error) {
	var uuid [UUIDLen]byte
	copy(uuid[:], b[1:])
	switch ServiceIDKind(b[0]) {
	case ServiceIDKindACI:
		return NewACI(uuid), nil
	case ServiceIDKindPNI:
		return NewPNI(uuid), nil
	default:
		return ServiceID{}, ErrInvalidServiceID
	}
}

// ParseServiceIDString parses the standard string representation. UUID parsing
// is case-insensitive and accepts only the hyphenated form. A "PNI:" prefix
// selects a PNI; any other input is parsed as a bare ACI UUID.
func ParseServiceIDString(input string) (ServiceID, error) {
	if rest, ok := strip(input, "PNI:"); ok {
		uuid, err := parseHyphenatedUUID(rest)
		if err != nil {
			return ServiceID{}, err
		}
		return NewPNI(uuid), nil
	}
	uuid, err := parseHyphenatedUUID(input)
	if err != nil {
		return ServiceID{}, err
	}
	return NewACI(uuid), nil
}

// Compare returns -1, 0, or +1 reporting whether s sorts before, equal to, or
// after other. The ordering matches the fixed-width binary ordering used by
// upstream (kind tag first, then UUID bytes).
func (s ServiceID) Compare(other ServiceID) int {
	a := s.ServiceIDFixedWidthBinary()
	b := other.ServiceIDFixedWidthBinary()
	return bytes.Compare(a[:], b[:])
}

// strip returns the remainder of s after prefix and true if s begins with
// prefix; otherwise it returns s and false.
func strip(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return s, false
}
