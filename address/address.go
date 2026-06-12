package address

import (
	"errors"
	"fmt"
)

// MaxValidDeviceID is the largest value a [DeviceID] may hold. Device IDs are
// constrained to the range 1..=127.
const MaxValidDeviceID = 127

// ErrInvalidDeviceID is returned when constructing a [DeviceID] from a value
// outside the valid range 1..=127.
var ErrInvalidDeviceID = errors.New("device ID is out of range")

// DeviceID identifies a particular Signal client instance for some user. Valid
// device IDs are in the range 1..=127.
type DeviceID struct {
	id uint8
}

// NewDeviceID constructs a [DeviceID] if id is in the valid range 1..=127,
// returning [ErrInvalidDeviceID] otherwise.
func NewDeviceID(id uint32) (DeviceID, error) {
	if id == 0 || id > MaxValidDeviceID {
		return DeviceID{}, ErrInvalidDeviceID
	}
	return DeviceID{id: uint8(id)}, nil
}

// Value returns the device ID as a uint32.
func (d DeviceID) Value() uint32 {
	return uint32(d.id)
}

// String implements fmt.Stringer, rendering the numeric device ID.
func (d DeviceID) String() string {
	return fmt.Sprintf("%d", d.id)
}

// ProtocolAddress represents a unique Signal client instance as a
// (name, device ID) pair, where name is a user's globally-unique public
// identity (usually a service-ID string).
type ProtocolAddress struct {
	name     string
	deviceID DeviceID
}

// NewProtocolAddress creates a new address from a user identity name and a
// device ID.
func NewProtocolAddress(name string, deviceID DeviceID) ProtocolAddress {
	return ProtocolAddress{name: name, deviceID: deviceID}
}

// Name returns the user identity name. This is usually a service-ID string.
func (a ProtocolAddress) Name() string {
	return a.name
}

// DeviceID returns the device identifier component of the address.
func (a ProtocolAddress) DeviceID() DeviceID {
	return a.deviceID
}

// String implements fmt.Stringer, rendering the address as "name.deviceID".
func (a ProtocolAddress) String() string {
	return fmt.Sprintf("%s.%s", a.name, a.deviceID)
}

// hyphenatedUUIDLen is the length of the canonical hyphenated UUID string form
// (e.g. "8c78cd2a-16ff-427d-83dc-1a5e36ce713d").
const hyphenatedUUIDLen = 36

// hyphenPositions are the byte offsets at which a hyphenated UUID carries its
// '-' separators (the 8-4-4-4-12 grouping).
var hyphenPositions = [...]int{8, 13, 18, 23}

// parseHyphenatedUUID parses the canonical hyphenated UUID string form,
// case-insensitively. Only the hyphenated form is accepted: any other length,
// missing or misplaced hyphens, or non-hex digits are rejected with
// [ErrInvalidServiceID].
func parseHyphenatedUUID(s string) ([UUIDLen]byte, error) {
	var out [UUIDLen]byte
	if len(s) != hyphenatedUUIDLen {
		return out, ErrInvalidServiceID
	}
	for _, pos := range hyphenPositions {
		if s[pos] != '-' {
			return out, ErrInvalidServiceID
		}
	}
	// Decode the hex digits, skipping the four hyphen positions.
	bi := 0
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		hi, ok := hexVal(s[i])
		if !ok {
			return out, ErrInvalidServiceID
		}
		i++
		lo, ok := hexVal(s[i])
		if !ok {
			return out, ErrInvalidServiceID
		}
		out[bi] = hi<<4 | lo
		bi++
	}
	return out, nil
}

// hexVal decodes a single ASCII hex digit (upper or lower case), reporting
// false if c is not a hex digit.
func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

const lowerHex = "0123456789abcdef"

// formatUUID renders a raw UUID in the canonical lower-case hyphenated form.
func formatUUID(uuid [UUIDLen]byte) string {
	var buf [hyphenatedUUIDLen]byte
	bi := 0
	for i := 0; i < UUIDLen; i++ {
		if bi == 8 || bi == 13 || bi == 18 || bi == 23 {
			buf[bi] = '-'
			bi++
		}
		buf[bi] = lowerHex[uuid[i]>>4]
		buf[bi+1] = lowerHex[uuid[i]&0x0f]
		bi += 2
	}
	return string(buf[:])
}
