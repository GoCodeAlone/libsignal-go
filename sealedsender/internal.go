// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package sealedsender

import (
	"encoding/hex"
	"fmt"
)

// cloneBytes returns a defensive copy of b (nil-preserving), so getters and
// constructors never alias caller-owned or proto-owned backing arrays.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// uuidStringFromBytes renders a 16-byte UUID in the canonical lowercase
// 8-4-4-4-12 hyphenated form, matching how upstream maps a sender certificate's
// uuidBytes field to a string (uuid::Uuid::from_slice(..).to_string()). It does
// not interpret version/variant bits — any 16 bytes are formatted verbatim.
func uuidStringFromBytes(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("uuid must be 16 bytes, got %d", len(b))
	}
	h := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]), nil
}
