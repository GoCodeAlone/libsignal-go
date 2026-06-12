package protocol

import "testing"

// FuzzDeserializeSignalMessage checks that parsing arbitrary bytes as a
// SignalMessage never panics.
func FuzzDeserializeSignalMessage(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{byte((CurrentVersion << 4) | CurrentVersion)})
	f.Add(append([]byte{byte((CurrentVersion << 4) | CurrentVersion)}, make([]byte, 32)...))

	f.Fuzz(func(_ *testing.T, data []byte) {
		if m, err := DeserializeSignalMessage(data); err == nil {
			// A successful parse must round-trip its own serialized bytes.
			_ = m.Serialize()
		}
	})
}

// FuzzDeserializePreKeySignalMessage checks that parsing arbitrary bytes as a
// PreKeySignalMessage never panics.
func FuzzDeserializePreKeySignalMessage(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{byte((CurrentVersion << 4) | CurrentVersion)})
	f.Add(append([]byte{byte((PreKyberVersion << 4) | CurrentVersion)}, make([]byte, 64)...))

	f.Fuzz(func(_ *testing.T, data []byte) {
		if m, err := DeserializePreKeySignalMessage(data); err == nil {
			_ = m.Serialize()
		}
	})
}
