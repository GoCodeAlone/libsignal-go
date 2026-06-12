package crypto

import (
	"encoding/hex"
	"testing"
)

// HKDF-SHA256 test vectors from RFC 5869 Appendix A.1-A.3 (the SHA-256 cases).
func TestHKDFSHA256RFC5869(t *testing.T) {
	cases := []struct {
		name    string
		ikm     string
		salt    string
		info    string
		length  int
		wantPRK string
		wantOKM string
	}{
		{
			name:    "A.1 basic",
			ikm:     "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:    "000102030405060708090a0b0c",
			info:    "f0f1f2f3f4f5f6f7f8f9",
			length:  42,
			wantPRK: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			wantOKM: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name:    "A.2 longer inputs",
			ikm:     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
			salt:    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info:    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			length:  82,
			wantPRK: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
			wantOKM: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
		{
			name:    "A.3 zero-length salt and info",
			ikm:     "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:    "",
			info:    "",
			length:  42,
			wantPRK: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			wantOKM: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ikm := mustHex(t, tc.ikm)
			salt := mustHex(t, tc.salt)
			info := mustHex(t, tc.info)

			prk := HKDFExtractSHA256(salt, ikm)
			if got := hex.EncodeToString(prk); got != tc.wantPRK {
				t.Fatalf("PRK = %s, want %s", got, tc.wantPRK)
			}

			okm, err := HKDFExpandSHA256(prk, info, tc.length)
			if err != nil {
				t.Fatalf("HKDFExpandSHA256: %v", err)
			}
			if got := hex.EncodeToString(okm); got != tc.wantOKM {
				t.Fatalf("OKM (expand) = %s, want %s", got, tc.wantOKM)
			}

			// One-shot HKDF (Extract+Expand) must match too.
			okm2, err := HKDFSHA256(ikm, salt, info, tc.length)
			if err != nil {
				t.Fatalf("HKDFSHA256: %v", err)
			}
			if got := hex.EncodeToString(okm2); got != tc.wantOKM {
				t.Fatalf("OKM (one-shot) = %s, want %s", got, tc.wantOKM)
			}
		})
	}
}

// HMAC-SHA256 test vectors from RFC 4231 (cases 1, 2, 4).
func TestHMACSHA256RFC4231(t *testing.T) {
	cases := []struct {
		name string
		key  string
		data string
		want string
	}{
		{
			name: "case 1",
			key:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			data: "4869205468657265", // "Hi There"
			want: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		},
		{
			name: "case 2",
			key:  "4a656665",                                                 // "Jefe"
			data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f", // "what do ya want for nothing?"
			want: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		},
		{
			name: "case 4",
			key:  "0102030405060708090a0b0c0d0e0f10111213141516171819",
			data: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
			want: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := HMACSHA256(mustHex(t, tc.key), mustHex(t, tc.data))
			if hex.EncodeToString(got) != tc.want {
				t.Fatalf("HMAC = %x, want %s", got, tc.want)
			}
			if len(got) != 32 {
				t.Fatalf("HMAC length = %d, want 32", len(got))
			}
		})
	}
}

func TestHKDFExpandRejectsTooLong(t *testing.T) {
	prk := HMACSHA256(nil, nil)
	// HKDF-Expand max output is 255*HashLen = 255*32 = 8160 bytes.
	if _, err := HKDFExpandSHA256(prk, nil, 255*32+1); err == nil {
		t.Fatal("expected error for over-long HKDF expand, got nil")
	}
}
