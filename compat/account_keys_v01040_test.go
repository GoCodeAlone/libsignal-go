package compat

import (
	"bytes"
	"testing"

	"github.com/GoCodeAlone/libsignal-go/accountkeys"
)

func accountKey32(t *testing.T, encoded string) [32]byte {
	t.Helper()
	raw := mustHex(t, encoded)
	if len(raw) != 32 {
		t.Fatalf("account-key fixture: expected 32 bytes, got %d", len(raw))
	}
	return [32]byte(raw)
}

func TestAccountKeysV01040Vectors(t *testing.T) {
	var batch struct {
		Note struct {
			UpstreamTag       string `json:"upstream_tag"`
			UpstreamCommit    string `json:"upstream_commit"`
			UpstreamTagObject string `json:"upstream_tag_object"`
		} `json:"_note"`
		SVRCases []struct {
			Label                        string `json:"label"`
			SVRKey                       string `json:"svr_key"`
			RegistrationLock             string `json:"registration_lock"`
			RegistrationRecoveryPassword string `json:"registration_recovery_password"`
			StorageServiceKey            string `json:"storage_service_key"`
			LoggingKey                   string `json:"logging_key"`
		} `json:"svr_cases"`
		PinCases []struct {
			PIN              string `json:"pin"`
			Salt             string `json:"salt"`
			EncryptionKey    string `json:"encryption_key"`
			MasterKey        string `json:"master_key"`
			EncodedMasterKey string `json:"encrypted_master_key"`
			DecodedMasterKey string `json:"decoded_master_key"`
			Tampered         []struct {
				EncodedMasterKey string `json:"encrypted_master_key"`
				Accepted         bool   `json:"accepted"`
			} `json:"tampered"`
		} `json:"pin_cases"`
		Cases []struct {
			EntropyPool   string `json:"entropy_pool"`
			MediaName     string `json:"media_name"`
			MediaID       string `json:"media_id"`
			MediaKey      string `json:"media_encryption_key_data"`
			MediaAESKey   string `json:"media_aes_key"`
			MediaHMACKey  string `json:"media_hmac_key"`
			ThumbnailKey  string `json:"thumbnail_transit_encryption_key_data"`
			ThumbnailAES  string `json:"thumbnail_aes_key"`
			ThumbnailHMAC string `json:"thumbnail_hmac_key"`
		} `json:"cases"`
		MFACases []struct {
			Label                    string `json:"label"`
			SVRKey                   string `json:"svr_key"`
			Name                     string `json:"name"`
			CreatedAtMillis          uint64 `json:"created_at_millis"`
			IV                       string `json:"iv"`
			EncryptedMetadata        string `json:"encrypted_metadata"`
			DecryptedName            string `json:"decrypted_name"`
			DecryptedCreatedAtMillis uint64 `json:"decrypted_created_at_millis"`
		} `json:"mfa_cases"`
		MFAInvalidCases []struct {
			Label             string `json:"label"`
			SVRKey            string `json:"svr_key"`
			EncryptedMetadata string `json:"encrypted_metadata"`
			Accepted          bool   `json:"accepted"`
		} `json:"mfa_invalid_cases"`
		MFAInvalidNames []struct {
			Name            string `json:"name"`
			CreatedAtMillis uint64 `json:"created_at_millis"`
		} `json:"mfa_invalid_name_cases"`
	}
	loadVectors(t, "account-keys", &batch)
	if batch.Note.UpstreamTag != "v0.104.0" || batch.Note.UpstreamCommit != "257105c55a7389ca6b1e85185e2769465e6729f1" || batch.Note.UpstreamTagObject != "03b9987415e6dcb3d83dfde6a16b52d2b59a7b44" {
		t.Fatal("account-key oracle fixture lacks the approved immutable upstream pin")
	}
	if len(batch.SVRCases) < 4 || len(batch.PinCases) < 2 || len(batch.Cases) == 0 || len(batch.MFACases) < 5 || len(batch.MFAInvalidCases) < 6 || len(batch.MFAInvalidNames) < 3 {
		t.Fatal("account-key oracle fixture is missing required coverage")
	}
	for _, tc := range batch.SVRCases {
		t.Run("svr/"+tc.Label, func(t *testing.T) {
			key := accountkeys.NewSVRKey(accountKey32(t, tc.SVRKey))
			for _, check := range []struct {
				got  [32]byte
				want string
			}{
				{key.DeriveRegistrationLock(), tc.RegistrationLock},
				{key.DeriveRegistrationRecoveryPassword(), tc.RegistrationRecoveryPassword},
				{key.DeriveStorageServiceKey(), tc.StorageServiceKey},
				{key.DeriveLoggingKey(), tc.LoggingKey},
			} {
				if check.got != accountKey32(t, check.want) {
					t.Fatal("SVR derivation differs from upstream")
				}
			}
		})
	}
	for _, tc := range batch.PinCases {
		hash := accountkeys.CreatePinHash([]byte(tc.PIN), accountKey32(t, tc.Salt))
		if hash.EncryptionKey != accountKey32(t, tc.EncryptionKey) {
			t.Fatal("PIN encryption key differs from upstream")
		}
		encoded := hash.EncodeMasterKey(accountKey32(t, tc.MasterKey))
		if !bytes.Equal(encoded[:], mustHex(t, tc.EncodedMasterKey)) {
			t.Fatal("PIN master-key encryption differs from upstream")
		}
		decoded, err := hash.DecodeMasterKey(encoded)
		if err != nil || decoded != accountKey32(t, tc.DecodedMasterKey) {
			t.Fatal("PIN master-key decryption differs from upstream")
		}
		if len(tc.Tampered) < 3 {
			t.Fatal("PIN fixture lacks tampered IV and ciphertext cases")
		}
		for _, invalid := range tc.Tampered {
			got, err := hash.DecodeMasterKey([48]byte(mustHex(t, invalid.EncodedMasterKey)))
			if invalid.Accepted || err == nil || got != ([32]byte{}) {
				t.Fatal("PIN tamper rejection differs from upstream")
			}
		}
	}
	for _, tc := range batch.Cases {
		pool, err := accountkeys.ParseAccountEntropyPool(tc.EntropyPool)
		if err != nil {
			t.Fatal(err)
		}
		backup := accountkeys.DeriveBackupKey(pool)
		id := backup.DeriveMediaID(tc.MediaName)
		if !bytes.Equal(id[:], mustHex(t, tc.MediaID)) {
			t.Fatal("media ID differs from upstream")
		}
		for _, check := range []struct {
			got       [accountkeys.MediaEncryptionKeyLen]byte
			full, aes string
			hmac      string
		}{
			{backup.DeriveMediaEncryptionKeyData(id), tc.MediaKey, tc.MediaAESKey, tc.MediaHMACKey},
			{backup.DeriveThumbnailTransitEncryptionKeyData(id), tc.ThumbnailKey, tc.ThumbnailAES, tc.ThumbnailHMAC},
		} {
			if !bytes.Equal(check.got[:], mustHex(t, check.full)) || !bytes.Equal(check.got[:accountkeys.MediaEncryptionAESKeyLen], mustHex(t, check.aes)) || !bytes.Equal(check.got[accountkeys.MediaEncryptionKeyLen-accountkeys.MediaEncryptionHMACKeyLen:], mustHex(t, check.hmac)) {
				t.Fatal("media key data or AES/HMAC split differs from upstream")
			}
		}
	}
	for _, tc := range batch.MFACases {
		t.Run("mfa/"+tc.Label, func(t *testing.T) {
			key := accountkeys.NewSVRKey(accountKey32(t, tc.SVRKey))
			metadata, err := accountkeys.NewMFAMetadata(tc.Name, tc.CreatedAtMillis)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := metadata.Encrypt(key, bytes.NewReader(mustHex(t, tc.IV)))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encrypted[:], mustHex(t, tc.EncryptedMetadata)) {
				t.Fatal("Go MFA ciphertext differs from real upstream Rust output")
			}
			parsed, err := accountkeys.ParseEncryptedMFAMetadata(mustHex(t, tc.EncryptedMetadata))
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := parsed.Decrypt(key)
			if err != nil || decrypted.Name() != tc.DecryptedName || decrypted.CreatedAtEpochMillis() != tc.DecryptedCreatedAtMillis {
				t.Fatal("Go decryption of upstream MFA ciphertext differs from upstream")
			}
		})
	}
	for _, tc := range batch.MFAInvalidCases {
		encrypted, err := accountkeys.ParseEncryptedMFAMetadata(mustHex(t, tc.EncryptedMetadata))
		var decrypted accountkeys.MFAMetadata
		if err == nil {
			decrypted, err = encrypted.Decrypt(accountkeys.NewSVRKey(accountKey32(t, tc.SVRKey)))
		}
		if tc.Accepted || err == nil || decrypted != (accountkeys.MFAMetadata{}) {
			t.Fatalf("upstream rejected MFA case %q but Go returned plaintext or no error", tc.Label)
		}
	}
	for _, tc := range batch.MFAInvalidNames {
		if got, err := accountkeys.NewMFAMetadata(tc.Name, tc.CreatedAtMillis); err == nil || got != (accountkeys.MFAMetadata{}) {
			t.Fatal("Go accepted an MFA name rejected by upstream")
		}
	}
}
