// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package admin

import (
	"net/http"

	encryption_model "code.gitea.io/gitea/models/encryption"
	"code.gitea.io/gitea/modules/encryption"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/services/context"
	encryption_service "code.gitea.io/gitea/services/encryption"
)

// EncryptionStatusResponse represents the encryption status response
type EncryptionStatusResponse struct {
	Enabled               bool                     `json:"enabled"`
	Algorithm             string                   `json:"algorithm"`
	PostQuantum           bool                     `json:"post_quantum"`
	EncryptStorage        bool                     `json:"encrypt_storage"`
	EncryptDatabaseFields bool                     `json:"encrypt_database_fields"`
	FullyMigrated         bool                     `json:"fully_migrated"`
	MigrationProgress     []MigrationProgressEntry `json:"migration_progress,omitempty"`
}

// MigrationProgressEntry represents a single table/storage migration progress
type MigrationProgressEntry struct {
	TableName   string `json:"table_name,omitempty"`
	StorageName string `json:"storage_name,omitempty"`
	LastID      int64  `json:"last_id"`
	TotalRows   int64  `json:"total_rows"`
	Completed   bool   `json:"completed"`
}

// GetEncryptionStatus returns the current encryption status
func GetEncryptionStatus(ctx *context.APIContext) {
	resp := EncryptionStatusResponse{
		Enabled:               setting.Encryption.Enabled,
		Algorithm:             setting.Encryption.Algorithm,
		PostQuantum:           setting.Encryption.PostQuantum,
		EncryptStorage:        setting.Encryption.EncryptStorage,
		EncryptDatabaseFields: setting.Encryption.EncryptDatabaseFields,
	}

	if setting.Encryption.Enabled {
		migrated, _ := encryption_model.IsFullyMigrated(ctx)
		resp.FullyMigrated = migrated

		progress, err := encryption_model.GetAllProgress(ctx)
		if err == nil {
			resp.MigrationProgress = make([]MigrationProgressEntry, len(progress))
			for i, p := range progress {
				resp.MigrationProgress[i] = MigrationProgressEntry{
					TableName:   p.TableName,
					StorageName: p.StorageName,
					LastID:      p.LastID,
					TotalRows:   p.TotalRows,
					Completed:   p.Completed,
				}
			}
		}
	}

	ctx.JSON(http.StatusOK, resp)
}

// TriggerEncryptionMigration triggers the encryption migration
func TriggerEncryptionMigration(ctx *context.APIContext) {
	if !setting.Encryption.Enabled {
		ctx.APIError(http.StatusBadRequest, "Encryption is not enabled")
		return
	}

	go func() {
		_ = encryption_service.MigrateExistingData(ctx)
	}()

	ctx.JSON(http.StatusAccepted, map[string]string{
		"status": "migration triggered",
	})
}

// BackupEncryptionKey exports the master key encrypted with hybrid post-quantum encapsulation
func BackupEncryptionKey(ctx *context.APIContext) {
	if !setting.Encryption.Enabled {
		ctx.APIError(http.StatusBadRequest, "Encryption is not enabled")
		return
	}

	kp, err := encryption.GenerateHybridKeyPair()
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}

	masterKey := encryption.MasterKeyFromString(setting.Encryption.MasterKey)
	encap, err := encryption.HybridEncapsulate(masterKey, kp.X25519Public, kp.MLKEMPublic)
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}

	encapData, err := encryption.MarshalHybridEncapsulation(encap)
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}

	ctx.JSON(http.StatusOK, map[string]any{
		"key_pair": map[string]any{
			"x25519_private": kp.X25519Private,
			"x25519_public":  kp.X25519Public,
			"mlkem_seed":     kp.MLKEMSeed,
			"mlkem_public":   kp.MLKEMPublic,
		},
		"encapsulated_master_key": encapData,
		"warning":                 "Store the key pair securely. It is required to recover the master key.",
	})
}
