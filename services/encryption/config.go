// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"context"

	encryption_model "code.gitea.io/gitea/models/encryption"
	"code.gitea.io/gitea/modules/encryption"
	"code.gitea.io/gitea/modules/setting"
)

// EffectiveConfig represents the resolved encryption configuration
// after applying the hierarchy: repo → org → instance.
type EffectiveConfig struct {
	Enabled               bool
	Algorithm             string
	EncryptStorage        bool
	EncryptDatabaseFields bool
}

// GetEffectiveConfig returns the effective encryption configuration for the given scope.
// It checks repo-level, then org-level, then falls back to instance-level defaults.
func GetEffectiveConfig(ctx context.Context, repoID, ownerID int64) *EffectiveConfig {
	// Check for per-repo or per-org overrides
	cfg, err := encryption_model.GetRepoEncryptionConfig(ctx, repoID, ownerID)
	if err == nil && cfg != nil {
		return &EffectiveConfig{
			Enabled:               cfg.Enabled,
			Algorithm:             cfg.Algorithm,
			EncryptStorage:        cfg.EncryptStorage,
			EncryptDatabaseFields: cfg.EncryptDatabaseFields,
		}
	}

	// Fall back to instance-level config from app.ini
	return &EffectiveConfig{
		Enabled:               setting.Encryption.Enabled,
		Algorithm:             setting.Encryption.Algorithm,
		EncryptStorage:        setting.Encryption.EncryptStorage,
		EncryptDatabaseFields: setting.Encryption.EncryptDatabaseFields,
	}
}

// GetKeyScope returns the appropriate KeyScope for encryption operations.
func GetKeyScope(repoID, ownerID int64) encryption.KeyScope {
	return encryption.KeyScope{
		OrgID:  ownerID,
		RepoID: repoID,
	}
}

// IsEncryptionEnabled checks if encryption is enabled for the given scope.
func IsEncryptionEnabled(ctx context.Context, repoID, ownerID int64) bool {
	cfg := GetEffectiveConfig(ctx, repoID, ownerID)
	return cfg.Enabled
}

// InitEncryption initializes the global encryption key manager if encryption is enabled.
func InitEncryption() {
	if !setting.Encryption.Enabled {
		return
	}

	masterKey := encryption.MasterKeyFromString(setting.Encryption.MasterKey)
	alg := encryption.Algorithm(setting.Encryption.Algorithm)
	if setting.Encryption.PostQuantum {
		alg = encryption.AlgorithmAES256GCMMLkem
	}
	encryption.InitGlobalManager(masterKey, alg)
}
