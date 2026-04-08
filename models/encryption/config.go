// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"context"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/timeutil"
)

func init() {
	db.RegisterModel(new(EncryptionConfig))
}

// EncryptionConfig stores per-scope encryption configuration.
// OwnerID=0 and RepoID=0 means instance-level config.
// OwnerID>0 and RepoID=0 means org/user-level config.
// OwnerID=0 and RepoID>0 means repo-level config.
type EncryptionConfig struct {
	ID                    int64              `xorm:"pk autoincr"`
	OwnerID               int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	RepoID                int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	Enabled               bool               `xorm:"NOT NULL DEFAULT false"`
	Algorithm             string             `xorm:"VARCHAR(64) NOT NULL DEFAULT 'aes-256-gcm'"`
	EncryptStorage        bool               `xorm:"NOT NULL DEFAULT true"`
	EncryptDatabaseFields bool               `xorm:"NOT NULL DEFAULT true"`
	CreatedUnix           timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix           timeutil.TimeStamp `xorm:"updated"`
}

// GetEncryptionConfig retrieves encryption config for the given scope.
// Returns nil if no config is found.
func GetEncryptionConfig(ctx context.Context, ownerID, repoID int64) (*EncryptionConfig, error) {
	cfg := &EncryptionConfig{
		OwnerID: ownerID,
		RepoID:  repoID,
	}
	has, err := db.GetEngine(ctx).Where("owner_id = ? AND repo_id = ?", ownerID, repoID).Get(cfg)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, nil
	}
	return cfg, nil
}

// CreateOrUpdateEncryptionConfig creates or updates encryption config for the given scope.
func CreateOrUpdateEncryptionConfig(ctx context.Context, cfg *EncryptionConfig) error {
	existing, err := GetEncryptionConfig(ctx, cfg.OwnerID, cfg.RepoID)
	if err != nil {
		return err
	}
	if existing != nil {
		cfg.ID = existing.ID
		_, err = db.GetEngine(ctx).ID(cfg.ID).AllCols().Update(cfg)
		return err
	}
	_, err = db.GetEngine(ctx).Insert(cfg)
	return err
}

// GetRepoEncryptionConfig retrieves the effective encryption config for a repo.
// Checks repo-level, then org-level, then returns nil for instance-level defaults.
func GetRepoEncryptionConfig(ctx context.Context, repoID, ownerID int64) (*EncryptionConfig, error) {
	// Check repo-level
	if repoID > 0 {
		cfg, err := GetEncryptionConfig(ctx, 0, repoID)
		if err != nil {
			return nil, err
		}
		if cfg != nil {
			return cfg, nil
		}
	}

	// Check org/user-level
	if ownerID > 0 {
		cfg, err := GetEncryptionConfig(ctx, ownerID, 0)
		if err != nil {
			return nil, err
		}
		if cfg != nil {
			return cfg, nil
		}
	}

	// No overrides, return nil to indicate instance defaults apply
	return nil, nil
}
