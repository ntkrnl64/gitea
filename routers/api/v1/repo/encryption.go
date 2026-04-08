// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"net/http"

	encryption_model "code.gitea.io/gitea/models/encryption"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/services/context"
)

// EncryptionConfigResponse represents the encryption configuration for a repo
type EncryptionConfigResponse struct {
	Enabled               bool   `json:"enabled"`
	Algorithm             string `json:"algorithm"`
	EncryptStorage        bool   `json:"encrypt_storage"`
	EncryptDatabaseFields bool   `json:"encrypt_database_fields"`
	Inherited             bool   `json:"inherited"`
}

// GetRepoEncryptionConfig returns the encryption config for a repository
func GetRepoEncryptionConfig(ctx *context.APIContext) {
	cfg, err := encryption_model.GetEncryptionConfig(ctx, 0, ctx.Repo.Repository.ID)
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}

	if cfg != nil {
		ctx.JSON(http.StatusOK, EncryptionConfigResponse{
			Enabled:               cfg.Enabled,
			Algorithm:             cfg.Algorithm,
			EncryptStorage:        cfg.EncryptStorage,
			EncryptDatabaseFields: cfg.EncryptDatabaseFields,
			Inherited:             false,
		})
		return
	}

	ctx.JSON(http.StatusOK, EncryptionConfigResponse{
		Enabled:               setting.Encryption.Enabled,
		Algorithm:             setting.Encryption.Algorithm,
		EncryptStorage:        setting.Encryption.EncryptStorage,
		EncryptDatabaseFields: setting.Encryption.EncryptDatabaseFields,
		Inherited:             true,
	})
}

// UpdateRepoEncryptionConfig updates the encryption config for a repository
func UpdateRepoEncryptionConfig(ctx *context.APIContext) {
	cfg := &encryption_model.EncryptionConfig{
		RepoID:                ctx.Repo.Repository.ID,
		Enabled:               ctx.FormBool("enabled"),
		Algorithm:             ctx.FormString("algorithm"),
		EncryptStorage:        ctx.FormBool("encrypt_storage"),
		EncryptDatabaseFields: ctx.FormBool("encrypt_database_fields"),
	}
	if cfg.Algorithm == "" {
		cfg.Algorithm = setting.Encryption.Algorithm
	}

	if err := encryption_model.CreateOrUpdateEncryptionConfig(ctx, cfg); err != nil {
		ctx.APIErrorInternal(err)
		return
	}

	ctx.JSON(http.StatusOK, EncryptionConfigResponse{
		Enabled:               cfg.Enabled,
		Algorithm:             cfg.Algorithm,
		EncryptStorage:        cfg.EncryptStorage,
		EncryptDatabaseFields: cfg.EncryptDatabaseFields,
		Inherited:             false,
	})
}
