// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"net/http"

	encryption_model "code.gitea.io/gitea/models/encryption"
	"code.gitea.io/gitea/services/context"
)

// GetRepoEncryptionKey returns the current user's encrypted copy of the repo key.
func GetRepoEncryptionKey(ctx *context.APIContext) {
	key, err := encryption_model.GetRepoKeyForUser(ctx, ctx.Repo.Repository.ID, ctx.Doer.ID)
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}
	if key == nil {
		ctx.JSON(http.StatusOK, map[string]any{
			"e2e_enabled": false,
		})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"e2e_enabled":        true,
		"encrypted_repo_key": key.EncryptedRepoKey,
		"algorithm":          key.Algorithm,
	})
}

// SetRepoEncryptionKey stores an encrypted repo key for a user.
// The repo key is encrypted CLIENT-SIDE with the target user's public key.
func SetRepoEncryptionKey(ctx *context.APIContext) {
	encryptedKey := ctx.FormString("encrypted_repo_key")
	userID := ctx.FormInt64("user_id")

	if encryptedKey == "" {
		ctx.APIError(http.StatusBadRequest, "encrypted_repo_key is required")
		return
	}
	if userID <= 0 {
		userID = ctx.Doer.ID
	}

	key := &encryption_model.RepoEncryptionKey{
		RepoID:           ctx.Repo.Repository.ID,
		UserID:           userID,
		EncryptedRepoKey: encryptedKey,
		Algorithm:        "x25519+mlkem768+aes-256-gcm",
	}
	if err := encryption_model.UpsertRepoKeyForUser(ctx, key); err != nil {
		ctx.APIErrorInternal(err)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"status": "repo key stored",
	})
}

// ListRepoEncryptionKeys returns all users who have a copy of the repo key.
func ListRepoEncryptionKeys(ctx *context.APIContext) {
	keys, err := encryption_model.GetRepoKeyUsers(ctx, ctx.Repo.Repository.ID)
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}
	result := make([]map[string]any, len(keys))
	for i, k := range keys {
		result[i] = map[string]any{
			"user_id":   k.UserID,
			"algorithm": k.Algorithm,
		}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"keys": result,
	})
}

// DeleteRepoEncryptionKeys removes all E2E keys for a repo (disables E2E).
func DeleteRepoEncryptionKeys(ctx *context.APIContext) {
	if err := encryption_model.DeleteRepoKeysForRepo(ctx, ctx.Repo.Repository.ID); err != nil {
		ctx.APIErrorInternal(err)
		return
	}
	ctx.Status(http.StatusNoContent)
}
