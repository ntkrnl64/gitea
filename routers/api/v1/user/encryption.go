// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package user

import (
	"net/http"

	encryption_model "code.gitea.io/gitea/models/encryption"
	"code.gitea.io/gitea/services/context"
)

// GetUserEncryptionKey returns the current user's E2E encryption public key and encrypted private key
func GetUserEncryptionKey(ctx *context.APIContext) {
	key, err := encryption_model.GetUserEncryptionKey(ctx, ctx.Doer.ID)
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}
	if key == nil {
		ctx.JSON(http.StatusOK, map[string]any{
			"has_key": false,
		})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"has_key":               true,
		"public_key":            key.PublicKey,
		"encrypted_private_key": key.EncryptedPrivateKey,
		"kdf_salt":              key.KeyDerivationSalt,
		"kdf_iterations":        key.KDFIterations,
		"algorithm":             key.Algorithm,
	})
}

// CreateUserEncryptionKey stores the user's E2E key pair.
// The private key must be encrypted CLIENT-SIDE before sending.
// The server never sees the plaintext private key.
func CreateUserEncryptionKey(ctx *context.APIContext) {
	publicKey := ctx.FormString("public_key")
	encPrivKey := ctx.FormString("encrypted_private_key")
	salt := ctx.FormString("kdf_salt")
	iterations := ctx.FormInt("kdf_iterations")

	if publicKey == "" || encPrivKey == "" || salt == "" {
		ctx.APIError(http.StatusBadRequest, "public_key, encrypted_private_key, and kdf_salt are required")
		return
	}
	if iterations < 100000 {
		iterations = 600000
	}

	key := &encryption_model.UserEncryptionKey{
		UserID:              ctx.Doer.ID,
		PublicKey:           publicKey,
		EncryptedPrivateKey: encPrivKey,
		KeyDerivationSalt:   salt,
		KDFIterations:       iterations,
		Algorithm:           "x25519+mlkem768+aes-256-gcm",
	}
	if err := encryption_model.CreateUserEncryptionKey(ctx, key); err != nil {
		ctx.APIError(http.StatusConflict, err.Error())
		return
	}
	ctx.JSON(http.StatusCreated, map[string]any{
		"status": "key pair stored",
	})
}

// DeleteUserEncryptionKey removes the user's E2E key pair.
func DeleteUserEncryptionKey(ctx *context.APIContext) {
	if err := encryption_model.DeleteUserEncryptionKey(ctx, ctx.Doer.ID); err != nil {
		ctx.APIErrorInternal(err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

// GetUserPublicKey returns another user's public key (for key sharing).
func GetUserPublicKey(ctx *context.APIContext) {
	key, err := encryption_model.GetUserEncryptionKey(ctx, ctx.ContextUser.ID)
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}
	if key == nil {
		ctx.APIError(http.StatusNotFound, "user has no encryption key")
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"user_id":    ctx.ContextUser.ID,
		"public_key": key.PublicKey,
		"algorithm":  key.Algorithm,
	})
}
