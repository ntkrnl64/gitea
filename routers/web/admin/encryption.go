// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package admin

import (
	"net/http"

	encryption_model "code.gitea.io/gitea/models/encryption"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/templates"
	"code.gitea.io/gitea/services/context"
	encryption_service "code.gitea.io/gitea/services/encryption"
)

const tplEncryption templates.TplName = "admin/encryption"

// Encryption shows encryption settings and status
func Encryption(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.encryption")
	ctx.Data["PageIsAdminEncryption"] = true

	ctx.Data["EncryptionEnabled"] = setting.Encryption.Enabled
	ctx.Data["EncryptionAlgorithm"] = setting.Encryption.Algorithm
	ctx.Data["EncryptionPostQuantum"] = setting.Encryption.PostQuantum
	ctx.Data["EncryptStorage"] = setting.Encryption.EncryptStorage
	ctx.Data["EncryptDatabaseFields"] = setting.Encryption.EncryptDatabaseFields

	if setting.Encryption.Enabled {
		migrated, _ := encryption_model.IsFullyMigrated(ctx)
		ctx.Data["FullyMigrated"] = migrated

		progress, err := encryption_model.GetAllProgress(ctx)
		if err == nil {
			ctx.Data["MigrationProgress"] = progress
		}
	}

	ctx.HTML(http.StatusOK, tplEncryption)
}

// EncryptionPost handles encryption settings actions
func EncryptionPost(ctx *context.Context) {
	action := ctx.FormString("action")

	switch action {
	case "migrate":
		if !setting.Encryption.Enabled {
			ctx.Flash.Error("Encryption is not enabled")
			ctx.Redirect(setting.AppSubURL + "/admin/encryption")
			return
		}
		go func() {
			if err := encryption_service.MigrateExistingData(ctx); err != nil {
				_ = err // logged within MigrateExistingData
			}
		}()
		ctx.Flash.Success("Encryption migration has been triggered")
	default:
		ctx.Flash.Error("Unknown action")
	}

	ctx.Redirect(setting.AppSubURL + "/admin/encryption")
}
