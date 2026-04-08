// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package cron

import (
	"context"

	user_model "code.gitea.io/gitea/models/user"
	encryption_service "code.gitea.io/gitea/services/encryption"
)

func registerEncryptExistingData() {
	RegisterTaskFatal("encrypt_existing_data", &BaseConfig{
		Enabled:    false,
		RunAtStart: false,
		Schedule:   "@every 1h",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return encryption_service.MigrateExistingData(ctx)
	})
}

func init() {
	registerEncryptExistingData()
}
