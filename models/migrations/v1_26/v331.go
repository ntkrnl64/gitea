// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v1_26

import (
	"xorm.io/xorm"
)

func AddEncryptionTables(x *xorm.Engine) error {
	type EncryptionConfig struct {
		ID                    int64  `xorm:"pk autoincr"`
		OwnerID               int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
		RepoID                int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
		Enabled               bool   `xorm:"NOT NULL DEFAULT false"`
		Algorithm             string `xorm:"VARCHAR(64) NOT NULL DEFAULT 'aes-256-gcm'"`
		EncryptStorage        bool   `xorm:"NOT NULL DEFAULT true"`
		EncryptDatabaseFields bool   `xorm:"NOT NULL DEFAULT true"`
		CreatedUnix           int64  `xorm:"created"`
		UpdatedUnix           int64  `xorm:"updated"`
	}

	type EncryptionKeyMeta struct {
		ID          int64  `xorm:"pk autoincr"`
		KeyID       string `xorm:"VARCHAR(64) UNIQUE NOT NULL"`
		Scope       string `xorm:"VARCHAR(32) NOT NULL"`
		ScopeID     int64  `xorm:"NOT NULL DEFAULT 0"`
		Algorithm   string `xorm:"VARCHAR(64) NOT NULL"`
		Version     int    `xorm:"NOT NULL DEFAULT 1"`
		Active      bool   `xorm:"NOT NULL DEFAULT true"`
		CreatedUnix int64  `xorm:"created"`
	}

	type EncryptionMigrationProgress struct {
		ID          int64  `xorm:"pk autoincr"`
		TableName   string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
		StorageName string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
		LastID      int64  `xorm:"NOT NULL DEFAULT 0"`
		TotalRows   int64  `xorm:"NOT NULL DEFAULT 0"`
		Completed   bool   `xorm:"NOT NULL DEFAULT false"`
		UpdatedUnix int64  `xorm:"updated"`
	}

	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true},
		new(EncryptionConfig), new(EncryptionKeyMeta), new(EncryptionMigrationProgress))
	return err
}
