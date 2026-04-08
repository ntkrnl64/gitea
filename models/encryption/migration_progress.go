// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"context"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/timeutil"
)

func init() {
	db.RegisterModel(new(EncryptionMigrationProgress))
}

// EncryptionMigrationProgress tracks the progress of encrypting existing data.
type EncryptionMigrationProgress struct {
	ID          int64              `xorm:"pk autoincr"`
	TableName   string             `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
	StorageName string             `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
	LastID      int64              `xorm:"NOT NULL DEFAULT 0"`
	TotalRows   int64              `xorm:"NOT NULL DEFAULT 0"`
	Completed   bool               `xorm:"NOT NULL DEFAULT false"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

// GetOrCreateProgress retrieves or creates a migration progress record.
func GetOrCreateProgress(ctx context.Context, tableName, storageName string) (*EncryptionMigrationProgress, error) {
	progress := &EncryptionMigrationProgress{}
	has, err := db.GetEngine(ctx).
		Where("table_name = ? AND storage_name = ?", tableName, storageName).
		Get(progress)
	if err != nil {
		return nil, err
	}
	if has {
		return progress, nil
	}

	progress = &EncryptionMigrationProgress{
		TableName:   tableName,
		StorageName: storageName,
	}
	_, err = db.GetEngine(ctx).Insert(progress)
	if err != nil {
		return nil, err
	}
	return progress, nil
}

// UpdateProgress updates the migration progress.
func UpdateProgress(ctx context.Context, progress *EncryptionMigrationProgress) error {
	_, err := db.GetEngine(ctx).ID(progress.ID).Cols("last_id", "total_rows", "completed").Update(progress)
	return err
}

// GetAllProgress retrieves all migration progress records.
func GetAllProgress(ctx context.Context) ([]*EncryptionMigrationProgress, error) {
	records := make([]*EncryptionMigrationProgress, 0, 20)
	return records, db.GetEngine(ctx).Find(&records)
}

// IsFullyMigrated checks if all known tables/storages have been migrated.
func IsFullyMigrated(ctx context.Context) (bool, error) {
	records, err := GetAllProgress(ctx)
	if err != nil {
		return false, err
	}
	if len(records) == 0 {
		return false, nil
	}
	for _, r := range records {
		if !r.Completed {
			return false, nil
		}
	}
	return true, nil
}
