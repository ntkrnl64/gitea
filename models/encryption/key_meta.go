// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"context"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/timeutil"
)

func init() {
	db.RegisterModel(new(EncryptionKeyMeta))
}

// EncryptionKeyMeta tracks encryption key metadata for auditing and rotation.
type EncryptionKeyMeta struct {
	ID          int64              `xorm:"pk autoincr"`
	KeyID       string             `xorm:"VARCHAR(64) UNIQUE NOT NULL"`
	Scope       string             `xorm:"VARCHAR(32) NOT NULL"` // "instance", "org", "repo"
	ScopeID     int64              `xorm:"NOT NULL DEFAULT 0"`
	Algorithm   string             `xorm:"VARCHAR(64) NOT NULL"`
	Version     int                `xorm:"NOT NULL DEFAULT 1"`
	Active      bool               `xorm:"NOT NULL DEFAULT true"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
}

// EnsureKeyMeta creates a key metadata record if it doesn't exist.
func EnsureKeyMeta(ctx context.Context, keyID, scope string, scopeID int64, algorithm string) error {
	existing := &EncryptionKeyMeta{}
	has, err := db.GetEngine(ctx).Where("key_id = ?", keyID).Get(existing)
	if err != nil {
		return err
	}
	if has {
		return nil
	}

	meta := &EncryptionKeyMeta{
		KeyID:     keyID,
		Scope:     scope,
		ScopeID:   scopeID,
		Algorithm: algorithm,
		Version:   1,
		Active:    true,
	}
	_, err = db.GetEngine(ctx).Insert(meta)
	return err
}

// GetActiveKeys returns all active encryption keys.
func GetActiveKeys(ctx context.Context) ([]*EncryptionKeyMeta, error) {
	keys := make([]*EncryptionKeyMeta, 0, 10)
	return keys, db.GetEngine(ctx).Where("active = ?", true).Find(&keys)
}
