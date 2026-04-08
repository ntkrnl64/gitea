// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"context"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/timeutil"
)

func init() {
	db.RegisterModel(new(RepoEncryptionKey))
}

// RepoEncryptionKey stores a repository's symmetric encryption key,
// encrypted with hybrid post-quantum key exchange (X25519 + ML-KEM-768).
// Each collaborator gets their own copy wrapped with their public keys.
// The server NEVER has the plaintext repo key.
type RepoEncryptionKey struct {
	ID               int64              `xorm:"pk autoincr"`
	RepoID           int64              `xorm:"INDEX NOT NULL"`
	UserID           int64              `xorm:"INDEX NOT NULL"`
	EncryptedRepoKey string             `xorm:"TEXT NOT NULL"` // base64(sender_x25519_pub[32] + mlkem_ct[1088] + aes_gcm(repo_key))
	Algorithm        string             `xorm:"VARCHAR(64) NOT NULL DEFAULT 'x25519+mlkem768+aes-256-gcm'"`
	CreatedUnix      timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix      timeutil.TimeStamp `xorm:"updated"`
}

// GetRepoKeyForUser returns the encrypted repo key for a specific user.
func GetRepoKeyForUser(ctx context.Context, repoID, userID int64) (*RepoEncryptionKey, error) {
	key := &RepoEncryptionKey{}
	has, err := db.GetEngine(ctx).Where("repo_id = ? AND user_id = ?", repoID, userID).Get(key)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, nil
	}
	return key, nil
}

// GetRepoKeyUsers returns all users who have a copy of the repo key.
func GetRepoKeyUsers(ctx context.Context, repoID int64) ([]*RepoEncryptionKey, error) {
	keys := make([]*RepoEncryptionKey, 0)
	return keys, db.GetEngine(ctx).Where("repo_id = ?", repoID).Find(&keys)
}

// UpsertRepoKeyForUser creates or updates the encrypted repo key for a user.
func UpsertRepoKeyForUser(ctx context.Context, key *RepoEncryptionKey) error {
	existing, err := GetRepoKeyForUser(ctx, key.RepoID, key.UserID)
	if err != nil {
		return err
	}
	if existing != nil {
		key.ID = existing.ID
		_, err = db.GetEngine(ctx).ID(key.ID).AllCols().Update(key)
		return err
	}
	_, err = db.GetEngine(ctx).Insert(key)
	return err
}

// DeleteRepoKeysForRepo deletes all key copies for a repository.
func DeleteRepoKeysForRepo(ctx context.Context, repoID int64) error {
	_, err := db.GetEngine(ctx).Where("repo_id = ?", repoID).Delete(&RepoEncryptionKey{})
	return err
}

// DeleteRepoKeyForUser removes a user's access to a repo's encryption key.
func DeleteRepoKeyForUser(ctx context.Context, repoID, userID int64) error {
	_, err := db.GetEngine(ctx).Where("repo_id = ? AND user_id = ?", repoID, userID).Delete(&RepoEncryptionKey{})
	return err
}

// IsRepoE2EEnabled checks if a repository has E2E encryption set up
// (at least one user has a key for it).
func IsRepoE2EEnabled(ctx context.Context, repoID int64) (bool, error) {
	return db.GetEngine(ctx).Where("repo_id = ?", repoID).Exist(&RepoEncryptionKey{})
}
