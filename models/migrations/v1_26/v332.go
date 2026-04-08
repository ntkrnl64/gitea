// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v1_26

import (
	"xorm.io/xorm"
)

func AddE2EEncryptionKeyTables(x *xorm.Engine) error {
	type UserEncryptionKey struct {
		ID                  int64  `xorm:"pk autoincr"`
		UserID              int64  `xorm:"UNIQUE NOT NULL INDEX"`
		PublicKey           string `xorm:"TEXT NOT NULL"`
		EncryptedPrivateKey string `xorm:"TEXT NOT NULL"`
		KeyDerivationSalt   string `xorm:"VARCHAR(128) NOT NULL"`
		KDFIterations       int    `xorm:"NOT NULL DEFAULT 600000"`
		Algorithm           string `xorm:"VARCHAR(64) NOT NULL DEFAULT 'x25519+aes-256-gcm'"`
		CreatedUnix         int64  `xorm:"created"`
		UpdatedUnix         int64  `xorm:"updated"`
	}

	type RepoEncryptionKey struct {
		ID               int64  `xorm:"pk autoincr"`
		RepoID           int64  `xorm:"INDEX NOT NULL"`
		UserID           int64  `xorm:"INDEX NOT NULL"`
		EncryptedRepoKey string `xorm:"TEXT NOT NULL"`
		Algorithm        string `xorm:"VARCHAR(64) NOT NULL DEFAULT 'x25519+aes-256-gcm'"`
		CreatedUnix      int64  `xorm:"created"`
		UpdatedUnix      int64  `xorm:"updated"`
	}

	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true},
		new(UserEncryptionKey), new(RepoEncryptionKey))
	return err
}
