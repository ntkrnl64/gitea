// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"context"
	"fmt"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/timeutil"
	"code.gitea.io/gitea/modules/util"
)

func init() {
	db.RegisterModel(new(UserEncryptionKey))
}

// UserEncryptionKey stores a user's hybrid post-quantum E2E encryption key pair.
// PublicKey contains bundled X25519 + ML-KEM-768 public keys.
// EncryptedPrivateKey contains both private keys encrypted with the user's
// passphrase-derived key (PBKDF2 + AES-256-GCM).
// The server NEVER has access to the plaintext private keys.
type UserEncryptionKey struct {
	ID                  int64              `xorm:"pk autoincr"`
	UserID              int64              `xorm:"UNIQUE NOT NULL INDEX"`
	PublicKey           string             `xorm:"TEXT NOT NULL"`    // base64(x25519_pub[32] + mlkem768_pub[1184])
	EncryptedPrivateKey string             `xorm:"TEXT NOT NULL"`    // base64(nonce + AES-GCM(x25519_priv + mlkem768_priv))
	KeyDerivationSalt   string             `xorm:"VARCHAR(128) NOT NULL"` // base64 salt for PBKDF2
	KDFIterations       int                `xorm:"NOT NULL DEFAULT 600000"`
	Algorithm           string             `xorm:"VARCHAR(64) NOT NULL DEFAULT 'x25519+mlkem768+aes-256-gcm'"`
	CreatedUnix         timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix         timeutil.TimeStamp `xorm:"updated"`
}

// GetUserEncryptionKey returns the user's E2E key pair, or nil if not set up.
func GetUserEncryptionKey(ctx context.Context, userID int64) (*UserEncryptionKey, error) {
	key := &UserEncryptionKey{}
	has, err := db.GetEngine(ctx).Where("user_id = ?", userID).Get(key)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, nil
	}
	return key, nil
}

// CreateUserEncryptionKey creates a new user E2E key pair.
func CreateUserEncryptionKey(ctx context.Context, key *UserEncryptionKey) error {
	existing, err := GetUserEncryptionKey(ctx, key.UserID)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("user %d already has an encryption key, delete it first", key.UserID)
	}
	_, err = db.GetEngine(ctx).Insert(key)
	return err
}

// DeleteUserEncryptionKey deletes a user's E2E key pair.
// WARNING: This makes all E2E encrypted content unrecoverable for this user.
func DeleteUserEncryptionKey(ctx context.Context, userID int64) error {
	_, err := db.GetEngine(ctx).Where("user_id = ?", userID).Delete(&UserEncryptionKey{})
	return err
}

// GetPublicKeysByUserIDs returns public keys for multiple users (for key distribution).
func GetPublicKeysByUserIDs(ctx context.Context, userIDs []int64) (map[int64]string, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	keys := make([]*UserEncryptionKey, 0, len(userIDs))
	if err := db.GetEngine(ctx).In("user_id", userIDs).Find(&keys); err != nil {
		return nil, err
	}
	result := make(map[int64]string, len(keys))
	for _, k := range keys {
		result[k.UserID] = k.PublicKey
	}
	return result, nil
}

// HasEncryptionKey checks if a user has set up E2E encryption.
func HasEncryptionKey(ctx context.Context, userID int64) (bool, error) {
	return db.GetEngine(ctx).Where("user_id = ?", userID).Exist(&UserEncryptionKey{})
}

// ErrUserNoEncryptionKey is returned when a user has no E2E key pair.
type ErrUserNoEncryptionKey struct {
	UserID int64
}

func (e ErrUserNoEncryptionKey) Error() string {
	return fmt.Sprintf("user %d has no encryption key", e.UserID)
}

func (e ErrUserNoEncryptionKey) Unwrap() error {
	return util.ErrNotExist
}
