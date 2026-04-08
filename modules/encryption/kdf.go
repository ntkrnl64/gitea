// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey derives a 32-byte sub-key from a parent key using HKDF-SHA256.
// The info string encodes the scope (e.g., "instance", "org:123", "repo:456").
func DeriveKey(parentKey [32]byte, info string) [32]byte {
	var derived [32]byte
	r := hkdf.New(sha256.New, parentKey[:], nil, []byte(info))
	if _, err := io.ReadFull(r, derived[:]); err != nil {
		// HKDF with SHA-256 should never fail for 32-byte output
		panic(fmt.Sprintf("encryption: HKDF derivation failed: %v", err))
	}
	return derived
}

// DeriveInstanceKey derives the instance-level KEK from the master key.
func DeriveInstanceKey(masterKey [32]byte) [32]byte {
	return DeriveKey(masterKey, "gitea-encryption:instance:v1")
}

// DeriveOrgKey derives an organization-level KEK from the instance key.
func DeriveOrgKey(instanceKey [32]byte, orgID int64) [32]byte {
	return DeriveKey(instanceKey, fmt.Sprintf("gitea-encryption:org:%d:v1", orgID))
}

// DeriveRepoKey derives a repository-level KEK from a parent key.
// The parent key should be the org key if the repo belongs to an org,
// or the instance key for user-owned repos.
func DeriveRepoKey(parentKey [32]byte, repoID int64) [32]byte {
	return DeriveKey(parentKey, fmt.Sprintf("gitea-encryption:repo:%d:v1", repoID))
}

// MasterKeyFromString derives a 32-byte master key from a string secret
// using SHA-256. This is used when the master key is provided as a string
// in the configuration.
func MasterKeyFromString(secret string) [32]byte {
	return sha256.Sum256([]byte(secret))
}
