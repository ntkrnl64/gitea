// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"fmt"
	"sync"
)

var (
	globalManager *KeyManager
	managerMu     sync.Mutex
)

// KeyManager manages the encryption key hierarchy and provides
// key derivation, DEK generation, and envelope operations.
type KeyManager struct {
	masterKey   [32]byte
	instanceKey [32]byte
	algorithm   Algorithm
	keyCache    sync.Map // map[KeyScope][32]byte
}

// NewKeyManager creates a new KeyManager from the master key.
func NewKeyManager(masterKey [32]byte, algorithm Algorithm) *KeyManager {
	km := &KeyManager{
		masterKey: masterKey,
		algorithm: algorithm,
	}
	km.instanceKey = DeriveInstanceKey(masterKey)
	return km
}

// InitGlobalManager initializes the global key manager singleton.
// Must be called once during application startup when encryption is enabled.
func InitGlobalManager(masterKey [32]byte, algorithm Algorithm) {
	managerMu.Lock()
	defer managerMu.Unlock()
	globalManager = NewKeyManager(masterKey, algorithm)
}

// ResetGlobalManager resets the global manager (for testing only).
func ResetGlobalManager() {
	managerMu.Lock()
	defer managerMu.Unlock()
	globalManager = nil
}

// GetGlobalManager returns the global key manager, or nil if not initialized.
func GetGlobalManager() *KeyManager {
	return globalManager
}

// IsEnabled returns true if the global encryption manager has been initialized.
func IsEnabled() bool {
	return globalManager != nil
}

// GetKEK returns the key-encrypting key and its ID for the given scope.
func (km *KeyManager) GetKEK(scope KeyScope) ([32]byte, KeyID) {
	// Check cache first
	if cached, ok := km.keyCache.Load(scope); ok {
		kek := cached.([32]byte)
		return kek, km.keyIDForScope(scope)
	}

	var kek [32]byte
	if scope.RepoID > 0 {
		// Repo-scoped key
		var parentKey [32]byte
		if scope.OrgID > 0 {
			parentKey = DeriveOrgKey(km.instanceKey, scope.OrgID)
		} else {
			parentKey = km.instanceKey
		}
		kek = DeriveRepoKey(parentKey, scope.RepoID)
	} else if scope.OrgID > 0 {
		// Org-scoped key
		kek = DeriveOrgKey(km.instanceKey, scope.OrgID)
	} else {
		// Instance-scoped key
		kek = km.instanceKey
	}

	km.keyCache.Store(scope, kek)
	return kek, km.keyIDForScope(scope)
}

// NewEnvelope generates a new DEK, wraps it for the given scope, and returns
// the envelope and the plaintext DEK for use in encryption.
func (km *KeyManager) NewEnvelope(scope KeyScope, chunkSize int, plaintextSize int64) (*KeyEnvelope, [32]byte, error) {
	dek, err := GenerateDEK()
	if err != nil {
		return nil, [32]byte{}, err
	}

	kek, keyID := km.GetKEK(scope)
	encKey, err := WrapDEK(kek, keyID, dek)
	if err != nil {
		return nil, [32]byte{}, err
	}

	cs := uint32(0)
	if chunkSize > 0 {
		cs = uint32(chunkSize)
	}

	env := &KeyEnvelope{
		Version:       envelopeVersion,
		EncKey:        *encKey,
		ChunkSize:     cs,
		PlaintextSize: plaintextSize,
	}
	return env, dek, nil
}

// OpenEnvelope unwraps the DEK from an envelope.
func (km *KeyManager) OpenEnvelope(env *KeyEnvelope) ([32]byte, error) {
	// The KeyID encodes the scope, so we can derive the correct KEK
	scope, err := km.scopeFromKeyID(env.EncKey.KeyID)
	if err != nil {
		return [32]byte{}, err
	}

	kek, _ := km.GetKEK(scope)
	return UnwrapDEK(kek, &env.EncKey)
}

func (km *KeyManager) keyIDForScope(scope KeyScope) KeyID {
	if scope.RepoID > 0 {
		if scope.OrgID > 0 {
			return KeyID(fmt.Sprintf("org-%d-repo-%d-v1", scope.OrgID, scope.RepoID))
		}
		return KeyID(fmt.Sprintf("repo-%d-v1", scope.RepoID))
	}
	if scope.OrgID > 0 {
		return KeyID(fmt.Sprintf("org-%d-v1", scope.OrgID))
	}
	return KeyID("inst-v1")
}

func (km *KeyManager) scopeFromKeyID(kid KeyID) (KeyScope, error) {
	var scope KeyScope
	s := string(kid)

	if s == "inst-v1" {
		return scope, nil
	}

	// Try org-repo pattern first
	var orgID, repoID int64
	if n, _ := fmt.Sscanf(s, "org-%d-repo-%d-v1", &orgID, &repoID); n == 2 {
		return KeyScope{OrgID: orgID, RepoID: repoID}, nil
	}
	if n, _ := fmt.Sscanf(s, "repo-%d-v1", &repoID); n == 1 {
		return KeyScope{RepoID: repoID}, nil
	}
	if n, _ := fmt.Sscanf(s, "org-%d-v1", &orgID); n == 1 {
		return KeyScope{OrgID: orgID}, nil
	}

	return scope, fmt.Errorf("encryption: unknown key ID format: %s", kid)
}
