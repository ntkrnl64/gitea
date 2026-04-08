// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"crypto/rand"
	"encoding/hex"

	"code.gitea.io/gitea/modules/log"
)

// Encryption settings
var Encryption = struct {
	Enabled               bool
	Algorithm             string
	PostQuantum           bool
	MasterKey             string
	EncryptStorage        bool
	EncryptDatabaseFields bool
	ChunkSize             int64
}{
	Algorithm:             "aes-256-gcm",
	EncryptStorage:        true,
	EncryptDatabaseFields: true,
	ChunkSize:             65536,
}

func loadEncryptionFrom(rootCfg ConfigProvider) {
	sec := rootCfg.Section("encryption")

	Encryption.Enabled = sec.Key("ENABLED").MustBool(false)
	if !Encryption.Enabled {
		return
	}

	Encryption.Algorithm = sec.Key("ALGORITHM").MustString("aes-256-gcm")
	Encryption.PostQuantum = sec.Key("POST_QUANTUM").MustBool(false)
	Encryption.EncryptStorage = sec.Key("ENCRYPT_STORAGE").MustBool(true)
	Encryption.EncryptDatabaseFields = sec.Key("ENCRYPT_DATABASE_FIELDS").MustBool(true)
	Encryption.ChunkSize = sec.Key("CHUNK_SIZE").MustInt64(65536)

	Encryption.MasterKey = loadSecret(sec, "MASTER_KEY_URI", "MASTER_KEY")
	if Encryption.MasterKey == "" {
		// Auto-generate a master key if none is provided
		log.Warn("No encryption master key configured, generating one automatically")
		Encryption.MasterKey = generateSaveEncryptionMasterKey(rootCfg)
	}

	log.Info("Encryption enabled with algorithm: %s, post-quantum: %v", Encryption.Algorithm, Encryption.PostQuantum)
}

func generateSaveEncryptionMasterKey(rootCfg ConfigProvider) string {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		log.Fatal("Failed to generate encryption master key: %v", err)
	}
	key := hex.EncodeToString(keyBytes)

	saveCfg, err := rootCfg.PrepareSaving()
	if err != nil {
		log.Fatal("Error saving encryption master key: %v", err)
	}
	rootCfg.Section("encryption").Key("MASTER_KEY").SetValue(key)
	saveCfg.Section("encryption").Key("MASTER_KEY").SetValue(key)
	if err = saveCfg.Save(); err != nil {
		log.Fatal("Error saving encryption master key: %v", err)
	}
	return key
}
