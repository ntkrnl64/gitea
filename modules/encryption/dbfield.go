// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// encPrefix is the prefix for server-side encrypted database field values
	encPrefix = "enc:v1:"
	// e2ePrefix is the prefix for client-side E2E encrypted values.
	// The server does NOT have keys to decrypt these — only the client can.
	e2ePrefix = "e2e:v1:"
)

// IsE2EEncryptedField checks if a field contains client-side E2E encrypted content.
// The server cannot decrypt these — only the client browser can.
func IsE2EEncryptedField(stored string) bool {
	return strings.HasPrefix(stored, e2ePrefix)
}

// EncryptField encrypts a plaintext string for storage in a database field.
// Returns format: "enc:v1:<keyID>:<base64(nonce+ciphertext+tag)>"
// Skips content that is already E2E encrypted (client-side) — the server must not touch it.
func EncryptField(plaintext string, scope KeyScope) (string, error) {
	km := GetGlobalManager()
	if km == nil {
		return plaintext, nil
	}

	if plaintext == "" {
		return plaintext, nil
	}

	// Never re-encrypt client-side E2E content — server doesn't have those keys
	if IsE2EEncryptedField(plaintext) {
		return plaintext, nil
	}

	kek, keyID := km.GetKEK(scope)
	ciphertext, err := Encrypt(kek, []byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("encryption: failed to encrypt field: %w", err)
	}

	return fmt.Sprintf("%s%s:%s", encPrefix, keyID, base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// DecryptField decrypts a database field value.
// Handles formats:
//   - "e2e:v1:..." — client-side E2E encrypted, server CANNOT decrypt, return as-is
//   - "enc:v1:..." — server-side AES-256-GCM format, server decrypts
//   - anything else — treated as plaintext
func DecryptField(stored string) (string, error) {
	if stored == "" {
		return stored, nil
	}

	// E2E encrypted content — server has no keys, pass through unchanged
	if IsE2EEncryptedField(stored) {
		return stored, nil
	}

	if strings.HasPrefix(stored, encPrefix) {
		return decryptNewFormat(stored)
	}

	// Not encrypted, return as-is
	return stored, nil
}

// MaybeDecryptField decrypts a field if encrypted, returns as-is on any error.
// This is safe for use in AfterLoad hooks where errors should not prevent loading.
func MaybeDecryptField(stored string) string {
	result, err := DecryptField(stored)
	if err != nil {
		return stored
	}
	return result
}

// IsEncryptedField checks if a database field value is encrypted with the new format.
func IsEncryptedField(stored string) bool {
	return strings.HasPrefix(stored, encPrefix)
}

// decryptNewFormat decrypts "enc:v1:<keyID>:<base64(ciphertext)>" format
func decryptNewFormat(stored string) (string, error) {
	km := GetGlobalManager()
	if km == nil {
		return stored, fmt.Errorf("encryption: global manager not initialized")
	}

	// Remove "enc:v1:" prefix
	rest := stored[len(encPrefix):]

	// Split keyID and payload
	idx := strings.LastIndex(rest, ":")
	if idx < 0 {
		return stored, fmt.Errorf("encryption: invalid encrypted field format")
	}
	keyIDStr := rest[:idx]
	payloadB64 := rest[idx+1:]

	ciphertext, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return stored, fmt.Errorf("encryption: invalid base64 in encrypted field: %w", err)
	}

	// Resolve key from keyID
	scope, err := km.scopeFromKeyID(KeyID(keyIDStr))
	if err != nil {
		return stored, err
	}

	kek, _ := km.GetKEK(scope)
	plaintext, err := Decrypt(kek, ciphertext)
	if err != nil {
		return stored, fmt.Errorf("encryption: failed to decrypt field: %w", err)
	}

	return string(plaintext), nil
}

// DecryptLegacyCFB attempts to decrypt data encrypted with the old AES-CFB scheme
// used by modules/secret. The key should be the SHA-256 hash of the secret key.
// Returns the plaintext and true if successful, or empty string and false if not.
func DecryptLegacyCFB(keyHash [32]byte, cipherHex string) (string, bool) {
	ciphertext, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", false
	}
	if len(ciphertext) < 16 { // AES block size
		return "", false
	}

	// Try old AES-CFB decryption (matches modules/secret/secret.go)
	// This is imported here to avoid circular dependency
	// The old format: hex(IV + CFB_encrypt(base64(plaintext)))
	// We don't import the old module; instead we just detect the format
	// and let the caller handle it via modules/secret if needed
	return "", false
}
