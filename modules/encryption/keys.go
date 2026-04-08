// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// KeyID uniquely identifies an encryption key in the hierarchy
type KeyID string

// KeyScope identifies the encryption scope for key derivation
type KeyScope struct {
	OrgID  int64
	RepoID int64
}

// InstanceScope returns the instance-level (global) scope
func InstanceScope() KeyScope {
	return KeyScope{}
}

// EncryptedKey is a DEK encrypted (wrapped) by a KEK
type EncryptedKey struct {
	KeyID      KeyID  `json:"kid"`
	Algorithm  string `json:"alg"`
	Ciphertext []byte `json:"ct"` // nonce + wrapped DEK + GCM tag
}

// KeyEnvelope is prepended to encrypted storage objects.
// It contains the wrapped DEK and metadata needed for decryption.
type KeyEnvelope struct {
	Version       uint8        `json:"v"`
	EncKey        EncryptedKey `json:"ek"`
	ChunkSize     uint32       `json:"cs"`  // chunk size for streaming, 0 for block mode
	PlaintextSize int64        `json:"pts"` // original plaintext size, -1 if unknown
}

const (
	envelopeVersion   = 1
	envelopeHeaderTag = 0xE7 // magic byte to identify encrypted objects
)

// GenerateDEK generates a random 256-bit data encryption key
func GenerateDEK() ([32]byte, error) {
	var dek [32]byte
	if _, err := io.ReadFull(rand.Reader, dek[:]); err != nil {
		return dek, fmt.Errorf("encryption: failed to generate DEK: %w", err)
	}
	return dek, nil
}

// WrapDEK encrypts a DEK with a KEK using AES-256-GCM
func WrapDEK(kek [32]byte, kekID KeyID, dek [32]byte) (*EncryptedKey, error) {
	ct, err := Encrypt(kek, dek[:])
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to wrap DEK: %w", err)
	}
	return &EncryptedKey{
		KeyID:      kekID,
		Algorithm:  string(AlgorithmAES256GCM),
		Ciphertext: ct,
	}, nil
}

// UnwrapDEK decrypts a wrapped DEK using the KEK
func UnwrapDEK(kek [32]byte, ek *EncryptedKey) ([32]byte, error) {
	var dek [32]byte
	plaintext, err := Decrypt(kek, ek.Ciphertext)
	if err != nil {
		return dek, fmt.Errorf("encryption: failed to unwrap DEK: %w", err)
	}
	if len(plaintext) != 32 {
		return dek, fmt.Errorf("encryption: unwrapped DEK has invalid size %d", len(plaintext))
	}
	copy(dek[:], plaintext)
	return dek, nil
}

// MarshalEnvelope serializes a KeyEnvelope for storage.
// Format: [1-byte magic][4-byte header length (big-endian)][JSON envelope]
func MarshalEnvelope(env *KeyEnvelope) ([]byte, error) {
	jsonData, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to marshal envelope: %w", err)
	}

	header := make([]byte, 5+len(jsonData))
	header[0] = envelopeHeaderTag
	binary.BigEndian.PutUint32(header[1:5], uint32(len(jsonData)))
	copy(header[5:], jsonData)
	return header, nil
}

// UnmarshalEnvelope deserializes a KeyEnvelope from storage.
// Returns the envelope and the number of bytes consumed from data.
func UnmarshalEnvelope(data []byte) (*KeyEnvelope, int, error) {
	if len(data) < 5 {
		return nil, 0, fmt.Errorf("encryption: data too short for envelope header")
	}
	if data[0] != envelopeHeaderTag {
		return nil, 0, fmt.Errorf("encryption: invalid envelope magic byte")
	}

	headerLen := int(binary.BigEndian.Uint32(data[1:5]))
	totalLen := 5 + headerLen
	if len(data) < totalLen {
		return nil, 0, fmt.Errorf("encryption: data too short for envelope body")
	}

	var env KeyEnvelope
	if err := json.Unmarshal(data[5:totalLen], &env); err != nil {
		return nil, 0, fmt.Errorf("encryption: failed to unmarshal envelope: %w", err)
	}
	return &env, totalLen, nil
}

// IsEncryptedData checks if data starts with the encryption envelope magic byte
func IsEncryptedData(data []byte) bool {
	return len(data) > 0 && data[0] == envelopeHeaderTag
}

// ReadEnvelopeFromReader reads a KeyEnvelope from a reader.
// Returns the envelope and any extra bytes read past the envelope.
func ReadEnvelopeFromReader(r io.Reader) (*KeyEnvelope, error) {
	// Read magic byte + header length
	headerPrefix := make([]byte, 5)
	if _, err := io.ReadFull(r, headerPrefix); err != nil {
		return nil, fmt.Errorf("encryption: failed to read envelope header: %w", err)
	}
	if headerPrefix[0] != envelopeHeaderTag {
		return nil, fmt.Errorf("encryption: invalid envelope magic byte")
	}

	headerLen := int(binary.BigEndian.Uint32(headerPrefix[1:5]))
	headerBody := make([]byte, headerLen)
	if _, err := io.ReadFull(r, headerBody); err != nil {
		return nil, fmt.Errorf("encryption: failed to read envelope body: %w", err)
	}

	var env KeyEnvelope
	if err := json.Unmarshal(headerBody, &env); err != nil {
		return nil, fmt.Errorf("encryption: failed to unmarshal envelope: %w", err)
	}
	return &env, nil
}
