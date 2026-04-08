// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Algorithm represents a supported encryption algorithm
type Algorithm string

const (
	AlgorithmAES256GCM      Algorithm = "aes-256-gcm"
	AlgorithmAES256GCMMLkem Algorithm = "aes-256-gcm+mlkem768"
)

// ValidAlgorithm checks if the given algorithm string is supported
func ValidAlgorithm(alg string) bool {
	switch Algorithm(alg) {
	case AlgorithmAES256GCM, AlgorithmAES256GCMMLkem:
		return true
	}
	return false
}

var (
	ErrInvalidKey        = errors.New("encryption: invalid key size, must be 32 bytes")
	ErrCiphertextTooShort = errors.New("encryption: ciphertext too short")
	ErrDecryptionFailed  = errors.New("encryption: decryption failed")
)

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Returns nonce (12 bytes) + ciphertext + GCM tag (16 bytes).
func Encrypt(key [32]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("encryption: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("encryption: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("encryption: failed to generate nonce: %w", err)
	}

	// Seal appends ciphertext+tag to nonce
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext produced by Encrypt.
// Input format: nonce (12 bytes) + ciphertext + GCM tag (16 bytes).
func Decrypt(key [32]byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("encryption: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("encryption: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize+aead.Overhead() {
		return nil, ErrCiphertextTooShort
	}

	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// newAEAD creates a new AES-256-GCM AEAD from a 32-byte key
func newAEAD(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
