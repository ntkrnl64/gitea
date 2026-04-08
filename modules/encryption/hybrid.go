// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HybridKeyPair contains both X25519 and ML-KEM-768 key pairs
// for post-quantum hybrid key encapsulation.
type HybridKeyPair struct {
	X25519Private []byte `json:"x25519_priv"`
	X25519Public  []byte `json:"x25519_pub"`
	MLKEMSeed     []byte `json:"mlkem_seed"` // 64-byte seed to reconstruct DecapsulationKey768
	MLKEMPublic   []byte `json:"mlkem_pub"`  // EncapsulationKey768 bytes
}

// HybridEncapsulation contains the encapsulated shared secret
type HybridEncapsulation struct {
	X25519Ephemeral []byte `json:"x25519_eph"` // ephemeral X25519 public key
	MLKEMCiphertext []byte `json:"mlkem_ct"`   // ML-KEM-768 ciphertext
	WrappedKey      []byte `json:"wrapped"`    // AES-GCM encrypted master key
}

// GenerateHybridKeyPair generates a new X25519 + ML-KEM-768 key pair
// for post-quantum hybrid key backup/escrow.
func GenerateHybridKeyPair() (*HybridKeyPair, error) {
	// Generate X25519 key pair
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to generate X25519 key: %w", err)
	}

	// Generate ML-KEM-768 key pair
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to generate ML-KEM-768 key: %w", err)
	}

	return &HybridKeyPair{
		X25519Private: x25519Key.Bytes(),
		X25519Public:  x25519Key.PublicKey().Bytes(),
		MLKEMSeed:     dk.Bytes(),
		MLKEMPublic:   dk.EncapsulationKey().Bytes(),
	}, nil
}

// HybridEncapsulate performs X25519 + ML-KEM-768 hybrid key encapsulation
// to protect the master key for backup/escrow purposes.
func HybridEncapsulate(masterKey [32]byte, recipientX25519Pub []byte, recipientMLKEMPub []byte) (*HybridEncapsulation, error) {
	// X25519 key agreement
	recipientKey, err := ecdh.X25519().NewPublicKey(recipientX25519Pub)
	if err != nil {
		return nil, fmt.Errorf("encryption: invalid X25519 public key: %w", err)
	}

	ephemeralKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to generate ephemeral key: %w", err)
	}

	x25519SS, err := ephemeralKey.ECDH(recipientKey)
	if err != nil {
		return nil, fmt.Errorf("encryption: X25519 key exchange failed: %w", err)
	}

	// ML-KEM-768 encapsulation
	ek, err := mlkem.NewEncapsulationKey768(recipientMLKEMPub)
	if err != nil {
		return nil, fmt.Errorf("encryption: invalid ML-KEM-768 public key: %w", err)
	}

	mlkemSS, mlkemCT := ek.Encapsulate()

	// Combine shared secrets via HKDF
	combinedSS := append(x25519SS, mlkemSS...)
	wrappingKey, err := deriveHybridKey(combinedSS)
	if err != nil {
		return nil, err
	}

	// Wrap the master key with the combined shared secret
	wrapped, err := Encrypt(wrappingKey, masterKey[:])
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to wrap master key: %w", err)
	}

	return &HybridEncapsulation{
		X25519Ephemeral: ephemeralKey.PublicKey().Bytes(),
		MLKEMCiphertext: mlkemCT,
		WrappedKey:      wrapped,
	}, nil
}

// HybridDecapsulate reverses the encapsulation to recover the master key.
func HybridDecapsulate(kp *HybridKeyPair, encap *HybridEncapsulation) ([32]byte, error) {
	var masterKey [32]byte

	// X25519 key agreement
	privKey, err := ecdh.X25519().NewPrivateKey(kp.X25519Private)
	if err != nil {
		return masterKey, fmt.Errorf("encryption: invalid X25519 private key: %w", err)
	}

	ephPub, err := ecdh.X25519().NewPublicKey(encap.X25519Ephemeral)
	if err != nil {
		return masterKey, fmt.Errorf("encryption: invalid ephemeral public key: %w", err)
	}

	x25519SS, err := privKey.ECDH(ephPub)
	if err != nil {
		return masterKey, fmt.Errorf("encryption: X25519 key exchange failed: %w", err)
	}

	// ML-KEM-768 decapsulation
	dk, err := mlkem.NewDecapsulationKey768(kp.MLKEMSeed)
	if err != nil {
		return masterKey, fmt.Errorf("encryption: invalid ML-KEM-768 seed: %w", err)
	}

	mlkemSS, err := dk.Decapsulate(encap.MLKEMCiphertext)
	if err != nil {
		return masterKey, fmt.Errorf("encryption: ML-KEM-768 decapsulation failed: %w", err)
	}

	// Combine shared secrets via HKDF
	combinedSS := append(x25519SS, mlkemSS...)
	wrappingKey, err := deriveHybridKey(combinedSS)
	if err != nil {
		return masterKey, err
	}

	// Unwrap the master key
	plaintext, err := Decrypt(wrappingKey, encap.WrappedKey)
	if err != nil {
		return masterKey, fmt.Errorf("encryption: failed to unwrap master key: %w", err)
	}

	if len(plaintext) != 32 {
		return masterKey, fmt.Errorf("encryption: unwrapped master key has invalid size %d", len(plaintext))
	}
	copy(masterKey[:], plaintext)
	return masterKey, nil
}

// MarshalHybridEncapsulation serializes the encapsulation to JSON
func MarshalHybridEncapsulation(encap *HybridEncapsulation) ([]byte, error) {
	return json.Marshal(encap)
}

// UnmarshalHybridEncapsulation deserializes the encapsulation from JSON
func UnmarshalHybridEncapsulation(data []byte) (*HybridEncapsulation, error) {
	var encap HybridEncapsulation
	if err := json.Unmarshal(data, &encap); err != nil {
		return nil, fmt.Errorf("encryption: failed to unmarshal hybrid encapsulation: %w", err)
	}
	return &encap, nil
}

func deriveHybridKey(combinedSS []byte) ([32]byte, error) {
	var key [32]byte
	r := hkdf.New(sha256.New, combinedSS, []byte("gitea-hybrid-key-backup"), []byte("v1"))
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return key, fmt.Errorf("encryption: HKDF derivation failed: %w", err)
	}
	return key, nil
}
