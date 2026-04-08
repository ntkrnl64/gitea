// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	key := MasterKeyFromString("test-key-for-encryption")
	plaintext := []byte("Hello, World! This is a test of AES-256-GCM encryption.")

	ciphertext, err := Encrypt(key, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)
	assert.Greater(t, len(ciphertext), len(plaintext))

	decrypted, err := Decrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key := MasterKeyFromString("test-key")
	plaintext := []byte("")

	ciphertext, err := Encrypt(key, plaintext)
	require.NoError(t, err)

	decrypted, err := Decrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := MasterKeyFromString("key-one")
	key2 := MasterKeyFromString("key-two")
	plaintext := []byte("secret data")

	ciphertext, err := Encrypt(key1, plaintext)
	require.NoError(t, err)

	_, err = Decrypt(key2, ciphertext)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecryptTooShort(t *testing.T) {
	key := MasterKeyFromString("key")
	_, err := Decrypt(key, []byte("short"))
	assert.ErrorIs(t, err, ErrCiphertextTooShort)
}

func TestKeyDerivationHierarchy(t *testing.T) {
	master := MasterKeyFromString("master-secret")
	inst := DeriveInstanceKey(master)

	// Instance key should be deterministic
	inst2 := DeriveInstanceKey(master)
	assert.Equal(t, inst, inst2)

	// Different master keys produce different instance keys
	master2 := MasterKeyFromString("different-master")
	inst3 := DeriveInstanceKey(master2)
	assert.NotEqual(t, inst, inst3)

	// Org keys
	orgKey1 := DeriveOrgKey(inst, 1)
	orgKey2 := DeriveOrgKey(inst, 2)
	assert.NotEqual(t, orgKey1, orgKey2)
	assert.NotEqual(t, orgKey1, inst)

	// Repo keys
	repoKey1 := DeriveRepoKey(orgKey1, 100)
	repoKey2 := DeriveRepoKey(orgKey1, 200)
	assert.NotEqual(t, repoKey1, repoKey2)

	// Repo key derived from different org key is different
	repoKey3 := DeriveRepoKey(orgKey2, 100)
	assert.NotEqual(t, repoKey1, repoKey3)
}

func TestDEKWrapUnwrap(t *testing.T) {
	kek := MasterKeyFromString("kek-for-testing")
	dek, err := GenerateDEK()
	require.NoError(t, err)

	encKey, err := WrapDEK(kek, "test-key-id", dek)
	require.NoError(t, err)
	assert.Equal(t, KeyID("test-key-id"), encKey.KeyID)

	unwrapped, err := UnwrapDEK(kek, encKey)
	require.NoError(t, err)
	assert.Equal(t, dek, unwrapped)

	// Wrong KEK should fail
	wrongKEK := MasterKeyFromString("wrong-kek")
	_, err = UnwrapDEK(wrongKEK, encKey)
	assert.Error(t, err)
}

func TestKeyEnvelopeMarshalUnmarshal(t *testing.T) {
	kek := MasterKeyFromString("envelope-test")
	dek, err := GenerateDEK()
	require.NoError(t, err)

	encKey, err := WrapDEK(kek, "inst-v1", dek)
	require.NoError(t, err)

	env := &KeyEnvelope{
		Version:       1,
		EncKey:        *encKey,
		ChunkSize:     65536,
		PlaintextSize: 12345,
	}

	data, err := MarshalEnvelope(env)
	require.NoError(t, err)
	assert.True(t, IsEncryptedData(data))

	env2, consumed, err := UnmarshalEnvelope(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), consumed)
	assert.Equal(t, env.Version, env2.Version)
	assert.Equal(t, env.ChunkSize, env2.ChunkSize)
	assert.Equal(t, env.PlaintextSize, env2.PlaintextSize)
	assert.Equal(t, env.EncKey.KeyID, env2.EncKey.KeyID)
}

func TestEnvelopeFromReader(t *testing.T) {
	kek := MasterKeyFromString("reader-test")
	dek, err := GenerateDEK()
	require.NoError(t, err)

	encKey, err := WrapDEK(kek, "inst-v1", dek)
	require.NoError(t, err)

	env := &KeyEnvelope{
		Version:       1,
		EncKey:        *encKey,
		ChunkSize:     65536,
		PlaintextSize: -1,
	}

	data, err := MarshalEnvelope(env)
	require.NoError(t, err)

	// Append some extra data after the envelope
	extra := []byte("extra-data-after-envelope")
	combined := append(data, extra...)

	r := bytes.NewReader(combined)
	env2, err := ReadEnvelopeFromReader(r)
	require.NoError(t, err)
	assert.Equal(t, env.Version, env2.Version)

	// Reader should be positioned after the envelope
	remaining, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, extra, remaining)
}

func TestStreamingEncryptDecrypt(t *testing.T) {
	key := MasterKeyFromString("stream-test-key")

	// Generate random plaintext
	plaintext := make([]byte, 200000) // ~200KB, spans multiple chunks
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	// Encrypt
	encReader := NewEncryptingReader(key, bytes.NewReader(plaintext), DefaultChunkSize)
	encrypted, err := io.ReadAll(encReader)
	require.NoError(t, err)
	assert.Greater(t, len(encrypted), len(plaintext))

	// Decrypt
	decReader := NewDecryptingReader(key, bytes.NewReader(encrypted))
	decrypted, err := io.ReadAll(decReader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestStreamingSmallData(t *testing.T) {
	key := MasterKeyFromString("small-stream")
	plaintext := []byte("small")

	encReader := NewEncryptingReader(key, bytes.NewReader(plaintext), DefaultChunkSize)
	encrypted, err := io.ReadAll(encReader)
	require.NoError(t, err)

	decReader := NewDecryptingReader(key, bytes.NewReader(encrypted))
	decrypted, err := io.ReadAll(decReader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestStreamingEmpty(t *testing.T) {
	key := MasterKeyFromString("empty-stream")
	plaintext := []byte{}

	encReader := NewEncryptingReader(key, bytes.NewReader(plaintext), DefaultChunkSize)
	encrypted, err := io.ReadAll(encReader)
	require.NoError(t, err)

	decReader := NewDecryptingReader(key, bytes.NewReader(encrypted))
	decrypted, err := io.ReadAll(decReader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestStreamingExactChunkSize(t *testing.T) {
	key := MasterKeyFromString("exact-chunk")
	plaintext := make([]byte, DefaultChunkSize) // exactly one chunk
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	encReader := NewEncryptingReader(key, bytes.NewReader(plaintext), DefaultChunkSize)
	encrypted, err := io.ReadAll(encReader)
	require.NoError(t, err)

	decReader := NewDecryptingReader(key, bytes.NewReader(encrypted))
	decrypted, err := io.ReadAll(decReader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestKeyManager(t *testing.T) {
	master := MasterKeyFromString("manager-test")
	km := NewKeyManager(master, AlgorithmAES256GCM)

	// Test envelope creation and opening
	scope := KeyScope{OrgID: 5, RepoID: 42}
	env, dek, err := km.NewEnvelope(scope, DefaultChunkSize, 1000)
	require.NoError(t, err)
	assert.Equal(t, uint8(1), env.Version)
	assert.Equal(t, KeyID("org-5-repo-42-v1"), env.EncKey.KeyID)

	// Open the envelope
	dek2, err := km.OpenEnvelope(env)
	require.NoError(t, err)
	assert.Equal(t, dek, dek2)

	// Test instance scope
	env2, _, err := km.NewEnvelope(InstanceScope(), 0, -1)
	require.NoError(t, err)
	assert.Equal(t, KeyID("inst-v1"), env2.EncKey.KeyID)

	// Test org scope
	env3, _, err := km.NewEnvelope(KeyScope{OrgID: 10}, 0, -1)
	require.NoError(t, err)
	assert.Equal(t, KeyID("org-10-v1"), env3.EncKey.KeyID)
}

func TestDBFieldEncryption(t *testing.T) {
	master := MasterKeyFromString("dbfield-test")
	InitGlobalManager(master, AlgorithmAES256GCM)
	defer ResetGlobalManager()

	scope := KeyScope{RepoID: 1}
	plaintext := "This is issue content that should be encrypted"

	encrypted, err := EncryptField(plaintext, scope)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(encrypted, "enc:v1:"))
	assert.True(t, IsEncryptedField(encrypted))

	decrypted, err := DecryptField(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestDBFieldPlaintext(t *testing.T) {
	// Without global manager, fields pass through
	ResetGlobalManager()

	plaintext := "just plain text"
	result := MaybeDecryptField(plaintext)
	assert.Equal(t, plaintext, result)
}

func TestDBFieldEmpty(t *testing.T) {
	master := MasterKeyFromString("empty-field")
	InitGlobalManager(master, AlgorithmAES256GCM)
	defer ResetGlobalManager()

	encrypted, err := EncryptField("", KeyScope{})
	require.NoError(t, err)
	assert.Equal(t, "", encrypted)

	decrypted, err := DecryptField("")
	require.NoError(t, err)
	assert.Equal(t, "", decrypted)
}

func TestHybridKeyEncapsulation(t *testing.T) {
	// Generate key pair
	kp, err := GenerateHybridKeyPair()
	require.NoError(t, err)
	assert.NotEmpty(t, kp.X25519Private)
	assert.NotEmpty(t, kp.X25519Public)
	assert.NotEmpty(t, kp.MLKEMSeed)
	assert.NotEmpty(t, kp.MLKEMPublic)

	// Encapsulate master key
	masterKey := MasterKeyFromString("hybrid-test-master")
	encap, err := HybridEncapsulate(masterKey, kp.X25519Public, kp.MLKEMPublic)
	require.NoError(t, err)
	assert.NotEmpty(t, encap.X25519Ephemeral)
	assert.NotEmpty(t, encap.MLKEMCiphertext)
	assert.NotEmpty(t, encap.WrappedKey)

	// Decapsulate
	recovered, err := HybridDecapsulate(kp, encap)
	require.NoError(t, err)
	assert.Equal(t, masterKey, recovered)
}

func TestHybridEncapsulationSerialization(t *testing.T) {
	kp, err := GenerateHybridKeyPair()
	require.NoError(t, err)

	masterKey := MasterKeyFromString("serial-test")
	encap, err := HybridEncapsulate(masterKey, kp.X25519Public, kp.MLKEMPublic)
	require.NoError(t, err)

	// Serialize
	data, err := MarshalHybridEncapsulation(encap)
	require.NoError(t, err)

	// Deserialize
	encap2, err := UnmarshalHybridEncapsulation(data)
	require.NoError(t, err)

	// Recover
	recovered, err := HybridDecapsulate(kp, encap2)
	require.NoError(t, err)
	assert.Equal(t, masterKey, recovered)
}

func TestEncryptedStreamSize(t *testing.T) {
	assert.Equal(t, int64(-1), EncryptedStreamSize(-1, DefaultChunkSize))

	// Empty: just the end-of-stream marker
	assert.Equal(t, int64(chunkHeaderSize), EncryptedStreamSize(0, DefaultChunkSize))

	// One byte: one chunk + EOS marker
	expected := int64(1+chunkOverhead) + int64(chunkHeaderSize)
	assert.Equal(t, expected, EncryptedStreamSize(1, DefaultChunkSize))
}

func TestValidAlgorithm(t *testing.T) {
	assert.True(t, ValidAlgorithm("aes-256-gcm"))
	assert.True(t, ValidAlgorithm("aes-256-gcm+mlkem768"))
	assert.False(t, ValidAlgorithm("aes-128-gcm"))
	assert.False(t, ValidAlgorithm(""))
}
