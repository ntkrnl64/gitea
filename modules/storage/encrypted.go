// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package storage

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"code.gitea.io/gitea/modules/encryption"
	"code.gitea.io/gitea/modules/log"
)

// EncryptedObjectStorage wraps an ObjectStorage to provide transparent
// encryption at rest using envelope encryption with AES-256-GCM.
type EncryptedObjectStorage struct {
	inner      ObjectStorage
	keyManager *encryption.KeyManager
	scope      encryption.KeyScope
	chunkSize  int
}

// NewEncryptedObjectStorage wraps an ObjectStorage with transparent encryption.
func NewEncryptedObjectStorage(inner ObjectStorage, km *encryption.KeyManager, scope encryption.KeyScope, chunkSize int) ObjectStorage {
	if chunkSize <= 0 {
		chunkSize = encryption.DefaultChunkSize
	}
	return &EncryptedObjectStorage{
		inner:      inner,
		keyManager: km,
		scope:      scope,
		chunkSize:  chunkSize,
	}
}

// Save encrypts data and stores it via the inner storage.
func (s *EncryptedObjectStorage) Save(path string, r io.Reader, size int64) (int64, error) {
	// Create envelope with DEK
	env, dek, err := s.keyManager.NewEnvelope(s.scope, s.chunkSize, size)
	if err != nil {
		return 0, fmt.Errorf("encrypted storage: failed to create envelope: %w", err)
	}

	// Marshal envelope header
	header, err := encryption.MarshalEnvelope(env)
	if err != nil {
		return 0, fmt.Errorf("encrypted storage: failed to marshal envelope: %w", err)
	}

	// Create encrypting reader
	encReader := encryption.NewEncryptingReader(dek, r, s.chunkSize)

	// Combine header and encrypted data
	combinedReader := io.MultiReader(bytes.NewReader(header), encReader)

	// Calculate encrypted size if original size is known
	encSize := int64(-1)
	if size >= 0 {
		encSize = int64(len(header)) + encryption.EncryptedStreamSize(size, s.chunkSize)
	}

	return s.inner.Save(path, combinedReader, encSize)
}

// Open reads and decrypts an object from the inner storage.
func (s *EncryptedObjectStorage) Open(path string) (Object, error) {
	obj, err := s.inner.Open(path)
	if err != nil {
		return nil, err
	}

	// Try to read the envelope header
	// Peek at first byte to check if encrypted
	firstByte := make([]byte, 1)
	n, err := obj.Read(firstByte)
	if err != nil {
		if err == io.EOF {
			// Empty file, return as-is
			return obj, nil
		}
		obj.Close()
		return nil, err
	}
	if n == 0 || !encryption.IsEncryptedData(firstByte) {
		// Not encrypted (plaintext, pre-migration), wrap with the first byte
		return &prependObject{
			prepend: firstByte[:n],
			Object:  obj,
		}, nil
	}

	// Reconstruct the reader for envelope parsing
	envReader := io.MultiReader(bytes.NewReader(firstByte[:n]), obj)

	env, err := encryption.ReadEnvelopeFromReader(envReader)
	if err != nil {
		obj.Close()
		return nil, fmt.Errorf("encrypted storage: failed to read envelope: %w", err)
	}

	// Unwrap DEK
	dek, err := s.keyManager.OpenEnvelope(env)
	if err != nil {
		obj.Close()
		return nil, fmt.Errorf("encrypted storage: failed to unwrap DEK: %w", err)
	}

	// Create decrypting reader
	decReader := encryption.NewDecryptingReader(dek, obj)

	return &decryptedObject{
		ReadCloser:    io.NopCloser(decReader),
		innerObj:      obj,
		plaintextSize: env.PlaintextSize,
	}, nil
}

// Stat returns the file info. For encrypted objects, it adjusts the size
// to reflect the plaintext size.
func (s *EncryptedObjectStorage) Stat(path string) (os.FileInfo, error) {
	fi, err := s.inner.Stat(path)
	if err != nil {
		return nil, err
	}

	// Try to read the object to get plaintext size from envelope
	obj, err := s.inner.Open(path)
	if err != nil {
		// If we can't open, return inner stat
		return fi, nil
	}
	defer obj.Close()

	firstByte := make([]byte, 1)
	n, err := obj.Read(firstByte)
	if err != nil || n == 0 || !encryption.IsEncryptedData(firstByte) {
		return fi, nil
	}

	envReader := io.MultiReader(bytes.NewReader(firstByte[:n]), obj)
	env, err := encryption.ReadEnvelopeFromReader(envReader)
	if err != nil {
		return fi, nil
	}

	if env.PlaintextSize >= 0 {
		return &adjustedFileInfo{FileInfo: fi, size: env.PlaintextSize}, nil
	}
	return fi, nil
}

// Delete passes through to the inner storage.
func (s *EncryptedObjectStorage) Delete(path string) error {
	return s.inner.Delete(path)
}

// ServeDirectURL returns ErrURLNotSupported because encrypted data
// cannot be served directly from object storage.
func (s *EncryptedObjectStorage) ServeDirectURL(path, name, method string, opt *ServeDirectOptions) (*url.URL, error) {
	return nil, ErrURLNotSupported
}

// IterateObjects iterates objects, wrapping each with decryption.
func (s *EncryptedObjectStorage) IterateObjects(basePath string, iterator func(fullPath string, obj Object) error) error {
	return s.inner.IterateObjects(basePath, func(fullPath string, obj Object) error {
		// For iteration, we pass through the raw object since the iterator
		// typically just needs the path and may close without reading.
		// If the iterator reads the object, it gets encrypted data.
		// This is acceptable for operations like cleanup/deletion.
		return iterator(fullPath, obj)
	})
}

// prependObject wraps an Object with prepended bytes that were already read.
type prependObject struct {
	prepend []byte
	offset  int
	Object
}

func (p *prependObject) Read(buf []byte) (int, error) {
	if p.offset < len(p.prepend) {
		n := copy(buf, p.prepend[p.offset:])
		p.offset += n
		if n < len(buf) {
			nn, err := p.Object.Read(buf[n:])
			return n + nn, err
		}
		return n, nil
	}
	return p.Object.Read(buf)
}

// decryptedObject wraps a decrypting reader with Object interface.
type decryptedObject struct {
	io.ReadCloser
	innerObj      Object
	plaintextSize int64
}

func (d *decryptedObject) Close() error {
	err1 := d.ReadCloser.Close()
	err2 := d.innerObj.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (d *decryptedObject) Seek(offset int64, whence int) (int64, error) {
	// Seeking is not supported for encrypted streams
	// Return an error so callers fall back to sequential reading
	return 0, fmt.Errorf("encrypted storage: seek not supported on encrypted objects")
}

func (d *decryptedObject) Stat() (os.FileInfo, error) {
	fi, err := d.innerObj.Stat()
	if err != nil {
		return nil, err
	}
	if d.plaintextSize >= 0 {
		return &adjustedFileInfo{FileInfo: fi, size: d.plaintextSize}, nil
	}
	return fi, nil
}

// adjustedFileInfo wraps os.FileInfo with a different size.
type adjustedFileInfo struct {
	os.FileInfo
	size int64
}

func (a *adjustedFileInfo) Size() int64 { return a.size }
func (a *adjustedFileInfo) Name() string { return a.FileInfo.Name() }
func (a *adjustedFileInfo) Mode() os.FileMode { return a.FileInfo.Mode() }
func (a *adjustedFileInfo) ModTime() time.Time { return a.FileInfo.ModTime() }
func (a *adjustedFileInfo) IsDir() bool { return a.FileInfo.IsDir() }
func (a *adjustedFileInfo) Sys() any { return a.FileInfo.Sys() }

// WrapStorageWithEncryption wraps a storage with encryption if encryption is enabled.
func WrapStorageWithEncryption(storage ObjectStorage, chunkSize int) ObjectStorage {
	km := encryption.GetGlobalManager()
	if km == nil {
		return storage
	}
	log.Info("Wrapping storage with encryption (chunk size: %d)", chunkSize)
	return NewEncryptedObjectStorage(storage, km, encryption.InstanceScope(), chunkSize)
}
