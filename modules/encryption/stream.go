// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// DefaultChunkSize is the default size for streaming encryption chunks (64 KiB)
	DefaultChunkSize = 64 * 1024
	// chunkNonceSize is the GCM nonce size (12 bytes)
	chunkNonceSize = 12
	// chunkTagSize is the GCM authentication tag size (16 bytes)
	chunkTagSize = 16
	// chunkHeaderSize is 4 bytes for the encrypted chunk length
	chunkHeaderSize = 4
)

// chunkOverhead is the per-chunk overhead: 4 (length) + 12 (nonce) + 16 (tag)
const chunkOverhead = chunkHeaderSize + chunkNonceSize + chunkTagSize

// EncryptingReader wraps a source reader and produces encrypted chunked output.
// Each chunk: [4-byte encrypted chunk len (big-endian)][12-byte nonce][ciphertext][16-byte tag]
type EncryptingReader struct {
	src       io.Reader
	key       [32]byte
	chunkSize int
	buf       []byte // plaintext read buffer
	out       *bytes.Buffer
	counter   uint64
	done      bool
	err       error
}

// NewEncryptingReader creates a reader that encrypts data from src in chunks.
func NewEncryptingReader(key [32]byte, src io.Reader, chunkSize int) *EncryptingReader {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	return &EncryptingReader{
		src:       src,
		key:       key,
		chunkSize: chunkSize,
		buf:       make([]byte, chunkSize),
		out:       bytes.NewBuffer(nil),
	}
}

func (r *EncryptingReader) Read(p []byte) (int, error) {
	// If we have buffered encrypted output, serve from it
	if r.out.Len() > 0 {
		return r.out.Read(p)
	}
	if r.done {
		return 0, r.err
	}

	// Read next chunk of plaintext
	n, err := io.ReadFull(r.src, r.buf)
	if n > 0 {
		if encErr := r.encryptChunk(r.buf[:n]); encErr != nil {
			r.done = true
			r.err = encErr
			return 0, encErr
		}
	}
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			r.done = true
			r.err = io.EOF
			// Write end-of-stream marker (zero-length chunk)
			r.out.Write([]byte{0, 0, 0, 0})
		} else {
			r.done = true
			r.err = err
			return 0, err
		}
	}

	r.counter++
	return r.out.Read(p)
}

func (r *EncryptingReader) encryptChunk(plaintext []byte) error {
	aead, err := newAEAD(r.key)
	if err != nil {
		return err
	}

	// Derive chunk nonce from counter
	nonce := make([]byte, chunkNonceSize)
	binary.BigEndian.PutUint64(nonce[4:], r.counter)

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Write chunk: [4-byte len][12-byte nonce][ciphertext+tag]
	encLen := len(nonce) + len(ciphertext)
	lenBuf := make([]byte, chunkHeaderSize)
	binary.BigEndian.PutUint32(lenBuf, uint32(encLen))
	r.out.Write(lenBuf)
	r.out.Write(nonce)
	r.out.Write(ciphertext)

	return nil
}

// DecryptingReader wraps a source reader and produces decrypted output from chunked encrypted data.
type DecryptingReader struct {
	src     io.Reader
	key     [32]byte
	out     *bytes.Buffer
	counter uint64
	done    bool
}

// NewDecryptingReader creates a reader that decrypts chunked encrypted data from src.
func NewDecryptingReader(key [32]byte, src io.Reader) *DecryptingReader {
	return &DecryptingReader{
		src: src,
		key: key,
		out: bytes.NewBuffer(nil),
	}
}

func (r *DecryptingReader) Read(p []byte) (int, error) {
	// Serve from buffered decrypted output
	if r.out.Len() > 0 {
		return r.out.Read(p)
	}
	if r.done {
		return 0, io.EOF
	}

	// Read chunk header (4-byte length)
	lenBuf := make([]byte, chunkHeaderSize)
	if _, err := io.ReadFull(r.src, lenBuf); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			r.done = true
			return 0, io.EOF
		}
		return 0, fmt.Errorf("encryption: failed to read chunk header: %w", err)
	}

	chunkLen := int(binary.BigEndian.Uint32(lenBuf))
	if chunkLen == 0 {
		// End-of-stream marker
		r.done = true
		return 0, io.EOF
	}

	if chunkLen < chunkNonceSize+chunkTagSize {
		return 0, fmt.Errorf("encryption: chunk too small: %d", chunkLen)
	}

	// Read the encrypted chunk
	chunkData := make([]byte, chunkLen)
	if _, err := io.ReadFull(r.src, chunkData); err != nil {
		return 0, fmt.Errorf("encryption: failed to read chunk data: %w", err)
	}

	// Decrypt
	aead, err := newAEAD(r.key)
	if err != nil {
		return 0, err
	}

	nonce := chunkData[:chunkNonceSize]
	ciphertext := chunkData[chunkNonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("encryption: chunk decryption failed: %w", err)
	}

	r.out.Write(plaintext)
	r.counter++

	return r.out.Read(p)
}

// EncryptedStreamSize calculates the total encrypted size for a given plaintext size and chunk size.
// Returns -1 if plaintextSize is unknown (-1).
func EncryptedStreamSize(plaintextSize int64, chunkSize int) int64 {
	if plaintextSize < 0 {
		return -1
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	numChunks := plaintextSize / int64(chunkSize)
	remainder := plaintextSize % int64(chunkSize)

	total := numChunks * int64(chunkSize+chunkOverhead)
	if remainder > 0 {
		total += remainder + int64(chunkOverhead)
	}
	// End-of-stream marker (4 zero bytes)
	total += chunkHeaderSize
	return total
}
