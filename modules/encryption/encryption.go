// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

// Package encryption provides end-to-end encryption at rest for Gitea.
// It supports AES-256-GCM for data encryption and optionally ML-KEM-768
// (post-quantum) for key backup/escrow via hybrid key encapsulation.
//
// Key hierarchy:
//
//	Master Key (config) → Instance KEK → Org KEK → Repo KEK
//
// Data is encrypted using envelope encryption: each object gets a random
// DEK (data encryption key) which is wrapped by the appropriate scope's KEK.
package encryption
