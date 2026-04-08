// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package encryption

import (
	"context"

	"code.gitea.io/gitea/models/db"
	encryption_model "code.gitea.io/gitea/models/encryption"
	"code.gitea.io/gitea/modules/encryption"
	"code.gitea.io/gitea/modules/log"
	secret_module "code.gitea.io/gitea/modules/secret"
	"code.gitea.io/gitea/modules/setting"
)

const migrationBatchSize = 100

// MigrateExistingData encrypts existing plaintext data in the database.
// It processes data in batches and tracks progress so it can be resumed.
func MigrateExistingData(ctx context.Context) error {
	if !setting.Encryption.Enabled {
		return nil
	}

	km := encryption.GetGlobalManager()
	if km == nil {
		return nil
	}

	engine := db.GetEngine(ctx)

	tables := []struct {
		name    string
		migrate func(ctx context.Context, engine db.Engine, lastID int64) (int64, error)
	}{
		{"issue", migrateIssues},
		{"comment", migrateComments},
		{"issue_content_history", migrateContentHistory},
		{"secret", migrateSecrets},
		{"webhook", migrateWebhooks},
		{"hook_task", migrateHookTasks},
		{"repository", migrateRepositories},
	}

	for _, t := range tables {
		progress, err := encryption_model.GetOrCreateProgress(ctx, t.name, "")
		if err != nil {
			return err
		}
		if progress.Completed {
			log.Info("Encryption migration: %s already completed", t.name)
			continue
		}

		log.Info("Encryption migration: processing %s from ID %d", t.name, progress.LastID)

		for {
			newLastID, err := t.migrate(ctx, engine, progress.LastID)
			if err != nil {
				log.Error("Encryption migration error for %s: %v", t.name, err)
				return err
			}
			if newLastID == progress.LastID {
				progress.Completed = true
				if err := encryption_model.UpdateProgress(ctx, progress); err != nil {
					return err
				}
				log.Info("Encryption migration: %s completed", t.name)
				break
			}
			progress.LastID = newLastID
			if err := encryption_model.UpdateProgress(ctx, progress); err != nil {
				return err
			}
		}
	}

	return nil
}

func migrateIssues(ctx context.Context, engine db.Engine, lastID int64) (int64, error) {
	type Issue struct {
		ID      int64  `xorm:"pk"`
		RepoID  int64  `xorm:"INDEX"`
		Title   string `xorm:"name"`
		Content string `xorm:"LONGTEXT"`
	}

	var issues []Issue
	err := engine.Table("issue").Where("id > ?", lastID).OrderBy("id ASC").Limit(migrationBatchSize).Find(&issues)
	if err != nil || len(issues) == 0 {
		return lastID, err
	}

	for _, issue := range issues {
		if (encryption.IsEncryptedField(issue.Title) || encryption.IsE2EEncryptedField(issue.Title)) &&
			(encryption.IsEncryptedField(issue.Content) || encryption.IsE2EEncryptedField(issue.Content)) {
			lastID = issue.ID
			continue
		}

		scope := encryption.KeyScope{RepoID: issue.RepoID}
		needsUpdate := false
		title := issue.Title
		content := issue.Content

		if !encryption.IsEncryptedField(issue.Title) && issue.Title != "" {
			if enc, err := encryption.EncryptField(issue.Title, scope); err == nil {
				title = enc
				needsUpdate = true
			}
		}
		if !encryption.IsEncryptedField(issue.Content) && issue.Content != "" {
			if enc, err := encryption.EncryptField(issue.Content, scope); err == nil {
				content = enc
				needsUpdate = true
			}
		}

		if needsUpdate {
			if _, err := engine.Table("issue").Where("id = ?", issue.ID).
				Cols("name", "content").
				Update(&Issue{Title: title, Content: content}); err != nil {
				return lastID, err
			}
		}
		lastID = issue.ID
	}
	return lastID, nil
}

func migrateComments(ctx context.Context, engine db.Engine, lastID int64) (int64, error) {
	type Comment struct {
		ID      int64  `xorm:"pk"`
		Content string `xorm:"LONGTEXT"`
	}

	var comments []Comment
	err := engine.Table("comment").Where("id > ?", lastID).OrderBy("id ASC").Limit(migrationBatchSize).Find(&comments)
	if err != nil || len(comments) == 0 {
		return lastID, err
	}

	scope := encryption.InstanceScope()
	for _, c := range comments {
		if encryption.IsEncryptedField(c.Content) || c.Content == "" {
			lastID = c.ID
			continue
		}
		if enc, err := encryption.EncryptField(c.Content, scope); err == nil {
			if _, err := engine.Table("comment").Where("id = ?", c.ID).
				Cols("content").
				Update(&Comment{Content: enc}); err != nil {
				return lastID, err
			}
		}
		lastID = c.ID
	}
	return lastID, nil
}

func migrateContentHistory(ctx context.Context, engine db.Engine, lastID int64) (int64, error) {
	type ContentHistory struct {
		ID          int64  `xorm:"pk"`
		ContentText string `xorm:"LONGTEXT"`
	}

	var records []ContentHistory
	err := engine.Table("issue_content_history").Where("id > ?", lastID).OrderBy("id ASC").Limit(migrationBatchSize).Find(&records)
	if err != nil || len(records) == 0 {
		return lastID, err
	}

	scope := encryption.InstanceScope()
	for _, r := range records {
		if encryption.IsEncryptedField(r.ContentText) || r.ContentText == "" {
			lastID = r.ID
			continue
		}
		if enc, err := encryption.EncryptField(r.ContentText, scope); err == nil {
			if _, err := engine.Table("issue_content_history").Where("id = ?", r.ID).
				Cols("content_text").
				Update(&ContentHistory{ContentText: enc}); err != nil {
				return lastID, err
			}
		}
		lastID = r.ID
	}
	return lastID, nil
}

func migrateSecrets(ctx context.Context, engine db.Engine, lastID int64) (int64, error) {
	type Secret struct {
		ID      int64  `xorm:"pk"`
		OwnerID int64  `xorm:"INDEX"`
		RepoID  int64  `xorm:"INDEX"`
		Name    string
		Data    string `xorm:"LONGTEXT"`
	}

	var secrets []Secret
	err := engine.Table("secret").Where("id > ?", lastID).OrderBy("id ASC").Limit(migrationBatchSize).Find(&secrets)
	if err != nil || len(secrets) == 0 {
		return lastID, err
	}

	for _, s := range secrets {
		if encryption.IsEncryptedField(s.Data) {
			lastID = s.ID
			continue
		}

		// Decrypt with old scheme first
		plaintext, err := secret_module.DecryptSecret(setting.SecretKey, s.Data)
		if err != nil {
			log.Error("Encryption migration: cannot decrypt secret %d %q with legacy scheme: %v", s.ID, s.Name, err)
			lastID = s.ID
			continue
		}

		// Re-encrypt with new scheme
		scope := encryption.KeyScope{OrgID: s.OwnerID, RepoID: s.RepoID}
		enc, err := encryption.EncryptField(plaintext, scope)
		if err != nil {
			log.Error("Encryption migration: cannot re-encrypt secret %d: %v", s.ID, err)
			lastID = s.ID
			continue
		}

		if _, err := engine.Table("secret").Where("id = ?", s.ID).
			Cols("data").
			Update(&Secret{Data: enc}); err != nil {
			return lastID, err
		}
		lastID = s.ID
	}
	return lastID, nil
}

func migrateWebhooks(ctx context.Context, engine db.Engine, lastID int64) (int64, error) {
	type Webhook struct {
		ID                           int64  `xorm:"pk"`
		RepoID                       int64  `xorm:"INDEX"`
		URL                          string `xorm:"url TEXT"`
		Secret                       string `xorm:"TEXT"`
		HeaderAuthorizationEncrypted string `xorm:"TEXT"`
	}

	var webhooks []Webhook
	err := engine.Table("webhook").Where("id > ?", lastID).OrderBy("id ASC").Limit(migrationBatchSize).Find(&webhooks)
	if err != nil || len(webhooks) == 0 {
		return lastID, err
	}

	for _, w := range webhooks {
		scope := encryption.KeyScope{RepoID: w.RepoID}
		needsUpdate := false
		wURL := w.URL
		wSecret := w.Secret
		wHeader := w.HeaderAuthorizationEncrypted

		if !encryption.IsEncryptedField(w.URL) && w.URL != "" {
			if enc, err := encryption.EncryptField(w.URL, scope); err == nil {
				wURL = enc
				needsUpdate = true
			}
		}
		if !encryption.IsEncryptedField(w.Secret) && w.Secret != "" {
			if enc, err := encryption.EncryptField(w.Secret, scope); err == nil {
				wSecret = enc
				needsUpdate = true
			}
		}
		if !encryption.IsEncryptedField(w.HeaderAuthorizationEncrypted) && w.HeaderAuthorizationEncrypted != "" {
			if enc, err := encryption.EncryptField(w.HeaderAuthorizationEncrypted, scope); err == nil {
				wHeader = enc
				needsUpdate = true
			}
		}

		if needsUpdate {
			if _, err := engine.Table("webhook").Where("id = ?", w.ID).
				Cols("url", "secret", "header_authorization_encrypted").
				Update(&Webhook{URL: wURL, Secret: wSecret, HeaderAuthorizationEncrypted: wHeader}); err != nil {
				return lastID, err
			}
		}
		lastID = w.ID
	}
	return lastID, nil
}

func migrateHookTasks(ctx context.Context, engine db.Engine, lastID int64) (int64, error) {
	type HookTask struct {
		ID              int64  `xorm:"pk"`
		PayloadContent  string `xorm:"LONGTEXT"`
		RequestContent  string `xorm:"LONGTEXT"`
		ResponseContent string `xorm:"LONGTEXT"`
	}

	var tasks []HookTask
	err := engine.Table("hook_task").Where("id > ?", lastID).OrderBy("id ASC").Limit(migrationBatchSize).Find(&tasks)
	if err != nil || len(tasks) == 0 {
		return lastID, err
	}

	scope := encryption.InstanceScope()
	for _, t := range tasks {
		needsUpdate := false
		payload := t.PayloadContent
		request := t.RequestContent
		response := t.ResponseContent

		if !encryption.IsEncryptedField(t.PayloadContent) && t.PayloadContent != "" {
			if enc, err := encryption.EncryptField(t.PayloadContent, scope); err == nil {
				payload = enc
				needsUpdate = true
			}
		}
		if !encryption.IsEncryptedField(t.RequestContent) && t.RequestContent != "" {
			if enc, err := encryption.EncryptField(t.RequestContent, scope); err == nil {
				request = enc
				needsUpdate = true
			}
		}
		if !encryption.IsEncryptedField(t.ResponseContent) && t.ResponseContent != "" {
			if enc, err := encryption.EncryptField(t.ResponseContent, scope); err == nil {
				response = enc
				needsUpdate = true
			}
		}

		if needsUpdate {
			if _, err := engine.Table("hook_task").Where("id = ?", t.ID).
				Cols("payload_content", "request_content", "response_content").
				Update(&HookTask{PayloadContent: payload, RequestContent: request, ResponseContent: response}); err != nil {
				return lastID, err
			}
		}
		lastID = t.ID
	}
	return lastID, nil
}

func migrateRepositories(ctx context.Context, engine db.Engine, lastID int64) (int64, error) {
	type Repository struct {
		ID          int64  `xorm:"pk"`
		Description string `xorm:"TEXT"`
	}

	var repos []Repository
	err := engine.Table("repository").Where("id > ?", lastID).OrderBy("id ASC").Limit(migrationBatchSize).Find(&repos)
	if err != nil || len(repos) == 0 {
		return lastID, err
	}

	for _, r := range repos {
		if encryption.IsEncryptedField(r.Description) || r.Description == "" {
			lastID = r.ID
			continue
		}
		scope := encryption.KeyScope{RepoID: r.ID}
		if enc, err := encryption.EncryptField(r.Description, scope); err == nil {
			if _, err := engine.Table("repository").Where("id = ?", r.ID).
				Cols("description").
				Update(&Repository{Description: enc}); err != nil {
				return lastID, err
			}
		}
		lastID = r.ID
	}
	return lastID, nil
}
