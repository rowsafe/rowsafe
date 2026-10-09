package meilisearch

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Restores without Rowsafe (`rowsafe-agent meilisearch download-backup`):
// with the bucket's settings and the passphrase in the environment, list a
// database's snapshots or decrypt one into a file Meilisearch starts from
// (--import-snapshot).

// BackupInfo is one snapshot in the bucket.
type BackupInfo struct {
	Label, Version, Source, Mark string
	TakenAt                      string
	Indexes                      int
	Documents                    int64
}

// Backups lists the finished snapshots of the folder stanza, oldest first.
func Backups(ctx context.Context, env agent.EngineEnv, stanza string) ([]BackupInfo, error) {
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: stanza})
	if err != nil {
		return nil, err
	}
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]BackupInfo, 0, len(docs))
	for _, d := range docs {
		out = append(out, BackupInfo{Label: d.Label, Version: d.Version, Source: d.Source, Mark: d.Mark,
			TakenAt: d.TakenAt.UTC().Format("2006-01-02 15:04:05Z"), Indexes: len(d.Indexes), Documents: d.documents()})
	}
	return out, nil
}

// DownloadBackup decrypts snapshot label of stanza into the new file to.
func DownloadBackup(ctx context.Context, env agent.EngineEnv, stanza, label, to string) error {
	if !labelRE.MatchString(label) {
		return fmt.Errorf("invalid label %q", label)
	}
	if !filepath.IsAbs(to) {
		return errors.New("--to must be an absolute path")
	}
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: stanza})
	if err != nil {
		return err
	}
	_, err = download(ctx, r, label, to)
	return err
}
