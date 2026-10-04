package redis

import (
	"context"
	"errors"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// BackupInfo is one snapshot in the bucket (download-backup).
type BackupInfo struct {
	Label   string
	Engine  string
	Version string
	Source  string
	TakenAt time.Time
}

// Backups lists the finished snapshots of the database in folder stanza.
func Backups(ctx context.Context, env agent.EngineEnv, stanza string) ([]BackupInfo, error) {
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: stanza})
	if err != nil {
		return nil, err
	}
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return nil, err
	}
	var out []BackupInfo
	for _, d := range docs {
		out = append(out, BackupInfo{Label: d.Label, Engine: d.Engine, Version: d.Version, Source: d.Source, TakenAt: d.TakenAt})
	}
	return out, nil
}

// DownloadBackup decrypts snapshot label into the file to (it must not
// exist).
func DownloadBackup(ctx context.Context, env agent.EngineEnv, stanza, label, to string) error {
	if !labelRE.MatchString(label) {
		return errors.New("that isn't a snapshot label (list them without --label)")
	}
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: stanza})
	if err != nil {
		return err
	}
	return downloadTo(ctx, r, backupKey(label, rdbName), to)
}
