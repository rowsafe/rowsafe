package qdrant

import (
	"context"
	"errors"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// BackupInfo is one snapshot in the bucket (download-backup).
type BackupInfo struct {
	Label       string
	Version     string
	Source      string
	Mark        string
	TakenAt     time.Time
	Collections int
	Points      int64
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
		out = append(out, BackupInfo{Label: d.Label, Version: d.Version, Source: d.Source, Mark: d.Mark, TakenAt: d.TakenAt,
			Collections: d.userCollections(), Points: d.totalPoints()})
	}
	return out, nil
}

// DownloadBackup decrypts snapshot label into the file to (it must not
// exist): a full storage snapshot any Qdrant of the same or a newer
// version starts from (qdrant --storage-snapshot FILE).
func DownloadBackup(ctx context.Context, env agent.EngineEnv, stanza, label, to string) error {
	if !labelRE.MatchString(label) {
		return errors.New("that isn't a snapshot label (list them without --label)")
	}
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: stanza})
	if err != nil {
		return err
	}
	_, err = downloadSnapshot(ctx, r, backupPrefix+label+"/", to)
	return err
}
