package agent

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// lostSourceFacts reads a lost source's PostgreSQL major and size from its
// backups, when nobody could say them: on a server without an account,
// sudo rowsafe restore NAME --from-bucket knows only the database's name
// (its backup folder). The backups' own record has the version (the newest
// entry of the stanza's history) and each backup's size.
func (a *Agent) lostSourceFacts(ctx context.Context, ops forkOps, p protocol.ForkRestoreParams, repo pgbackrest.Repo) (int, int64, error) {
	probe := forkRecord{ID: p.ForkID, Port: 5432, DataDir: filepath.Join(a.cfg.StateDir, "fork", p.ForkID, "probe"),
		SourceConf: filepath.Join(a.cfg.ConfigDir, "fork-"+p.ForkID+"-probe.conf")}
	if err := a.writeForkSourceConf(probe, p.Source, repo, filepath.Join(a.cfg.StateDir, "fork", p.ForkID)); err != nil {
		return 0, 0, err
	}
	defer os.Remove(probe.SourceConf)
	cli := pgbackrest.CLI{Bin: a.cfg.PgBackRestBin, ConfigPath: probe.SourceConf, Stanza: p.Source.Stanza, Runner: a.runner}
	stanzas, err := ops.sourceInfo(ctx, cli)
	if err != nil {
		return 0, 0, fmt.Errorf("Rowsafe can't read %s's backups from this server: %w (%s)", cmp.Or(p.Source.Name, p.Source.Stanza), err, lostSourceHint)
	}
	latest, err := pgbackrest.LatestBackup(stanzas, p.Source.Stanza)
	if err != nil {
		return 0, 0, lostSourceError(stanzas, p, err)
	}
	major := 0
	for _, s := range stanzas {
		if s.Name != p.Source.Stanza {
			continue
		}
		newest := -1
		for _, db := range s.DB {
			if db.ID > newest {
				newest, major = db.ID, 0
				if n, err := strconv.Atoi(db.Version); err == nil {
					major = n
				}
			}
		}
	}
	if major == 0 {
		return 0, 0, fmt.Errorf("the backups of %s don't say which PostgreSQL version they are of", p.Source.Stanza)
	}
	return major, latest.Info.Size, nil
}

// lostSourceError says plainly why a lost source's backups can't be read
// here: they can't be decrypted (another passphrase), or there are none
// where this server looks (another bucket, name or folder).
func lostSourceError(stanzas []pgbackrest.Stanza, p protocol.ForkRestoreParams, err error) error {
	name, folder := cmp.Or(p.Source.Name, p.Source.Stanza), cmp.Or(p.SourceFolder, p.Source.Stanza)
	for _, s := range stanzas {
		if s.Name != p.Source.Stanza {
			continue
		}
		msg := s.RepoMessage()
		switch {
		case strings.Contains(msg, "CryptoError") || strings.Contains(msg, "FormatError") && strings.Contains(msg, "outside of section"):
			return fmt.Errorf("%s's backups are in this server's bucket, but this server's backup passphrase can't decrypt them: "+
				"it must be the old server's (ROWSAFE_REPO_CIPHER_PASS in its /etc/rowsafe/agent.env)", name)
		case strings.Contains(msg, "missing stanza path"):
			return fmt.Errorf("no backups of %s in this server's bucket (folder %s): check the name (its name on the old server), "+
				"--folder, and that this server uses the old server's bucket", name, folder)
		}
	}
	return fmt.Errorf("nothing to restore from: %w (%s)", err, lostSourceHint)
}
