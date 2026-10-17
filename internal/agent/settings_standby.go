package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/maintenance"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// Settings tasks run package maintenance's settings change (the CLI runs
// it too, without an agent); a standby's carry the checks below.

func (a *Agent) settingsTarget(db protocol.DatabaseSpec) collect.Target {
	return collect.Target{SocketDir: db.SocketDir, Port: db.Port, User: a.cfg.PGUser}
}

func (a *Agent) changeSettings(ctx context.Context, db protocol.DatabaseSpec, p protocol.SettingsParams, tl *taskLog) (*protocol.SettingsResult, error) {
	var standby *maintenance.Standby
	if p.Standby {
		r, ok := a.followingStandby(db) // standby_updates.go
		if !ok {
			return nil, errors.New("this server doesn't run a standby of this database")
		}
		db.Port, db.SocketDir = r.Database.Port, r.Database.SocketDir
		standby = &maintenance.Standby{
			Allowed:  standbySettingsAllowed,
			KeepConf: func() (func() error, error) { return standbyConfKeeper(r.DataDir) },
		}
	}
	return maintenance.ChangeSettingsAt(ctx, a.target(db), a.settingsTarget(db), p, standby, tl)
}

// standbySettingsAllowed refuses what a standby's settings task may not
// change: settings that apply without a restart (a standby's own value
// would quietly differ from its primary's), and those Rowsafe's standby
// configuration sets (standbyBlock).
func standbySettingsAllowed(changes []protocol.SettingChange, current map[string]protocol.PGSetting) error {
	for _, c := range changes {
		if c.Name == "hot_standby" || slices.Contains(hotStandbySettings, c.Name) {
			return fmt.Errorf("Rowsafe sets %s on a standby itself (from the primary's value)", c.Name)
		}
		if s, ok := current[c.Name]; !ok || tune.ApplyMode(s.Context) != "restart" {
			return fmt.Errorf("on a standby Rowsafe only changes settings that wait for a restart, and %s doesn't", c.Name)
		}
	}
	return nil
}

// standbyConfKeeper reads Rowsafe's standby block in dataDir's
// postgresql.auto.conf and returns what puts it back after ALTER SYSTEM
// rewrote the file: PostgreSQL keeps every setting in order (the one it
// changes moves to the end) but drops comments, the block's markers among
// them, so a later setStandbyConf couldn't replace the block any more.
func standbyConfKeeper(dataDir string) (func() error, error) {
	path := filepath.Join(dataDir, "postgresql.auto.conf")
	cur, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block := hbaBlockRE.FindString(string(cur))
	if block == "" {
		return func() error { return nil }, nil
	}
	return func() error {
		now, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(now), block) {
			return nil
		}
		return writeFileAtomic(path, []byte(withStandbyBlock(string(now), block)), 0o600)
	}, nil
}

// withStandbyBlock is content (as ALTER SYSTEM wrote it) with block's
// settings as the block again, at the end: the last line of each of its
// names is taken out (the block's own, as the block never names a setting
// the task changes) and the block appended as it was, so the values in
// effect stay the same.
func withStandbyBlock(content, block string) string {
	names := map[string]bool{}
	for _, l := range strings.Split(block, "\n") {
		if n := confLineName(l); n != "" {
			names[n] = true
		}
	}
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if n := confLineName(lines[i]); names[n] {
			delete(names, n)
			lines = slices.Delete(lines, i, i+1)
		}
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n\n" + strings.TrimLeft(block, "\n")
}

// confLineName is the setting a configuration line sets ("" for comments
// and blank lines).
func confLineName(line string) string {
	l := strings.TrimSpace(line)
	if l == "" || strings.HasPrefix(l, "#") {
		return ""
	}
	if i := strings.IndexAny(l, " \t="); i > 0 {
		return strings.ToLower(l[:i])
	}
	return ""
}
