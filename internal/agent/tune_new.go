package agent

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// TuneNew gives a PostgreSQL the installer has just created (and nothing
// else: `rowsafe-agent postgres tune`, run for --install-postgres's own
// cluster once, while it is new and empty) Rowsafe's recommended settings
// for this server: what Tune for this server recommends (package tune, a
// mixed workload), without the optional ones (they change what apps see),
// checked and applied like a settings task. It refuses a cluster that
// already has databases of its own. It never restarts PostgreSQL: the
// result says which settings wait for a restart. The settings task's log
// goes to log.
func TuneNew(ctx context.Context, socketDir string, port int, user string, log io.Writer) (*protocol.SettingsResult, error) {
	a := &Agent{cfg: Config{PGUser: user}}
	db := protocol.DatabaseSpec{SocketDir: socketDir, Port: port}
	if err := a.newCluster(ctx, db); err != nil {
		return nil, err
	}
	snap, err := collect.ReadSettings(ctx, a.settingsTarget(db), settingsProcRoot)
	if err != nil {
		return nil, err
	}
	changes := newServerChanges(*snap)
	if len(changes) == 0 {
		return &protocol.SettingsResult{Snapshot: snap, Summary: "The settings already suit this server."}, nil
	}
	tl := &taskLog{}
	res, err := a.changeSettings(ctx, db, protocol.SettingsParams{Kind: protocol.SettingsKindTune, Changes: changes}, tl)
	io.WriteString(log, tl.String())
	return res, err
}

// newServerChanges are the recommendations TuneNew applies.
func newServerChanges(snap protocol.SettingsSnapshot) []protocol.SettingChange {
	var out []protocol.SettingChange
	for _, r := range tune.Recommend(tune.InputFrom(snap, "", "")) {
		if !r.Optional {
			out = append(out, protocol.SettingChange{Name: r.Name, Value: r.Value})
		}
	}
	return out
}

// newCluster refuses a cluster with databases besides PostgreSQL's own
// (postgres, template0, template1): someone uses it already.
func (a *Agent) newCluster(ctx context.Context, db protocol.DatabaseSpec) error {
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var names []string
	if err := conn.QueryRow(ctx, `SELECT coalesce(array_agg(datname ORDER BY datname), '{}') FROM pg_database
		WHERE datname NOT IN ('postgres', 'template0', 'template1')`).Scan(&names); err != nil {
		return err
	}
	if len(names) > 0 {
		return fmt.Errorf("this PostgreSQL isn't new (it has the databases %s): Rowsafe only tunes a new one by itself; use Tune for this server in the dashboard", strings.Join(names, ", "))
	}
	return nil
}
