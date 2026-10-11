package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// A standby follows its primary by GTID (gtid.go) when both servers can:
//
//   - MySQL: gtid_mode ON on both (an empty server becoming the standby
//     is switched to the primary's gtid_mode online first, so the two
//     match either way) and the binary log on.
//   - MariaDB: the binary log on and log_slave_updates on both, so the
//     promoted standby's binary log holds the old primary's transactions
//     with their GTIDs and the old primary can follow it from its own.
//
// Otherwise it follows by binary log position, as before. Servers Rowsafe
// creates (--install-mysql, --install-mariadb) have what GTIDs need.

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// followsByGTID decides whether this server follows a primary with the
// given settings (StandbyPrepareResult.Settings) by GTID.
func (s *server) followsByGTID(primary map[string]int, f facts) bool {
	if !f.LogBin || primary[settingLogBin] != 1 {
		return false
	}
	if s.flavor.mariadb() {
		return f.ReplicaUpdates && primary[settingReplicaUpdates] == 1
	}
	return primary[settingGTID] == 1 && strings.EqualFold(f.GTIDMode, "ON")
}

// gtidModes are MySQL's gtid_mode values, in the order it moves through them.
var gtidModes = []string{"OFF", "OFF_PERMISSIVE", "ON_PERMISSIVE", "ON"}

// matchGTIDMode switches MySQL's gtid_mode on this (empty) server on or
// off, one step at a time as MySQL requires, and keeps it after a restart
// (SET PERSIST). Turning it on turns enforce_gtid_consistency on first.
func (s *server) matchGTIDMode(ctx context.Context, conn *sql.DB, cur string, on bool, log agent.TaskLogger) error {
	i := slices.Index(gtidModes, strings.ToUpper(cur))
	if i < 0 {
		return fmt.Errorf("unknown gtid_mode %q", cur)
	}
	var steps []string
	if on {
		if _, err := conn.ExecContext(ctx, "SET PERSIST enforce_gtid_consistency = ON"); err != nil {
			return fmt.Errorf("turning enforce_gtid_consistency on: %w", err)
		}
		steps = gtidModes[i+1:]
	} else {
		for j := i - 1; j >= 0; j-- {
			steps = append(steps, gtidModes[j])
		}
	}
	for _, m := range steps {
		if _, err := conn.ExecContext(ctx, "SET PERSIST gtid_mode = "+m); err != nil {
			return fmt.Errorf("setting gtid_mode to %s: %w", m, err)
		}
	}
	if len(steps) > 0 {
		log.Printf("set gtid_mode to %s here, as on the primary (this server is empty)", steps[len(steps)-1])
	}
	return nil
}

// adoptGTIDs makes the seeded standby hold the primary's GTIDs at the seed:
// its own binary logs and GTIDs are cleared (it holds nothing of its own:
// the copy was loaded outside its binary log), then MySQL's gtid_purged or
// MariaDB's binary log state and replication position are set.
func (s *server) adoptGTIDs(ctx context.Context, conn *sql.DB, g seedGTIDs, version string) error {
	c, err := conn.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if s.flavor.mariadb() {
		if _, err := parseMariaState(g.Set); err != nil {
			return err
		}
		if _, err := parseMariaState(g.Pos); err != nil {
			return err
		}
		stmts := []string{"RESET MASTER"}
		if g.Set != "" {
			stmts = append(stmts, "SET GLOBAL gtid_binlog_state = "+quoteString(g.Set))
		}
		stmts = append(stmts, "SET GLOBAL gtid_slave_pos = "+quoteString(g.Pos))
		for _, q := range stmts {
			if _, err := c.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("giving the standby the primary's GTIDs (%s): %w", strings.SplitN(q, " =", 2)[0], err)
			}
		}
		return nil
	}
	if _, err := parseGTIDSet(g.Set); err != nil {
		return err
	}
	reset := "RESET MASTER"
	if _, n := numericVersion(version); n >= 80200 {
		reset = "RESET BINARY LOGS AND GTIDS"
	}
	if _, err := c.ExecContext(ctx, reset); err != nil {
		return fmt.Errorf("clearing the standby's own GTIDs: %w", err)
	}
	if g.Set != "" {
		if _, err := c.ExecContext(ctx, "SET GLOBAL gtid_purged = "+quoteString(g.Set)); err != nil {
			return fmt.Errorf("giving the standby the primary's GTIDs: %w", err)
		}
	}
	return nil
}

// prepareReattachGTID gets a fenced old primary ready to follow the new
// primary by GTID from its own data. MySQL: it must hold no transaction
// the new primary lacks; the new primary's GTIDs come sealed with the
// replication login (secretGTIDExecuted) and this server compares them
// (GTID_SUBSET). MariaDB checks that itself when it connects, from the
// position set here (its own binary log's).
func (s *server) prepareReattachGTID(ctx context.Context, conn *sql.DB, sec protocol.StandbySecrets) error {
	if s.flavor.mariadb() {
		if _, err := conn.ExecContext(ctx, "SET GLOBAL gtid_slave_pos = @@global.gtid_binlog_pos"); err != nil {
			return fmt.Errorf("setting where the old primary follows from: %w", err)
		}
		return nil
	}
	theirs, ok := sec.EngineData[secretGTIDExecuted]
	if !ok {
		return errors.New("the new primary didn't say which transactions it holds")
	}
	if _, err := parseGTIDSet(theirs); err != nil {
		return fmt.Errorf("the new primary's GTIDs: %w", err)
	}
	var subset int
	if err := conn.QueryRowContext(ctx, "SELECT GTID_SUBSET(@@global.gtid_executed, ?)", theirs).Scan(&subset); err != nil {
		return fmt.Errorf("comparing with the new primary's GTIDs: %w", err)
	}
	if subset != 1 {
		return errors.New("the old primary holds changes the new primary doesn't have (GTIDs not on the new primary), so Rowsafe " +
			"won't turn it into a standby: keep it as it is, and add a standby on an empty server instead")
	}
	return nil
}
