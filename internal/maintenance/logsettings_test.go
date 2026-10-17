package maintenance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/internal/pgscratch"
	"github.com/rowsafe/rowsafe/protocol"
)

// The logging fix on a real cluster: it turns on what's missing, reloads
// (no restart), and a second run changes nothing.
func TestLogSettingsFix(t *testing.T) {
	c := pgscratch.Start(t, "log_checkpoints=on", "log_min_duration_statement=250")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tg := pginspect.Target{SocketDir: c.SocketDir, Port: c.Port, User: c.User, AppName: AppName}
	tl := &taskLog{}
	res, err := Run(ctx, tg, protocol.MaintenanceParams{Action: protocol.MaintLogSettings}, tl)
	if err != nil {
		t.Fatalf("%v\n%s", err, tl)
	}
	if !strings.Contains(res.Summary, "queries waiting for a lock") || !strings.Contains(res.Summary, "nothing restarted") ||
		strings.Contains(res.Summary, "slow statements") {
		t.Errorf("summary: %s", res.Summary)
	}
	conn, err := c.Connect(ctx, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var lockWaits, prefix, minDur string
	if err := conn.QueryRow(ctx, `SELECT current_setting('log_lock_waits'), current_setting('log_line_prefix'),
		current_setting('log_min_duration_statement')`).Scan(&lockWaits, &prefix, &minDur); err != nil {
		t.Fatal(err)
	}
	if lockWaits != "on" || !strings.Contains(prefix, "client=%h") || minDur != "250ms" {
		t.Errorf("after the fix: log_lock_waits=%s log_line_prefix=%q log_min_duration_statement=%s", lockWaits, prefix, minDur)
	}
	res, err = Run(ctx, tg, protocol.MaintenanceParams{Action: protocol.MaintLogSettings}, &taskLog{})
	if err != nil || !strings.Contains(res.Summary, "nothing changed") {
		t.Errorf("second run: %v %+v", err, res)
	}
}
