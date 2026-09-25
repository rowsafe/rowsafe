package collect

import (
	"context"
	"errors"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// Databases of other engines never get a PostgreSQL connection: they go to
// Options.Engine, or are left out.
func TestCollectOtherEngines(t *testing.T) {
	dbs := []protocol.DatabaseSpec{
		{ID: "db_m", Port: 3306, Engine: protocol.EngineMySQL},
		{ID: "db_x", Port: 3307, Engine: protocol.EngineMariaDB},
		{ID: "db_o", Port: 27017, Engine: protocol.EngineMongoDB},
	}
	o := Options{ProcRoot: t.TempDir(), Databases: func() []protocol.DatabaseSpec { return dbs }}
	if r := New(o).Collect(t.Context()); len(r.Databases) != 0 {
		t.Fatalf("without Engine: %+v", r.Databases)
	}
	var asked []string
	o.Engine = func(_ context.Context, db protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error) {
		asked = append(asked, db.ID)
		switch db.Engine {
		case protocol.EngineMySQL:
			return &protocol.DatabaseMonitoring{Metrics: map[string]float64{"up": 1}}, nil
		case protocol.EngineMariaDB:
			return nil, errors.New("access denied")
		}
		return nil, nil // no monitoring for this engine
	}
	r := New(o).Collect(t.Context())
	if len(asked) != 3 || len(r.Databases) != 2 {
		t.Fatalf("asked %v, report %+v", asked, r.Databases)
	}
	if m := r.Databases[0]; m.DatabaseID != "db_m" || m.Metrics["up"] != 1 || m.Error != "" {
		t.Errorf("mysql = %+v", m)
	}
	if m := r.Databases[1]; m.DatabaseID != "db_x" || m.Error != "access denied" {
		t.Errorf("mariadb = %+v", m)
	}
}
