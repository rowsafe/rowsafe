package maintenance

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestValidateEnableRLS(t *testing.T) {
	ok := protocol.MaintenanceParams{Action: protocol.MaintEnableRLS, DB: "app", Tables: []string{"public.profiles"}}
	if err := Validate(ok); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]protocol.MaintenanceParams{
		"no db":     {Action: protocol.MaintEnableRLS, Tables: []string{"public.t"}},
		"no tables": {Action: protocol.MaintEnableRLS, DB: "app"},
		"bad name":  {Action: protocol.MaintEnableRLS, DB: "app", Tables: []string{"a\x00b"}},
		"too many":  {Action: protocol.MaintEnableRLS, DB: "app", Tables: make([]string, protocol.MaxRLSTables+1)},
	} {
		if err := Validate(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEnableRLSAgainstPostgres(t *testing.T) {
	e := newFixEnv(t)
	e.exec(`CREATE TABLE profiles (id int, user_id int)`)
	e.exec(`CREATE POLICY own ON profiles USING (user_id = 1)`)
	e.exec(`CREATE SCHEMA "My App"`)
	e.exec(`CREATE TABLE "My App"."Notes" (id int)`)
	e.exec(`CREATE TABLE done (id int)`)
	e.exec(`ALTER TABLE done ENABLE ROW LEVEL SECURITY`)

	res := e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintEnableRLS, DB: e.db,
		Tables: []string{"public.profiles", "My App.Notes", "public.done"}}, "Turned on row-level security for 2 tables.")
	if !strings.Contains(strings.Join(res.Details, "\n"), `ALTER TABLE "My App"."Notes" DISABLE ROW LEVEL SECURITY`) ||
		!strings.Contains(strings.Join(res.Details, "\n"), "Already on: public.done") {
		t.Fatalf("details %q", res.Details)
	}
	var n int
	if err := e.conn.QueryRow(t.Context(), `SELECT count(*) FROM pg_class WHERE relname IN ('profiles', 'Notes', 'done') AND relrowsecurity`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("tables with row-level security on: %d, %v", n, err)
	}
	e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintEnableRLS, DB: e.db, Tables: []string{"profiles"}}, "already on")
	e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintEnableRLS, DB: e.db, Tables: []string{"public.gone"}}, "no longer exists")
	e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintEnableRLS, DB: e.db, Tables: []string{"pg_catalog.pg_class"}}, "PostgreSQL itself")
}
