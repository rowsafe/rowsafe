package localcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// copiesHeartbeat sends the agent's copies report.
func copiesHeartbeat(a *fakeAgent, copies ...protocol.CopyState) protocol.HeartbeatResponse {
	var hb protocol.HeartbeatResponse
	a.call("POST", "/v1/agent/heartbeat", protocol.HeartbeatRequest{Hostname: "db1", AgentVersion: "0.10.18",
		Copies: &protocol.CopiesReport{Copies: copies, PortMin: 55440, PortMax: 55539,
			Addresses: []protocol.HostAddress{{IP: "10.0.0.5", Interface: "eth1", Private: true}, {IP: "203.0.113.7", Interface: "eth0"}}}}, &hb)
	return hb
}

func TestGuardPreview(t *testing.T) {
	_, a, c, now := setup(t)
	ctx := context.Background()
	db := activeDB(t, a, c, now)

	sql := "ALTER TABLE users ADD CONSTRAINT email_unique UNIQUE (email);"
	for _, req := range []protocol.CreatePreviewRequest{{SQL: " "}, {SQL: sql, DB: `a"b`}, {SQL: sql, FreshMinutes: -2}} {
		if _, err := c.CreatePreview(ctx, "shop", req); apiStatus(err) != http.StatusBadRequest {
			t.Errorf("preview %+v: %v", req, err)
		}
	}
	p, err := c.CreatePreview(ctx, "shop", protocol.CreatePreviewRequest{SQL: sql, Label: "0042_unique.sql", Source: "cli"})
	if err != nil || p.Status != protocol.StatusQueued || p.Database != "shop" || p.Source != "cli" || p.SQLBytes != len(sql) {
		t.Fatalf("preview: %+v %v", p, err)
	}
	// Two previews wait side by side (each is its own task).
	p2, err := c.CreatePreview(ctx, "shop", protocol.CreatePreviewRequest{SQL: "SELECT 1;"})
	if err != nil || p2.TaskID == p.TaskID {
		t.Fatalf("a second preview: %+v %v", p2, err)
	}

	task := a.claimOne(protocol.TaskPreviewMigration)
	var params protocol.PreviewParams
	if err := json.Unmarshal(task.Params, &params); err != nil || params.PreviewID != p.ID || params.SQL != sql || task.Database == nil || task.Database.ID != db.ID {
		t.Fatalf("task: %+v %+v %v", task, params, err)
	}
	copiesHeartbeat(a, protocol.CopyState{ID: "pvc1", DatabaseID: db.ID, Kind: protocol.CopyKindPreview, Status: protocol.CopyRestoring})
	if got, _ := c.Preview(ctx, p.ID); got.Status != protocol.StatusRunning || got.Step != protocol.PreviewStepRestoring {
		t.Fatalf("restoring: %+v", got)
	}
	copiesHeartbeat(a, protocol.CopyState{ID: "pvc1", DatabaseID: db.ID, Kind: protocol.CopyKindPreview, Status: protocol.CopyReady})
	if got, _ := c.Preview(ctx, p.ID); got.Step != protocol.PreviewStepRunning {
		t.Fatalf("running: %+v", got)
	}
	// The migration fails on the real data: the preview worked.
	res := protocol.PreviewResult{PreviewID: p.ID, Verdict: protocol.PreviewFailed, Summary: "Fails: duplicate key value violates unique constraint",
		Error: &protocol.PreviewError{Statement: 1, Code: "23505", Message: "could not create unique index"}}
	a.done(task, protocol.StatusSucceeded, res)
	got, err := c.WaitPreview(ctx, p.ID, nil)
	if err != nil || got.Verdict != protocol.PreviewFailed || got.Result == nil || got.Result.Error.Code != "23505" || got.FinishedAt == nil {
		t.Fatalf("finished: %+v %v", got, err)
	}
	list, err := c.Previews(ctx, "shop")
	if err != nil || len(list) != 2 || list[0].ID != p2.ID || list[1].Result != nil || list[1].Verdict != protocol.PreviewFailed {
		t.Fatalf("list: %+v %v", list, err)
	}
	// The SQL is gone from the finished task.
	if tv, err := c.Task(ctx, task.ID); err != nil || strings.Contains(string(tv.Params), "UNIQUE") {
		t.Fatalf("SQL kept: %s %v", tv.Params, err)
	}

	// At most five wait per database.
	for i := 0; i < 4; i++ {
		if _, err := c.CreatePreview(ctx, "shop", protocol.CreatePreviewRequest{SQL: "SELECT 1;"}); err != nil && i < 3 {
			t.Fatal(err)
		}
	}
	if _, err := c.CreatePreview(ctx, "shop", protocol.CreatePreviewRequest{SQL: "SELECT 1;"}); apiStatus(err) != http.StatusTooManyRequests {
		t.Fatalf("a sixth: %v", err)
	}
}

func TestGuardSafeCopies(t *testing.T) {
	_, a, c, now := setup(t)
	ctx := context.Background()
	db := activeDB(t, a, c, now)
	_, verifier, _ := client.NewCopyPasswordFor(protocol.EnginePostgreSQL)
	if _, err := c.CreateSafeCopy(ctx, "shop", protocol.CreateSafeCopyRequest{PasswordVerifier: verifier}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "hasn't reported") {
		t.Fatalf("before the agent reported its copies: %v", err)
	}
	copiesHeartbeat(a)

	password, verifier, err := client.NewCopyPasswordFor(protocol.EnginePostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.SafeCopies(ctx, "shop")
	if err != nil || !info.Available || info.Limit != maxLiveCopies || len(info.Addresses) != 2 {
		t.Fatalf("info: %+v %v", info, err)
	}
	for _, req := range []protocol.CreateSafeCopyRequest{
		{},                           // no password verifier
		{PasswordVerifier: "secret"}, // not a verifier
		{PasswordVerifier: verifier, Hours: 200},
		{PasswordVerifier: verifier, Masking: protocol.MaskingNone},                        // not confirmed
		{PasswordVerifier: verifier, Listen: "private"},                                    // nobody allowed
		{PasswordVerifier: verifier, Listen: "192.0.2.1", AllowFrom: []string{"10.0.0.9"}}, // not an address here
		{PasswordVerifier: verifier, Listen: "*", AllowFrom: []string{"0.0.0.0/0"}},        // the internet
		{PasswordVerifier: verifier, Port: 80},                                             // a low port
		{PasswordVerifier: verifier, Role: "postgres"},
	} {
		if _, err := c.CreateSafeCopy(ctx, "shop", req); apiStatus(err) != http.StatusBadRequest {
			t.Errorf("copy %+v: %v", req, err)
		}
	}
	if _, err := c.CreateSafeCopy(ctx, "shop", protocol.CreateSafeCopyRequest{PasswordVerifier: verifier, Port: 5432}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("PostgreSQL's own port: %v", err)
	}

	// Masked, on localhost, on the port the person chose.
	rules := []protocol.MaskingRule{{DB: "shop", Table: "public.users", Column: "name", Strategy: "keep"}}
	if _, err := c.PutMasking(ctx, "shop", rules); err != nil {
		t.Fatal(err)
	}
	resp, err := c.CreateSafeCopy(ctx, "shop", protocol.CreateSafeCopyRequest{PasswordVerifier: verifier, Port: 6543, Hours: 2})
	if err != nil || resp.Copy.Status != protocol.CopyRestoring || !resp.Copy.Masked || resp.Copy.Host != protocol.CopyListenLocal ||
		resp.Copy.Port != 6543 || len(resp.Copy.AllowFrom) != 1 || resp.Copy.AllowFrom[0] != "127.0.0.1" || !resp.Copy.Expires.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("copy: %+v %v", resp, err)
	}
	cp := resp.Copy
	if _, err := c.CreateSafeCopy(ctx, "shop", protocol.CreateSafeCopyRequest{PasswordVerifier: verifier, Port: 6543}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("the same port twice: %v", err)
	}
	task := a.claimOne(protocol.TaskSafeCopy)
	var p protocol.SafeCopyParams
	if err := json.Unmarshal(task.Params, &p); err != nil || p.CopyID != cp.ID || p.Masking.Mode != protocol.MaskingRules || len(p.Masking.Rules) != 1 ||
		p.Access.Listen != protocol.CopyListenLocal || p.Access.Port != 6543 || !p.Access.PortChosen || p.Access.PasswordVerifier != verifier ||
		p.Access.Role != "rowsafe_"+cp.ID {
		t.Fatalf("params: %+v %v", p, err)
	}
	live := protocol.CopyState{ID: cp.ID, DatabaseID: db.ID, Kind: protocol.CopyKindSafe, Status: protocol.CopyMasking, Port: 6543}
	copiesHeartbeat(a, live)
	if info, _ := c.SafeCopies(ctx, "shop"); len(info.Copies) != 1 || info.Copies[0].Status != protocol.CopyMasking {
		t.Fatalf("masking: %+v", info.Copies)
	}
	a.done(task, protocol.StatusSucceeded, protocol.SafeCopyResult{CopyID: cp.ID, Listen: "127.0.0.1", Port: 6543, Role: p.Access.Role,
		Databases: []string{"postgres", "shop"}, Expires: p.Expires, Masking: protocol.MaskingReport{Mode: protocol.MaskingRules, Tables: 1, Columns: 2}})
	live.Status, live.PasswordVersion = protocol.CopyReady, 1
	hb := copiesHeartbeat(a, live)
	if hb.Copies == nil || len(hb.Copies.Expires) != 1 || len(hb.Copies.Drop) != 0 || len(hb.Copies.Passwords) != 0 {
		t.Fatalf("heartbeat: %+v", hb.Copies)
	}
	info, _ = c.SafeCopies(ctx, "shop")
	got := info.Copies[0]
	if got.Status != protocol.CopyReady || !got.HasPassword || got.DB != "shop" || got.Masking == nil || got.Masking.Columns != 2 ||
		got.ConnectionString != "postgresql://"+p.Access.Role+"@127.0.0.1:6543/shop?sslmode=require" {
		t.Fatalf("ready: %+v", got)
	}
	if conn := client.ConnectionString(got, password); !strings.Contains(conn, ":"+password+"@127.0.0.1:6543/") {
		t.Fatalf("with the password: %s", conn)
	}

	// Extend, a new password, then delete: the heartbeat carries each.
	if _, err := c.ExtendSafeCopy(ctx, "shop", cp.ID, 48); err != nil {
		t.Fatal(err)
	}
	_, verifier2, _ := client.NewCopyPasswordFor(protocol.EnginePostgreSQL)
	if got, err := c.SetSafeCopyPassword(ctx, "shop", cp.ID, verifier2); err != nil || !got.PasswordPending {
		t.Fatalf("password: %+v %v", got, err)
	}
	hb = copiesHeartbeat(a, live)
	if len(hb.Copies.Expires) != 1 || !hb.Copies.Expires[0].Expires.Equal(now.Add(48*time.Hour)) || len(hb.Copies.Passwords) != 1 ||
		hb.Copies.Passwords[0].Version != 2 || hb.Copies.Passwords[0].Verifier != verifier2 {
		t.Fatalf("extend and password: %+v", hb.Copies)
	}
	live.PasswordVersion = 2
	if hb = copiesHeartbeat(a, live); len(hb.Copies.Passwords) != 0 {
		t.Fatalf("the password once applied: %+v", hb.Copies.Passwords)
	}
	if got, err := c.DeleteSafeCopy(ctx, "shop", cp.ID); err != nil || got.Status != protocol.CopyDeleting {
		t.Fatalf("delete: %+v %v", got, err)
	}
	if hb = copiesHeartbeat(a, live); len(hb.Copies.Drop) != 1 || hb.Copies.Drop[0] != cp.ID {
		t.Fatalf("drop: %+v", hb.Copies)
	}
	copiesHeartbeat(a) // the agent deleted it
	if info, _ := c.SafeCopies(ctx, "shop"); info.Copies[0].Status != protocol.CopyRemoved || info.Used != 0 {
		t.Fatalf("removed: %+v", info)
	}

	// A copy deleted before it started is gone at once; one that expired on
	// the server is gone once the agent stops reporting it.
	resp, err = c.CreateSafeCopy(ctx, "shop", protocol.CreateSafeCopyRequest{PasswordVerifier: verifier, Listen: "private", AllowFrom: []string{"10.0.0.0/24"}})
	if err != nil || resp.Copy.Host != "10.0.0.5" || resp.Copy.Port != 55440 {
		t.Fatalf("private: %+v %v", resp, err)
	}
	if got, err := c.DeleteSafeCopy(ctx, "shop", resp.Copy.ID); err != nil || got.Status != protocol.CopyRemoved {
		t.Fatalf("delete queued: %+v %v", got, err)
	}
	if a.claimOne("", protocol.TaskSafeCopy) != nil {
		t.Fatal("a deleted copy's task ran")
	}
	resp, err = c.CreateSafeCopy(ctx, "shop", protocol.CreateSafeCopyRequest{PasswordVerifier: verifier, Masking: protocol.MaskingNone, NoMaskingConfirm: "shop"})
	if err != nil || resp.Copy.Masked {
		t.Fatalf("unmasked: %+v %v", resp, err)
	}
	task = a.claimOne(protocol.TaskSafeCopy)
	p = protocol.SafeCopyParams{}
	if err := json.Unmarshal(task.Params, &p); err != nil || p.Masking.Mode != protocol.MaskingNone || p.Access.PortChosen {
		t.Fatalf("unmasked params: %+v", p)
	}
	a.done(task, protocol.StatusSucceeded, protocol.SafeCopyResult{CopyID: resp.Copy.ID, Port: 55441, Expires: p.Expires})
	copiesHeartbeat(a, protocol.CopyState{ID: resp.Copy.ID, DatabaseID: db.ID, Kind: protocol.CopyKindSafe, Status: protocol.CopyReady, Port: 55441})
	*now = now.Add(25 * time.Hour)
	copiesHeartbeat(a) // expired on the server
	if info, _ := c.SafeCopies(ctx, "shop"); info.Used != 0 {
		t.Fatalf("expired: %+v", info)
	}
	// A failed copy is gone (the agent removed what it made).
	resp, _ = c.CreateSafeCopy(ctx, "shop", protocol.CreateSafeCopyRequest{PasswordVerifier: verifier})
	a.done(a.claimOne(protocol.TaskSafeCopy), protocol.StatusFailed, nil)
	if info, _ := c.SafeCopies(ctx, "shop"); info.Used != 0 || info.Copies[0].ID != resp.Copy.ID || info.Copies[0].Status != protocol.CopyRemoved {
		t.Fatalf("failed: %+v", info.Copies)
	}
}

func TestGuardMasking(t *testing.T) {
	_, a, c, now := setup(t)
	ctx := context.Background()
	activeDB(t, a, c, now)

	// The first look reads the tables (names and types only).
	info, err := c.Masking(ctx, "shop")
	if err != nil || len(info.Columns) != 0 || info.SchemaTask == nil || info.SchemaTask.Status != protocol.StatusQueued || len(info.Strategies) == 0 {
		t.Fatalf("first look: %+v %v", info, err)
	}
	if _, err := c.RefreshMaskingSchema(ctx, "shop"); err != nil {
		t.Fatal(err) // already queued: the same task
	}
	task := a.claimOne(protocol.TaskCopySchema)
	if a.claimOne("", protocol.TaskCopySchema) != nil {
		t.Fatal("the schema was read twice")
	}
	a.done(task, protocol.StatusSucceeded, protocol.CopySchemaResult{Databases: []protocol.SchemaDatabase{{Name: "shop", Tables: []protocol.SchemaTable{{
		Name: "public.users", Rows: 1000, Columns: []protocol.SchemaColumn{
			{Name: "id", Type: "bigint", Unique: true}, {Name: "email", Type: "text", Unique: true}, {Name: "created_at", Type: "timestamp with time zone"},
		}}}}}})
	info, err = c.Masking(ctx, "shop")
	if err != nil || len(info.Columns) != 3 || info.SchemaAt == nil || info.Masked == 0 {
		t.Fatalf("schema: %+v %v", info, err)
	}
	var email protocol.MaskingColumn
	for _, col := range info.Columns {
		if col.Column == "email" {
			email = col
		}
	}
	if email.Strategy == "keep" || email.Saved {
		t.Fatalf("email is masked by default: %+v", email)
	}
	if _, err := c.PutMasking(ctx, "shop", []protocol.MaskingRule{{DB: "shop", Table: "public.users", Column: "email", Strategy: "nope"}}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("unknown strategy: %v", err)
	}
	info, err = c.PutMasking(ctx, "shop", []protocol.MaskingRule{{DB: "shop", Table: "public.users", Column: "email", Strategy: "keep"}})
	if err != nil || len(info.Rules) != 1 || info.UpdatedBy != "root on db1" {
		t.Fatalf("put: %+v %v", info, err)
	}
	for _, col := range info.Columns {
		if col.Column == "email" && (col.Strategy != "keep" || !col.Saved) {
			t.Fatalf("saved rule: %+v", col)
		}
	}
}
