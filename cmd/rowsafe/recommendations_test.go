package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func testRecommendations() []protocol.Recommendation {
	p, _ := json.Marshal(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: "shop", Tables: []string{"public.orders"}, Columns: []string{"customer_id"}})
	return []protocol.Recommendation{
		{Finding: protocol.Finding{ID: "integer_overflow:shop.public.tickets.id", Severity: protocol.SeverityCritical,
			Title: "tickets.id will run out of numbers (93% used)", Explanation: "It runs out around 3 January 2027.", Action: "Change it to bigint.",
			Command: "ALTER TABLE tickets ADD COLUMN id_new bigint;"},
			Group: protocol.RecGroupSchema, Impact: 95, Cost: "No automatic fix.", Source: "advisor",
			Steps: []string{"Add a bigint copy", "Fill it in batches"}},
		{Finding: protocol.Finding{ID: "fk_without_index:shop.public.orders.orders_customer_id_fkey", Severity: protocol.SeverityWarning,
			Title: "orders.customer_id points to customers but has no index", Explanation: "Deletes scan orders.", Action: "Create the index.",
			Fixes: []protocol.FindingFix{{ID: "create_index:shop.public.orders.customer_id", Kind: protocol.FixMaintenance, Label: "Create the index",
				Params: p, Available: true, Confirm: "Create an index on orders (customer_id)?"}}},
			Group: protocol.RecGroupSchema, Impact: 60, Cost: "About 300 MB of disk.", Source: "advisor"},
		{Finding: protocol.Finding{ID: "n_plus_one:42", Severity: protocol.SeverityInfo, Title: "A query runs once per row of another (N+1)",
			Explanation: "...", Action: "Load them in one query."}, Group: protocol.RecGroupQueries, Impact: 45, Source: "advisor"},
	}
}

func TestRecommendationsCommand(t *testing.T) {
	f := &fakeAPI{dbs: dbs("shop"), health: map[string]int{"shop": 90}, findings: []protocol.Finding{}}
	_, _ = cliEnv(t, f)
	var dismissed []string
	var dismissBody protocol.DismissRecommendationRequest
	inner := f.handler(t)
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, v any) { w.Header().Set("Content-Type", "application/json"); _ = json.NewEncoder(w).Encode(v) }
	mux.HandleFunc("GET /v1/recommendations", func(w http.ResponseWriter, r *http.Request) {
		top := testRecommendations()[0]
		j(w, protocol.RecommendationsOverview{Databases: []protocol.DatabaseRecommendations{{Database: "shop", Host: "db1", Count: 3, Critical: 1, Top: &top}}})
	})
	mux.HandleFunc("GET /v1/databases/{ref}/recommendations", func(w http.ResponseWriter, r *http.Request) {
		j(w, protocol.RecommendationsResponse{Database: r.PathValue("ref"), Available: true, Recommendations: testRecommendations(),
			Dismissed: []protocol.Recommendation{}})
	})
	mux.HandleFunc("POST /v1/databases/{ref}/recommendations/{id}/dismiss", func(w http.ResponseWriter, r *http.Request) {
		dismissed = append(dismissed, r.PathValue("id"))
		_ = json.NewDecoder(r.Body).Decode(&dismissBody)
		j(w, protocol.RecommendationDismissal{Reason: dismissBody.Reason, By: "key:test"})
	})
	mux.Handle("/", inner)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	t.Setenv("ROWSAFE_URL", ts.URL)
	ctx := t.Context()

	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"recommendations"}) })
	if err != nil || !strings.Contains(out, "tickets.id will run out of numbers") || !strings.Contains(out, "rowsafe recommendations NAME") {
		t.Fatalf("fleet: %v\n%s", err, out)
	}
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"recommendations", "shop"}) })
	for _, want := range []string{"shop: 3 recommendations", "SCHEMA", "QUERIES", "What it costs: About 300 MB of disk.",
		"1. Add a bigint copy", "Fix: rowsafe fix shop fk_without_index:shop.public.orders.orders_customer_id_fkey  (Create the index)",
		"--dismiss n_plus_one:42"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	out, _ = captureStdout(t, func() error { return dispatch(ctx, []string{"recommendations", "shop", "--group", "queries"}) })
	if strings.Contains(out, "SCHEMA") || !strings.Contains(out, "N+1") {
		t.Errorf("--group queries:\n%s", out)
	}
	if err := dispatch(ctx, []string{"recommendations", "shop", "--group", "nope"}); err == nil {
		t.Error("an unknown group was accepted")
	}
	out, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"recommendations", "shop", "--dismiss", "n_plus_one:42", "--reason", "intended", "--note", "batch job"})
	})
	if err != nil || len(dismissed) != 1 || dismissed[0] != "n_plus_one:42" || dismissBody.Reason != "intended" || dismissBody.Note != "batch job" ||
		!strings.Contains(out, "--restore n_plus_one:42") {
		t.Fatalf("dismiss: %v %v %+v\n%s", err, dismissed, dismissBody, out)
	}

	// rowsafe fix offers the recommendations' fixes too, and applies them by id.
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"fix", "shop"}) })
	if err != nil || !strings.Contains(out, "Create the index") {
		t.Fatalf("fix list: %v\n%s", err, out)
	}
	stdin = strings.NewReader("shop\n")
	t.Cleanup(func() { stdin = os.Stdin })
	_, _ = captureStdout(t, func() error {
		return dispatch(ctx, []string{"fix", "shop", "fk_without_index:shop.public.orders.orders_customer_id_fkey", "--yes"})
	})
	if len(f.fixes) != 1 || f.fixes[0].FindingID != "fk_without_index:shop.public.orders.orders_customer_id_fkey" ||
		f.fixes[0].FixID != "create_index:shop.public.orders.customer_id" {
		t.Fatalf("fixes sent %+v", f.fixes)
	}
}
