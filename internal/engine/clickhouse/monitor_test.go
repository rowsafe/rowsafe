package clickhouse

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeServer answers queries whose text contains a key with its rows
// (JSONEachRow), and anything else with no rows.
func fakeServer(t *testing.T, answers map[string]string) *client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(r.Body)
		for k, rows := range answers {
			if strings.Contains(string(q), k) {
				io.WriteString(w, rows)
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/")
	return newClient(u, Login{User: "rowsafe"})
}

func TestStatusMutationTextFollowsQueryTextSetting(t *testing.T) {
	c := fakeServer(t, map[string]string{"system.mutations": `{"database":"shop","table":"orders","mutation_id":"mutation_7.txt",` +
		`"command":"UPDATE email = 'alice@example.com' WHERE id = 42","created":1700000000,"parts_to_do":3,` +
		`"latest_fail_reason":"Code: 6. DB::Exception: Cannot parse string 'alice@example.com' as UInt32. (CANNOT_PARSE_TEXT) (version 24.8.1.1)",` +
		`"failed_at":1700000100}` + "\n"})
	ctx := context.Background()

	on := status(ctx, c, 0, true)
	if len(on.Mutations) != 1 || !strings.Contains(on.Mutations[0].Command, "alice") || !strings.Contains(on.Mutations[0].FailReason, "alice") {
		t.Fatalf("with query text: %+v", on.Mutations)
	}

	off := status(ctx, c, 0, false)
	if len(off.Mutations) != 1 {
		t.Fatalf("without query text: %+v", off.Mutations)
	}
	m := off.Mutations[0]
	if m.Command != "" || strings.Contains(m.FailReason, "alice") || strings.Contains(m.FailReason, "42") {
		t.Fatalf("values sent with query text collection off: %+v", m)
	}
	if m.MutationID != "mutation_7.txt" || m.Table != "orders" || m.PartsToDo != 3 || m.FailedAt == nil ||
		!strings.HasPrefix(m.FailReason, "CANNOT_PARSE_TEXT") {
		t.Fatalf("the mutation lost what the dashboard shows: %+v", m)
	}
	if got := reasonWithoutText("something odd 'secret'"); strings.Contains(got, "secret") || got == "" {
		t.Fatalf("reason without an error name: %q", got)
	}
	if got := reasonWithoutText("Code: 6. DB::Exception: Cannot parse 'X (TOPSECRET)' as UInt32. (CANNOT_PARSE_TEXT) (version 25.8.1)"); got !=
		"CANNOT_PARSE_TEXT (the details stay on the server: query text collection is off)" {
		t.Fatalf("a value that looks like an error name: %q", got)
	}
	if reasonWithoutText("") != "" {
		t.Fatal("a mutation that hasn't failed got a reason")
	}
}
