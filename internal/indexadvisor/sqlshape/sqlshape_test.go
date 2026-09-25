package sqlshape

import (
	"slices"
	"testing"

	"github.com/rowsafe/rowsafe/internal/indexadvisor"
)

func preds(s indexadvisor.Shape, kind string) []string {
	var out []string
	for _, p := range s.Preds {
		if p.Kind == kind {
			out = append(out, p.Col.Qual+"."+p.Col.Col)
		}
	}
	slices.Sort(out)
	return out
}

func TestParseSelect(t *testing.T) {
	s := Parse(`SELECT o.id, o.total FROM orders o JOIN customers c ON c.id = o.customer_id
		WHERE o.customer_id = $1 AND o.created_at > $2 AND o.deleted_at IS NULL AND (o.status = $3 OR o.status = $4)
		ORDER BY o.created_at DESC LIMIT $5`)
	if s.Error != "" || s.Kind != "select" || !s.ReadOnly {
		t.Fatalf("shape = %+v", s)
	}
	if len(s.Relations) != 2 || s.Relations[0].Name != "orders" || s.Relations[0].Alias != "o" {
		t.Fatalf("relations = %+v", s.Relations)
	}
	if got := preds(s, indexadvisor.PredEq); !slices.Equal(got, []string{"o.customer_id"}) {
		t.Errorf("eq = %v", got)
	}
	if got := preds(s, indexadvisor.PredRange); !slices.Equal(got, []string{"o.created_at"}) {
		t.Errorf("range = %v", got)
	}
	if got := preds(s, indexadvisor.PredJoin); !slices.Equal(got, []string{"c.id", "o.customer_id"}) {
		t.Errorf("join = %v", got)
	}
	if got := preds(s, indexadvisor.PredIsNull); !slices.Equal(got, []string{"o.deleted_at"}) {
		t.Errorf("isnull = %v", got)
	}
	if len(s.Sort) != 1 || s.Sort[0].Col.Col != "created_at" || !s.Sort[0].Desc {
		t.Errorf("sort = %+v", s.Sort)
	}
	if !s.Limit || s.LimitParam != 5 || s.MaxParam != 5 {
		t.Errorf("limit = %v %d, max param %d", s.Limit, s.LimitParam, s.MaxParam)
	}
	for _, p := range s.Preds {
		if p.Kind == indexadvisor.PredEq && p.Param != 1 {
			t.Errorf("eq param = %d", p.Param)
		}
	}
}

func TestParseOther(t *testing.T) {
	cases := map[string]string{
		"UPDATE accounts SET balance = balance - $1 WHERE id = $2":            "update",
		"DELETE FROM sessions WHERE expires_at < $1":                          "delete",
		"INSERT INTO t (a) SELECT a FROM s WHERE b = $1":                      "insert",
		"SELECT * FROM jobs WHERE state = ANY($1) FOR UPDATE SKIP LOCKED":     "select",
		"WITH x AS (DELETE FROM q WHERE id = $1 RETURNING *) SELECT * FROM x": "select",
	}
	for q, kind := range cases {
		s := Parse(q)
		if s.Kind != kind {
			t.Errorf("%s: kind %q, want %q", q, s.Kind, kind)
		}
		if s.ReadOnly {
			t.Errorf("%s: read-only", q)
		}
	}
	if s := Parse("SELECT $1 FROM"); s.Error == "" || s.Kind != "other" {
		t.Errorf("syntax error: %+v", s)
	}
	if s := Parse("SELECT 1; SELECT 2"); s.Error == "" {
		t.Errorf("two statements: %+v", s)
	}
	s := Parse("SELECT count(*) FROM jobs WHERE queue = $1 AND id IN (SELECT job_id FROM runs WHERE started_at >= $2) AND pg_sleep(1) IS NOT NULL")
	if !slices.Contains(s.Funcs, "pg_sleep") || !slices.Contains(s.Funcs, "count") {
		t.Errorf("funcs = %v", s.Funcs)
	}
	if got := preds(s, indexadvisor.PredRange); !slices.Equal(got, []string{".started_at"}) {
		t.Errorf("range in subquery = %v", got)
	}
	if got := preds(s, indexadvisor.PredJoin); !slices.Equal(got, []string{".id"}) {
		t.Errorf("semi-join = %v", got)
	}
	s = Parse("SELECT * FROM events e WHERE e.account_id = $1 ORDER BY lower(e.name)")
	if len(s.Sort) != 0 || !slices.Contains(s.Star, "") {
		t.Errorf("expression sort or star: %+v", s)
	}
	s = Parse("SELECT id FROM t WHERE a IN ($1, $2, $3) AND b BETWEEN $4 AND $5")
	if got := preds(s, indexadvisor.PredEq); !slices.Equal(got, []string{".a"}) {
		t.Errorf("in = %v", got)
	}
	if got := preds(s, indexadvisor.PredRange); !slices.Equal(got, []string{".b"}) {
		t.Errorf("between = %v", got)
	}
	// PostgreSQL 18 squashes IN lists into a comment.
	s = Parse("SELECT id FROM t WHERE a IN ($1 /*, ... */)")
	if got := preds(s, indexadvisor.PredEq); !slices.Equal(got, []string{".a"}) {
		t.Errorf("squashed in = %v (%s)", got, s.Error)
	}
}
