package protocol

import "testing"

func TestScrubPlan(t *testing.T) {
	for in, want := range map[string]string{
		"(status = $1)":                         "(status = $1)",
		"((status)::text = 'paid'::text)":       "((status)::text = '?'::text)",
		"(note = 'it''s'::text)":                "(note = '?'::text)",
		"(amount > 100.5)":                      "(amount > ?)",
		"(t1.col_2 = $12)":                      "(t1.col_2 = $12)",
		"(x = E'a\\nb')":                        "(x = '?')",
		"(id = ANY ('{1,2,3}'::integer[]))":     "(id = ANY ('?'::integer[]))",
		"(created_at > (now() - $1::interval))": "(created_at > (now() - $1::interval))",
		"(n < -3)":                              "(n < ?)",
	} {
		if got := ScrubPlan(in); got != want {
			t.Errorf("ScrubPlan(%q) = %q, want %q", in, got, want)
		}
	}
	if PlanHasLiterals("Filter: (a = '?'::text)") || !PlanHasLiterals("Filter: (a = 'x'::text)") {
		t.Error("PlanHasLiterals")
	}
}
