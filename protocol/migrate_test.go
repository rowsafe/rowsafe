package protocol

import (
	"strings"
	"testing"
)

func TestDetectMigrateProvider(t *testing.T) {
	cases := map[string]string{
		"db-postgresql-fra1-12345-do-user-1-0.b.db.ondigitalocean.com": "digitalocean",
		"mydb.abc123xyz.eu-central-1.rds.amazonaws.com":                "rds",
		"mycluster.cluster-abc123.us-east-1.rds.amazonaws.com":         "aurora",
		"mycluster.cluster-ro-abc123.us-east-1.rds.amazonaws.com":      "aurora",
		"db.abcdefghijklmnop.supabase.co":                              "supabase",
		"aws-0-eu-central-1.pooler.supabase.com":                       "supabase",
		"ep-cool-darkness-123456.eu-central-1.aws.neon.tech":           "neon",
		"ec2-1-2-3-4.compute-1.amazonaws.com":                          "heroku",
		"dpg-abc123-a.frankfurt-postgres.render.com":                   "render",
		"monorail.proxy.rlwy.net":                                      "railway",
		"p.abc123.db.postgresbridge.com":                               "crunchy",
		"myserver.postgres.database.azure.com":                         "azure",
		"10.0.0.5":                                                     "other",
		"DB.ABC.SUPABASE.CO.":                                          "supabase",
	}
	for host, want := range cases {
		if got := DetectMigrateProvider(host, nil).ID; got != want {
			t.Errorf("DetectMigrateProvider(%q) = %q, want %q", host, got, want)
		}
	}
	if got := DetectMigrateProvider("34.1.2.3", map[string]bool{"cloudsql.logical_decoding": true}).ID; got != "cloudsql" {
		t.Errorf("Cloud SQL by setting = %q", got)
	}
	if got := DetectMigrateProvider("10.1.2.3", map[string]bool{"rds.logical_replication": true}).ID; got != "rds" {
		t.Errorf("RDS by setting = %q", got)
	}
	if MigrateProviderByID("nope").ID != "other" || MigrateProviderByID("neon").Name != "Neon" {
		t.Error("MigrateProviderByID")
	}
	for _, p := range append(MigrateProviders, otherProvider) {
		if p.Docs == "" || p.Name == "" {
			t.Errorf("provider %s lacks docs or name", p.ID)
		}
	}
}

func TestParseSQLiteSource(t *testing.T) {
	tok := "eyJhbGciOiJFZERTQSJ9.eyJhIjoicncifQ.c2lnbmF0dXJl-_x"
	for in, want := range map[string]SQLiteSource{
		"libsql://app-acme.turso.io?authToken=" + tok:  {Provider: SQLiteSourceTurso, URL: "https://app-acme.turso.io", Token: tok},
		" https://App-Acme.turso.io/?authToken=" + tok: {Provider: SQLiteSourceTurso, URL: "https://app-acme.turso.io", Token: tok},
		"http://10.0.0.5:8080?authToken=" + tok:        {Provider: SQLiteSourceLibSQL, URL: "http://10.0.0.5:8080", Token: tok},
		"d1://0123456789abcdef0123456789ABCDEF/1b2c3d4e-0000-4000-8000-0123456789ab?token=cf_TOKEN-123": {Provider: SQLiteSourceD1,
			AccountID: "0123456789abcdef0123456789abcdef", DatabaseID: "1b2c3d4e-0000-4000-8000-0123456789ab", Token: "cf_TOKEN-123"},
	} {
		got, err := ParseSQLiteSource(in)
		if err != nil || got != want {
			t.Errorf("ParseSQLiteSource(%q) = %+v, %v", in, got, err)
			continue
		}
		again, err := ParseSQLiteSource(got.String())
		if err != nil || again != got {
			t.Errorf("round trip of %q: %+v %v", got.String(), again, err)
		}
	}
	for _, bad := range []string{"", "postgres://u:p@h/db", "libsql://app-acme.turso.io", "libsql://app-acme.turso.io/db?authToken=" + tok,
		"http://app-acme.turso.io?authToken=" + tok, "libsql://app-acme.turso.io?authToken=bad%20token%20here",
		"d1://nope/1b2c3d4e-0000-4000-8000-0123456789ab?token=abcdefgh1", "d1://0123456789abcdef0123456789abcdef/nope?token=abcdefgh1",
		"d1://0123456789abcdef0123456789abcdef/1b2c3d4e-0000-4000-8000-0123456789ab"} {
		if _, err := ParseSQLiteSource(bad); err == nil {
			t.Errorf("ParseSQLiteSource(%q) accepted", bad)
		} else if strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "bad token") {
			t.Errorf("the error shows the token: %v", err)
		}
	}
	s, _ := ParseSQLiteSource("libsql://app-acme.turso.io?authToken=" + tok)
	if s.Database() != "app-acme" || s.Host() != "app-acme.turso.io" || MigrateProviderByID("d1").Name != "Cloudflare D1" {
		t.Errorf("display: %q %q", s.Database(), s.Host())
	}
}
