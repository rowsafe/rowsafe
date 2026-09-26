package protocol

import "testing"

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
