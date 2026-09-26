package pgbackrest

import (
	"strings"
	"testing"
)

func testConfig(r Repo) string {
	return RenderConfig(r, ConfigInput{Stanza: "app", DataDir: "/var/lib/postgresql/18/main", Port: 5432,
		SocketDir: "/var/run/postgresql", User: "postgres", RetentionFull: 2})
}

func TestRenderConfigSessionToken(t *testing.T) {
	if strings.Contains(testConfig(testRepo), "repo1-s3-token") {
		t.Error("a long-lived key must not get a token line")
	}
	r := testRepo
	r.Token = "SESSION"
	if !strings.Contains(testConfig(r), "repo1-s3-key-secret=SECRET\nrepo1-s3-token=SESSION\n") {
		t.Errorf("token missing:\n%s", testConfig(r))
	}
	r.Token = "x\n[evil]"
	if r.Validate() == nil {
		t.Error("a token with a newline must be rejected")
	}
}

// Rotation replaces only the credentials, keeping everything else byte for
// byte, and adds or drops the session token.
func TestSetCredentials(t *testing.T) {
	r := testRepo
	r.Token = "OLDTOKEN"
	conf := testConfig(r)

	next := r
	next.Key, next.KeySecret, next.Token = "AKID2", "SECRET2", "NEWTOKEN"
	got, ok := SetCredentials(conf, next)
	if !ok {
		t.Fatal("SetCredentials found no key")
	}
	if want := testConfig(next); got != want {
		t.Errorf("rotated config differs from a fresh render:\n%s\nwant:\n%s", got, want)
	}

	next.Token = ""
	got, _ = SetCredentials(conf, next)
	if strings.Contains(got, "repo1-s3-token") || got != testConfig(next) {
		t.Errorf("dropping the token:\n%s", got)
	}
	// From a long-lived key to temporary credentials.
	next.Token = "T3"
	got, _ = SetCredentials(testConfig(testRepo), next)
	if got != testConfig(next) {
		t.Errorf("adding a token:\n%s", got)
	}
	if _, ok := SetCredentials("[global]\nlog-level-console=info\n", next); ok {
		t.Error("a config without repo1-s3-key is not ours")
	}
}

func TestLocation(t *testing.T) {
	conf := testConfig(testRepo)
	if got, want := Location(conf), testRepo.Location("app"); got != want || got != "acct.eu.r2.cloudflarestorage.com:/rowsafe-backups/rowsafe/app" {
		t.Errorf("Location(conf) = %q, Repo.Location = %q", got, want)
	}
	r := testRepo
	r.Port = 9000
	r.Key = "OTHER" // credentials don't matter
	if Location(testConfig(r)) != r.Location("app") || r.Location("app") == testRepo.Location("app") {
		t.Error("the port is part of the location")
	}
	r = testRepo
	r.PathPrefix = "/orgs/org_1"
	if Location(testConfig(r)) != "acct.eu.r2.cloudflarestorage.com:/rowsafe-backups/orgs/org_1/app" {
		t.Errorf("got %q", Location(testConfig(r)))
	}
	r.PathPrefix = "/"
	if Location(testConfig(r)) != r.Location("app") || !strings.HasSuffix(r.Location("app"), "rowsafe-backups/app") {
		t.Errorf("root prefix: %q vs %q", Location(testConfig(r)), r.Location("app"))
	}
	if Location("nothing") != "" {
		t.Error("no bucket, no location")
	}
}

func TestRepoID(t *testing.T) {
	a := testRepo.ID()
	if len(a) != 12 || strings.ContainsAny(a, "/.") {
		t.Fatalf("ID %q", a)
	}
	r := testRepo
	r.Key, r.KeySecret, r.CipherPass = "k", "s", "p"
	if r.ID() != a {
		t.Error("credentials must not change the ID")
	}
	r.Bucket = "other"
	if r.ID() == a {
		t.Error("another bucket is another repository")
	}
	if (Repo{}).ID() != "" {
		t.Error("no bucket, no ID")
	}
}
