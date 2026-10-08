package mysql

import (
	"testing"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
)

// TestStoreFolder: a database's objects are under <prefix>/<engine>/<name>/
// in a bucket of the customer's, and under <prefix>/<name>/ in Rowsafe
// Storage, the folder it keeps (and deletes) per database, so a database
// named like an engine never shares a folder with that engine's databases.
func TestStoreFolder(t *testing.T) {
	repo := pgbackrest.Repo{Endpoint: "minio", Port: 9000, Bucket: "b", Key: "k", KeySecret: "s",
		CipherPass: "a-long-enough-test-passphrase", PathPrefix: "/rowsafe"}
	own, err := openStore(repo, "mariadb", "shop", 16)
	if err != nil {
		t.Fatal(err)
	}
	if own.prefix != "rowsafe/mariadb/shop/" {
		t.Errorf("own bucket: %s", own.prefix)
	}
	repo.PathPrefix, repo.Token, repo.Managed = "/orgs/org_1", "session", true
	managed, err := openStore(repo, "mariadb", "shop", 16)
	if err != nil {
		t.Fatal(err)
	}
	if managed.prefix != "orgs/org_1/shop/" || managed.creds != "k\x00session" {
		t.Errorf("Rowsafe Storage: %s %q", managed.prefix, managed.creds)
	}
}
