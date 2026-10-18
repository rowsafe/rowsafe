package protocol

import "time"

// ---- Restore from the bucket (a server on its own) ----
//
// On a server installed with --no-account, `sudo rowsafe restore NAME
// --from-bucket` restores a database whose own server is lost (or that is
// moving here) from its backups in this server's own storage: this server
// was installed with the same bucket and passphrase as the old one, so its
// agent reads the backups with its own settings, as a lost source's on
// another server (ForkRestoreParams.OwnRepo). The passphrase was given on
// this server and never leaves it; a wrong one fails here, plainly.
//
// The database is restored into an empty PostgreSQL cluster here (its own
// empty data kept aside) or a new one, then protected like any database:
// backups start for it in a new folder of the bucket; the old server's
// backups stay as they are.
//
//	POST /v1/restores/from-bucket   BucketRestoreRequest -> 202 BucketRestoreResponse

// BucketRestoreRequest restores a database from the bucket onto this server.
type BucketRestoreRequest struct {
	// Source is the database's name on the old server (its backup folder);
	// Folder its folder when that isn't the name (a fresh start).
	Source string `json:"source"`
	Folder string `json:"folder,omitempty"`
	// Name is the restored database's name here (default: Source).
	Name string `json:"name,omitempty"`
	// At is the point to restore; nil: the latest the backups hold.
	At *time.Time `json:"at,omitempty"`
	// Port is the empty cluster to restore into (0: the only one Rowsafe
	// may restart here); NewCluster creates one instead (root allowed it:
	// rowsafe-allow create-cluster), on Port when set.
	Port       int  `json:"port,omitempty"`
	NewCluster bool `json:"new_cluster,omitempty"`
	// Confirm is Name: the cluster's own (empty) data is set aside.
	Confirm string `json:"confirm"`
}

// BucketRestoreResponse is the queued restore: its task (fork_restore),
// and where it goes.
type BucketRestoreResponse struct {
	Task      TaskView `json:"task"`
	Name      string   `json:"name"`
	Placement string   `json:"placement"` // ForkEmptyCluster | ForkNewCluster
	Port      int      `json:"port,omitempty"`
}
