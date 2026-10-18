package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe restore NAME --from-bucket, on a server on its own: a database
// whose own server is lost, or that moves here, restored from its backups
// in this server's storage (installed with the same bucket and passphrase
// as the old server; protocol/restore_bucket.go). Then it is protected here.

// fromBucket reports whether a restore's args ask for --from-bucket.
func fromBucket(args []string) bool {
	return slices.ContainsFunc(args, func(a string) bool {
		return a == "--from-bucket" || a == "-from-bucket" || strings.HasPrefix(a, "--from-bucket=") || strings.HasPrefix(a, "-from-bucket=")
	})
}

// errFromBucketElsewhere: --from-bucket runs on the new server itself.
var errFromBucketElsewhere = errors.New("--from-bucket runs on the server the database goes to: install Rowsafe there with --no-account and the same storage and passphrase " +
	"as the old server, then run sudo rowsafe restore NAME --from-bucket on it. With the dashboard, use Restore to another server there")

// bucketWait is how long the CLI follows the restored database's setup.
var bucketWait = 15 * time.Minute

func restoreFromBucketCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	_ = fs.Bool("from-bucket", true, "restore from this server's backup storage (the old server's bucket and passphrase)")
	as := fs.String("as", "", "the restored database's name here (default: its name on the old server)")
	to := fs.String("to", "", `the point: a time ("14:04", "10m ago", "2026-09-24 14:04"); default: the latest in the backups`)
	folder := fs.String("folder", "", "its backup folder in the bucket, when it isn't the name (a fresh start: shop-20260901-120000)")
	port := fs.Int("port", 0, "the empty PostgreSQL to restore into (default: the only one Rowsafe may restart here)")
	newCluster := fs.Bool("new-cluster", false, "create a new PostgreSQL cluster for it instead (root allowed it: rowsafe-allow create-cluster)")
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	noWait := fs.Bool("no-wait", false, "return once the restore is queued")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if !onServer {
		return errFromBucketElsewhere
	}
	if len(pos) != 1 {
		return newUsageError("which database? sudo rowsafe restore NAME --from-bucket, with its name on the old server")
	}
	req := protocol.BucketRestoreRequest{Source: pos[0], Folder: *folder, Name: *as, Port: *port, NewCluster: *newCluster}
	if req.Name == "" {
		req.Name = req.Source
	}
	point := "the latest point its backups hold"
	if strings.TrimSpace(*to) != "" {
		at, err := parseRewindTime(*to)
		if err != nil {
			return newUsageError(`--to takes a time here ("14:04", "10m ago", "2026-09-24 14:04"): the old server's Marks were kept on it. Leave it out for the latest point`)
		}
		req.At, point = &at, describeTime(at)
	}
	where := "the empty PostgreSQL Rowsafe may restart here (its own empty data is kept aside)"
	switch {
	case req.NewCluster:
		where = "a new PostgreSQL cluster"
	case req.Port != 0:
		where = fmt.Sprintf("the empty PostgreSQL on port %d (its own empty data is kept aside)", req.Port)
	}
	fmt.Printf("Restore %s from this server's backup storage, as it was at %s, into %s.\n", req.Source, point, where)
	fmt.Println("  - It reads the backups with this server's own storage settings: the same bucket and passphrase as the old server.")
	fmt.Println("    Nothing is sent anywhere.")
	if req.Name != req.Source {
		fmt.Printf("  - It is added here as %s and protected: backups, Marks and Proof.\n", req.Name)
	} else {
		fmt.Printf("  - It is added here as %s and protected: its backups start in a new folder; the old ones stay as they are.\n", req.Name)
	}
	if err := confirmTypedAs(*yes, req.Name, fmt.Sprintf("Type the database name (%s) to restore it here: ", req.Name)); err != nil {
		return err
	}
	req.Confirm = req.Name
	resp, err := c.RestoreFromBucket(ctx, req)
	if err != nil {
		return apiErr(err)
	}
	if *noWait {
		fmt.Printf("Restore queued (task %s): sudo rowsafe task %s\n", resp.Task.ID, resp.Task.ID)
		return nil
	}
	status := ""
	done, err := waitTask(ctx, c, resp.Task.ID, func(v protocol.TaskView) {
		if v.Status == status {
			return
		}
		status = v.Status
		switch v.Status {
		case protocol.StatusQueued:
			fmt.Fprintf(os.Stderr, "Waiting for the agent to start the restore (task %s)...\n", v.ID)
		case protocol.StatusRunning:
			fmt.Fprintln(os.Stderr, "Restoring: downloading the backup and replaying the changes after it...")
		}
	})
	if err != nil {
		return err
	}
	var res protocol.ForkRestoreResult
	_ = json.Unmarshal(done.Result, &res)
	if done.Status != protocol.StatusSucceeded {
		fmt.Printf("The restore didn't work: %s\n", orText(res.Summary, orText(done.Error, "the task ended as "+done.Status)))
		return exitError(1)
	}
	fmt.Printf("Restored %s into the PostgreSQL on port %d (PostgreSQL %d).\n", req.Source, res.Port, res.Major)
	if res.RecoveredTo != nil {
		fmt.Printf("It has everything up to the last change its backups hold: %s.\n", describeTime(*res.RecoveredTo))
	}
	return followProtection(ctx, c, req.Name)
}

// followProtection waits for a newly added database to be protected,
// saying what happens.
func followProtection(ctx context.Context, c *client.Client, name string) error {
	deadline := time.Now().Add(bucketWait)
	last := ""
	for {
		db, err := c.Database(ctx, name)
		if err == nil && db.Status != last {
			last = db.Status
			switch db.Status {
			case protocol.DBActive:
				fmt.Printf("%s is protected here: the first full backup and Proof run now (sudo rowsafe status %s).\n", name, name)
				return nil
			case protocol.DBAwaitingRestart:
				fmt.Printf("Turning on backups for %s needs a restart: sudo rowsafe restart %s (it asks first).\n", name, name)
				return nil
			default:
				fmt.Fprintf(os.Stderr, "Turning on backups for %s (%s)...\n", name, db.Status)
			}
		}
		if ts, terr := c.Tasks(ctx, name, 10); terr == nil {
			if i := slices.IndexFunc(ts, func(t protocol.TaskView) bool { return t.Type == protocol.TaskAdopt }); i >= 0 && ts[i].Status == protocol.StatusFailed {
				fmt.Printf("%s is restored, but turning on its backups failed: %s\nsudo rowsafe add %s postgres://... tries again.\n",
					name, orText(ts[i].Error, "see sudo rowsafe tasks "+name), name)
				return exitError(1)
			}
		}
		if time.Now().After(deadline) {
			fmt.Printf("%s is restored; its backups are still being set up: sudo rowsafe status %s\n", name, name)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// rowsafe proof NAME --from-bucket, on another server on its own: a
// restore test of NAME's backups here, from this server's storage (the same
// bucket and passphrase). Nothing is added or changed on either server.
func proofFromBucketCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("proof", flag.ContinueOnError)
	_ = fs.Bool("from-bucket", true, "test the backups in this server's storage (the database's own server's bucket and passphrase)")
	folder := fs.String("folder", "", "its backup folder in the bucket, when it isn't the name (a fresh start: shop-20260901-120000)")
	noWait := fs.Bool("no-wait", false, "return once the test is queued")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if !onServer {
		return errProofFromBucketElsewhere
	}
	if len(pos) != 1 {
		return newUsageError("which database? sudo rowsafe proof NAME --from-bucket, with its name on its own server")
	}
	name := pos[0]
	fmt.Printf("Restore test of %s's backups on this server: the newest point is restored into a scratch copy from this server's\n", name)
	fmt.Println("storage (the same bucket and passphrase), started privately and checked, then deleted. Nothing else changes.")
	resp, err := c.ProofFromBucket(ctx, protocol.BucketProofRequest{Source: name, Folder: *folder})
	if err != nil {
		return apiErr(err)
	}
	if *noWait {
		fmt.Printf("Restore test queued (task %s): sudo rowsafe task %s\n", resp.Task.ID, resp.Task.ID)
		return nil
	}
	status := ""
	done, err := waitTask(ctx, c, resp.Task.ID, func(v protocol.TaskView) {
		if v.Status != status && v.Status == protocol.StatusRunning {
			fmt.Fprintln(os.Stderr, "Restoring and checking...")
		}
		status = v.Status
	})
	if err != nil {
		return err
	}
	var res protocol.ForkRestoreResult
	_ = json.Unmarshal(done.Result, &res)
	d := res.Drill
	if d == nil {
		fmt.Printf("The restore test didn't run: %s\n", orText(done.Error, "the task ended as "+done.Status))
		return exitError(1)
	}
	verdict := "passed"
	if !d.Passed || done.Status != protocol.StatusSucceeded {
		verdict = "FAILED"
	}
	fmt.Printf("Restore test of %s on this server: %s in %s (backup %s)\n", name, verdict, humanDurationSeconds(d.DurationSeconds), orText(d.BackupLabel, "-"))
	if d.RecoveredTo != nil {
		fmt.Printf("  Recovered to:  %s\n", describeTime(*d.RecoveredTo))
	}
	for _, db := range d.Databases {
		fmt.Printf("  Database %-20s restored, %d tables\n", db.Name, db.RestoredTables)
	}
	for _, f := range d.Failures {
		fmt.Printf("  problem: %s\n", f)
	}
	for _, w := range d.Warnings {
		fmt.Printf("  note:    %s\n", w)
	}
	if verdict != "passed" {
		return exitError(1)
	}
	fmt.Printf("Its own server isn't asked, so the databases aren't compared with production there: its weekly Proof does that.\n")
	return nil
}

// errProofFromBucketElsewhere: proof --from-bucket runs on the other server.
var errProofFromBucketElsewhere = errors.New("--from-bucket runs on another server installed with Rowsafe (--no-account) and the same storage and passphrase " +
	"as the database's own server: sudo rowsafe proof NAME --from-bucket there")
