package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe db: the databases, users and extensions inside a database server
// (Databases & users). A new password is generated on the server and
// encrypted there to a key pair this command makes in memory, so only this
// terminal ever sees it; the control plane only relays the ciphertext.

func dbCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return dbList(ctx, c, args)
	}
	switch args[0] {
	case "ls":
		return dbList(ctx, c, args[1:])
	case "create":
		return dbCreate(ctx, c, args[1:])
	case "drop":
		return dbDrop(ctx, c, args[1:])
	case "users":
		return dbUsers(ctx, c, args[1:])
	case "user":
		if len(args) > 1 {
			switch args[1] {
			case "add":
				return dbUserAdd(ctx, c, args[2:])
			case "password":
				return dbUserPassword(ctx, c, args[2:])
			case "remove":
				return dbUserRemove(ctx, c, args[2:])
			}
		}
		return fmt.Errorf("which one? rowsafe db user add | password | remove\n%s", strings.TrimSpace(helpFor([]string{"db user"})))
	case "ext":
		return dbExt(ctx, c, args[1:])
	}
	return fmt.Errorf("unknown command %q. The db commands:\n%s", "db "+args[0], strings.TrimSpace(helpFor([]string{"db"})))
}

// onFlag is --on NAME: the Rowsafe database (server) to act on; the usual
// NAME rules apply when it is omitted.
func onFlag(fs *flag.FlagSet) *string {
	return fs.String("on", "", "the database server in Rowsafe (default: see `rowsafe help names`)")
}

// dbRun queues one action and waits for it; with a password, it opens the
// sealed secret with key.
func dbRun(ctx context.Context, c *client.Client, server string, p protocol.DBAdminParams, key *ecdh.PrivateKey) (protocol.TaskView, *protocol.DBAdminResult, *protocol.DBSecret, error) {
	if key != nil {
		p.PublicKey = protocol.EncodeSealKey(key.PublicKey())
	}
	resp, err := c.DBAdmin(ctx, server, p)
	if err != nil {
		return protocol.TaskView{}, nil, nil, err
	}
	if len(resp.Tasks) == 0 {
		return protocol.TaskView{}, nil, nil, errors.New("the control plane queued nothing")
	}
	var last protocol.TaskView
	for _, t := range resp.Tasks {
		status := ""
		last, err = c.WaitTask(ctx, t.ID, func(v protocol.TaskView) {
			if v.Status == status {
				return
			}
			status = v.Status
			switch {
			case v.Type == protocol.TaskRestorePoint && v.Status == protocol.StatusQueued:
				fmt.Fprintln(os.Stderr, "Saving a Mark first, so you can get it back...")
			case v.Status == protocol.StatusQueued:
				fmt.Fprintln(os.Stderr, "Waiting for the agent...")
			case v.Status == protocol.StatusRunning:
				fmt.Fprintln(os.Stderr, "Running...")
			}
		})
		if err != nil {
			return last, nil, nil, err
		}
		if last.Status != protocol.StatusSucceeded {
			break
		}
	}
	var res *protocol.DBAdminResult
	if len(last.Result) > 0 && last.Type == protocol.TaskDBAdmin {
		res = new(protocol.DBAdminResult)
		if err := json.Unmarshal(last.Result, res); err != nil {
			return last, nil, nil, err
		}
	}
	if last.Status != protocol.StatusSucceeded {
		return last, res, nil, errors.New(orText(last.Error, "the task "+last.Status))
	}
	if key == nil || res == nil || res.Connection == nil {
		return last, res, nil, nil
	}
	sealed, err := c.DBAdminSecret(ctx, server, last.ID)
	if err != nil {
		return last, res, nil, fmt.Errorf("the password was set, but fetching it failed (%w); run `rowsafe db user password %s` for a new one", err, res.Connection.User)
	}
	plain, err := protocol.Open(key, []byte(last.ID), &sealed)
	if err != nil {
		return last, res, nil, err
	}
	var s protocol.DBSecret
	if err := json.Unmarshal(plain, &s); err != nil {
		return last, res, nil, err
	}
	return last, res, &s, nil
}

func newSealKey() (*ecdh.PrivateKey, error) { return ecdh.P256().GenerateKey(rand.Reader) }

func printDBResult(res *protocol.DBAdminResult) {
	if res == nil {
		return
	}
	fmt.Println(res.Summary)
	for _, d := range res.Details {
		fmt.Println("  " + d)
	}
}

// printSecret shows a new password, once.
func printSecret(s *protocol.DBSecret) {
	if s == nil {
		return
	}
	fmt.Printf("\nConnection string for %s (save it now: Rowsafe doesn't keep the password and can't show it again):\n\n", s.User)
	fmt.Printf("  %s\n\n", s.URL)
	fmt.Printf("  user      %s\n  password  %s\n  database  %s\n  host      %s\n  port      %d\n  sslmode   %s\n", s.User, s.Password, s.Database, s.Host, s.Port, s.SSLMode)
	fmt.Printf("\nIn a .env file:\n  DATABASE_URL=%s\n", s.URL)
}

// nameList is a repeatable, comma-separated flag.
type nameList []string

func (l *nameList) String() string { return strings.Join(*l, ",") }
func (l *nameList) Set(v string) error {
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			*l = append(*l, x)
		}
	}
	return nil
}

// dbList: rowsafe db [ls] [--on NAME] [--json]
func dbList(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("db", flag.ContinueOnError)
	on := onFlag(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := positionals(fs, args); err != nil {
		return err
	}
	server, err := resolveDatabase(ctx, c, *on)
	if err != nil {
		return err
	}
	_, res, _, err := dbRun(ctx, c, server, protocol.DBAdminParams{Action: protocol.DBAdminList}, nil)
	if err != nil {
		return err
	}
	if res == nil || res.Inventory == nil {
		return errors.New("the agent didn't send the list")
	}
	inv := res.Inventory
	if *asJSON {
		return printJSON(inv)
	}
	fmt.Printf("Databases on %s (PostgreSQL %s). Every one is backed up with the server.\n\n", server, inv.ServerVersion)
	t := newTable("DATABASE", "OWNER", "SIZE", "CONNECTIONS", "EXTENSIONS")
	for _, d := range inv.Databases {
		if d.IsTemplate {
			continue
		}
		var exts []string
		for _, e := range d.Extensions {
			if e.Name != "plpgsql" {
				exts = append(exts, e.Name)
			}
		}
		name := d.Name
		if d.System {
			name += " (PostgreSQL's)"
		}
		t.row(name, d.Owner, humanBytes(d.SizeBytes), fmt.Sprint(d.Connections), orText(strings.Join(exts, ", "), "-"))
	}
	t.flush()
	fmt.Println()
	printUsers(inv)
	return nil
}

func printUsers(inv *protocol.DBInventory) {
	t := newTable("USER", "CAN LOG IN", "DATABASES", "PASSWORD", "NOTE")
	for _, u := range inv.Users {
		note := u.SystemReason
		if note == "" && u.Superuser {
			note = "superuser"
		}
		t.row(u.Name, yesNo(u.Login), orText(strings.Join(u.Databases, ", "), "-"), u.Password, note)
	}
	t.flush()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// dbUsers: rowsafe db users [--on NAME] [--json]
func dbUsers(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("db users", flag.ContinueOnError)
	on := onFlag(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := positionals(fs, args); err != nil {
		return err
	}
	server, err := resolveDatabase(ctx, c, *on)
	if err != nil {
		return err
	}
	_, res, _, err := dbRun(ctx, c, server, protocol.DBAdminParams{Action: protocol.DBAdminList}, nil)
	if err != nil {
		return err
	}
	if res == nil || res.Inventory == nil {
		return errors.New("the agent didn't send the list")
	}
	if *asJSON {
		return printJSON(res.Inventory.Users)
	}
	printUsers(res.Inventory)
	return nil
}

// dbCreate: rowsafe db create DB [--owner USER] [--extension EXT]... [--template T] [--locale L] [--host H] [--on NAME]
func dbCreate(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("db create", flag.ContinueOnError)
	on := onFlag(fs)
	owner := fs.String("owner", "", "an existing user to own it (default: a new user named like the database)")
	newOwner := fs.String("new-owner", "", "the name of the new user that owns it (default: the database's name)")
	var exts nameList
	fs.Var(&exts, "extension", "an extension to turn on (repeat, or comma-separated)")
	template := fs.String("template", "", "template1 (default) or template0")
	locale := fs.String("locale", "", "collation, e.g. en_US.UTF-8 (default: the server's)")
	host := fs.String("host", "", "the address to put in the connection string (default: the one apps use)")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: rowsafe db create DB [--owner USER] [--extension EXT]... [--on NAME]")
	}
	p := protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: pos[0], Extensions: exts,
		Template: *template, Locale: *locale, Host: *host}
	if *owner != "" {
		p.Owner = *owner
	} else {
		p.CreateOwner, p.Owner = true, *newOwner
	}
	if err := protocol.ValidateDBAdmin(withKeyPlaceholder(p)); err != nil {
		return err
	}
	server, err := resolveDatabase(ctx, c, *on)
	if err != nil {
		return err
	}
	var key *ecdh.PrivateKey
	if p.CreateOwner {
		if key, err = newSealKey(); err != nil {
			return err
		}
	}
	_, res, secret, err := dbRun(ctx, c, server, p, key)
	printDBResult(res)
	if err != nil {
		return err
	}
	printSecret(secret)
	return nil
}

// withKeyPlaceholder lets ValidateDBAdmin check params before the key
// exists.
func withKeyPlaceholder(p protocol.DBAdminParams) protocol.DBAdminParams {
	if protocol.DBAdminMakesPassword(p) && p.PublicKey == "" {
		if k, err := newSealKey(); err == nil {
			p.PublicKey = protocol.EncodeSealKey(k.PublicKey())
		}
	}
	return p
}

// dbDrop: rowsafe db drop DB [--yes] [--on NAME]
func dbDrop(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("db drop", flag.ContinueOnError)
	on := onFlag(fs)
	yes := fs.Bool("yes", false, "don't ask (you still confirm with the name: --yes means DB is the confirmation)")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: rowsafe db drop DB [--on NAME]")
	}
	name := pos[0]
	server, err := resolveDatabase(ctx, c, *on)
	if err != nil {
		return err
	}
	if !*yes {
		if !stdinIsTerminal() {
			return errors.New("removing a database deletes everything in it: pass --yes to confirm")
		}
		fmt.Printf("This removes the database %s on %s and everything in it. Rowsafe saves a Mark first, so you can get it back with Rewind.\n", name, server)
		fmt.Printf("Type the database's name (%s) to remove it: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was removed")
		}
	}
	_, res, _, err := dbRun(ctx, c, server, protocol.DBAdminParams{Action: protocol.DBAdminDropDatabase, Database: name, Confirm: name}, nil)
	printDBResult(res)
	return err
}

// dbUserAdd: rowsafe db user add USER --db DB[,DB] [--access read_only|read_write|owner] [--host H] [--on NAME]
func dbUserAdd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("db user add", flag.ContinueOnError)
	on := onFlag(fs)
	var dbs nameList
	fs.Var(&dbs, "db", "a database it may use (repeat, or comma-separated)")
	access := fs.String("access", protocol.DBAccessReadWrite, "read_only, read_write or owner")
	host := fs.String("host", "", "the address to put in the connection string (default: the one apps use)")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: rowsafe db user add USER --db DB [--access read_only|read_write|owner] [--on NAME]")
	}
	p := protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: pos[0], Databases: dbs,
		Access: strings.ReplaceAll(*access, "-", "_"), Host: *host}
	if err := protocol.ValidateDBAdmin(withKeyPlaceholder(p)); err != nil {
		return err
	}
	server, err := resolveDatabase(ctx, c, *on)
	if err != nil {
		return err
	}
	key, err := newSealKey()
	if err != nil {
		return err
	}
	_, res, secret, err := dbRun(ctx, c, server, p, key)
	printDBResult(res)
	if err != nil {
		return err
	}
	printSecret(secret)
	return nil
}

// dbUserPassword: rowsafe db user password USER [--host H] [--on NAME]
func dbUserPassword(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("db user password", flag.ContinueOnError)
	on := onFlag(fs)
	host := fs.String("host", "", "the address to put in the connection string (default: the one apps use)")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: rowsafe db user password USER [--on NAME]")
	}
	server, err := resolveDatabase(ctx, c, *on)
	if err != nil {
		return err
	}
	key, err := newSealKey()
	if err != nil {
		return err
	}
	_, res, secret, err := dbRun(ctx, c, server, protocol.DBAdminParams{Action: protocol.DBAdminResetPassword, User: pos[0], Host: *host}, key)
	printDBResult(res)
	if err != nil {
		return err
	}
	printSecret(secret)
	return nil
}

// dbUserRemove: rowsafe db user remove USER [--reassign-to USER] [--yes] [--on NAME]
func dbUserRemove(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("db user remove", flag.ContinueOnError)
	on := onFlag(fs)
	to := fs.String("reassign-to", "", "the user that gets the tables it owns")
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: rowsafe db user remove USER [--reassign-to USER] [--on NAME]")
	}
	server, err := resolveDatabase(ctx, c, *on)
	if err != nil {
		return err
	}
	if !*yes && !confirm(fmt.Sprintf("Remove the user %s from %s? Apps that log in as it stop working.", pos[0], server)) {
		return errors.New("cancelled; nothing was removed")
	}
	_, res, _, err := dbRun(ctx, c, server, protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: pos[0], ReassignTo: *to}, nil)
	printDBResult(res)
	return err
}

// dbExt: rowsafe db ext on|off DB EXT [--allow-untrusted] [--on NAME]
func dbExt(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("db ext", flag.ContinueOnError)
	on := onFlag(fs)
	untrusted := fs.Bool("allow-untrusted", false, "allow an extension that lets database users run programs on the server")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 3 || (pos[0] != "on" && pos[0] != "off") {
		return errors.New("usage: rowsafe db ext on|off DB EXTENSION [--on NAME]")
	}
	p := protocol.DBAdminParams{Action: protocol.DBAdminEnableExtension, Database: pos[1], Extension: pos[2]}
	if pos[0] == "off" {
		p.Action = protocol.DBAdminDisableExtension
	} else if *untrusted {
		p.AllowUntrusted, p.Confirm = true, pos[2]
	}
	server, err := resolveDatabase(ctx, c, *on)
	if err != nil {
		return err
	}
	_, res, _, err := dbRun(ctx, c, server, p, nil)
	printDBResult(res)
	return err
}
