package meilisearch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Databases & users for Meilisearch: "databases" are indexes, "users" are
// API keys on chosen indexes with one of three presets
// (protocol.MeilisearchKeyActions). A new key is made by Meilisearch on
// this server and leaves it only sealed to the person who asked. Rowsafe's
// own key, the keys of rewinds and keys with every right are listed and
// never changed from here.

type mdba struct {
	e    *Engine
	env  agent.EngineEnv
	spec protocol.DatabaseSpec
	s    server
	c    *client
	p    protocol.DBAdminParams
	log  agent.TaskLogger
	res  *protocol.DBAdminResult
	// key made for the requester (sealed into the result)
	newKey string
	secret *protocol.DBConnection
}

func (e *Engine) dbadmin(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, p protocol.DBAdminParams, log agent.TaskLogger) (*protocol.DBAdminResult, error) {
	if err := protocol.ValidateDBAdminFor(protocol.EngineMeilisearch, p); err != nil {
		return nil, agent.Sentence(err)
	}
	start := time.Now()
	c, s, err := connect(ctx, env, db)
	if err != nil {
		return nil, agent.Sentence(err)
	}
	defer c.close()
	d := &mdba{e: e, env: env, spec: db, s: s, c: c, p: p, log: log, res: &protocol.DBAdminResult{Action: p.Action}}
	if p.Action != protocol.DBAdminList && s.NoAuth {
		err = errors.New("this Meilisearch has no master key, so it has no API keys to manage: anyone who reaches it can do everything")
	}
	if err == nil {
		switch p.Action {
		case protocol.DBAdminList:
		case protocol.DBAdminCreateDatabase:
			err = d.createIndex(ctx)
		case protocol.DBAdminDropDatabase:
			err = d.dropIndex(ctx)
		case protocol.DBAdminCreateUser:
			err = d.createKey(ctx)
		case protocol.DBAdminResetPassword:
			err = d.resetKey(ctx)
		case protocol.DBAdminDropUser:
			err = d.dropKey(ctx)
		default:
			err = fmt.Errorf("%s has no %s", display, strings.ReplaceAll(p.Action, "_", " "))
		}
	}
	inv, ierr := d.inventory(ctx)
	if ierr != nil {
		log.Printf("couldn't read the indexes and keys afterwards: %v", ierr)
		if p.Action == protocol.DBAdminList && err == nil {
			err = ierr
		}
	} else {
		d.res.Inventory = inv
		if p.Action == protocol.DBAdminList {
			d.res.Summary = fmt.Sprintf("%s and %s.", plural(int64(len(inv.Databases)), "index", "indexes"), plural(int64(len(inv.Users)), "API key", "API keys"))
		}
	}
	if err == nil && d.secret != nil {
		cn := agent.DBConnectionFor(*d.secret, p.Host, inv, db.Port, s.LocalPort > 0 || s.TLS)
		var sealed *protocol.SealedSecret
		if sealed, err = agent.SealDBSecret(p.PublicKey, taskID, cn, d.newKey); err == nil {
			d.res.Secret, d.res.Connection = sealed, &cn
			log.Printf("the API key %s was encrypted for the person who asked; Rowsafe can't read it", cn.User)
		}
	}
	d.res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		err = agent.Sentence(err)
		log.Printf("failed: %v", err)
	} else {
		log.Printf("%s", d.res.Summary)
	}
	return d.res, err
}

// protectedReason says why a key isn't changed from Rowsafe ("": it is).
func (d *mdba) protectedReason(k apiKey) string {
	switch {
	case k.UID == d.s.KeyUID:
		return "Rowsafe's own key"
	case strings.HasPrefix(k.name(), "Rowsafe rewind "):
		return "a key of a rewind in progress"
	case slices.Contains(k.Actions, "*"):
		return "an administrator key (every right): change it with the master key"
	}
	return ""
}

func (d *mdba) wait(ctx context.Context, t task, err error) error {
	if err != nil {
		return err
	}
	_, err = d.c.waitTask(ctx, t, 10*time.Minute)
	return err
}

func (d *mdba) createIndex(ctx context.Context) error {
	uid := d.p.Database
	if isTemporary(uid) {
		return errors.New("names starting with rowsafe-restore- are Rowsafe's")
	}
	if _, err := d.c.index(ctx, uid); err == nil {
		return fmt.Errorf("there is already an index named %s", uid)
	}
	t, err := d.c.enqueue(ctx, http.MethodPost, "/indexes", nil, map[string]any{"uid": uid})
	if err := d.wait(ctx, t, err); err != nil {
		return err
	}
	d.res.Summary = fmt.Sprintf("Created the index %s.", uid)
	if d.p.CreateOwner {
		name := d.p.Owner
		if name == "" {
			name = uid
		}
		if err := d.makeKey(ctx, name, protocol.DBAccessOwner, []string{uid}); err != nil {
			return fmt.Errorf("the index %s was created, but its key wasn't: %w", uid, err)
		}
		d.res.Summary = fmt.Sprintf("Created the index %s and the API key %s, which manages it.", uid, name)
	}
	return nil
}

func (d *mdba) dropIndex(ctx context.Context) error {
	uid := d.p.Database
	if isTemporary(uid) {
		return errors.New("that index is Rowsafe's, kept from a rewind: remove it from Rewind")
	}
	if _, err := d.c.index(ctx, uid); err != nil {
		if isCode(err, "index_not_found") {
			return fmt.Errorf("there is no index named %s", uid)
		}
		return err
	}
	t, err := d.c.enqueue(ctx, http.MethodDelete, "/indexes/"+uid, nil, nil)
	if err := d.wait(ctx, t, err); err != nil {
		return err
	}
	d.res.Summary = fmt.Sprintf("Removed the index %s and its documents.", uid)
	return nil
}

// keyNamed finds the one key named name (or whose uid starts with it).
func (d *mdba) keyNamed(ctx context.Context, name string) (apiKey, error) {
	keys, err := d.c.keys(ctx)
	if err != nil {
		return apiKey{}, err
	}
	var found []apiKey
	for _, k := range keys {
		if keyLabel(k) == name || k.UID == name {
			found = append(found, k)
		}
	}
	switch len(found) {
	case 0:
		return apiKey{}, fmt.Errorf("there is no API key named %s", name)
	case 1:
		return found[0], nil
	}
	return apiKey{}, fmt.Errorf("%d API keys are named %s: change them with the master key", len(found), name)
}

// makeKey makes a key for the requester (sealed into the result).
func (d *mdba) makeKey(ctx context.Context, name, access string, indexes []string) error {
	keys, err := d.c.keys(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if keyLabel(k) == name {
			return fmt.Errorf("there is already an API key named %s", name)
		}
	}
	actions := protocol.MeilisearchKeyActions[access]
	if len(actions) == 0 {
		return fmt.Errorf("unknown access %q", access)
	}
	desc := "Made with Rowsafe: " + accessWords(access)
	k, err := d.c.createKey(ctx, apiKey{Name: &name, Description: &desc, Actions: actions, Indexes: indexes})
	if err != nil {
		return err
	}
	d.newKey = k.Key
	db := "*"
	if len(indexes) == 1 {
		db = indexes[0]
	}
	d.secret = &protocol.DBConnection{Engine: protocol.EngineMeilisearch, User: name, Database: db}
	return nil
}

func accessWords(access string) string {
	switch access {
	case protocol.DBAccessReadOnly:
		return "searches"
	case protocol.DBAccessReadWrite:
		return "searches, adds and deletes documents"
	}
	return "searches, changes documents and the index's settings"
}

func (d *mdba) createKey(ctx context.Context) error {
	idx := d.p.Databases
	if slices.Contains(idx, "*") {
		idx = []string{"*"}
	}
	if err := d.makeKey(ctx, d.p.User, d.p.Access, idx); err != nil {
		return err
	}
	on := "every index"
	if idx[0] != "*" {
		on = joinAnd(idx)
	}
	d.res.Summary = fmt.Sprintf("Created the API key %s: %s, on %s.", d.p.User, accessWords(d.p.Access), on)
	return nil
}

// resetKey gives a key a new value: Meilisearch can't change a key, so a
// new one with the same name and rights replaces it.
func (d *mdba) resetKey(ctx context.Context) error {
	old, err := d.keyNamed(ctx, d.p.User)
	if err != nil {
		return err
	}
	if why := d.protectedReason(old); why != "" {
		return fmt.Errorf("%s is %s", d.p.User, why)
	}
	name := keyLabel(old)
	k, err := d.c.createKey(ctx, apiKey{Name: &name, Description: old.Description, Actions: old.Actions, Indexes: old.Indexes, ExpiresAt: old.ExpiresAt})
	if err != nil {
		return err
	}
	if err := d.c.deleteKey(ctx, old.UID); err != nil {
		_ = d.c.deleteKey(context.WithoutCancel(ctx), k.UID)
		return fmt.Errorf("removing the old key: %w", err)
	}
	d.newKey = k.Key
	db := "*"
	if len(old.Indexes) == 1 {
		db = old.Indexes[0]
	}
	d.secret = &protocol.DBConnection{Engine: protocol.EngineMeilisearch, User: name, Database: db}
	d.res.Summary = fmt.Sprintf("The API key %s was replaced by a new one with the same rights; the old one no longer works.", name)
	return nil
}

func (d *mdba) dropKey(ctx context.Context) error {
	k, err := d.keyNamed(ctx, d.p.User)
	if err != nil {
		return err
	}
	if why := d.protectedReason(k); why != "" {
		return fmt.Errorf("%s is %s", d.p.User, why)
	}
	if err := d.c.deleteKey(ctx, k.UID); err != nil {
		return err
	}
	d.res.Summary = fmt.Sprintf("Removed the API key %s: apps using it are refused from now on.", keyLabel(k))
	return nil
}

const maxListed = 500

func (d *mdba) inventory(ctx context.Context) (*protocol.DBInventory, error) {
	in, err := inspect(ctx, d.c)
	if err != nil {
		return nil, err
	}
	inv := &protocol.DBInventory{CollectedAt: time.Now().UTC(), Engine: protocol.EngineMeilisearch, AgentUser: agentKeyName,
		ServerVersion: in.Version, Port: d.spec.Port, SSL: d.s.LocalPort > 0 || d.s.TLS,
		Databases: []protocol.DBDatabase{}, Users: []protocol.DBUser{}, Extensions: []protocol.DBExtension{}}
	listen := d.s.Listen
	if listen == "" {
		listen = "*"
	}
	inv.Addresses, inv.SuggestedHost, inv.LocalOnly = agent.DBServerAddresses(listen, nil)
	for _, i := range in.Indexes {
		if len(inv.Databases) >= maxListed {
			inv.Truncated = true
			break
		}
		inv.Databases = append(inv.Databases, protocol.DBDatabase{Name: i.UID, SizeBytes: i.Stats.IndexSize, Keys: i.Stats.NumberOfDocuments,
			AllowConnections: true})
	}
	if d.s.NoAuth {
		inv.ManageBlocked = "This Meilisearch has no master key, so it has no API keys: anyone who reaches it can read and change everything. " +
			"Give it a master key, then run the Rowsafe installer on the server again."
		return inv, nil
	}
	keys, err := d.c.keys(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for _, k := range keys {
		if strings.HasPrefix(k.name(), "Rowsafe rewind ") {
			continue
		}
		if len(inv.Users) >= maxListed {
			inv.Truncated = true
			break
		}
		u := protocol.DBUser{Name: keyLabel(k), Login: k.ExpiresAt == nil || k.ExpiresAt.After(now), Superuser: slices.Contains(k.Actions, "*"),
			Password: protocol.PasswordSet, ValidUntil: k.ExpiresAt, Databases: k.Indexes, Access: protocol.MeilisearchKeyAccess(k.Actions)}
		if why := d.protectedReason(k); why != "" {
			u.System, u.SystemReason = true, why
		}
		inv.Users = append(inv.Users, u)
	}
	return inv, nil
}
