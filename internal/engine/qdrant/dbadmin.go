package qdrant

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Databases & users for Qdrant: "users" are API keys, JSON Web Tokens the
// agent signs on the server with Rowsafe's key and hands only to the person
// who asked (sealed to their browser's key). The agent's own list of keys
// (keys.go) says which exist; Rowsafe's collection in Qdrant only lets
// Qdrant check them (value_exists), and reconcile keeps it to the list.
// "Databases" are the collections, listed with their points; removing one
// deletes it (the control plane takes a Mark first).

func (e *Engine) dbadmin(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, p protocol.DBAdminParams, tl agent.TaskLogger) (*protocol.DBAdminResult, error) {
	if err := protocol.ValidateDBAdminFor(protocol.EngineQdrant, p); err != nil {
		return nil, agent.Sentence(err)
	}
	start := time.Now()
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, agent.Sentence(err)
	}
	defer c.Close()
	l, _, _ := loadLogin(env, db.Port)
	res := &protocol.DBAdminResult{Action: p.Action}
	var token string
	var made *keyEntry
	if p.Action != protocol.DBAdminList {
		if why, _ := manageBlocked(l); why != "" {
			err = errors.New(why)
		}
	}
	if err == nil {
		keysMu.Lock()
		var list keyList
		var rr reconcileResult
		list, rr, err = reconcileLocked(ctx, env, db.Port, c)
		logReconcile(tl, rr)
		if err == nil {
			switch p.Action {
			case protocol.DBAdminList:
			case protocol.DBAdminCreateUser, protocol.DBAdminResetPassword:
				made, token, err = makeKey(ctx, env, db.Port, c, l, &list, p)
				if err == nil {
					res.Summary = madeWords(p.Action, *made)
				}
			case protocol.DBAdminDropUser:
				var k keyEntry
				k, err = dropKey(ctx, env, db.Port, c, &list, p.User)
				if err == nil {
					res.Summary = droppedWords(k)
				}
			case protocol.DBAdminDropDatabase:
				var renewed, removed []string
				renewed, removed, err = dropCollection(ctx, env, db.Port, c, &list, p.Database)
				if err == nil {
					res.Summary = fmt.Sprintf("Removed the collection %s.", p.Database)
					if len(removed) > 0 {
						res.Summary += fmt.Sprintf(" The keys limited to it (%s) were removed with it.", strings.Join(removed, ", "))
					}
					if len(renewed) > 0 {
						res.Summary += fmt.Sprintf(" The keys that also reached it (%s) keep their other collections, but their tokens "+
							"stopped working: make a new token for each in Databases & users.", strings.Join(renewed, ", "))
					}
				}
			default:
				err = fmt.Errorf("Qdrant has no %s", strings.ReplaceAll(p.Action, "_", " "))
			}
		}
		keysMu.Unlock()
	}
	inv, ierr := inventory(ctx, env, db, c, l)
	if ierr != nil {
		tl.Printf("couldn't read the collections and keys afterwards: %v", ierr)
		if p.Action == protocol.DBAdminList && err == nil {
			err = ierr
		}
	} else {
		res.Inventory = inv
		if p.Action == protocol.DBAdminList {
			res.Summary = fmt.Sprintf("%d collections and %d keys.", len(inv.Databases), len(inv.Users))
		}
	}
	if err == nil && made != nil {
		cn := agent.DBConnectionFor(protocol.DBConnection{Engine: protocol.EngineQdrant, User: made.Name}, p.Host, inv, db.Port, c.base.Scheme == "https")
		var sealed *protocol.SealedSecret
		if sealed, err = agent.SealDBSecret(p.PublicKey, taskID, cn, token); err == nil {
			res.Secret, res.Connection = sealed, &cn
			tl.Printf("the token for %s was encrypted for the person who asked; Rowsafe can't read it", made.Name)
		}
	}
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		err = agent.Sentence(err)
		tl.Printf("failed: %v", err)
	} else {
		tl.Printf("%s", res.Summary)
	}
	return res, err
}

// manageBlocked says why keys can't be made here ("" when they can), and
// what root does on the server to allow it.
func manageBlocked(l Login) (string, string) {
	switch {
	case l.Key == "":
		return "This Qdrant asks for no key, so a key made here would protect nothing: turn keys on in Qdrant's configuration first " +
			"(service.api_key, and service.jwt_rbac: true), then run the Rowsafe installer on the server again", "curl -fsSL https://rowsafe.sh | sudo sh"
	case !l.JWT:
		return "Rowsafe makes keys as JSON Web Tokens, which this Qdrant doesn't take yet: set service.jwt_rbac: true in its configuration " +
			"and restart it, then run the Rowsafe installer on the server again", "curl -fsSL https://rowsafe.sh | sudo sh"
	}
	return "", ""
}

// logReconcile says in the task's log what reconcile undid.
func logReconcile(tl agent.TaskLogger, rr reconcileResult) {
	if rr.Removed > 0 || rr.Restored > 0 {
		tl.Printf("someone changed Rowsafe's list of keys in Qdrant: removed %d entries Rowsafe didn't write, wrote back %d keys (%s)",
			rr.Removed, rr.Restored, strings.Join(rr.Keys, ", "))
	}
	if len(rr.Expired) > 0 {
		tl.Printf("keys past their expiry left the list: %s", strings.Join(rr.Expired, ", "))
	}
}

func madeWords(action string, k keyEntry) string {
	var b strings.Builder
	if action == protocol.DBAdminCreateUser {
		fmt.Fprintf(&b, "Made the key %s, with %s.", k.Name, accessWords(k))
	} else {
		fmt.Fprintf(&b, "Made a new token for the key %s; the old one no longer works.", k.Name)
	}
	if k.ExpiresAt != nil {
		fmt.Fprintf(&b, " It expires on %s.", dateWords(k.ExpiresAt))
	}
	if k.admin() {
		b.WriteString(" An admin key can change everything here, Rowsafe's list of keys included, so its expiry is what ends it for certain.")
	}
	return b.String()
}

func droppedWords(k keyEntry) string {
	if !k.admin() {
		return fmt.Sprintf("Removed the key %s: its token no longer works.", k.Name)
	}
	return fmt.Sprintf("Removed the admin key %s: its token stops working now, unless it was misused to change Rowsafe's list of keys "+
		"(Rowsafe undoes such changes and tells you); it ends for certain when it expires, on %s.", k.Name, dateWords(k.ExpiresAt))
}

// makeKey makes a new key (create_user) or a new token for one
// (reset_password), records it in the list, writes its point and signs
// its token. keysMu is held.
func makeKey(ctx context.Context, env agent.EngineEnv, port int, c *client, l Login, list *keyList, p protocol.DBAdminParams) (*keyEntry, string, error) {
	if err := ensureKeysCollection(ctx, c); err != nil {
		return nil, "", err
	}
	i := list.find(p.User)
	nonce, err := newNonce()
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	var k keyEntry
	switch p.Action {
	case protocol.DBAdminCreateUser:
		if i >= 0 {
			return nil, "", fmt.Errorf("there is a key named %s already", p.User)
		}
		names, err := c.collectionNames(ctx)
		if err != nil {
			return nil, "", err
		}
		for _, d := range p.Databases {
			if !slices.Contains(names, d) || ownColl(d) {
				return nil, "", fmt.Errorf("there is no collection %s", d)
			}
		}
		k = keyEntry{Name: p.User, Access: p.Access, Collections: slices.Clone(p.Databases), CreatedAt: now}
		if k.admin() {
			k.Collections = nil
		}
	default:
		if i < 0 {
			return nil, "", fmt.Errorf("there is no key named %s made in Rowsafe", p.User)
		}
		k = list.Keys[i]
	}
	days, err := expiryDays(k, p.ExpiresDays)
	if err != nil {
		return nil, "", err
	}
	k.Nonce, k.ExpiresDays, k.ExpiresAt = nonce, days, nil
	if days > 0 {
		at := now.Add(time.Duration(days) * 24 * time.Hour)
		k.ExpiresAt = &at
	}
	next := *list
	next.Keys = slices.Clone(list.Keys)
	if i >= 0 {
		next.Keys[i] = k
	} else {
		next.Keys = append(next.Keys, k)
	}
	// The list first: a point the list doesn't hold would be removed.
	if err := saveKeyList(env, port, next); err != nil {
		return nil, "", err
	}
	*list = next
	undo := func() {
		uctx := context.WithoutCancel(ctx)
		_ = deleteKeyByName(uctx, c, k.Name)
		if i < 0 {
			list.Keys = slices.DeleteFunc(list.Keys, func(e keyEntry) bool { return e.Name == k.Name })
			_ = saveKeyList(env, port, *list)
		}
	}
	if err := deleteKeyByName(ctx, c, k.Name); err != nil { // other points naming it
		undo()
		return nil, "", err
	}
	if err := putKeyPoints(ctx, c, []keyEntry{k}); err != nil {
		undo()
		return nil, "", fmt.Errorf("recording the key: %w", err)
	}
	token, err := signToken(l.Key, keyClaims(k))
	if err != nil {
		undo()
		return nil, "", err
	}
	// The token must work before it is handed out.
	check := &client{base: c.base, http: c.http, bearer: token}
	if _, err := check.root(ctx); err == nil {
		if _, err := check.collectionNames(ctx); err != nil {
			undo()
			return nil, "", fmt.Errorf("Qdrant doesn't take the new key: %w", err)
		}
	}
	return &k, token, nil
}

// dropKey removes a key: from the list, then every point that names it.
func dropKey(ctx context.Context, env agent.EngineEnv, port int, c *client, list *keyList, name string) (keyEntry, error) {
	i := list.find(name)
	if i < 0 {
		return keyEntry{}, fmt.Errorf("there is no key named %s made in Rowsafe (Qdrant's own keys are root's, in its configuration)", name)
	}
	k := list.Keys[i]
	list.Keys = slices.Delete(slices.Clone(list.Keys), i, i+1)
	if err := saveKeyList(env, port, *list); err != nil {
		return k, err
	}
	return k, deleteKeyByName(ctx, c, name)
}

// revokeAdminKeys removes every admin key (MaintQdrantRevokeAdminKeys).
func revokeAdminKeys(ctx context.Context, env agent.EngineEnv, port int, c *client) ([]keyEntry, error) {
	keysMu.Lock()
	defer keysMu.Unlock()
	list, _, err := reconcileLocked(ctx, env, port, c)
	if err != nil {
		return nil, err
	}
	var gone []keyEntry
	for _, k := range slices.Clone(list.Keys) {
		if !k.admin() {
			continue
		}
		if _, err := dropKey(ctx, env, port, c, &list, k.Name); err != nil {
			return gone, err
		}
		gone = append(gone, k)
	}
	// What Pulse reported is dealt with: a misused key that keeps changing
	// the list makes the next check report it again.
	if list.Repair != nil {
		list.Repair = nil
		if err := saveKeyList(env, port, list); err != nil {
			return gone, err
		}
	}
	return gone, nil
}

// dropCollection deletes a collection. Keys limited to it go with it; keys
// that also reached other collections lose it and get a new nonce, so the
// token that named it stops working (a new collection of the same name
// must not be open to it): renewed lists them, for new tokens.
func dropCollection(ctx context.Context, env agent.EngineEnv, port int, c *client, list *keyList, name string) (renewed, removed []string, err error) {
	if ownColl(name) {
		return nil, nil, errors.New("that collection is Rowsafe's own (the keys made here); Rowsafe doesn't remove it")
	}
	names, err := c.collectionNames(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !slices.Contains(names, name) {
		return nil, nil, fmt.Errorf("there is no collection %s", name)
	}
	if err := c.deleteCollection(ctx, name); err != nil {
		return nil, nil, err
	}
	next := *list
	next.Keys = nil
	var changed []keyEntry
	for _, k := range list.Keys {
		i := slices.Index(k.Collections, name)
		if i < 0 {
			next.Keys = append(next.Keys, k)
			continue
		}
		if len(k.Collections) == 1 {
			removed = append(removed, k.Name)
			continue
		}
		k.Collections = slices.Delete(slices.Clone(k.Collections), i, i+1)
		nonce, err := newNonce()
		if err != nil {
			return nil, nil, err
		}
		k.Nonce = nonce
		next.Keys = append(next.Keys, k)
		changed = append(changed, k)
		renewed = append(renewed, k.Name)
	}
	if len(changed) == 0 && len(removed) == 0 {
		return nil, nil, nil
	}
	if err := saveKeyList(env, port, next); err != nil {
		return nil, nil, err
	}
	*list = next
	for _, n := range removed {
		_ = deleteKeyByName(ctx, c, n)
	}
	return renewed, removed, putKeyPoints(ctx, c, changed)
}

// inventory lists the collections and keys.
func inventory(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, c *client, l Login) (*protocol.DBInventory, error) {
	in, err := inspect(ctx, c, false)
	if err != nil {
		return nil, err
	}
	inv := &protocol.DBInventory{CollectedAt: time.Now().UTC(), Engine: protocol.EngineQdrant, ServerVersion: in.Version, Port: db.Port,
		SSL: c.base.Scheme == "https", AgentUser: "rowsafe", Databases: []protocol.DBDatabase{}, Users: []protocol.DBUser{}, Extensions: []protocol.DBExtension{}}
	listen := "0.0.0.0"
	if fc, _, ok := readConfig(); ok && fc.Service.Host != "" {
		listen = fc.Service.Host
	}
	if !inDocker() {
		inv.Addresses, inv.SuggestedHost, inv.LocalOnly = agent.DBServerAddresses(listen, nil)
	}
	if why, cmd := manageBlocked(l); why != "" {
		inv.ManageBlocked, inv.ManageCommand = why, cmd
	}
	for _, ci := range in.userCollections() {
		inv.Databases = append(inv.Databases, protocol.DBDatabase{Name: ci.Name, SizeBytes: ci.SizeBytes, Points: ci.Points, AllowConnections: true})
	}
	inv.Users = append(inv.Users, protocol.DBUser{Name: "api_key", Login: true, Superuser: true, Password: protocol.PasswordSet, Access: protocol.DBAccessOwner,
		System: true, SystemReason: "Qdrant's own admin key, root's, in its configuration on the server"})
	if l.Source == "alt" {
		inv.Users = append(inv.Users, protocol.DBUser{Name: "rowsafe", Login: true, Superuser: true, Password: protocol.PasswordSet, Access: protocol.DBAccessOwner,
			System: true, SystemReason: "Rowsafe's own key (it makes the keys here and the backups)"})
	}
	if inv.ManageBlocked != "" {
		return inv, nil // no keys can be made here
	}
	list, _, err := reconcile(ctx, env, db.Port, c) // what it undid is reported by monitoring
	if err != nil {
		return inv, err
	}
	keys := slices.Clone(list.Keys)
	slices.SortFunc(keys, func(a, b keyEntry) int { return strings.Compare(a.Name, b.Name) })
	for _, k := range keys {
		u := protocol.DBUser{Name: k.Name, Login: true, Password: protocol.PasswordSet, Access: k.Access, Databases: k.Collections,
			Superuser: k.admin(), ValidUntil: k.ExpiresAt}
		inv.Users = append(inv.Users, u)
	}
	return inv, nil
}
