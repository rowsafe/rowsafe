package qdrant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Databases & users for Qdrant: "users" are API keys, JSON Web Tokens the
// agent signs on the server with Rowsafe's key and hands only to the person
// who asked (sealed to their browser's key). Each key is a point in
// Rowsafe's own collection (protocol.QdrantKeysCollection: its name,
// access, collections and a random nonce, no vector); its token is valid
// only while that point holds that nonce (Qdrant's value_exists), so
// removing the key, or making it a new token, revokes the old token at
// once. "Databases" are the collections, listed with their points;
// removing one deletes it (the control plane takes a Mark first).

// keyRecord is a key as its point holds it.
type keyRecord struct {
	Name        string   `json:"key"`
	Nonce       string   `json:"nonce"`
	Access      string   `json:"access"`
	Collections []string `json:"collections,omitempty"`
	CreatedAt   string   `json:"created_at"`
}

// keyPointID is a key's point: a UUID made from its name.
func keyPointID(name string) string {
	h := sha256.Sum256([]byte("rowsafe-key:" + name))
	b := h[:16]
	b[6] = b[6]&0x0f | 0x50 // version 5-like
	b[8] = b[8]&0x3f | 0x80
	x := hex.EncodeToString(b)
	return x[:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:]
}

func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ensureKeysCollection creates Rowsafe's keys collection (no vectors) and
// its payload indexes when missing.
func ensureKeysCollection(ctx context.Context, c *client) error {
	_, err := c.collection(ctx, protocol.QdrantKeysCollection)
	if err == nil {
		return nil
	}
	if !isStatus(err, http.StatusNotFound) {
		return err
	}
	if err := c.call(ctx, http.MethodPut, collPath(protocol.QdrantKeysCollection), nil,
		map[string]any{"vectors": map[string]any{}, "on_disk_payload": false}, nil); err != nil {
		return fmt.Errorf("creating Rowsafe's keys collection: %w", err)
	}
	for _, f := range []string{"key", "nonce"} {
		if err := c.call(ctx, http.MethodPut, collPath(protocol.QdrantKeysCollection)+"/index", url.Values{"wait": {"true"}},
			map[string]any{"field_name": f, "field_schema": "keyword"}, nil); err != nil {
			return err
		}
	}
	return nil
}

// listKeys reads the keys made in Databases & users.
func listKeys(ctx context.Context, c *client) ([]keyRecord, error) {
	var out struct {
		Points []struct {
			Payload keyRecord `json:"payload"`
		} `json:"points"`
	}
	err := c.call(ctx, http.MethodPost, collPath(protocol.QdrantKeysCollection)+"/points/scroll", nil,
		map[string]any{"limit": 1000, "with_payload": true, "with_vector": false}, &out)
	if isStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var keys []keyRecord
	for _, p := range out.Points {
		if p.Payload.Name != "" {
			keys = append(keys, p.Payload)
		}
	}
	slices.SortFunc(keys, func(a, b keyRecord) int { return strings.Compare(a.Name, b.Name) })
	return keys, nil
}

func putKey(ctx context.Context, c *client, k keyRecord) error {
	pt := map[string]any{"id": keyPointID(k.Name), "vector": map[string]any{}, "payload": k}
	return c.call(ctx, http.MethodPut, collPath(protocol.QdrantKeysCollection)+"/points", url.Values{"wait": {"true"}},
		map[string]any{"points": []any{pt}}, nil)
}

func deleteKey(ctx context.Context, c *client, name string) error {
	return c.call(ctx, http.MethodPost, collPath(protocol.QdrantKeysCollection)+"/points/delete", url.Values{"wait": {"true"}},
		map[string]any{"points": []string{keyPointID(name)}}, nil)
}

// keyClaims are the token's claims for k.
func keyClaims(k keyRecord) map[string]any {
	var access any
	switch {
	case k.Access == protocol.DBAccessOwner:
		access = "m"
	case len(k.Collections) == 0:
		access = "r"
	default:
		mode := "r"
		if k.Access == protocol.DBAccessReadWrite {
			mode = "rw"
		}
		var list []map[string]any
		for _, c := range k.Collections {
			list = append(list, map[string]any{"collection": c, "access": mode})
		}
		access = list
	}
	return map[string]any{
		"access":  access,
		"subject": k.Name,
		"value_exists": map[string]any{"collection": protocol.QdrantKeysCollection,
			"matches": []map[string]any{{"key": "key", "value": k.Name}, {"key": "nonce", "value": k.Nonce}}},
	}
}

func accessWords(k keyRecord) string {
	switch {
	case k.Access == protocol.DBAccessOwner:
		return "admin access to every collection"
	case len(k.Collections) == 0:
		return "read-only access to every collection"
	case k.Access == protocol.DBAccessReadWrite:
		return "read-write access to " + strings.Join(k.Collections, ", ")
	}
	return "read-only access to " + strings.Join(k.Collections, ", ")
}

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
	var made *keyRecord
	if p.Action != protocol.DBAdminList {
		if why, _ := manageBlocked(l); why != "" {
			err = errors.New(why)
		}
	}
	if err == nil {
		switch p.Action {
		case protocol.DBAdminList:
		case protocol.DBAdminCreateUser, protocol.DBAdminResetPassword:
			made, token, err = makeKey(ctx, c, l, p)
			if err == nil {
				if p.Action == protocol.DBAdminCreateUser {
					res.Summary = fmt.Sprintf("Made the key %s, with %s.", made.Name, accessWords(*made))
				} else {
					res.Summary = fmt.Sprintf("Made a new token for the key %s; the old one no longer works.", made.Name)
				}
			}
		case protocol.DBAdminDropUser:
			err = dropKey(ctx, c, p.User)
			if err == nil {
				res.Summary = fmt.Sprintf("Removed the key %s: its token no longer works.", p.User)
			}
		case protocol.DBAdminDropDatabase:
			err = dropCollection(ctx, c, p.Database)
			if err == nil {
				res.Summary = fmt.Sprintf("Removed the collection %s.", p.Database)
			}
		default:
			err = fmt.Errorf("Qdrant has no %s", strings.ReplaceAll(p.Action, "_", " "))
		}
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

// makeKey makes a new key (create_user) or a new token for one
// (reset_password), and signs its token.
func makeKey(ctx context.Context, c *client, l Login, p protocol.DBAdminParams) (*keyRecord, string, error) {
	if err := ensureKeysCollection(ctx, c); err != nil {
		return nil, "", err
	}
	keys, err := listKeys(ctx, c)
	if err != nil {
		return nil, "", err
	}
	i := slices.IndexFunc(keys, func(k keyRecord) bool { return k.Name == p.User })
	nonce, err := newNonce()
	if err != nil {
		return nil, "", err
	}
	var k keyRecord
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
		k = keyRecord{Name: p.User, Access: p.Access, Collections: slices.Clone(p.Databases), CreatedAt: time.Now().UTC().Format(time.RFC3339)}
		if k.Access == protocol.DBAccessOwner {
			k.Collections = nil
		}
	default:
		if i < 0 {
			return nil, "", fmt.Errorf("there is no key named %s made in Rowsafe", p.User)
		}
		k = keys[i]
	}
	k.Nonce = nonce
	if err := putKey(ctx, c, k); err != nil {
		return nil, "", fmt.Errorf("recording the key: %w", err)
	}
	token, err := signToken(l.Key, keyClaims(k))
	if err != nil {
		return nil, "", err
	}
	// The token must work before it is handed out.
	check := &client{base: c.base, http: c.http, key: token}
	if _, err := check.root(ctx); err == nil {
		if _, err := check.collectionNames(ctx); err != nil {
			_ = deleteKey(context.WithoutCancel(ctx), c, k.Name)
			return nil, "", fmt.Errorf("Qdrant doesn't take the new key: %w", err)
		}
	}
	return &k, token, nil
}

func dropKey(ctx context.Context, c *client, name string) error {
	keys, err := listKeys(ctx, c)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(keys, func(k keyRecord) bool { return k.Name == name }) {
		return fmt.Errorf("there is no key named %s made in Rowsafe (Qdrant's own keys are root's, in its configuration)", name)
	}
	return deleteKey(ctx, c, name)
}

func dropCollection(ctx context.Context, c *client, name string) error {
	if ownColl(name) {
		return errors.New("that collection is Rowsafe's own (the keys made here); Rowsafe doesn't remove it")
	}
	names, err := c.collectionNames(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(names, name) {
		return fmt.Errorf("there is no collection %s", name)
	}
	if err := c.deleteCollection(ctx, name); err != nil {
		return err
	}
	// Keys limited to it lose it.
	keys, err := listKeys(ctx, c)
	if err != nil {
		return nil
	}
	for _, k := range keys {
		if i := slices.Index(k.Collections, name); i >= 0 {
			k.Collections = slices.Delete(k.Collections, i, i+1)
			if len(k.Collections) == 0 {
				_ = deleteKey(ctx, c, k.Name)
			} else {
				_ = putKey(ctx, c, k)
			}
		}
	}
	return nil
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
	keys, err := listKeys(ctx, c)
	if err != nil {
		return inv, err
	}
	for _, k := range keys {
		u := protocol.DBUser{Name: k.Name, Login: true, Password: protocol.PasswordSet, Access: k.Access, Databases: k.Collections,
			Superuser: k.Access == protocol.DBAccessOwner}
		inv.Users = append(inv.Users, u)
	}
	return inv, nil
}
