package client

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Changes to servers Rowsafe created, as a person makes them (the
// dashboard's own calls): owners and admins, or a read-write API key. The
// control plane refuses them for AI assistants (/mcp), which ask with
// approval requests instead.
//
//	POST   /v1/cloud/servers                 CreateCloudServerRequest -> 201 CloudServer,
//	                                         or 200 {"checkout_url", "server"} when it waits for payment
//	POST   /v1/cloud/servers/{id}/resize     {"size", "confirm": true} -> 202 CloudServer
//	PUT    /v1/cloud/servers/{id}/firewall   {"allowed_ips", "ssh_ips"} -> CloudServer
//	DELETE /v1/cloud/servers/{id}            {"confirm_name", "passphrase_saved", "with_standby"} -> 202 CloudServer
//	POST   /v1/cloud/servers/{id}/passphrase-saved -> CloudServer
//	POST   /v1/cloud/servers/{id}/retry      -> 202 CloudServer
//	POST   /v1/databases/{ref}/clone         CreateCloneRequest -> like POST /v1/cloud/servers
//	POST   /v1/databases/{ref}/backup-passphrase         {"public_key"} -> 202 {"task_id"}
//	POST   /v1/databases/{ref}/backup-passphrase/secret  {"task_id"} -> SealedSecret (once)

// CreateCloudServerRequest is a new Rowsafe Cloud server (Where "rowsafe").
// The region decides the cloud; Provider, when set, must match it.
type CreateCloudServerRequest struct {
	Where         string   `json:"where"`
	Provider      string   `json:"provider,omitempty"`
	Region        string   `json:"region"`
	Size          string   `json:"size"`
	Name          string   `json:"name"`
	Engine        string   `json:"engine"`
	EngineVersion string   `json:"engine_version,omitempty"`
	AllowedIPs    []string `json:"allowed_ips"`
	Standby       bool     `json:"standby,omitempty"`
	// Extensions (PostgreSQL 15 to 18): installed and turned on from the
	// start (protocol.PGPackagedExtensions' names).
	Extensions []string `json:"extensions,omitempty"`
}

// CreateCloneRequest copies a database, as it was now, at a moment or at a
// Mark, onto a new server (Rowsafe Cloud: a cloud billed by the hour).
type CreateCloneRequest struct {
	Where            string     `json:"where"`
	Provider         string     `json:"provider,omitempty"`
	Region           string     `json:"region"`
	Size             string     `json:"size"`
	Name             string     `json:"name"`
	At               *time.Time `json:"at,omitempty"`
	Mark             string     `json:"mark,omitempty"`
	DeleteAfterHours int        `json:"delete_after_hours"`
	AllowedIPs       []string   `json:"allowed_ips"`
}

// CloudServerCreated is the answer to a new server or clone: the server,
// and CheckoutURL when it waits for payment (the organization's first
// server billed by the hour sets up pay as you go; a size billed by the
// month is paid for first). Nothing is created or billed before.
type CloudServerCreated struct {
	Server      CloudServer `json:"server"`
	CheckoutURL string      `json:"checkout_url,omitempty"`
}

// createdServer reads either answer: the server itself (201), or
// {"checkout_url", "server"} (200).
func (c *Client) createdServer(ctx context.Context, path string, body any) (CloudServerCreated, error) {
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodPost, path, body, &raw); err != nil {
		return CloudServerCreated{}, err
	}
	var out CloudServerCreated
	var probe struct {
		CheckoutURL *string          `json:"checkout_url"`
		Server      *json.RawMessage `json:"server"`
	}
	if json.Unmarshal(raw, &probe) == nil && probe.Server != nil {
		if probe.CheckoutURL != nil {
			out.CheckoutURL = *probe.CheckoutURL
		}
		return out, json.Unmarshal(*probe.Server, &out.Server)
	}
	return out, json.Unmarshal(raw, &out.Server)
}

// CreateCloudServer creates a server (or records it waiting for payment).
func (c *Client) CreateCloudServer(ctx context.Context, req CreateCloudServerRequest) (CloudServerCreated, error) {
	return c.createdServer(ctx, "/v1/cloud/servers", req)
}

// CloneToNewServer clones the database ref onto a new server.
func (c *Client) CloneToNewServer(ctx context.Context, ref string, req CreateCloneRequest) (CloudServerCreated, error) {
	return c.createdServer(ctx, "/v1/databases/"+esc(ref)+"/clone", req)
}

// ResizeCloudServer moves a server to another size. The database is offline
// a few minutes while the server restarts (a pair switches over instead);
// Rowsafe saves a Mark first. Calling it is the confirmation.
func (c *Client) ResizeCloudServer(ctx context.Context, id, size string) (out CloudServer, err error) {
	body := struct {
		Size    string `json:"size"`
		Confirm bool   `json:"confirm"`
	}{size, true}
	return out, c.do(ctx, http.MethodPost, "/v1/cloud/servers/"+esc(id)+"/resize", body, &out)
}

// SetCloudFirewall replaces who may connect to PostgreSQL (allowed) and to
// SSH (sshIPs; always empty on Rowsafe Cloud). Pass the server's current
// SSHIPs to keep them: the call replaces both lists.
func (c *Client) SetCloudFirewall(ctx context.Context, id string, allowed, sshIPs []string) (out CloudServer, err error) {
	body := struct {
		AllowedIPs []string `json:"allowed_ips"`
		SSHIPs     []string `json:"ssh_ips"`
	}{nonNil(allowed), nonNil(sshIPs)}
	return out, c.do(ctx, http.MethodPut, "/v1/cloud/servers/"+esc(id)+"/firewall", body, &out)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// DeleteCloudServer deletes a server. confirmName must be its name;
// passphraseSaved says the backup passphrase was saved (required for a
// server with a database, unless it is a clone); withStandby deletes its
// standby server too.
func (c *Client) DeleteCloudServer(ctx context.Context, id, confirmName string, passphraseSaved, withStandby bool) (out CloudServer, err error) {
	body := struct {
		ConfirmName     string `json:"confirm_name"`
		PassphraseSaved bool   `json:"passphrase_saved"`
		WithStandby     bool   `json:"with_standby"`
	}{confirmName, passphraseSaved, withStandby}
	return out, c.do(ctx, http.MethodDelete, "/v1/cloud/servers/"+esc(id), body, &out)
}

// CloudPassphraseSaved records that the backup passphrase was saved.
func (c *Client) CloudPassphraseSaved(ctx context.Context, id string) (out CloudServer, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/cloud/servers/"+esc(id)+"/passphrase-saved", nil, &out)
}

// RetryCloudServer creates a failed server again.
func (c *Client) RetryCloudServer(ctx context.Context, id string) (out CloudServer, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/cloud/servers/"+esc(id)+"/retry", nil, &out)
}

// RequestBackupPassphrase queues the task that seals the database's backup
// passphrase to publicKey (protocol.EncodeSealKey) and returns its ID.
func (c *Client) RequestBackupPassphrase(ctx context.Context, ref, publicKey string) (string, error) {
	var out struct {
		TaskID string `json:"task_id"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/backup-passphrase",
		protocol.BackupPassphraseParams{PublicKey: publicKey}, &out)
	return out.TaskID, err
}

// BackupPassphraseSecret fetches the sealed passphrase of a finished task,
// once.
func (c *Client) BackupPassphraseSecret(ctx context.Context, ref, taskID string) (out protocol.SealedSecret, err error) {
	body := struct {
		TaskID string `json:"task_id"`
	}{taskID}
	return out, c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/backup-passphrase/secret", body, &out)
}
