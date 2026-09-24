package client

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Guard: migration previews and safe copies (see protocol/copies.go for the
// endpoints).

// CreatePreview runs SQL on a fresh copy of the database.
func (c *Client) CreatePreview(ctx context.Context, ref string, req protocol.CreatePreviewRequest) (out protocol.Preview, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/previews", req, &out)
}

// Previews lists the database's recent previews, newest first.
func (c *Client) Previews(ctx context.Context, ref string) (out []protocol.Preview, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/previews", nil, &out)
}

// Preview is one preview with its result.
func (c *Client) Preview(ctx context.Context, id string) (out protocol.Preview, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/previews/"+esc(id), nil, &out)
}

// WaitPreview polls a preview until its task has ended.
func (c *Client) WaitPreview(ctx context.Context, id string, onTick func(protocol.Preview)) (protocol.Preview, error) {
	for {
		p, err := c.Preview(ctx, id)
		if err != nil {
			return p, err
		}
		if onTick != nil {
			onTick(p)
		}
		switch p.Status {
		case protocol.StatusSucceeded, protocol.StatusFailed, protocol.StatusLost, protocol.StatusCancelled:
			return p, nil
		}
		select {
		case <-ctx.Done():
			return p, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// SafeCopies lists the database's safe copies and whether one can be made.
func (c *Client) SafeCopies(ctx context.Context, ref string) (out protocol.SafeCopiesInfo, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/safe-copies", nil, &out)
}

// CreateSafeCopy makes a masked copy reachable over TCP.
func (c *Client) CreateSafeCopy(ctx context.Context, ref string, req protocol.CreateSafeCopyRequest) (out protocol.CreateSafeCopyResponse, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/safe-copies", req, &out)
}

// DeleteSafeCopy deletes a safe copy (or stops it being made).
func (c *Client) DeleteSafeCopy(ctx context.Context, ref, id string) (out protocol.SafeCopy, err error) {
	return out, c.do(ctx, http.MethodDelete, "/v1/databases/"+esc(ref)+"/safe-copies/"+esc(id), nil, &out)
}

// ExtendSafeCopy keeps a safe copy hours longer, from now.
func (c *Client) ExtendSafeCopy(ctx context.Context, ref, id string, hours int) (out protocol.SafeCopy, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/safe-copies/"+esc(id)+"/extend",
		protocol.ExtendSafeCopyRequest{Hours: hours}, &out)
}

// Masking is the database's masking rules with its columns.
func (c *Client) Masking(ctx context.Context, ref string) (out protocol.MaskingInfo, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/masking", nil, &out)
}

// PutMasking replaces the database's masking rules.
func (c *Client) PutMasking(ctx context.Context, ref string, rules []protocol.MaskingRule) (out protocol.MaskingInfo, err error) {
	return out, c.do(ctx, http.MethodPut, "/v1/databases/"+esc(ref)+"/masking", protocol.PutMaskingRequest{Rules: rules}, &out)
}

// RefreshMaskingSchema reads production's tables and columns again.
func (c *Client) RefreshMaskingSchema(ctx context.Context, ref string) (out protocol.MaskingInfo, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/masking/refresh", nil, &out)
}

// ---- passwords that never leave the requester ----

const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// NewCopyPassword makes a random password for a safe copy and its
// SCRAM-SHA-256 verifier. Send only the verifier
// (CreateSafeCopyRequest.PasswordVerifier): PostgreSQL checks logins
// against it, and nobody can log in knowing only the verifier.
func NewCopyPassword() (password, verifier string, err error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	for i := range b {
		b[i] = passwordAlphabet[int(b[i])%len(passwordAlphabet)]
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	v, err := SCRAMVerifier(string(b), salt, 4096)
	return string(b), v, err
}

// SCRAMVerifier is PostgreSQL's stored form of a SCRAM-SHA-256 password
// (RFC 5802/7677). The password must be ASCII (SASLprep is then identity).
func SCRAMVerifier(password string, salt []byte, iterations int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	stored := sha256.Sum256(mac(salted, "Client Key"))
	server := mac(salted, "Server Key")
	enc := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, enc(salt), enc(stored[:]), enc(server)), nil
}

// ConnectionString is a safe copy's connection string; password may be ""
// (it was shown once).
func ConnectionString(cp protocol.SafeCopy, password string) string {
	if cp.Host == "" || cp.Port == 0 {
		return ""
	}
	u := url.URL{Scheme: "postgresql", Host: net.JoinHostPort(cp.Host, strconv.Itoa(cp.Port)), Path: "/" + cp.DB,
		RawQuery: "sslmode=require"}
	if password != "" {
		u.User = url.UserPassword(cp.Role, password)
	} else {
		u.User = url.User(cp.Role)
	}
	return u.String()
}
