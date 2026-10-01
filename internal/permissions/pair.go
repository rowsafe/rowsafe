package permissions

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/rowsafe/rowsafe/protocol"
)

// AgentEnvFile is the agent's configuration (ROWSAFE_URL and the
// ROWSAFE_PERMISSIONS_* overrides for a self-hosted control plane).
const AgentEnvFile = "/etc/rowsafe/agent.env"

// ParseEnvFile reads KEY=VALUE lines as systemd's EnvironmentFile= does for
// the simple forms the installer writes (KEY=value, KEY='value',
// KEY="value"); the last assignment wins.
func ParseEnvFile(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out
}

// RPFromEnv is the RP ID and origin passkeys are made for: the dashboard's,
// or a self-hosted control plane's (ROWSAFE_PERMISSIONS_RP_ID,
// ROWSAFE_PERMISSIONS_ORIGIN).
func RPFromEnv(env map[string]string) (rpID, origin string, err error) {
	rpID, origin = protocol.PermissionsRPID, protocol.PermissionsOrigin
	if v := env["ROWSAFE_PERMISSIONS_RP_ID"]; v != "" {
		rpID = v
	}
	if v := env["ROWSAFE_PERMISSIONS_ORIGIN"]; v != "" {
		origin = v
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil ||
		!(u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
		return "", "", fmt.Errorf("ROWSAFE_PERMISSIONS_ORIGIN must be an https origin like %s", protocol.PermissionsOrigin)
	}
	host := u.Hostname()
	if rpID == "" || strings.ContainsAny(rpID, "/:") || !(host == rpID || strings.HasSuffix(host, "."+rpID)) {
		return "", "", fmt.Errorf("ROWSAFE_PERMISSIONS_RP_ID (%s) must be the origin's host or a domain above it", rpID)
	}
	return rpID, origin, nil
}

// Pairer pairs a passkey with this server: root at the terminal.
type Pairer struct {
	ControlURL string // the agent's ROWSAFE_URL
	Token      string // the agent's token (agent.json)
	HostID     string
	RPID       string
	Origin     string
	OwnersFile string
	HTTP       *http.Client
	TTY        io.ReadWriter // the person at the server
	Now        func() time.Time
	Poll       time.Duration
	MaxWait    time.Duration
}

func (p *Pairer) say(format string, args ...any) { fmt.Fprintf(p.TTY, format+"\n", args...) }

func (p *Pairer) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(p.ControlURL, "/")+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e protocol.Error
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return &StatusError{Status: resp.StatusCode, Msg: e.Error}
	}
	return json.Unmarshal(data, out)
}

// StatusError is the control plane's error answer.
type StatusError struct {
	Status int
	Msg    string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("Rowsafe answered %d: %s", e.Status, e.Msg)
}

// ErrNotPaired: the person said the codes differ, or the pairing was
// declined or expired. Nothing changed.
var ErrNotPaired = errors.New("not paired: nothing changed")

// Pair runs the whole pairing and adds the passkey to the owners file once
// root confirmed the fingerprint.
func (p *Pairer) Pair(ctx context.Context) (*Owner, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	var pr protocol.PermissionOwnerPairing
	if err := p.call(ctx, http.MethodPost, "/v1/agent/permission-owners",
		protocol.PermissionOwnerPairingRequest{Challenge: challenge}, &pr); err != nil {
		var se *StatusError
		if errors.As(err, &se) && (se.Status == http.StatusNotFound || se.Status == http.StatusMethodNotAllowed) {
			return nil, errors.New("Rowsafe doesn't offer passkey pairing for this server yet")
		}
		return nil, fmt.Errorf("asking Rowsafe for a pairing link: %w", err)
	}
	if pr.ID == "" || strings.ContainsAny(pr.ID, "/?#") {
		return nil, errors.New("Rowsafe's answer has no pairing")
	}
	// The link must be on the dashboard the passkey is made for: a page
	// elsewhere could show any fingerprint.
	if !strings.HasPrefix(pr.URL, p.Origin+"/") || strings.IndexFunc(pr.URL, func(r rune) bool { return r <= ' ' || r >= 0x7f }) >= 0 {
		return nil, fmt.Errorf("Rowsafe gave a pairing link outside %s (%q); not pairing", p.Origin, pr.URL)
	}
	p.say("")
	p.say("Pair a passkey with this server, so its permissions can be changed with one")
	p.say("click in the Rowsafe dashboard (each change signed with that passkey).")
	p.say("")
	if pr.Code != "" {
		p.say("  Code: %s", cleanName(pr.Code))
	}
	p.say("  Open this link signed in to Rowsafe as an owner or admin:")
	p.say("  %s", pr.URL)
	p.say("  It will ask your device to create a passkey.")
	p.say("")
	deadline := p.Now().Add(p.MaxWait)
	if !pr.ExpiresAt.IsZero() && pr.ExpiresAt.Add(30*time.Second).Before(deadline) {
		deadline = pr.ExpiresAt.Add(30 * time.Second)
	}
	p.say("Waiting for the passkey (until %s; Ctrl-C to stop)...", deadline.Local().Format("15:04"))
	for pr.Status != "completed" {
		switch pr.Status {
		case "denied":
			p.say("The pairing was declined in the dashboard. Nothing changed.")
			return nil, ErrNotPaired
		case "expired":
			p.say("The link expired before a passkey was created. Nothing changed; run this again.")
			return nil, ErrNotPaired
		}
		if p.Now().After(deadline) {
			p.say("No passkey was created in time. Nothing changed; run this again.")
			return nil, ErrNotPaired
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(p.Poll):
		}
		var next protocol.PermissionOwnerPairing
		if err := p.call(ctx, http.MethodGet, "/v1/agent/permission-owners/"+url.PathEscape(pr.ID), nil, &next); err != nil {
			var se *StatusError
			if errors.As(err, &se) && (se.Status == http.StatusNotFound || se.Status == http.StatusGone) {
				p.say("The pairing is gone from Rowsafe. Nothing changed; run this again.")
				return nil, ErrNotPaired
			}
			continue // a network hiccup: keep waiting
		}
		if next.ID != pr.ID {
			return nil, errors.New("Rowsafe answered about another pairing")
		}
		pr.Status, pr.Attestation = next.Status, next.Attestation
	}
	att := pr.Attestation
	if att == nil {
		return nil, errors.New("Rowsafe says the passkey was created but sent none")
	}
	cred, err := VerifyRegistration(att.AttestationObject, att.ClientDataJSON, challenge, p.RPID, p.Origin)
	if err != nil {
		return nil, fmt.Errorf("the passkey can't be trusted: %w", err)
	}
	if !bytes.Equal(cred.ID, att.CredentialID) {
		return nil, errors.New("the passkey can't be trusted: its ID doesn't match the one Rowsafe reported")
	}
	name := cleanName(att.Name)
	owner := NewOwner(cred, name, p.RPID, p.Origin, p.HostID, p.Now())
	owners, err := ReadOwners(p.OwnersFile, true)
	if err != nil {
		return nil, err
	}
	if FindOwner(owners, owner.Fingerprint) >= 0 {
		p.say("This passkey (%s) is already paired with this server. Nothing changed.", owner.Fingerprint)
		return &owners[FindOwner(owners, owner.Fingerprint)], nil
	}
	p.say("")
	p.say("A passkey was created for %s.", name)
	ok, err := p.confirm(fmt.Sprintf("Does your browser show the same code? %s [y/N] ", owner.Fingerprint))
	if err != nil {
		return nil, err
	}
	if !ok {
		p.say("Not paired. Nothing changed. If the codes differ, the passkey Rowsafe sent isn't the one")
		p.say("your browser made: don't pair it, and tell your team.")
		return nil, ErrNotPaired
	}
	owners = append(owners, owner)
	if err := WriteOwners(p.OwnersFile, owners); err != nil {
		return nil, fmt.Errorf("saving %s: %w", p.OwnersFile, err)
	}
	p.say("Paired. %s can now change this server's permissions in the Rowsafe dashboard", name)
	p.say("with this passkey; each change is checked here, on the server, before anything changes.")
	return &owner, nil
}

func (p *Pairer) confirm(question string) (bool, error) {
	fmt.Fprint(p.TTY, question)
	line, err := bufio.NewReader(p.TTY).ReadString('\n')
	if err != nil && line == "" {
		return false, errors.New("no answer on the terminal")
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// cleanName keeps a name printable and short.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || unicode.Is(unicode.Bidi_Control, r) {
			return -1
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200]
	}
	s = strings.ToValidUTF8(strings.TrimSpace(s), "")
	if s == "" {
		s = "unnamed"
	}
	return s
}
