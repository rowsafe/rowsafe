package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Seams for tests.
var (
	sleepCtx = func(ctx context.Context, d time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
			return nil
		}
	}
	openBrowser = func(url string) error {
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "darwin":
			cmd = exec.Command("open", url)
		case "windows":
			cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
		default:
			cmd = exec.Command("xdg-open", url)
		}
		if err := cmd.Start(); err != nil {
			return err
		}
		go cmd.Wait() //nolint:errcheck // reap it; the browser outlives us
		return nil
	}
)

// canOpenBrowser is false over SSH or without a graphical session, where a
// browser would open (if at all) on the wrong machine.
func canOpenBrowser() bool {
	if overSSH() {
		return false
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "freebsd" {
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	}
	return true
}

func overSSH() bool {
	for _, v := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		if os.Getenv(v) != "" {
			return true
		}
	}
	return false
}

// clickable makes u a link the terminal opens on click (OSC 8). The text is
// still the whole URL, so terminals without OSC 8 show it as before.
func clickable(u string) string {
	fi, err := os.Stdout.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 || os.Getenv("TERM") == "dumb" {
		return u
	}
	return "\x1b]8;;" + u + "\x1b\\" + u + "\x1b]8;;\x1b\\"
}

// readSavedConfig reads the login file only, without environment overrides.
func readSavedConfig() (config, string, error) {
	var c config
	p, err := configPath()
	if err != nil {
		return c, "", err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return c, p, nil
	}
	if err != nil {
		return c, p, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, p, fmt.Errorf("reading %s: %w", p, err)
	}
	return c, p, nil
}

func saveConfig(c config) (string, error) {
	p, err := configPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return "", err
	}
	return p, os.Rename(tmp, p)
}

// loginURL is --url, then ROWSAFE_URL, then the saved login, then the
// hosted control plane.
func loginURL(flagURL string, saved config) string {
	for _, u := range []string{flagURL, os.Getenv("ROWSAFE_URL"), saved.URL, protocol.DefaultAPIURL} {
		if u = strings.TrimRight(strings.TrimSpace(u), "/"); u != "" {
			return u
		}
	}
	return protocol.DefaultAPIURL
}

func login(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	urlFlag := fs.String("url", "", "control plane URL (default "+protocol.DefaultAPIURL+")")
	key := fs.String("key", "", "log in with an existing API key (rsk_...) instead of the browser")
	host, _ := os.Hostname()
	name := fs.String("name", "rowsafe CLI on "+host, "what the new API key is called (shown in the dashboard)")
	yes := fs.Bool("yes", false, "on a server that runs Rowsafe without an account: connect it without asking")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	// On a server without an account, logging in connects it (handover.go).
	local, err := findNoAccount()
	if err != nil {
		return err
	}
	if local != nil {
		if err := local.ready(); err != nil {
			return fmt.Errorf("this server runs Rowsafe without an account, and logging in here connects it to the account. Not yet: %w", err)
		}
		if !*yes && !stdinIsTerminal() {
			return fmt.Errorf("this server runs Rowsafe without an account (%s), and logging in here connects it to the account: pass --yes for that (no terminal to ask on). Nothing was changed", local.what())
		}
	}
	saved, _, err := readSavedConfig()
	if err != nil {
		return err
	}
	url := loginURL(*urlFlag, saved)

	var cfg config
	if *key != "" {
		cfg, err = loginWithKey(ctx, url, strings.TrimSpace(*key))
	} else {
		cfg, err = loginWithBrowser(ctx, url, *name, canOpenBrowser())
	}
	if err != nil {
		return err
	}
	if local != nil {
		if err := connectNoAccount(ctx, local, cfg, *yes); err != nil {
			forgetLogin(ctx, cfg)
			return err
		}
	}
	p, err := saveConfig(cfg)
	if err != nil {
		return err
	}
	org := cfg.Org.Name
	if org == "" {
		org = cfg.Org.ID
	}
	at := ""
	if cfg.URL != protocol.DefaultAPIURL {
		at = " at " + cfg.URL
	}
	fmt.Printf("Logged in to %s%s. Key saved to %s\n", org, at, p)
	// A previous browser login's key is no longer used by anything.
	if saved.KeyID != "" && saved.APIKey != cfg.APIKey && saved.URL == cfg.URL {
		if err := client.New(saved.URL, saved.APIKey).Logout(ctx); err == nil {
			fmt.Printf("Revoked the previous login's API key (%s).\n", saved.KeyID)
		}
	}
	return nil
}

// connectNoAccount asks, then connects this server to cfg's account.
func connectNoAccount(ctx context.Context, local *noAccount, cfg config, yes bool) error {
	org := cfg.Org.Name
	if org == "" {
		org = cfg.Org.ID
	}
	if !yes {
		fmt.Printf("This server runs Rowsafe without an account (%s).\n", local.what())
		fmt.Printf("Connect it to %s? Its backups, Proofs and Marks come along; the Rowsafe agent restarts, PostgreSQL doesn't. [Y/n] ", org)
		if !answerYes() {
			return errors.New("not logged in: this server stays without an account, as it was. sudo rowsafe login connects it whenever you like")
		}
	}
	if err := local.connect(ctx, cfg, os.Stdout); err != nil {
		return fmt.Errorf("%w\nNot logged in", err)
	}
	fmt.Printf("%s is connected to %s: the dashboard, alerts and Rewind from anywhere. Backups went on all along.\n", local.hostname(), org)
	return nil
}

// forgetLogin revokes the key a browser login just made, when it isn't
// kept after all.
func forgetLogin(ctx context.Context, cfg config) {
	if cfg.KeyID != "" {
		_ = client.New(cfg.URL, cfg.APIKey).Logout(ctx)
	}
}

func loginWithKey(ctx context.Context, url, key string) (config, error) {
	me, err := client.New(url, key).WhoAmI(ctx)
	if err != nil {
		return config{}, fmt.Errorf("checking the API key: %w", err)
	}
	// KeyID stays empty: logout must not revoke a key it didn't create.
	return config{URL: url, APIKey: key, Org: &protocol.OrgBrief{ID: me.Org.ID, Name: me.Org.Name}}, nil
}

func loginWithBrowser(ctx context.Context, url, name string, browser bool) (config, error) {
	c := client.New(url, "")
	start, err := c.StartDeviceAuth(ctx, name)
	if err != nil {
		return config{}, fmt.Errorf("starting the login at %s: %w", url, err)
	}
	switch {
	case browser && openBrowser(start.VerificationURIComplete) == nil:
		fmt.Printf("Opened your browser: confirm the code %s there.\nIf it didn't open, copy this link into your browser:\n  %s\n", start.UserCode, clickable(start.VerificationURIComplete))
	case overSSH():
		fmt.Printf("This server has no browser. Copy this link, open it on your laptop or phone, and confirm the code %s:\n  %s\n", start.UserCode, clickable(start.VerificationURIComplete))
	default:
		fmt.Printf("Copy this link, open it in any browser, and confirm the code %s:\n  %s\n", start.UserCode, clickable(start.VerificationURIComplete))
	}
	fmt.Println("Waiting for you to approve...")

	interval := time.Duration(max(start.Interval, 1)) * time.Second
	ctx, cancel := context.WithTimeout(ctx, time.Duration(start.ExpiresIn)*time.Second)
	defer cancel()
	for {
		if err := sleepCtx(ctx, interval); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return config{}, errors.New("the login code expired before it was approved; run `rowsafe login` again")
			}
			return config{}, err
		}
		tok, err := c.PollDeviceToken(ctx, start.DeviceCode)
		if err == nil {
			return config{URL: url, APIKey: tok.APIKey, KeyID: tok.KeyID, Org: &tok.Org}, nil
		}
		var ae *client.APIError
		switch {
		case errors.As(err, &ae) && ae.Msg == protocol.DeviceAuthorizationPending:
		case errors.As(err, &ae) && ae.Msg == protocol.DeviceSlowDown:
			interval += 5 * time.Second
		case errors.As(err, &ae) && ae.Msg == protocol.DeviceAccessDenied:
			return config{}, errors.New("the login was declined in the browser")
		case errors.As(err, &ae) && ae.Msg == protocol.DeviceExpiredToken:
			return config{}, errors.New("the login code expired or was already used; run `rowsafe login` again")
		case errors.As(err, &ae) && ae.Status < http.StatusInternalServerError:
			return config{}, err
		case ctx.Err() != nil:
			return config{}, errors.New("the login code expired before it was approved; run `rowsafe login` again")
		default:
			// A network blip or a 5xx: keep polling until the code expires.
			fmt.Fprintln(os.Stderr, "(still waiting: "+err.Error()+")")
		}
	}
}

func whoami(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	me, err := client.New(cfg.URL, cfg.APIKey).WhoAmI(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(struct {
			URL string `json:"url"`
			protocol.WhoAmI
		}{cfg.URL, me})
	}
	// Who first (organization, person), then the key and where it points.
	fmt.Printf("Organization:  %s (%s), %s plan\n", me.Org.Name, me.Org.ID, me.Org.Plan)
	if k := me.APIKey; k != nil {
		if k.CreatedBy != "" {
			fmt.Printf("Acts as:       %s, with their rights in the dashboard\n", k.CreatedBy)
		}
		access := "read-write"
		if k.ReadOnly {
			access = "read-only"
		}
		from := ""
		if os.Getenv("ROWSAFE_API_KEY") != "" {
			from = ", from ROWSAFE_API_KEY"
		}
		fmt.Printf("API key:       %s (%s), %s%s\n", k.Name, k.ID, access, from)
	}
	fmt.Printf("Control plane: %s\n", cfg.URL)
	return nil
}

func logout(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	keepKey := fs.Bool("keep-key", false, "only forget the saved login; leave its API key valid")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	saved, p, err := readSavedConfig()
	if err != nil {
		return err
	}
	if saved.APIKey == "" {
		fmt.Println("Not logged in.")
		return nil
	}
	switch {
	case *keepKey:
	case saved.KeyID != "":
		err := client.New(loginURL("", saved), saved.APIKey).Logout(ctx)
		var ae *client.APIError
		switch {
		case err == nil:
			fmt.Printf("Revoked API key %s.\n", saved.KeyID)
		case errors.As(err, &ae) && ae.Status == http.StatusUnauthorized:
			// Already revoked.
		default:
			fmt.Fprintf(os.Stderr, "warning: could not revoke API key %s (%v); revoke it with `rowsafe api-keys revoke %s` or in the dashboard\n",
				saved.KeyID, err, saved.KeyID)
		}
	default:
		fmt.Println("The API key was not created by `rowsafe login`, so it stays valid; revoke it in the dashboard if it is no longer needed.")
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Println("Logged out; removed", p)
	if agentOnAccount() {
		fmt.Println("The Rowsafe agent on this server stays connected to the account: logging out only signs this CLI out.\n" +
			"To use this server without an account again, run the installer with --no-account:\n" +
			"  curl -fsSL https://rowsafe.sh | sudo sh -s -- --no-account")
	}
	return nil
}

// agentOnAccount reports whether this server's agent is connected to an
// account (only root can read agent.env: sudo rowsafe logout).
func agentOnAccount() bool {
	data, err := os.ReadFile(agentEnvPath)
	if err != nil {
		return false
	}
	_, local := protocol.LocalSocket(envValue(data, "ROWSAFE_URL"))
	return !local
}
