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
	for _, v := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		if os.Getenv(v) != "" {
			return false
		}
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "freebsd" {
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	}
	return true
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
	noBrowser := fs.Bool("no-browser", false, "print the login link instead of opening a browser")
	host, _ := os.Hostname()
	name := fs.String("name", "rowsafe CLI on "+host, "what the new API key is called (shown in the dashboard)")
	if _, err := parse(fs, args, false); err != nil {
		return err
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
		cfg, err = loginWithBrowser(ctx, url, *name, !*noBrowser && canOpenBrowser())
	}
	if err != nil {
		return err
	}
	p, err := saveConfig(cfg)
	if err != nil {
		return err
	}
	// A previous browser login's key is no longer used by anything.
	if saved.KeyID != "" && saved.APIKey != cfg.APIKey && saved.URL == cfg.URL {
		if err := client.New(saved.URL, saved.APIKey).Logout(ctx); err == nil {
			fmt.Printf("Revoked the previous login's API key (%s).\n", saved.KeyID)
		}
	}
	org := cfg.Org.Name
	if org == "" {
		org = cfg.Org.ID
	}
	fmt.Printf("Logged in to %s at %s. Credentials saved to %s\n", org, cfg.URL, p)
	return nil
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
	fmt.Printf("To log in, open\n\n  %s\n\nand confirm the code %s\n\n", start.VerificationURIComplete, start.UserCode)
	if browser {
		if openBrowser(start.VerificationURIComplete) == nil {
			fmt.Println("Opened it in your browser.")
		}
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

func whoami(ctx context.Context) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	me, err := client.New(cfg.URL, cfg.APIKey).WhoAmI(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Control plane: %s\n", cfg.URL)
	fmt.Printf("Organization:  %s (%s), %s plan\n", me.Org.Name, me.Org.ID, me.Org.Plan)
	if k := me.APIKey; k != nil {
		access := "read-write"
		if k.ReadOnly {
			access = "read-only"
		}
		fmt.Printf("API key:       %s (%s), %s\n", k.Name, k.ID, access)
	}
	if os.Getenv("ROWSAFE_API_KEY") != "" {
		fmt.Println("(credentials from ROWSAFE_API_KEY)")
	}
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
	return nil
}
