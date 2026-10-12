package meilisearch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Meilisearch in Docker: the agent runs as a sidecar
// (ghcr.io/rowsafe/agent:meilisearch1, built on the official
// getmeili/meilisearch image, whose program runs Proof and Rewind copies)
// and reaches Meilisearch at ROWSAFE_MEILISEARCH_URL on the compose
// network: plain HTTP there (a network private to the host, the one the
// apps use with their own keys), or HTTPS checked against
// ROWSAFE_MEILISEARCH_CA_FILE (or the system's authorities). It reads the
// snapshots Meilisearch writes from a volume both containers mount
// (ROWSAFE_MEILISEARCH_SNAPSHOT_DIR in the agent's container). No listener
// check: the agent can't see the other container's sockets, and the URL is
// what the person set in the compose file.

const (
	urlEnv      = "ROWSAFE_MEILISEARCH_URL"
	caEnv       = "ROWSAFE_MEILISEARCH_CA_FILE"
	snapDirEnv  = "ROWSAFE_MEILISEARCH_SNAPSHOT_DIR"
	binEnv      = "ROWSAFE_MEILISEARCH_BIN"
	dockerGuide = "https://rowsafe.sh/docs/guides/docker"
)

// inDocker: the agent is a Docker sidecar reaching Meilisearch in another
// container.
func inDocker() bool {
	return os.Getenv("ROWSAFE_MODE") == "docker-sidecar" && strings.TrimSpace(os.Getenv(urlEnv)) != ""
}

// sidecarURL reads ROWSAFE_MEILISEARCH_URL: http(s)://host[:port], nothing
// else.
func sidecarURL() (*url.URL, error) {
	raw := strings.TrimSpace(os.Getenv(urlEnv))
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s=%q isn't an address Rowsafe takes: give http://SERVICE:7700 (the meilisearch service on the compose network) "+
			"or https://HOST:PORT", urlEnv, raw)
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "7700")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

// remoteTLS checks a sidecar's https URL: against ROWSAFE_MEILISEARCH_CA_FILE
// when set, else the system's authorities.
func remoteTLS() (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	f := strings.TrimSpace(os.Getenv(caEnv))
	if f == "" {
		return c, nil
	}
	pem, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("reading %s (%s): %w", caEnv, f, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s (%s) holds no certificate", caEnv, f)
	}
	c.RootCAs = pool
	return c, nil
}

// newRemoteClient is a client for Meilisearch at base (a sidecar's URL).
func newRemoteClient(base *url.URL, key string) (*client, error) {
	tc, err := remoteTLS()
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig:     tc,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	return &client{base: base.Scheme + "://" + base.Host, key: key, http: &http.Client{Transport: tr}}, nil
}

// prodClient is a client for production with key: on this machine, its
// port's listener checked (scheme http or https), or, from a Docker
// sidecar, at its URL.
func (s server) prodClient(scheme, key string) (*client, error) {
	if s.URL != "" {
		u, err := url.Parse(s.URL)
		if err != nil || u.Host == "" {
			return nil, errors.New("Rowsafe's Meilisearch settings hold an address it can't read: run `rowsafe-agent meilisearch login` again")
		}
		return newRemoteClient(u, key)
	}
	return newClient(scheme, s.localPort(), key, prodCheck(s)), nil
}

// localScheme is how production speaks on its local port.
func (s server) localScheme() string {
	if s.TLS && s.LocalPort == 0 {
		return "https"
	}
	return "http"
}

// exportTarget is the address a temporary Meilisearch exports to (a rewind
// in place), and the network it must be allowed to reach: production on
// this machine, or, from a sidecar, production's container.
func (s server) exportTarget(ctx context.Context) (target, network string, err error) {
	if s.URL == "" {
		return "http://" + net.JoinHostPort("127.0.0.1", fmt.Sprint(s.localPort())), "127.0.0.1/32", nil
	}
	u, err := url.Parse(s.URL)
	if err != nil {
		return "", "", err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return "", "", fmt.Errorf("finding %s on the compose network: %w", u.Hostname(), err)
	}
	ip := ips[0].IP
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return s.URL, fmt.Sprintf("%s/%d", ip.String(), bits), nil
}
