package pgprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// probeOpenSearch asks OpenSearch's REST port for "/" without credentials,
// over TLS first (servers Rowsafe creates speak HTTPS only), then plain
// HTTP: a 401 means it asks for a password (the security plugin), a 200
// with a version means anyone can read and change everything.
func probeOpenSearch(ctx context.Context, addr string, o Options) Result {
	conn, err := dial(ctx, addr, o)
	if err != nil {
		return dialFailure(err)
	}
	conn.Close()
	res := probeOpenSearchOnce(ctx, addr, o, true)
	if res.State == protocol.OutsideNotPostgres || res.State == protocol.OutsideError {
		if p := probeOpenSearchOnce(ctx, addr, o, false); p.State != protocol.OutsideNotPostgres && p.State != protocol.OutsideError {
			return p
		}
	}
	return res
}

func probeOpenSearchOnce(ctx context.Context, addr string, o Options, overTLS bool) Result {
	tr := &http.Transport{DialContext: func(ctx context.Context, network, a string) (net.Conn, error) { return dial(ctx, addr, o) },
		DisableKeepAlives: true}
	scheme := "http"
	if overTLS {
		scheme = "https"
		// Only whether OpenSearch lets strangers in: its certificate isn't checked.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // a look from outside, nothing sent
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: o.DialTimeout + o.ReadTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+addr+"/", nil)
	resp, err := c.Do(req)
	notOS := Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like OpenSearch does."}
	if err != nil {
		return notOS
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	text := string(body)
	tlsWord := ""
	if overTLS {
		tlsWord = " over TLS"
	}
	switch {
	case resp.StatusCode == http.StatusOK && strings.Contains(text, `"distribution"`) && strings.Contains(text, "opensearch"):
		return Result{Reachable: true, State: protocol.OutsideNoPassword, TLS: overTLS, PlainLogins: !overTLS,
			Detail: "OpenSearch answered from the internet without any password" + tlsWord + ": anyone can read and change everything."}
	case resp.StatusCode == http.StatusUnauthorized:
		return Result{Reachable: true, State: protocol.OutsideAsksPassword, TLS: overTLS, PlainLogins: !overTLS,
			Detail: "OpenSearch answers from the internet and asks for a password" + tlsWord + ": anyone can try to guess one."}
	case resp.StatusCode == http.StatusForbidden:
		return Result{Reachable: true, State: protocol.OutsideRefusesLogins, TLS: overTLS, Detail: "OpenSearch answers but doesn't let this address in."}
	case resp.StatusCode == http.StatusBadRequest && !overTLS:
		return notOS // plain HTTP sent to an HTTPS port
	case resp.StatusCode == http.StatusOK:
		return notOS
	}
	return Result{Reachable: true, State: protocol.OutsideAsksPassword, TLS: overTLS, Detail: fmt.Sprintf("OpenSearch answers from the internet (HTTP %d).", resp.StatusCode)}
}
