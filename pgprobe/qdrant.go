package pgprobe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// probeQdrant looks at a Qdrant port (REST, 6333, or gRPC, 6334) from
// outside: one request without a key, nothing else. Over TLS first (its
// certificate isn't checked: only whether Qdrant lets strangers in), then
// plain HTTP, which a Qdrant with TLS on doesn't answer.
func probeQdrant(ctx context.Context, addr string, o Options) Result {
	conn, err := dial(ctx, addr, o)
	if err != nil {
		return dialFailure(err)
	}
	conn.Close()
	notQdrant := Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like Qdrant does."}
	if r, ok := qdrantREST(ctx, addr, o, true); ok {
		r.TLS = true
		if p, ok := qdrantREST(ctx, addr, o, false); ok {
			r.PlainLogins = true
			if p.State == protocol.OutsideNoPassword {
				r.State = protocol.OutsideNoPassword
			}
		}
		return r
	}
	if r, ok := qdrantGRPC(ctx, addr, o, true); ok {
		return r
	}
	if r, ok := qdrantGRPC(ctx, addr, o, false); ok {
		r.TLS, r.PlainLogins = false, true
		r.Detail += " Without TLS: keys and data cross the internet in the clear."
		return r
	}
	if r, ok := qdrantREST(ctx, addr, o, false); ok {
		r.PlainLogins = true
		r.Detail += " Without TLS: keys and data cross the internet in the clear."
		return r
	}
	return notQdrant
}

// qdrantREST lists the collections without a key over REST: ok false when
// what answers isn't Qdrant's REST API.
func qdrantREST(ctx context.Context, addr string, o Options, overTLS bool) (Result, bool) {
	tr := &http.Transport{DialContext: func(ctx context.Context, network, a string) (net.Conn, error) { return dial(ctx, addr, o) },
		DisableKeepAlives: true}
	scheme := "http"
	if overTLS {
		scheme = "https"
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // a look from outside, nothing sent
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: o.DialTimeout + o.ReadTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+addr+"/collections", nil)
	resp, err := c.Do(req)
	if err != nil {
		return Result{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	var env struct {
		Result *struct {
			Collections []json.RawMessage `json:"collections"`
		} `json:"result"`
	}
	tlsWord := ""
	if overTLS {
		tlsWord = " (over TLS)"
	}
	switch {
	case resp.StatusCode == http.StatusOK && json.Unmarshal(body, &env) == nil && env.Result != nil:
		return Result{Reachable: true, State: protocol.OutsideNoPassword,
			Detail: fmt.Sprintf("Qdrant listed its collections to the internet without any key%s: anyone can read and delete them.", tlsWord)}, true
	case (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) &&
		(strings.Contains(string(body), "API key") || strings.Contains(string(body), "JWT") || strings.Contains(string(body), "Unauthorized")):
		return Result{Reachable: true, State: protocol.OutsideAsksPassword,
			Detail: "Qdrant answers from the internet and asks for a key" + tlsWord + ": anyone can try one."}, true
	}
	return Result{}, false
}

// qdrantGRPC lists the collections without a key over gRPC, with TLS or
// in plain HTTP/2 (h2c) (qdrant.Collections/List, an empty message):
// grpc-status 0 means it let a stranger in, 16 (unauthenticated) or 7
// (permission denied) that it asks for a key.
func qdrantGRPC(ctx context.Context, addr string, o Options, overTLS bool) (Result, bool) {
	tr := &http.Transport{DialContext: func(ctx context.Context, network, a string) (net.Conn, error) { return dial(ctx, addr, o) },
		ForceAttemptHTTP2: true, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}} //nolint:gosec // a look from outside
	scheme := "https"
	if !overTLS {
		scheme = "http"
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetUnencryptedHTTP2(true)
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: o.DialTimeout + o.ReadTimeout}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, scheme+"://"+addr+"/qdrant.Collections/List", strings.NewReader("\x00\x00\x00\x00\x00"))
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	resp, err := c.Do(req)
	if err != nil || resp.ProtoMajor != 2 {
		if resp != nil {
			resp.Body.Close()
		}
		return Result{}, false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	status := resp.Trailer.Get("Grpc-Status")
	if status == "" {
		status = resp.Header.Get("Grpc-Status")
	}
	switch status {
	case "0":
		return Result{Reachable: true, State: protocol.OutsideNoPassword, TLS: overTLS,
			Detail: "Qdrant's gRPC API listed its collections to the internet without any key: anyone can read and delete them."}, true
	case "16", "7":
		how := "over TLS"
		if !overTLS {
			how = "without TLS"
		}
		return Result{Reachable: true, State: protocol.OutsideAsksPassword, TLS: overTLS,
			Detail: "Qdrant's gRPC API answers from the internet (" + how + ") and asks for a key: anyone can try one."}, true
	}
	return Result{}, false
}
