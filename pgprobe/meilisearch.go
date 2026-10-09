package pgprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// probeMeilisearch asks Meilisearch for its indexes without a key, the
// way a stranger would: plain HTTP first, then over TLS (servers Rowsafe
// creates serve only TLS on 7700; plain HTTP there gets a refusal). An
// answer with the indexes means it has no master key; 401 or 403 that it
// asks for a key.
func probeMeilisearch(ctx context.Context, addr string, o Options) Result {
	res := probeMeilisearchOnce(ctx, addr, o, false)
	if res.Reachable && res.State == protocol.OutsideNotPostgres {
		if t := probeMeilisearchOnce(ctx, addr, o, true); t.State != protocol.OutsideNotPostgres && t.State != protocol.OutsideError {
			t.PlainLogins, t.TLS = false, true
			t.Detail += " (over TLS)"
			return t
		}
	}
	return res
}

func probeMeilisearchOnce(ctx context.Context, addr string, o Options, overTLS bool) Result {
	conn, err := dial(ctx, addr, o)
	if err != nil {
		return dialFailure(err)
	}
	defer conn.Close()
	notMeili := Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like Meilisearch does."}
	_ = conn.SetDeadline(time.Now().Add(o.ReadTimeout))
	host, _, _ := net.SplitHostPort(addr)
	if overTLS {
		tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // only asks whether it answers
		if err := tc.HandshakeContext(ctx); err != nil {
			return notMeili
		}
		conn = tc
	}
	req := "GET /indexes HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: rowsafe-probe\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return notMeili
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return notMeili
	}
	defer resp.Body.Close()
	var body [512]byte
	n, _ := resp.Body.Read(body[:])
	text := string(body[:n])
	meili := strings.Contains(text, "meilisearch") || strings.Contains(text, `"code":`) && strings.Contains(text, `"type":`) ||
		strings.Contains(text, `"results"`)
	switch {
	case resp.StatusCode == http.StatusOK && strings.Contains(text, `"results"`):
		return Result{Reachable: true, State: protocol.OutsideNoPassword, PlainLogins: !overTLS,
			Detail: "Meilisearch answered from the internet without any key (it has no master key): anyone can read and change everything."}
	case (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && meili:
		return Result{Reachable: true, State: protocol.OutsideAsksPassword, PlainLogins: !overTLS,
			Detail: "Meilisearch answers from the internet and asks for an API key: anyone can try keys."}
	}
	return notMeili
}
