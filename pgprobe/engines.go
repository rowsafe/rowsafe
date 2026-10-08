package pgprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// ProbeEngine looks at the port of a database of engine the way a stranger
// would. PostgreSQL gets Probe. MySQL and MariaDB: the server's greeting
// says whether it lets this address try to log in at all and whether it
// offers TLS (nothing is sent back). ClickHouse (its HTTP port): one
// "SELECT 1" without credentials shows whether the default user lets
// anyone in. Redis and Valkey: one PING without credentials does the same
// (protected mode turns strangers away before any password). MongoDB: whether the port accepts connections (whether it
// asks for a password comes from the agent's report).
func ProbeEngine(ctx context.Context, engine, addr string, o Options) Result {
	if o.DialTimeout <= 0 {
		o.DialTimeout = 5 * time.Second
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = 5 * time.Second
	}
	switch protocol.NormalizeEngine(engine) {
	case protocol.EnginePostgreSQL:
		return Probe(ctx, addr, o)
	case protocol.EngineMySQL, protocol.EngineMariaDB:
		return probeMySQL(ctx, addr, o)
	case protocol.EngineClickHouse:
		return probeClickHouseHTTP(ctx, addr, o)
	case protocol.EngineRedis, protocol.EngineValkey:
		return probeRedis(ctx, engine, addr, o)
	}
	conn, err := dial(ctx, addr, o)
	if err != nil {
		return dialFailure(err)
	}
	conn.Close()
	return Result{Reachable: true, State: protocol.OutsideAsksPassword,
		Detail: fmt.Sprintf("%s accepts connections from the internet on this port.", protocol.EngineDisplayName(engine))}
}

// clientSSL is the TLS capability flag of MySQL's handshake.
const clientSSL = 0x800

func probeMySQL(ctx context.Context, addr string, o Options) Result {
	conn, err := dial(ctx, addr, o)
	if err != nil {
		return dialFailure(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(o.ReadTimeout))
	r := bufio.NewReader(conn)
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like MySQL does."}
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n <= 0 || n > 1<<16 {
		return Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like MySQL does."}
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like MySQL does."}
	}
	if p[0] == 0xff { // an error instead of a greeting: "Host ... is not allowed to connect"
		msg := ""
		if len(p) > 3 {
			msg = strings.TrimSpace(string(p[3:]))
			msg = strings.TrimPrefix(msg, "#HY000")
		}
		return Result{Reachable: true, State: protocol.OutsideRefusesLogins, Detail: "The server answers but turns this address away before any password: " + clip(msg)}
	}
	if p[0] != 10 {
		return Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like MySQL does."}
	}
	// Protocol 10: version\0, thread id (4), auth data (8), filler (1),
	// capability flags (lower 2).
	i := 1
	for i < len(p) && p[i] != 0 {
		i++
	}
	version := string(p[1:i])
	i += 1 + 4 + 8 + 1
	res := Result{Reachable: true, State: protocol.OutsideAsksPassword,
		Detail: "The server answers from the internet (" + clip(version) + ") and asks for a password: anyone can try to guess one."}
	if i+2 <= len(p) {
		caps := binary.LittleEndian.Uint16(p[i : i+2])
		res.TLS = caps&clientSSL != 0
	}
	res.PlainLogins = true // whether TLS is required shows only after a login; the agent reports require_secure_transport
	return res
}

func probeClickHouseHTTP(ctx context.Context, addr string, o Options) Result {
	res := probeClickHouseOnce(ctx, addr, o, false)
	if res.Reachable && res.State == protocol.OutsideNotPostgres {
		// An HTTPS port (servers Rowsafe creates: ClickHouse's 8443, the
		// plain ports on the server itself only) doesn't answer plain HTTP:
		// ask again over TLS.
		if t := probeClickHouseOnce(ctx, addr, o, true); t.State != protocol.OutsideNotPostgres && t.State != protocol.OutsideError {
			t.PlainLogins, t.TLS = false, true
			t.Detail += " (over TLS)"
			return t
		}
	}
	return res
}

func probeClickHouseOnce(ctx context.Context, addr string, o Options, overTLS bool) Result {
	conn, err := dial(ctx, addr, o)
	if err != nil {
		return dialFailure(err)
	}
	conn.Close()
	tr := &http.Transport{DialContext: func(ctx context.Context, network, a string) (net.Conn, error) { return dial(ctx, addr, o) },
		DisableKeepAlives: true}
	scheme := "http"
	if overTLS {
		scheme = "https"
		// Only whether ClickHouse lets strangers in: its certificate isn't checked.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // a look from outside, nothing sent
		tr.DialTLSContext = nil
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: o.DialTimeout + o.ReadTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+addr+"/?query=SELECT%201", nil)
	resp, err := c.Do(req)
	if err != nil {
		return Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like ClickHouse's HTTP interface does."}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	text := string(body)
	switch {
	case resp.StatusCode == http.StatusOK && strings.TrimSpace(text) == "1":
		return Result{Reachable: true, State: protocol.OutsideNoPassword, PlainLogins: true,
			Detail: "ClickHouse answered a query from the internet without any password (its default user)."}
	case strings.Contains(text, "Code: 516") || strings.Contains(text, "Code: 194") || strings.Contains(text, "Authentication failed") ||
		resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		if strings.Contains(text, "is not allowed") || strings.Contains(text, "Code: 195") {
			return Result{Reachable: true, State: protocol.OutsideRefusesLogins, Detail: "ClickHouse answers but doesn't let this address log in."}
		}
		return Result{Reachable: true, State: protocol.OutsideAsksPassword, PlainLogins: true,
			Detail: "ClickHouse answers from the internet and asks for a password: anyone can try to guess one."}
	case strings.Contains(text, "Code: 195"):
		return Result{Reachable: true, State: protocol.OutsideRefusesLogins, Detail: "ClickHouse answers but doesn't let this address log in."}
	case resp.StatusCode == http.StatusBadRequest && (overTLS || strings.Contains(text, "HTTPS")):
		// A web server, or plain HTTP sent to an HTTPS port.
		return Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like ClickHouse's HTTP interface does."}
	}
	return Result{Reachable: true, State: protocol.OutsideAsksPassword, Detail: fmt.Sprintf("ClickHouse answers from the internet (HTTP %d).", resp.StatusCode)}
}

func probeRedis(ctx context.Context, engine, addr string, o Options) Result {
	res := probeRedisOnce(ctx, engine, addr, o, false)
	if res.Reachable && res.State == protocol.OutsideNotPostgres {
		// A TLS-only port (servers Rowsafe creates: Valkey on 6380) answers
		// plain text with a TLS alert: ask again over TLS.
		if t := probeRedisOnce(ctx, engine, addr, o, true); t.State != protocol.OutsideNotPostgres && t.State != protocol.OutsideError {
			t.PlainLogins = false
			t.Detail += " (over TLS)"
			return t
		}
	}
	return res
}

func probeRedisOnce(ctx context.Context, engine, addr string, o Options, overTLS bool) Result {
	conn, err := dial(ctx, addr, o)
	if err != nil {
		return dialFailure(err)
	}
	defer conn.Close()
	name := protocol.EngineDisplayName(engine)
	_ = conn.SetDeadline(time.Now().Add(o.ReadTimeout))
	if overTLS {
		host, _, _ := net.SplitHostPort(addr)
		tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // only asks whether it answers
		if err := tc.HandshakeContext(ctx); err != nil {
			return Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like " + name + " does."}
		}
		conn = tc
	}
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like " + name + " does."}
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	line = strings.TrimSpace(line)
	switch {
	case err != nil && line == "":
		return Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like " + name + " does."}
	case line == "+PONG":
		return Result{Reachable: true, State: protocol.OutsideNoPassword, PlainLogins: true,
			Detail: name + " answered from the internet without any password: anyone can read and change everything."}
	case strings.HasPrefix(line, "-NOAUTH"), strings.HasPrefix(line, "-WRONGPASS"):
		return Result{Reachable: true, State: protocol.OutsideAsksPassword, PlainLogins: true,
			Detail: name + " answers from the internet and asks for a password: anyone can try to guess one."}
	case strings.HasPrefix(line, "-DENIED"):
		return Result{Reachable: true, State: protocol.OutsideRefusesLogins, Detail: name + " answers but its protected mode turns this address away."}
	}
	return Result{Reachable: true, State: protocol.OutsideNotPostgres, Detail: "Something answers on this port, but not like " + name + " does."}
}

func clip(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}
