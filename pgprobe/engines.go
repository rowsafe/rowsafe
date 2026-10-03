package pgprobe

import (
	"bufio"
	"context"
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
// anyone in. MongoDB: whether the port accepts connections (whether it
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
	conn, err := dial(ctx, addr, o)
	if err != nil {
		return dialFailure(err)
	}
	conn.Close()
	tr := &http.Transport{DialContext: func(ctx context.Context, network, a string) (net.Conn, error) { return dial(ctx, addr, o) },
		DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: o.DialTimeout + o.ReadTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/?query=SELECT%201", nil)
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
	}
	return Result{Reachable: true, State: protocol.OutsideAsksPassword, Detail: fmt.Sprintf("ClickHouse answers from the internet (HTTP %d).", resp.StatusCode)}
}

func clip(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}
