// Package pgprobe looks at a PostgreSQL port the way a stranger would: it
// connects, asks for TLS, and starts a login with a made-up user name
// ("rowsafe_outside_check") to see how far PostgreSQL lets it get. It never
// sends a password and closes the connection as soon as PostgreSQL asks
// for one, so it can't log in anywhere. PostgreSQL logs the attempt (for
// example "no pg_hba.conf entry for host ..., user rowsafe_outside_check").
package pgprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// User is the made-up user name of the login attempt.
const User = "rowsafe_outside_check"

// Result is what a probe found.
type Result struct {
	Reachable   bool
	State       string // protocol.Outside*
	TLS         bool   // PostgreSQL offers TLS
	PlainLogins bool   // a login without TLS gets as far as a password prompt, or further
	// Cert is the server's certificate when it offers TLS.
	Cert   *x509.Certificate
	Detail string
}

// Options tune a probe (zero values: 5 second timeouts).
type Options struct {
	DialTimeout time.Duration
	ReadTimeout time.Duration
	// Dial replaces net.Dialer (tests).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Probe checks addr ("host:port").
func Probe(ctx context.Context, addr string, o Options) Result {
	if o.DialTimeout <= 0 {
		o.DialTimeout = 5 * time.Second
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = 5 * time.Second
	}
	// First: TLS request, then a login inside TLS when it is offered.
	conn, err := dial(ctx, addr, o)
	if err != nil {
		return dialFailure(err)
	}
	res := Result{Reachable: true}
	offered, err := sslRequest(conn, o.ReadTimeout)
	if err != nil {
		conn.Close()
		res.State, res.Detail = protocol.OutsideNotPostgres, "Something answers on this port, but not like PostgreSQL does ("+err.Error()+")."
		return res
	}
	var first login
	if offered {
		res.TLS = true
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // only reads the certificate; never authenticates
		_ = tc.SetDeadline(time.Now().Add(o.ReadTimeout))
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			res.State, res.Detail = protocol.OutsideError, "PostgreSQL offers TLS, but the TLS handshake failed: "+err.Error()
			return res
		}
		if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 {
			res.Cert = certs[0]
		}
		first = startup(tc, o.ReadTimeout)
		tc.Close()
	} else {
		first = startup(conn, o.ReadTimeout)
		conn.Close()
	}
	res.State, res.Detail = first.state, first.detail
	if !offered {
		res.PlainLogins = first.state == protocol.OutsideAsksPassword || first.state == protocol.OutsideNoPassword
		return res
	}
	// TLS is offered: does PostgreSQL also take logins without it?
	conn, err = dial(ctx, addr, o)
	if err != nil {
		return res
	}
	plain := startup(conn, o.ReadTimeout)
	conn.Close()
	res.PlainLogins = plain.state == protocol.OutsideAsksPassword || plain.state == protocol.OutsideNoPassword
	if rank(plain.state) > rank(res.State) {
		res.State, res.Detail = plain.state, plain.detail
	}
	return res
}

// rank orders login states from safest to worst.
func rank(state string) int {
	switch state {
	case protocol.OutsideNoPassword:
		return 4
	case protocol.OutsideAsksPassword:
		return 3
	case protocol.OutsideError:
		return 2
	case protocol.OutsideRefusesLogins:
		return 1
	}
	return 0
}

func dial(ctx context.Context, addr string, o Options) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, o.DialTimeout)
	defer cancel()
	if o.Dial != nil {
		return o.Dial(dctx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(dctx, "tcp", addr)
}

func dialFailure(err error) Result {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return Result{State: protocol.OutsideClosed, Detail: "Nothing accepts connections on this port from the internet."}
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return Result{State: protocol.OutsideFiltered, Detail: "No answer: a firewall drops connections to this port."}
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return Result{State: protocol.OutsideFiltered, Detail: "The address can't be reached from the internet."}
	}
	return Result{State: protocol.OutsideError, Detail: "Could not connect: " + err.Error()}
}

// sslRequest asks for TLS: 'S' yes, 'N' no.
func sslRequest(conn net.Conn, timeout time.Duration) (bool, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	msg := make([]byte, 8)
	binary.BigEndian.PutUint32(msg[0:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], 80877103)
	if _, err := conn.Write(msg); err != nil {
		return false, err
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		return false, fmt.Errorf("no answer to a TLS request: %w", err)
	}
	switch b[0] {
	case 'S':
		return true, nil
	case 'N':
		return false, nil
	case 'E': // a very old server, or a pooler that rejects the request
		return false, errors.New("error answer to a TLS request")
	}
	return false, fmt.Errorf("unexpected answer %q to a TLS request", b[0])
}

type login struct{ state, detail string }

// startup starts a login as User and reads PostgreSQL's first answer.
func startup(conn net.Conn, timeout time.Duration) login {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var body []byte
	body = binary.BigEndian.AppendUint32(body, 196608) // protocol 3.0
	for _, kv := range [][2]string{{"user", User}, {"database", User}, {"application_name", "rowsafe-outside-check"}} {
		body = append(body, kv[0]...)
		body = append(body, 0)
		body = append(body, kv[1]...)
		body = append(body, 0)
	}
	body = append(body, 0)
	msg := binary.BigEndian.AppendUint32(nil, uint32(len(body)+4))
	msg = append(msg, body...)
	if _, err := conn.Write(msg); err != nil {
		return login{protocol.OutsideError, "Could not start a login: " + err.Error()}
	}
	r := bufio.NewReader(conn)
	typ, payload, err := readMessage(r)
	if err != nil {
		return login{protocol.OutsideError, "No answer to a login attempt: " + err.Error()}
	}
	switch typ {
	case 'R':
		if len(payload) < 4 {
			return login{protocol.OutsideError, "Malformed answer to a login attempt."}
		}
		switch code := binary.BigEndian.Uint32(payload[:4]); code {
		case 0:
			return login{protocol.OutsideNoPassword, "PostgreSQL let a made-up user in without asking for a password."}
		case 3:
			return login{protocol.OutsideAsksPassword, "PostgreSQL asks strangers for a password, and would receive it unencrypted over this connection."}
		default:
			return login{protocol.OutsideAsksPassword, "PostgreSQL asks strangers for a password: anyone on the internet can try to guess one."}
		}
	case 'E':
		code, message := errorFields(payload)
		lower := strings.ToLower(message)
		switch {
		case strings.Contains(lower, "pg_hba.conf"), strings.Contains(lower, "no encryption"),
			strings.Contains(lower, "client certificate"), strings.Contains(lower, "ident authentication"):
			return login{protocol.OutsideRefusesLogins, "PostgreSQL answers, but its access rules turn strangers away before any password."}
		case strings.Contains(lower, "does not exist"):
			return login{protocol.OutsideNoPassword, "PostgreSQL looked up a made-up user without asking for a password first: its rules trust connections from the internet."}
		case code == "28P01":
			return login{protocol.OutsideAsksPassword, "PostgreSQL checks passwords from strangers."}
		}
		return login{protocol.OutsideError, fmt.Sprintf("PostgreSQL answered a login attempt with an error (%s).", code)}
	}
	return login{protocol.OutsideNotPostgres, fmt.Sprintf("Unexpected answer %q to a login attempt.", typ)}
}

func readMessage(r *bufio.Reader) (byte, []byte, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return 0, nil, err
	}
	if n < 4 || n > 8192 {
		return 0, nil, fmt.Errorf("message length %d", n)
	}
	payload := make([]byte, n-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}

// errorFields reads the SQLSTATE and message of an ErrorResponse.
func errorFields(p []byte) (code, message string) {
	for len(p) > 0 && p[0] != 0 {
		field := p[0]
		end := 1
		for end < len(p) && p[end] != 0 {
			end++
		}
		value := string(p[1:end])
		switch field {
		case 'C':
			code = value
		case 'M':
			message = value
		}
		if end >= len(p) {
			break
		}
		p = p[end+1:]
	}
	return code, message
}
