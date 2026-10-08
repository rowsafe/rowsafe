package redis

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A small RESP2 client: commands as arrays of bulk strings, replies as
// Go values. It is all the agent needs (no cgo, no dependency), and it
// gives the replication link direct access to the byte stream.
//
// Replies: simple strings and bulk strings are string (binary safe),
// integers int64, arrays []any, a null bulk or array nil. A -ERR reply is
// returned as a respError (also as the error).

// respError is an error reply from the server ("ERR ...", "NOAUTH ...").
type respError string

func (e respError) Error() string { return string(e) }

// code is the error's first word ("ERR", "NOAUTH", "WRONGPASS", "NOPERM").
func (e respError) code() string {
	c, _, _ := strings.Cut(string(e), " ")
	return c
}

// isRespError reports whether err is a server error reply with one of codes
// (any code when none is given).
func isRespError(err error, codes ...string) bool {
	var re respError
	if !errors.As(err, &re) {
		return false
	}
	if len(codes) == 0 {
		return true
	}
	for _, c := range codes {
		if re.code() == c {
			return true
		}
	}
	return false
}

// Limits on what a reply may announce (a confused or hostile peer must not
// make the agent allocate gigabytes).
const (
	maxBulk      = 1 << 30 // proto-max-bulk-len is 512 MB by default
	maxArray     = 1 << 24
	maxLine      = 64 << 10
	defaultIOTTL = 30 * time.Second
)

// conn is one connection to a server.
type conn struct {
	nc      net.Conn
	br      *bufio.Reader
	bw      *bufio.Writer
	wmu     sync.Mutex // the replication link writes ACKs from another goroutine
	timeout time.Duration
}

// dialer opens connections (tests replace it).
var dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return d.DialContext(ctx, network, addr)
}

// dial connects to addr ("host:port", or a Unix socket path starting with
// "/") without signing in.
func dial(ctx context.Context, addr string) (*conn, error) {
	network := "tcp"
	if strings.HasPrefix(addr, "/") {
		network = "unix"
	}
	if network == "tcp" && loopbackAddr(addr) && localTLS(ctx, addr) {
		nc, err := dialTLSLocal(ctx, addr)
		if err != nil {
			tlsLocal.Delete(addr) // looked again on the next dial
			return nil, err
		}
		return newConn(nc), nil
	}
	nc, err := dialer(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return newConn(nc), nil
}

func newConn(nc net.Conn) *conn {
	return &conn{nc: nc, br: bufio.NewReaderSize(nc, 64<<10), bw: bufio.NewWriterSize(nc, 64<<10), timeout: defaultIOTTL}
}

// A server on this machine may speak only TLS: one the installer's
// --listen-public set up (servers Rowsafe creates) has no plain port at
// all, so nothing reaches it unencrypted over the network, and the agent
// connects to its TLS port on the loopback address. Whether a loopback
// address speaks TLS is found once (a TLS handshake: a plain server answers
// it with something that isn't TLS) and remembered; a failed TLS dial
// forgets it.
var tlsLocal sync.Map // addr -> bool

// tlsDetect: look for TLS on loopback addresses (tests with plain fakes
// turn it off).
var tlsDetect = true

func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// localTLS reports whether the loopback address speaks TLS.
func localTLS(ctx context.Context, addr string) bool {
	if !tlsDetect {
		return false
	}
	if v, ok := tlsLocal.Load(addr); ok {
		return v.(bool)
	}
	hctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	nc, err := dialTLSLocal(hctx, addr)
	is := err == nil
	if is {
		nc.Close()
	}
	var ne net.Error
	if is || !errors.As(err, &ne) || !ne.Timeout() { // a timeout tells nothing: look again next time
		var oe *net.OpError
		if is || !errors.As(err, &oe) || oe.Op != "dial" { // nor does a refused connection
			tlsLocal.Store(addr, is)
		}
	}
	return is
}

// dialTLSLocal opens a TLS connection to a server on this machine. Its
// certificate is for the server's public names (or self-signed): nothing
// to verify on the loopback address.
func dialTLSLocal(ctx context.Context, addr string) (net.Conn, error) {
	nc, err := dialer(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(nc, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // loopback only
	if err := tc.HandshakeContext(ctx); err != nil {
		nc.Close()
		return nil, err
	}
	return tc, nil
}

func (c *conn) Close() error { return c.nc.Close() }

// deadline sets the connection's deadline from ctx (or the default timeout).
func (c *conn) deadline(ctx context.Context) {
	d := time.Now().Add(c.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(d) {
		d = dl
	}
	_ = c.nc.SetDeadline(d)
}

// writeCommand buffers one command.
func (c *conn) writeCommand(args ...any) error {
	c.bw.WriteByte('*')
	c.bw.WriteString(strconv.Itoa(len(args)))
	c.bw.WriteString("\r\n")
	for _, a := range args {
		var s string
		switch v := a.(type) {
		case string:
			s = v
		case []byte:
			s = string(v)
		case int:
			s = strconv.Itoa(v)
		case int64:
			s = strconv.FormatInt(v, 10)
		case uint64:
			s = strconv.FormatUint(v, 10)
		case float64:
			s = strconv.FormatFloat(v, 'f', -1, 64)
		default:
			return fmt.Errorf("resp: unsupported argument type %T", a)
		}
		c.bw.WriteByte('$')
		c.bw.WriteString(strconv.Itoa(len(s)))
		c.bw.WriteString("\r\n")
		c.bw.WriteString(s)
		c.bw.WriteString("\r\n")
	}
	return nil
}

// do sends one command and reads its reply.
func (c *conn) do(ctx context.Context, args ...any) (any, error) {
	c.wmu.Lock()
	c.deadline(ctx)
	err := c.writeCommand(args...)
	if err == nil {
		err = c.bw.Flush()
	}
	c.wmu.Unlock()
	if err != nil {
		return nil, err
	}
	return c.readReply()
}

// pipeline sends commands together and reads their replies in order. A
// command's error reply is in its slot of errs; err is a connection error.
func (c *conn) pipeline(ctx context.Context, cmds [][]any) (replies []any, errs []error, err error) {
	c.wmu.Lock()
	c.deadline(ctx)
	for _, cmd := range cmds {
		if err = c.writeCommand(cmd...); err != nil {
			c.wmu.Unlock()
			return nil, nil, err
		}
	}
	err = c.bw.Flush()
	c.wmu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	replies, errs = make([]any, len(cmds)), make([]error, len(cmds))
	for i := range cmds {
		v, rerr := c.readReply()
		if rerr != nil && !isRespError(rerr) {
			return replies, errs, rerr
		}
		replies[i], errs[i] = v, rerr
	}
	return replies, errs, nil
}

// readLine reads one CRLF-terminated line (without the CRLF).
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		return "", errors.New("resp: line too long")
	}
	if err != nil {
		return "", err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", fmt.Errorf("resp: malformed line %q", clip(string(line), 80))
	}
	if len(line) > maxLine {
		return "", errors.New("resp: line too long")
	}
	return string(line[:len(line)-2]), nil
}

func (c *conn) readReply() (any, error) { return readReply(c.br) }

// readReply reads one reply.
func readReply(br *bufio.Reader) (any, error) {
	line, err := readLine(br)
	if err != nil {
		return nil, err
	}
	if line == "" {
		return nil, errors.New("resp: empty reply line")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, respError(line[1:])
	case ':':
		n, err := strconv.ParseInt(line[1:], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("resp: bad integer %q", clip(line, 40))
		}
		return n, nil
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil || n < -1 || n > maxBulk {
			return nil, fmt.Errorf("resp: bad bulk length %q", clip(line, 40))
		}
		if n == -1 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		if buf[n] != '\r' || buf[n+1] != '\n' {
			return nil, errors.New("resp: bulk string without CRLF")
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil || n < -1 || n > maxArray {
			return nil, fmt.Errorf("resp: bad array length %q", clip(line, 40))
		}
		if n == -1 {
			return nil, nil
		}
		out := make([]any, n)
		var firstErr error
		for i := range out {
			v, err := readReply(br)
			if err != nil {
				if !isRespError(err) {
					return nil, err
				}
				if firstErr == nil {
					firstErr = err
				}
				v = err
			}
			out[i] = v
		}
		return out, nil
	}
	return nil, fmt.Errorf("resp: unexpected reply %q", clip(line, 40))
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// ---- reply helpers

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int64:
		return strconv.FormatInt(x, 10)
	}
	return ""
}

func asInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	}
	return 0
}

func asArray(v any) []any {
	a, _ := v.([]any)
	return a
}

// str runs a command whose reply is a string.
func (c *conn) str(ctx context.Context, args ...any) (string, error) {
	v, err := c.do(ctx, args...)
	return asString(v), err
}

// integer runs a command whose reply is an integer.
func (c *conn) integer(ctx context.Context, args ...any) (int64, error) {
	v, err := c.do(ctx, args...)
	return asInt(v), err
}

// configGet reads one setting (CONFIG GET); "" when unknown.
func (c *conn) configGet(ctx context.Context, name string) (string, error) {
	v, err := c.do(ctx, "CONFIG", "GET", name)
	if err != nil {
		return "", err
	}
	a := asArray(v)
	for i := 0; i+1 < len(a); i += 2 {
		if strings.EqualFold(asString(a[i]), name) {
			return asString(a[i+1]), nil
		}
	}
	return "", nil
}

// info reads INFO sections into one map (key -> value).
func (c *conn) info(ctx context.Context, sections ...string) (infoMap, error) {
	args := []any{"INFO"}
	for _, s := range sections {
		args = append(args, s)
	}
	s, err := c.str(ctx, args...)
	if err != nil {
		return nil, err
	}
	return parseInfo(s), nil
}

// infoMap is INFO's key:value lines.
type infoMap map[string]string

func parseInfo(s string) infoMap {
	m := infoMap{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if ok {
			m[k] = v
		}
	}
	return m
}

func (m infoMap) int(k string) int64 {
	n, _ := strconv.ParseInt(m[k], 10, 64)
	return n
}

func (m infoMap) float(k string) float64 {
	f, _ := strconv.ParseFloat(m[k], 64)
	return f
}

// fields splits a "a=1,b=2" INFO value.
func fields(v string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(v, ",") {
		k, val, ok := strings.Cut(kv, "=")
		if ok {
			out[k] = val
		}
	}
	return out
}
