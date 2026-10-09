package meilisearch

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// Rowsafe's TLS front for Meilisearch (servers Rowsafe creates): it
// listens on the port apps use (7700), speaks TLS 1.2 or 1.3 with the
// server's certificate, and passes each connection's bytes to Meilisearch
// on 127.0.0.1 unchanged. It reads the certificate files again when they
// change, so a renewed certificate (Let's Encrypt, every few weeks) is
// served without restarting anything: Meilisearch loads its own TLS files
// only when it starts, and Rowsafe never restarts production by itself.
// Plain HTTP on that port gets a short refusal saying to use HTTPS.
//
// It runs as its own sandboxed systemd service
// (rowsafe-meilisearch-tls.service, as the system user
// rowsafe-meilisearch-tls, whose group may read the key), not inside the
// agent: updating or restarting the agent never interrupts apps'
// connections.
//
// Limits: a connection idle for IdleTimeout in either direction is closed;
// once one side has finished, the other gets CloseGrace to finish too;
// one address holds at most MaxPerIP connections. Meilisearch sees every
// request as coming from 127.0.0.1 (it takes no PROXY protocol), so the
// front logs each new client address (once per 10 minutes) and every
// refusal.

// FrontOptions configure RunTLSFront.
type FrontOptions struct {
	Listen   string // ":7700"
	Backend  string // "127.0.0.1:7701"
	CertFile string
	KeyFile  string
	// MaxConns caps open connections (0: 4096), MaxPerIP those from one
	// address (0: 256).
	MaxConns int
	MaxPerIP int
	// IdleTimeout closes a connection nothing was read on for that long
	// (0: 5 minutes); CloseGrace is how long the other direction may go on
	// once one has ended (0: 30 seconds).
	IdleTimeout time.Duration
	CloseGrace  time.Duration
	Log         *slog.Logger
}

// certReloader serves the certificate files, loading them again (at most
// once a second) when either changes. A pair that fails to load keeps the
// previous one in service.
type certReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	certMod, keyMod   time.Time
	checked           time.Time
	// failed are the files' times that didn't load (said once).
	failedCert, failedKey time.Time
	log                   *slog.Logger
}

func newCertReloader(certFile, keyFile string, log *slog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, log: log}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) load() error {
	cs, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	ks, err := os.Stat(r.keyFile)
	if err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert, r.certMod, r.keyMod = &c, cs.ModTime(), ks.ModTime()
	return nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) >= time.Second {
		r.checked = time.Now()
		cs, cerr := os.Stat(r.certFile)
		ks, kerr := os.Stat(r.keyFile)
		changed := cerr == nil && kerr == nil && (!cs.ModTime().Equal(r.certMod) || !ks.ModTime().Equal(r.keyMod))
		tried := changed && cs.ModTime().Equal(r.failedCert) && ks.ModTime().Equal(r.failedKey)
		if changed {
			if err := r.load(); err != nil {
				if !tried {
					r.log.Warn("the new certificate files don't load; still serving the previous certificate", "err", err)
				}
				r.failedCert, r.failedKey = cs.ModTime(), ks.ModTime()
			} else {
				r.log.Info("serving the new certificate")
			}
		}
	}
	return r.cert, nil
}

// frontTLSConfig is the TLS the front speaks: 1.2 or 1.3, HTTP/1.1 only
// (bytes pass through as they are, and Meilisearch speaks HTTP/1.1).
func frontTLSConfig(r *certReloader) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: r.get,
		NextProtos:     []string{"http/1.1"},
	}
}

// plainAnswer is a short HTTP answer before closing.
func plainAnswer(status, body string) string {
	return fmt.Sprintf("HTTP/1.1 %s\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", status, len(body), body)
}

var plainRefusal = plainAnswer("400 Bad Request", "This port speaks HTTPS only: use https://\n")

// RunTLSFront serves until ctx is done.
func RunTLSFront(ctx context.Context, o FrontOptions) error {
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	o.defaults()
	if _, _, err := net.SplitHostPort(o.Backend); err != nil {
		return fmt.Errorf("--to: %w", err)
	}
	rl, err := newCertReloader(o.CertFile, o.KeyFile, o.Log)
	if err != nil {
		return fmt.Errorf("loading the certificate: %w", err)
	}
	ln, err := net.Listen("tcp", o.Listen)
	if err != nil {
		return err
	}
	o.Log.Info("serving TLS", "listen", ln.Addr().String(), "to", o.Backend)
	return serveFront(ctx, ln, rl, o)
}

// clients counts open connections per address and when each address was
// last logged.
type clients struct {
	mu     sync.Mutex
	open   map[string]int
	logged map[string]time.Time
}

func (c *clients) add(ip string, max int) (ok, log bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open[ip] >= max {
		return false, false
	}
	c.open[ip]++
	now := time.Now()
	if now.Sub(c.logged[ip]) > 10*time.Minute {
		c.logged[ip] = now
		log = true
	}
	if len(c.logged) > 100000 { // forget old addresses
		for k, t := range c.logged {
			if now.Sub(t) > 10*time.Minute {
				delete(c.logged, k)
			}
		}
	}
	return true, log
}

func (c *clients) done(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open[ip]--; c.open[ip] <= 0 {
		delete(c.open, ip)
	}
}

func (o *FrontOptions) defaults() {
	if o.MaxConns <= 0 {
		o.MaxConns = 4096
	}
	if o.MaxPerIP <= 0 {
		o.MaxPerIP = 256
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 5 * time.Minute
	}
	if o.CloseGrace <= 0 {
		o.CloseGrace = 30 * time.Second
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
}

func serveFront(ctx context.Context, ln net.Listener, rl *certReloader, o FrontOptions) error {
	o.defaults()
	cfg := frontTLSConfig(rl)
	sem := make(chan struct{}, o.MaxConns)
	cl := &clients{open: map[string]int{}, logged: map[string]time.Time{}}
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		ip := remoteIP(nc)
		select {
		case sem <- struct{}{}:
		default:
			nc.Close() // too many connections: refuse rather than queue
			o.Log.Warn("refused a connection: too many open", "client", ip, "max", o.MaxConns)
			continue
		}
		ok, logIt := cl.add(ip, o.MaxPerIP)
		if !ok {
			<-sem
			nc.Close()
			o.Log.Warn("refused a connection: too many from one address", "client", ip, "max_per_address", o.MaxPerIP)
			continue
		}
		if logIt {
			o.Log.Info("client", "address", ip)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer cl.done(ip)
			handleFrontConn(ctx, nc, cfg, o)
		}()
	}
}

// peekedConn is a connection whose first bytes were read through br.
type peekedConn struct {
	net.Conn
	br *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) { return p.br.Read(b) }

func remoteIP(c net.Conn) string {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	h, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return h
}

// idleReader reads from c with a fresh deadline before every read.
type idleReader struct {
	c    net.Conn
	idle time.Duration
}

func (r idleReader) Read(b []byte) (int, error) {
	_ = r.c.SetReadDeadline(time.Now().Add(r.idle))
	return r.c.Read(b)
}

func handleFrontConn(ctx context.Context, nc net.Conn, cfg *tls.Config, o FrontOptions) {
	backend := o.Backend
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(nc)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] != 0x16 { // not a TLS handshake: most likely plain HTTP
		_, _ = io.WriteString(nc, plainRefusal)
		return
	}
	tc := tls.Server(&peekedConn{Conn: nc, br: br}, cfg)
	hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err = tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		return
	}
	_ = nc.SetDeadline(time.Time{})
	bc, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", backend)
	if err != nil {
		_, _ = io.WriteString(tc, plainAnswer("503 Service Unavailable", "Meilisearch isn't running.\n"))
		return
	}
	defer bc.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(bc, idleReader{c: tc, idle: o.IdleTimeout})
		if t, ok := bc.(*net.TCPConn); ok {
			_ = t.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(tc, idleReader{c: bc, idle: o.IdleTimeout})
		_ = tc.CloseWrite()
		done <- struct{}{}
	}()
	select {
	case <-done:
		// One side finished: the other gets a little while, then both close.
		select {
		case <-done:
		case <-time.After(o.CloseGrace):
		case <-ctx.Done():
		}
	case <-ctx.Done():
	}
}
