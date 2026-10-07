package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// This computer's public address, for "who can connect" (rowsafe cloud
// create, allow, connect). The control plane doesn't say where a request
// comes from, so with the hosted control plane the CLI asks rowsafe.sh's
// own edge (Cloudflare's /cdn-cgi/trace answers with the caller's address),
// once over IPv4 and once over IPv6: apps may reach the server over either.
// Nothing is sent but the request itself. With another control plane
// (self-hosted), people pass the address with --allow.

// traceURL answers "ip=ADDRESS" lines (tests replace it).
var traceURL = "https://rowsafe.sh/cdn-cgi/trace"

// publicAddresses returns this computer's public IPv4 and IPv6 addresses
// (one or both). Tests replace it.
var publicAddresses = func(ctx context.Context, apiURL string) ([]string, error) {
	if strings.TrimRight(apiURL, "/") != protocol.DefaultAPIURL {
		return nil, errors.New("this computer's public address can only be found with Rowsafe's hosted service: pass it with --allow (search \"what is my IP\")")
	}
	var out []string
	for _, network := range []string{"tcp4", "tcp6"} {
		if ip, err := traceAddress(ctx, network); err == nil && !slices.Contains(out, ip) {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("this computer's public address couldn't be found: pass it with --allow (search \"what is my IP\")")
	}
	return out, nil
}

// traceAddress asks traceURL over one network ("tcp4" or "tcp6").
func traceAddress(ctx context.Context, network string) (string, error) {
	d := &net.Dialer{Timeout: 4 * time.Second}
	hc := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "ip="); ok {
			a, err := netip.ParseAddr(strings.TrimSpace(v))
			if err != nil || !publicAddr(a) {
				return "", fmt.Errorf("not a public address: %q", v)
			}
			return a.Unmap().String(), nil
		}
	}
	return "", errors.New("no address in the answer")
}

func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate()
}

// myAddresses is this computer's public addresses as allow-list entries
// (203.0.113.4/32).
func myAddresses(ctx context.Context, apiURL string) ([]string, error) {
	mine, err := publicAddresses(ctx, apiURL)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(mine))
	for _, a := range mine {
		p, err := parseSource(a)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// expandAddresses turns --allow values into addresses or networks: "me"
// is this computer's public address(es); "none" is nobody.
func expandAddresses(ctx context.Context, apiURL string, in []string) ([]string, error) {
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		switch strings.ToLower(v) {
		case "":
			continue
		case "none":
			continue
		case "me", "my-ip", "my_ip":
			mine, err := myAddresses(ctx, apiURL)
			if err != nil {
				return nil, err
			}
			out = append(out, mine...)
			continue
		}
		p, err := parseSource(v)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return dedupe(out), nil
}

// parseSource checks an address or network and returns it as the control
// plane stores it (203.0.113.4/32, 203.0.113.0/24).
func parseSource(v string) (string, error) {
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return "", fmt.Errorf("%q isn't an IP address or network (like 203.0.113.4 or 203.0.113.0/24)", v)
		}
		return p.Masked().String(), nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return "", fmt.Errorf("%q isn't an IP address or network (like 203.0.113.4 or 203.0.113.0/24)", v)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()).String(), nil
}

// looksLikeSource reports whether an argument is an address, a network or
// "me" (not a server's name).
func looksLikeSource(v string) bool {
	switch strings.ToLower(v) {
	case "me", "my-ip", "my_ip", "none":
		return true
	}
	_, err := parseSource(v)
	return err == nil
}

func dedupe(in []string) []string {
	var out []string
	for _, v := range in {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// allowedFrom reports whether one of addrs falls in one of the allowed
// networks.
func allowedFrom(allowed, addrs []string) bool {
	for _, s := range allowed {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			if a, err2 := netip.ParseAddr(s); err2 == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				continue
			}
		}
		for _, v := range addrs {
			if a, err := netip.ParseAddr(strings.Split(v, "/")[0]); err == nil && p.Contains(a.Unmap()) {
				return true
			}
		}
	}
	return false
}

// shortSource shows 203.0.113.4/32 as 203.0.113.4.
func shortSource(s string) string {
	if p, err := netip.ParsePrefix(s); err == nil && p.IsSingleIP() {
		return p.Addr().String()
	}
	return s
}

func sourcesText(list []string) string {
	if len(list) == 0 {
		return "nobody"
	}
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = shortSource(s)
	}
	return strings.Join(out, ", ")
}
