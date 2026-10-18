package localcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/pglog"
	"github.com/rowsafe/rowsafe/protocol"
)

// Log forwarding on a server without an account: the entries this server
// keeps (logs.go) go to the destinations root adds (sudo rowsafe logs
// forward), straight from this server, in the hosted control plane's
// formats: Datadog, Better Stack, Papertrail, Grafana Loki,
// Elasticsearch/OpenSearch, a signed webhook, or syslog over TLS.

// Forwarding limits.
const (
	maxLogDestinations    = 10
	logForwardBatch       = 500 // entries per delivery
	logForwardMaxBatches  = 20  // per destination and round
	logForwardEvery       = 10 * time.Second
	logForwardTimeout     = 15 * time.Second
	logDestDefaultIndex   = "rowsafe-logs"
	logDestBetterStackURL = "https://in.logs.betterstack.com"
)

// logDatadogSites are Datadog's sites (the intake is http-intake.logs.<site>).
var logDatadogSites = []string{"datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu", "ap1.datadoghq.com",
	"ap2.datadoghq.com", "ddog-gov.com"}

// logDestRec is a destination with its secrets and delivery cursor.
type logDestRec struct {
	protocol.LogDestination
	Secret   string     `json:"secret,omitempty"`
	Signing  string     `json:"signing,omitempty"` // webhook signing secret
	Cursor   int64      `json:"cursor"`            // the newest entry delivered
	Failures int        `json:"failures,omitempty"`
	NextAt   *time.Time `json:"next_at,omitempty"` // no retry before this
}

// view is the destination as the API shows it: no secrets.
func (d *logDestRec) view() protocol.LogDestination {
	v := d.LogDestination
	v.SigningSecret = ""
	v.Filter.Kinds = nonNil(v.Filter.Kinds)
	v.Filter.DatabaseIDs = nonNil(v.Filter.DatabaseIDs)
	if v.Type == protocol.LogDestWebhook || v.Type == protocol.LogDestLoki || v.Type == protocol.LogDestElastic {
		v.Config.URL = redactURL(v.Config.URL)
	}
	return v
}

func (d *logDestRec) wants(l logLine) bool {
	if len(d.Filter.DatabaseIDs) > 0 && !slices.Contains(d.Filter.DatabaseIDs, l.DB) {
		return false
	}
	if len(d.Filter.Kinds) == 0 {
		return true
	}
	for _, k := range d.Filter.Kinds {
		kinds, errorsOnly, _ := logKindsFor(k)
		if (errorsOnly && pglog.IsError(l.Severity)) || slices.Contains(kinds, l.Kind) {
			return true
		}
	}
	return false
}

func logSecretHint(secret string) string {
	if len(secret) < 12 {
		return "••••"
	}
	return "••••" + secret[len(secret)-4:]
}

// validateLogDest checks a destination and fills defaults (the hosted
// control plane's rules; http:// only to this machine or a private network).
func (s *Server) validateLogDest(d *logDestRec) error {
	c := &d.Config
	checkURL := func(what string) error {
		c.URL = strings.TrimRight(strings.TrimSpace(c.URL), "/")
		if c.URL == "" {
			return fmt.Errorf("%s: --url is required", what)
		}
		if err := s.checkURL(c.URL); err != nil { // alerts.go
			return fmt.Errorf("%s: %w", what, err)
		}
		return nil
	}
	checkHost := func(what string) error {
		c.Host = strings.TrimSpace(c.Host)
		if c.Host == "" || strings.ContainsAny(c.Host, "/: ") {
			return fmt.Errorf("%s: --host is required (without https:// or a port)", what)
		}
		if c.Port < 1 || c.Port > 65535 {
			return fmt.Errorf("%s: --port must be a number from 1 to 65535", what)
		}
		return nil
	}
	switch d.Type {
	case protocol.LogDestDatadog:
		if c.Site == "" {
			c.Site = "datadoghq.com"
		}
		if !slices.Contains(logDatadogSites, c.Site) {
			return fmt.Errorf("Datadog: unknown site %q (one of %s)", c.Site, strings.Join(logDatadogSites, ", "))
		}
		if d.Secret == "" {
			return errors.New("Datadog: the API key is required")
		}
	case protocol.LogDestBetterStack:
		if c.URL == "" {
			c.URL = logDestBetterStackURL
		} else if !strings.Contains(c.URL, "://") {
			c.URL = "https://" + c.URL
		}
		if err := checkURL("Better Stack"); err != nil {
			return err
		}
		if d.Secret == "" {
			return errors.New("Better Stack: the source token is required")
		}
	case protocol.LogDestPapertrail:
		return checkHost("Papertrail")
	case protocol.LogDestSyslog:
		return checkHost("Syslog")
	case protocol.LogDestLoki:
		return checkURL("Grafana Loki")
	case protocol.LogDestElastic:
		if err := checkURL("Elasticsearch"); err != nil {
			return err
		}
		if c.Index == "" {
			c.Index = logDestDefaultIndex
		}
		if strings.ContainsAny(c.Index, ` "*\<|,>/?#`) || strings.ToLower(c.Index) != c.Index {
			return errors.New("Elasticsearch: the index name must be lowercase, without spaces or \\/*?\"<>|,#")
		}
	case protocol.LogDestWebhook:
		return checkURL("Webhook")
	default:
		return fmt.Errorf("--type is one of %s", strings.Join(protocol.LogDestTypes, ", "))
	}
	return nil
}

func validLogFilter(st *state, f *protocol.LogDestinationFilter) error {
	if len(f.Kinds) > 20 || len(f.DatabaseIDs) > 200 {
		return errors.New("the filter is too long")
	}
	for _, k := range f.Kinds {
		if _, _, ok := logKindsFor(k); !ok || k == "" || k == "all" {
			return fmt.Errorf("unknown kind %q in the filter", k)
		}
	}
	for i, ref := range f.DatabaseIDs {
		d := st.db(ref)
		if d == nil {
			return fmt.Errorf("no database %q on this server", ref)
		}
		f.DatabaseIDs[i] = d.ID
	}
	return nil
}

// ---- the API (rowsafe logs forward, rowsafe log-destinations) ----

func (s *Server) logDestRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/log-destinations", s.logDestList)
	mux.HandleFunc("POST /v1/log-destinations", s.logDestCreate)
	mux.HandleFunc("PATCH /v1/log-destinations/{id}", s.logDestUpdate)
	mux.HandleFunc("DELETE /v1/log-destinations/{id}", s.logDestDelete)
	mux.HandleFunc("POST /v1/log-destinations/{id}/test", s.logDestTest)
}

func (ls *logStore) dest(ref string) *logDestRec {
	for _, d := range ls.meta.Destinations {
		if d.ID == ref || d.Name == ref {
			return d
		}
	}
	return nil
}

func (s *Server) logDestList(w http.ResponseWriter, r *http.Request) {
	ls := s.logStore()
	ls.mu.Lock()
	out := []protocol.LogDestination{}
	for _, d := range ls.meta.Destinations {
		out = append(out, d.view())
	}
	ls.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) logDestCreate(w http.ResponseWriter, r *http.Request) {
	var req protocol.CreateLogDestinationRequest
	if !readJSON(w, r, &req) {
		return
	}
	req.Name, req.Secret = strings.TrimSpace(req.Name), strings.TrimSpace(req.Secret)
	if req.Name == "" || len(req.Name) > 100 {
		writeError(w, http.StatusBadRequest, "--name is required (at most 100 characters)")
		return
	}
	if len(req.Secret) > 4096 {
		writeError(w, http.StatusBadRequest, "the secret is too long")
		return
	}
	d := &logDestRec{LogDestination: protocol.LogDestination{ID: newID("ldst"), Type: req.Type, Name: req.Name,
		Config: req.Config, Filter: req.Filter, Enabled: true, CreatedAt: s.now().UTC()}, Secret: req.Secret}
	if err := s.validateLogDest(d); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var ferr error
	s.st.read(func(st *state) { ferr = validLogFilter(st, &d.Filter) })
	if ferr != nil {
		writeError(w, http.StatusBadRequest, ferr.Error())
		return
	}
	if d.Secret != "" {
		d.HasSecret, d.SecretHint = true, logSecretHint(d.Secret)
	}
	if d.Type == protocol.LogDestWebhook {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		d.Signing = "whsec_" + hex.EncodeToString(b)
	}
	ls := s.logStore()
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if len(ls.meta.Destinations) >= maxLogDestinations {
		writeError(w, http.StatusConflict, fmt.Sprintf("at most %d destinations", maxLogDestinations))
		return
	}
	if ls.dest(d.Name) != nil {
		writeError(w, http.StatusConflict, fmt.Sprintf("a destination named %q already exists", d.Name))
		return
	}
	d.Cursor = ls.last // from now on
	ls.meta.Destinations = append(ls.meta.Destinations, d)
	if err := ls.saveMeta(); err != nil {
		ls.meta.Destinations = ls.meta.Destinations[:len(ls.meta.Destinations)-1]
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := d.view()
	out.SigningSecret = d.Signing // shown once
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) logDestUpdate(w http.ResponseWriter, r *http.Request) {
	var req protocol.UpdateLogDestinationRequest
	if !readJSON(w, r, &req) {
		return
	}
	ls := s.logStore()
	ls.mu.Lock()
	cur := ls.dest(r.PathValue("id"))
	var d logDestRec
	if cur != nil {
		d = *cur
	}
	ls.mu.Unlock()
	if cur == nil {
		writeError(w, http.StatusNotFound, "no log destination "+r.PathValue("id")+" (sudo rowsafe logs forward list)")
		return
	}
	if req.Name != nil {
		n := strings.TrimSpace(*req.Name)
		if n == "" || len(n) > 100 {
			writeError(w, http.StatusBadRequest, "name must be 1 to 100 characters")
			return
		}
		d.Name = n
	}
	if req.Enabled != nil {
		d.Enabled = *req.Enabled
		d.Failures, d.NextAt = 0, nil
	}
	if req.Secret != nil && strings.TrimSpace(*req.Secret) != "" {
		d.Secret = strings.TrimSpace(*req.Secret)
		d.HasSecret, d.SecretHint = true, logSecretHint(d.Secret)
	}
	if req.Config != nil {
		d.Config = *req.Config
	}
	if req.Config != nil || req.Secret != nil {
		if err := s.validateLogDest(&d); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.Filter != nil {
		f := *req.Filter
		f.Kinds, f.DatabaseIDs = slices.Clone(f.Kinds), slices.Clone(f.DatabaseIDs)
		var ferr error
		s.st.read(func(st *state) { ferr = validLogFilter(st, &f) })
		if ferr != nil {
			writeError(w, http.StatusBadRequest, ferr.Error())
			return
		}
		d.Filter = f
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	cur = ls.dest(d.ID)
	if cur == nil {
		writeError(w, http.StatusNotFound, "no log destination "+r.PathValue("id"))
		return
	}
	d.Cursor = cur.Cursor // delivery moved on meanwhile
	prev := *cur
	*cur = d
	if err := ls.saveMeta(); err != nil {
		*cur = prev
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, d.view())
}

func (s *Server) logDestDelete(w http.ResponseWriter, r *http.Request) {
	ls := s.logStore()
	ls.mu.Lock()
	defer ls.mu.Unlock()
	d := ls.dest(r.PathValue("id"))
	if d == nil {
		writeError(w, http.StatusNotFound, "no log destination "+r.PathValue("id")+" (sudo rowsafe logs forward list)")
		return
	}
	prev := ls.meta.Destinations
	ls.meta.Destinations = slices.DeleteFunc(slices.Clone(prev), func(x *logDestRec) bool { return x.ID == d.ID })
	if err := ls.saveMeta(); err != nil {
		ls.meta.Destinations = prev
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logDestTest(w http.ResponseWriter, r *http.Request) {
	ls := s.logStore()
	ls.mu.Lock()
	var d *logDestRec
	if cur := ls.dest(r.PathValue("id")); cur != nil {
		cp := *cur
		d = &cp
	}
	ls.mu.Unlock()
	if d == nil {
		writeError(w, http.StatusNotFound, "no log destination "+r.PathValue("id")+" (sudo rowsafe logs forward list)")
		return
	}
	var host string
	s.st.read(func(st *state) { host = st.hostname() })
	test := protocol.ForwardedLog{ID: "test", Host: host, DatabaseID: "test", DatabaseName: "rowsafe-test",
		LogEntry: protocol.LogEntry{Time: s.now().UTC(), Severity: "LOG", Kind: protocol.LogKindOther,
			Message: "Test from Rowsafe: this destination receives your PostgreSQL logs."}}
	if err := s.sendLogs(r.Context(), d, []protocol.ForwardedLog{test}, newID("lgt")); err != nil {
		writeJSON(w, http.StatusOK, protocol.ChannelTestResult{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, protocol.ChannelTestResult{OK: true})
}

// ---- delivery ----

// forwardSoon wakes the forwarding loop (new entries arrived).
func (s *Server) forwardSoon() {
	select {
	case s.logStore().kick <- struct{}{}:
	default:
	}
}

// runLogForwarding delivers new entries to the destinations until ctx ends.
func (s *Server) runLogForwarding(ctx context.Context) {
	ls := s.logStore()
	t := time.NewTicker(logForwardEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-ls.kick:
		}
		s.ForwardLogs(ctx)
	}
}

// ForwardLogs runs one delivery round: each due destination's new entries,
// batch by batch.
func (s *Server) ForwardLogs(ctx context.Context) {
	ls := s.logStore()
	ls.mu.Lock()
	var due []string
	now := s.now()
	for _, d := range ls.meta.Destinations {
		if d.Enabled && d.Cursor < ls.last && (d.NextAt == nil || !now.Before(*d.NextAt)) {
			due = append(due, d.ID)
		}
	}
	ls.mu.Unlock()
	if len(due) == 0 {
		return
	}
	var host string
	names := map[string]string{}
	s.st.read(func(st *state) {
		host = st.hostname()
		for _, d := range st.Databases {
			names[d.ID] = d.Name
		}
	})
	for _, id := range due {
		for range logForwardMaxBatches {
			if ctx.Err() != nil || !s.forwardBatch(ctx, id, host, names) {
				break
			}
		}
	}
}

// forwardBatch sends one batch to a destination; false when there is
// nothing more to send now.
func (s *Server) forwardBatch(ctx context.Context, id, host string, names map[string]string) bool {
	ls := s.logStore()
	ls.mu.Lock()
	cur := ls.dest(id)
	if cur == nil || !cur.Enabled || cur.Cursor >= ls.last {
		ls.mu.Unlock()
		return false
	}
	d := *cur
	var entries []protocol.ForwardedLog
	next := d.Cursor
	_ = ls.since(d.Cursor, func(l logLine) bool {
		next = l.ID
		if d.wants(l) {
			entries = append(entries, protocol.ForwardedLog{ID: strconv.FormatInt(l.ID, 10), Host: host,
				DatabaseID: l.DB, DatabaseName: names[l.DB], LogEntry: l.LogEntry})
		}
		return len(entries) < logForwardBatch
	})
	if next == d.Cursor { // what was there is gone (older than the files)
		next = ls.last
	}
	ls.mu.Unlock()

	err := s.sendLogs(ctx, &d, entries, newID("lgf"))
	now := s.now().UTC()
	ls.mu.Lock()
	defer ls.mu.Unlock()
	cur = ls.dest(id)
	if cur == nil {
		return false
	}
	if err != nil {
		// 30s, 1m, 2m ... up to an hour.
		wait := min(30*time.Second*time.Duration(1<<min(cur.Failures, 7)), time.Hour)
		at := now.Add(wait)
		cur.Failures++
		cur.NextAt, cur.LastError, cur.LastErrorAt = &at, clipBytes(err.Error(), 300), &now
		if cur.Failures == 1 || wait == time.Hour {
			s.log.Warn("log forwarding failed", "destination", cur.Name, "type", cur.Type, "attempt", cur.Failures, "err", err)
		}
		_ = ls.saveMeta()
		return false
	}
	cur.Cursor, cur.Failures, cur.NextAt = next, 0, nil
	if len(entries) > 0 {
		cur.LastSentAt = &now
		cur.Delivered += int64(len(entries))
	}
	if err := ls.saveMeta(); err != nil {
		s.log.Warn("saving the log forwarding position", "err", err)
	}
	return next < ls.last
}

// sendLogs delivers entries to one destination.
func (s *Server) sendLogs(ctx context.Context, d *logDestRec, entries []protocol.ForwardedLog, deliveryID string) error {
	if len(entries) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, logForwardTimeout+5*time.Second)
	defer cancel()
	switch d.Type {
	case protocol.LogDestDatadog:
		return s.logsDatadog(ctx, d, entries)
	case protocol.LogDestBetterStack:
		return s.logsBetterStack(ctx, d, entries)
	case protocol.LogDestLoki:
		return s.logsLoki(ctx, d, entries)
	case protocol.LogDestElastic:
		return s.logsElastic(ctx, d, entries)
	case protocol.LogDestWebhook:
		return s.logsWebhook(ctx, d, entries, deliveryID)
	case protocol.LogDestPapertrail, protocol.LogDestSyslog:
		return s.logsSyslog(ctx, d, entries)
	}
	return fmt.Errorf("unknown destination type %q", d.Type)
}

// logLineText is an entry as one line of text, PostgreSQL style:
// "ERROR:  message  DETAIL: ...  STATEMENT: ..." with who and where first.
func logLineText(l protocol.ForwardedLog) string {
	var b strings.Builder
	if l.User != "" || l.Database != "" {
		fmt.Fprintf(&b, "%s@%s ", l.User, l.Database)
	}
	if l.Client != "" {
		fmt.Fprintf(&b, "client=%s ", l.Client)
	}
	b.WriteString(l.Severity + ":  ")
	if l.SQLState != "" {
		b.WriteString(l.SQLState + " ")
	}
	b.WriteString(l.Message)
	for _, p := range [][2]string{{"DETAIL", l.Detail}, {"HINT", l.Hint}, {"CONTEXT", l.Context}, {"STATEMENT", l.Statement}} {
		if p[1] != "" {
			b.WriteString("  " + p[0] + ":  " + strings.ReplaceAll(p[1], "\n", " "))
		}
	}
	return b.String()
}

// logLevel maps a PostgreSQL severity to the usual log levels.
func logLevel(sev string) string {
	switch sev {
	case "PANIC", "FATAL":
		return "critical"
	case "ERROR":
		return "error"
	case "WARNING":
		return "warning"
	case "NOTICE":
		return "notice"
	case "DEBUG1", "DEBUG2", "DEBUG3", "DEBUG4", "DEBUG5":
		return "debug"
	}
	return "info"
}

// logFields are an entry's attributes for JSON destinations.
func logFields(l protocol.ForwardedLog) map[string]any {
	m := map[string]any{
		"id": l.ID, "time": l.Time.UTC().Format(time.RFC3339Nano), "host": l.Host, "database_id": l.DatabaseID,
		"database_name": l.DatabaseName, "severity": l.Severity, "kind": l.Kind, "message": l.Message,
	}
	add := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	add("sqlstate", l.SQLState)
	add("detail", l.Detail)
	add("hint", l.Hint)
	add("context", l.Context)
	add("statement", l.Statement)
	add("user", l.User)
	add("database", l.Database)
	add("application", l.Application)
	add("client", l.Client)
	if l.PID != 0 {
		m["pid"] = l.PID
	}
	if l.DurationMs != nil {
		m["duration_ms"] = *l.DurationMs
	}
	if l.Redacted {
		m["redacted"] = true
	}
	return m
}

func (s *Server) logsPost(ctx context.Context, rawURL, contentType string, body []byte, h http.Header) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range h {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "Rowsafe-Logs/1")
	resp, err := s.logStore().http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST to %s: %w", req.URL.Host, unwrapURL(err)) // the URL may hold a secret
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("%s answered HTTP %d: redirects are not followed", req.URL.Host, resp.StatusCode)
	}
	if resp.StatusCode >= 300 {
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return nil, fmt.Errorf("%s refused the credentials (HTTP %d): check the API key or token", req.URL.Host, resp.StatusCode)
		}
		return nil, fmt.Errorf("%s answered HTTP %d: %s", req.URL.Host, resp.StatusCode, clipBytes(strings.TrimSpace(string(out)), 300))
	}
	return out, nil
}

func (s *Server) logsDatadog(ctx context.Context, d *logDestRec, entries []protocol.ForwardedLog) error {
	type ddLog struct {
		Source    string         `json:"ddsource"`
		Tags      string         `json:"ddtags"`
		Hostname  string         `json:"hostname"`
		Service   string         `json:"service"`
		Message   string         `json:"message"`
		Status    string         `json:"status"`
		Timestamp int64          `json:"timestamp"`
		Rowsafe   map[string]any `json:"rowsafe"`
	}
	tag := strings.NewReplacer(",", "_", " ", "_")
	out := make([]ddLog, 0, len(entries))
	for _, l := range entries {
		out = append(out, ddLog{Source: "postgresql", Service: "postgresql", Hostname: l.Host, Message: logLineText(l),
			Status: logLevel(l.Severity), Timestamp: l.Time.UnixMilli(), Rowsafe: logFields(l),
			Tags: fmt.Sprintf("source:rowsafe,database:%s,kind:%s", tag.Replace(l.DatabaseName), l.Kind)})
	}
	body, err := json.Marshal(out)
	if err != nil {
		return err
	}
	intake := "https://http-intake.logs." + d.Config.Site + "/api/v2/logs"
	if d.Config.URL != "" && s.allowHTTP { // tests
		intake = d.Config.URL
	}
	_, err = s.logsPost(ctx, intake, "application/json", body, http.Header{"Dd-Api-Key": {d.Secret}})
	return err
}

func (s *Server) logsBetterStack(ctx context.Context, d *logDestRec, entries []protocol.ForwardedLog) error {
	out := make([]map[string]any, 0, len(entries))
	for _, l := range entries {
		m := logFields(l)
		m["dt"] = l.Time.UTC().Format(time.RFC3339Nano)
		m["level"] = logLevel(l.Severity)
		m["message"] = logLineText(l)
		out = append(out, m)
	}
	body, err := json.Marshal(out)
	if err != nil {
		return err
	}
	_, err = s.logsPost(ctx, d.Config.URL, "application/json", body, http.Header{"Authorization": {"Bearer " + d.Secret}})
	return err
}

func basicOr(d *logDestRec, scheme string) http.Header {
	h := http.Header{}
	switch {
	case d.Config.Username != "":
		h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(d.Config.Username+":"+d.Secret)))
	case d.Secret != "":
		h.Set("Authorization", scheme+" "+d.Secret)
	}
	return h
}

func (s *Server) logsLoki(ctx context.Context, d *logDestRec, entries []protocol.ForwardedLog) error {
	type stream struct {
		Stream map[string]string `json:"stream"`
		Values [][]string        `json:"values"`
	}
	byLabels := map[string]*stream{}
	var order []string
	for _, l := range entries {
		labels := map[string]string{"source": "rowsafe", "host": l.Host, "database": l.DatabaseName, "level": logLevel(l.Severity), "kind": l.Kind}
		key := l.Host + "\x00" + l.DatabaseName + "\x00" + labels["level"] + "\x00" + l.Kind
		st := byLabels[key]
		if st == nil {
			st = &stream{Stream: labels}
			byLabels[key] = st
			order = append(order, key)
		}
		st.Values = append(st.Values, []string{strconv.FormatInt(l.Time.UnixNano(), 10), logLineText(l)})
	}
	payload := struct {
		Streams []*stream `json:"streams"`
	}{}
	for _, k := range order {
		payload.Streams = append(payload.Streams, byLabels[k])
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = s.logsPost(ctx, d.Config.URL+"/loki/api/v1/push", "application/json", body, basicOr(d, "Bearer"))
	return err
}

func (s *Server) logsElastic(ctx context.Context, d *logDestRec, entries []protocol.ForwardedLog) error {
	var b bytes.Buffer
	action, _ := json.Marshal(map[string]any{"create": map[string]string{"_index": d.Config.Index}})
	for _, l := range entries {
		doc := logFields(l)
		doc["@timestamp"] = l.Time.UTC().Format(time.RFC3339Nano)
		doc["log.level"] = logLevel(l.Severity)
		line, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		b.Write(action)
		b.WriteByte('\n')
		b.Write(line)
		b.WriteByte('\n')
	}
	out, err := s.logsPost(ctx, d.Config.URL+"/_bulk", "application/x-ndjson", b.Bytes(), basicOr(d, "ApiKey"))
	if err != nil {
		return err
	}
	var res struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
			Error  struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if json.Unmarshal(out, &res) == nil && res.Errors {
		for _, it := range res.Items {
			for _, r := range it {
				if r.Status >= 300 {
					return fmt.Errorf("the index refused entries: %s: %s", r.Error.Type, r.Error.Reason)
				}
			}
		}
		return errors.New("the index refused some entries")
	}
	return nil
}

// logWebhookPayload is the JSON body of a log webhook (the hosted one's).
type logWebhookPayload struct {
	Version    int                     `json:"version"`
	Event      string                  `json:"event"` // "logs"
	DeliveryID string                  `json:"delivery_id"`
	SentAt     time.Time               `json:"sent_at"`
	Entries    []protocol.ForwardedLog `json:"entries"`
}

func (s *Server) logsWebhook(ctx context.Context, d *logDestRec, entries []protocol.ForwardedLog, deliveryID string) error {
	now := s.now()
	body, err := json.Marshal(logWebhookPayload{Version: 1, Event: "logs", DeliveryID: deliveryID, SentAt: now.UTC(), Entries: entries})
	if err != nil {
		return err
	}
	h := http.Header{}
	h.Set("X-Rowsafe-Event", "logs")
	h.Set("X-Rowsafe-Delivery", deliveryID)
	h.Set(signatureHeader, sign(d.Signing, now.Unix(), body)) // alerts.go
	_, err = s.logsPost(ctx, d.Config.URL, "application/json", body, h)
	return err
}

// ---- syslog over TLS ----

func syslogSeverity(sev string) int {
	switch sev {
	case "PANIC":
		return 1 // alert
	case "FATAL":
		return 2 // critical
	case "ERROR":
		return 3
	case "WARNING":
		return 4
	case "NOTICE":
		return 5
	case "DEBUG1", "DEBUG2", "DEBUG3", "DEBUG4", "DEBUG5":
		return 7
	}
	return 6 // informational
}

// syslogMessage formats one RFC 5424 message (facility local0) with RFC
// 5425 octet-counting framing.
func syslogMessage(l protocol.ForwardedLog) []byte {
	host := l.Host
	if host == "" {
		host = "-"
	}
	procID := "-"
	if l.PID != 0 {
		procID = strconv.Itoa(l.PID)
	}
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	sd := fmt.Sprintf(`[rowsafe@32473 database="%s" kind="%s"`, esc.Replace(l.DatabaseName), esc.Replace(l.Kind))
	if l.SQLState != "" {
		sd += fmt.Sprintf(` sqlstate="%s"`, esc.Replace(l.SQLState))
	}
	sd += "]"
	msg := fmt.Sprintf("<%d>1 %s %s %s %s %s %s %s", 16*8+syslogSeverity(l.Severity), l.Time.UTC().Format(time.RFC3339Nano),
		syslogField(host, 255), "postgresql", procID, syslogField(l.Kind, 32), sd, logLineText(l))
	return []byte(strconv.Itoa(len(msg)) + " " + msg)
}

func syslogField(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r <= 32 || r >= 127 {
			return '_'
		}
		return r
	}, s)
	if s == "" {
		return "-"
	}
	return s[:min(len(s), n)]
}

func (s *Server) logsSyslog(ctx context.Context, d *logDestRec, entries []protocol.ForwardedLog) error {
	addr := net.JoinHostPort(d.Config.Host, strconv.Itoa(d.Config.Port))
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: d.Config.Host}
	if t := s.logStore().tls; t != nil {
		cfg = t.Clone()
		cfg.ServerName = d.Config.Host
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: logForwardTimeout}, Config: cfg}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connecting to %s over TLS: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(logForwardTimeout))
	var b bytes.Buffer
	for _, l := range entries {
		b.Write(syslogMessage(l))
	}
	if _, err := conn.Write(b.Bytes()); err != nil {
		return fmt.Errorf("sending to %s: %w", addr, err)
	}
	return nil
}
