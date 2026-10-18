package localcp

// Prometheus metrics on a server on its own: off unless root sets
// ROWSAFE_METRICS_LISTEN in /etc/rowsafe/agent.env. Then the agent serves
// GET /metrics (the Prometheus text format) on that address with what this
// server knows: whether each database is protected, its newest backups and
// Proofs, continuous backup, firing alerts, the agent's version, and the
// monitoring readings the agent collects (collect.Catalog), all named
// rowsafe_* with the labels database and host. The names the hosted control
// plane exports (rowsafed's /metrics) are kept where they mean the same, so
// rules written for one work with the other.
//
// Nothing listens on the network by default: an address that isn't
// loopback is refused unless ROWSAFE_METRICS_TOKEN is set too, and with a
// token every scrape must send it as a bearer token.

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// The settings in /etc/rowsafe/agent.env.
const (
	MetricsListenEnv = "ROWSAFE_METRICS_LISTEN" // e.g. 127.0.0.1:9188
	MetricsTokenEnv  = "ROWSAFE_METRICS_TOKEN"  // required off loopback
)

const minMetricsToken = 16

// MetricsConfig is where to serve metrics ("" Listen: off) and the bearer
// token scrapes must send ("" Token: none, loopback only).
type MetricsConfig struct {
	Listen string
	Token  string
}

// MetricsConfigFrom reads and checks the settings.
func MetricsConfigFrom(getenv func(string) string) (MetricsConfig, error) {
	c := MetricsConfig{Listen: strings.TrimSpace(getenv(MetricsListenEnv)), Token: strings.TrimSpace(getenv(MetricsTokenEnv))}
	if c.Listen == "" {
		if c.Token != "" {
			return c, fmt.Errorf("%s is set but %s isn't: set the address to serve metrics on, e.g. %s=127.0.0.1:9188",
				MetricsTokenEnv, MetricsListenEnv, MetricsListenEnv)
		}
		return c, nil
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return c, fmt.Errorf("%s=%s is not an address and port, e.g. 127.0.0.1:9188", MetricsListenEnv, c.Listen)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return c, fmt.Errorf("%s=%s: the port must be a number from 1 to 65535", MetricsListenEnv, c.Listen)
	}
	if c.Token != "" {
		if len(c.Token) < minMetricsToken || strings.ContainsAny(c.Token, " \t\r\n") {
			return c, fmt.Errorf("%s must be at least %d characters without spaces (e.g. the output of: openssl rand -hex 32)",
				MetricsTokenEnv, minMetricsToken)
		}
		return c, nil
	}
	if !loopbackHost(host) {
		return c, fmt.Errorf("%s=%s would let anyone who can reach this server read its metrics: listen on 127.0.0.1, "+
			"or set %s too (a long random value Prometheus sends as its bearer token)", MetricsListenEnv, c.Listen, MetricsTokenEnv)
	}
	return c, nil
}

// loopbackHost is true for localhost and loopback addresses ("" and
// 0.0.0.0 are every interface).
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// serveMetrics serves /metrics when agent.env asks for it, until ctx ends.
// A wrong setting or a busy port is logged and leaves the rest of the agent
// running: backups matter more than metrics.
func (s *Server) serveMetrics(ctx context.Context) {
	cfg, err := MetricsConfigFrom(os.Getenv)
	if err != nil {
		s.log.Error("metrics are off", "err", err)
		return
	}
	if cfg.Listen == "" {
		return
	}
	l, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		s.log.Error("metrics are off: can't listen", "address", cfg.Listen, "err", err)
		return
	}
	srv := &http.Server{Handler: s.MetricsHandler(cfg.Token), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	s.log.Info("serving Prometheus metrics", "address", l.Addr().String(), "token", cfg.Token != "")
	go func() {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("metrics stopped", "err", err)
		}
	}()
}

// MetricsHandler serves GET /metrics, with the bearer token when set.
func (s *Server) MetricsHandler(token string) http.Handler {
	want := []byte("Bearer " + token)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="rowsafe"`)
			http.Error(w, "send the token in ROWSAFE_METRICS_TOKEN as a bearer token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.writeMetrics(w)
	})
	return mux
}

// ---- The newest monitoring report, in memory ----

// readings is the newest monitoring report of each database and of the
// host (not saved: a restart waits for the next report, a minute).
type readings struct {
	mu     sync.Mutex
	hostAt time.Time
	host   map[string]float64
	dbs    map[string]reading
}

type reading struct {
	at      time.Time
	failed  bool
	metrics map[string]float64
}

func (r *readings) record(rep protocol.MonitoringReport, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(rep.Host) > 0 {
		r.hostAt, r.host = now, rep.Host
	}
	if r.dbs == nil {
		r.dbs = map[string]reading{}
	}
	for _, d := range rep.Databases {
		r.dbs[d.DatabaseID] = reading{at: now, failed: d.Error != "", metrics: d.Metrics}
	}
}

func (r *readings) snapshot() (hostAt time.Time, host map[string]float64, dbs map[string]reading) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hostAt, r.host, maps.Clone(r.dbs)
}

// ---- The text format ----

// Families this file writes; a collected metric with one of these names
// would clash (TestMetricNamesDontClash).
var metricFamilies = []string{
	"rowsafe_agent_info", "rowsafe_agent_last_seen_timestamp_seconds", "rowsafe_agent_update_available",
	"rowsafe_database_info", "rowsafe_database_status_since_timestamp_seconds", "rowsafe_database_protected",
	"rowsafe_backup_last_success_timestamp_seconds", "rowsafe_backup_last_size_bytes",
	"rowsafe_backup_last_stored_bytes", "rowsafe_backup_last_duration_seconds",
	"rowsafe_recovery_window_start_timestamp_seconds",
	"rowsafe_drill_last_run_timestamp_seconds", "rowsafe_drill_last_success_timestamp_seconds", "rowsafe_drill_last_passed",
	"rowsafe_archiver_up", "rowsafe_wal_last_archived_timestamp_seconds", "rowsafe_wal_archive_failed_total",
	"rowsafe_wal_last_failed_timestamp_seconds", "rowsafe_archiver_report_timestamp_seconds",
	"rowsafe_task_last_failure_timestamp_seconds", "rowsafe_alert_firing",
	"rowsafe_monitoring_report_timestamp_seconds", "rowsafe_database_up",
}

// collectedName is the family of a metric from collect.Catalog.
func collectedName(scope, name string) string {
	if scope == collect.ScopeHost {
		return "rowsafe_host_" + name
	}
	return "rowsafe_" + name
}

func (s *Server) writeMetrics(w io.Writer) {
	now := s.now()
	offer := s.updates.current()
	hostAt, hostReading, dbReadings := s.prom.snapshot()
	m := &promWriter{w: w}
	s.st.read(func(st *state) {
		host := st.Host.Hostname
		dbs := slices.Clone(st.Databases)
		slices.SortFunc(dbs, func(a, b *dbRec) int { return strings.Compare(a.Name, b.Name) })
		prot := make([]protocol.Protection, len(dbs))
		for i, d := range dbs {
			prot[i] = st.protection(d, now)
		}
		dbl := func(d *dbRec, extra ...string) []string {
			return append([]string{"database", d.Name, "host", host}, extra...)
		}

		// The agent.
		m.help("rowsafe_agent_info", "gauge", "The agent's version and platform; value is always 1.")
		if st.Host.ID != "" {
			m.sample("rowsafe_agent_info", 1, "host", host, "version", st.Host.AgentVersion, "platform", st.Host.Platform)
		}
		m.help("rowsafe_agent_last_seen_timestamp_seconds", "gauge", "Last heartbeat from the agent.")
		m.ts("rowsafe_agent_last_seen_timestamp_seconds", st.Host.LastSeen, "host", host)
		m.help("rowsafe_agent_update_available", "gauge",
			"1 when Rowsafe has promoted a newer stable agent than the one running (label version), 0 when it is up to date.")
		if st.Host.ID != "" {
			if o := s.updates.offerFor(st.Host.AgentVersion); o != nil {
				m.sample("rowsafe_agent_update_available", 1, "host", host, "version", o.Version)
			} else if offer != nil {
				m.sample("rowsafe_agent_update_available", 0, "host", host, "version", "")
			}
		}

		// Databases.
		m.help("rowsafe_database_info", "gauge", "Databases on this server; value is always 1.")
		for _, d := range dbs {
			m.sample("rowsafe_database_info", 1, dbl(d, "engine", protocol.NormalizeEngine(d.Engine), "status", d.Status)...)
		}
		m.help("rowsafe_database_status_since_timestamp_seconds", "gauge", "When the database entered its current status.")
		for _, d := range dbs {
			m.ts("rowsafe_database_status_since_timestamp_seconds", &d.StatusSince, dbl(d, "status", d.Status)...)
		}
		m.help("rowsafe_database_protected", "gauge",
			"1 when the database is protected (rowsafe status NAME): continuous backup works, a backup in the last 26 hours and a passing Proof in the last 8 days.")
		for i, d := range dbs {
			m.sample("rowsafe_database_protected", boolValue(prot[i].Protected), dbl(d)...)
		}

		// Backups: the newest successful one of each type, and of any type.
		newest := map[[2]string]protocol.Backup{}
		for _, b := range st.Backups {
			for _, typ := range []string{"any", b.Type} {
				k := [2]string{b.DatabaseID, typ}
				if cur, ok := newest[k]; !ok || b.StoppedAt.After(cur.StoppedAt) {
					newest[k] = b
				}
			}
		}
		backupTypes := []string{"any", protocol.BackupFull, protocol.BackupDiff, protocol.BackupIncr}
		each := func(fn func(d *dbRec, typ string, b protocol.Backup)) {
			for _, d := range dbs {
				for _, typ := range backupTypes {
					if b, ok := newest[[2]string{d.ID, typ}]; ok {
						fn(d, typ, b)
					}
				}
			}
		}
		m.help("rowsafe_backup_last_success_timestamp_seconds", "gauge", "Stop time of the newest successful backup (type any, full, diff or incr).")
		each(func(d *dbRec, typ string, b protocol.Backup) {
			m.ts("rowsafe_backup_last_success_timestamp_seconds", &b.StoppedAt, dbl(d, "type", typ)...)
		})
		m.help("rowsafe_backup_last_size_bytes", "gauge", "Size of the database the newest successful backup copied.")
		each(func(d *dbRec, typ string, b protocol.Backup) {
			m.sample("rowsafe_backup_last_size_bytes", float64(b.SizeBytes), dbl(d, "type", typ)...)
		})
		m.help("rowsafe_backup_last_stored_bytes", "gauge", "What the newest successful backup added to the backup storage (compressed; a diff or incr only stores changes).")
		each(func(d *dbRec, typ string, b protocol.Backup) {
			m.sample("rowsafe_backup_last_stored_bytes", float64(b.RepoSizeBytes), dbl(d, "type", typ)...)
		})
		m.help("rowsafe_backup_last_duration_seconds", "gauge", "How long the newest successful backup took.")
		each(func(d *dbRec, typ string, b protocol.Backup) {
			if b.StoppedAt.After(b.StartedAt) && !b.StartedAt.IsZero() {
				m.sample("rowsafe_backup_last_duration_seconds", b.StoppedAt.Sub(b.StartedAt).Seconds(), dbl(d, "type", typ)...)
			}
		})
		m.help("rowsafe_recovery_window_start_timestamp_seconds", "gauge", "The oldest moment the database can be restored to (start of the oldest full backup kept).")
		for i, d := range dbs {
			m.ts("rowsafe_recovery_window_start_timestamp_seconds", prot[i].RecoveryWindowStart, dbl(d)...)
		}

		// Proof.
		lastDrill := map[string]time.Time{}
		for _, x := range st.Drills {
			if x.CreatedAt.After(lastDrill[x.DatabaseID]) {
				lastDrill[x.DatabaseID] = x.CreatedAt
			}
		}
		m.help("rowsafe_drill_last_run_timestamp_seconds", "gauge", "When the newest Proof (restore test) ran, passed or not.")
		for _, d := range dbs {
			if at, ok := lastDrill[d.ID]; ok {
				m.ts("rowsafe_drill_last_run_timestamp_seconds", &at, dbl(d)...)
			}
		}
		m.help("rowsafe_drill_last_success_timestamp_seconds", "gauge", "When the newest passing Proof (restore test) ran.")
		for i, d := range dbs {
			m.ts("rowsafe_drill_last_success_timestamp_seconds", prot[i].LastDrillPassedAt, dbl(d)...)
		}
		m.help("rowsafe_drill_last_passed", "gauge", "1 if the newest Proof (restore test) passed, 0 if it failed.")
		for i, d := range dbs {
			if p := prot[i].LastDrillPassed; p != nil {
				m.sample("rowsafe_drill_last_passed", boolValue(*p), dbl(d)...)
			}
		}

		// Continuous backup (PostgreSQL's WAL archiving).
		m.help("rowsafe_archiver_up", "gauge",
			"1 if the agent's newest report of continuous backup (pg_stat_archiver) succeeded and is under 10 minutes old; exported once setup is applied.")
		for i, d := range dbs {
			if d.Status != protocol.DBPendingAdopt {
				m.sample("rowsafe_archiver_up", boolValue(prot[i].ArchiverUp), dbl(d)...)
			}
		}
		archiver := []struct {
			name, typ, help string
			value           func(d *dbRec) (float64, bool)
		}{
			{"rowsafe_wal_last_archived_timestamp_seconds", "gauge", "Last change-log (WAL) segment archived to the backup storage.",
				func(d *dbRec) (float64, bool) { return unixTime(d.Archiver.LastArchivedTime) }},
			{"rowsafe_wal_archive_failed_total", "counter", "Failed change-log (WAL) archive attempts since PostgreSQL's statistics were reset.",
				func(d *dbRec) (float64, bool) { return float64(d.Archiver.FailedCount), true }},
			{"rowsafe_wal_last_failed_timestamp_seconds", "gauge", "Last failed change-log (WAL) archive attempt.",
				func(d *dbRec) (float64, bool) { return unixTime(d.Archiver.LastFailedTime) }},
			{"rowsafe_archiver_report_timestamp_seconds", "gauge", "When the agent last read the continuous backup status.",
				func(d *dbRec) (float64, bool) { return unixTime(d.ArchiverAt) }},
		}
		for _, f := range archiver {
			m.help(f.name, f.typ, f.help)
			for _, d := range dbs {
				if d.Archiver == nil {
					continue
				}
				if v, ok := f.value(d); ok {
					m.sample(f.name, v, dbl(d)...)
				}
			}
		}

		// Tasks and alerts.
		m.help("rowsafe_task_last_failure_timestamp_seconds", "gauge",
			"When the newest task of a type (backup, check, drill...) finished, when it failed or was lost.")
		for i, d := range dbs {
			for _, t := range prot[i].OpenFailedTasks {
				typ := t.Type
				if t.Type == protocol.TaskBackup {
					typ = strings.ReplaceAll(openKey(t.Type, t.Params), ":", "_") // backup_full, backup_diff
				}
				m.ts("rowsafe_task_last_failure_timestamp_seconds", t.FinishedAt, dbl(d, "type", typ)...)
			}
		}
		firing := map[string]*alertRec{}
		for _, a := range st.Alerts {
			if a.State == "firing" {
				firing[a.Key] = a
			}
		}
		m.help("rowsafe_alert_firing", "gauge", "1 while the alert rule fires for the database (the alerts sudo rowsafe alerts lists), 0 when it doesn't.")
		for _, d := range dbs {
			for _, r := range localRules {
				m.sample("rowsafe_alert_firing", boolValue(firing[r.name+":"+d.ID] != nil), dbl(d, "rule", r.name, "severity", r.severity)...)
			}
		}

		// The agent's monitoring readings, while fresh.
		m.help("rowsafe_monitoring_report_timestamp_seconds", "gauge", "When the agent last sent monitoring readings of the database (about every minute).")
		for _, d := range dbs {
			if r, ok := dbReadings[d.ID]; ok {
				m.ts("rowsafe_monitoring_report_timestamp_seconds", &r.at, dbl(d)...)
			}
		}
		m.help("rowsafe_database_up", "gauge", "1 when the agent could query the database in its newest reading (under 10 minutes old), 0 when it couldn't.")
		fresh := map[string]reading{}
		for _, d := range dbs {
			r, ok := dbReadings[d.ID]
			if !ok {
				continue
			}
			up := !r.failed && now.Sub(r.at) < metricsFresh
			m.sample("rowsafe_database_up", boolValue(up), dbl(d)...)
			if now.Sub(r.at) < metricsFresh {
				fresh[d.ID] = r
			}
		}
		hostFresh := now.Sub(hostAt) < metricsFresh
		for _, c := range collect.Catalog {
			name := collectedName(c.Scope, c.Name)
			if !validMetricName(name) {
				continue
			}
			switch c.Scope {
			case collect.ScopeDatabase:
				wrote := false
				for _, d := range dbs {
					if v, ok := fresh[d.ID].metrics[c.Name]; ok {
						if !wrote {
							m.help(name, "gauge", catalogHelp(c))
							wrote = true
						}
						m.sample(name, v, dbl(d)...)
					}
				}
			case collect.ScopeHost:
				if v, ok := hostReading[c.Name]; ok && hostFresh {
					m.help(name, "gauge", catalogHelp(c))
					m.sample(name, v, "host", host)
				}
			}
		}
	})
}

func catalogHelp(c collect.Metric) string {
	if c.Unit == "" || c.Unit == "count" {
		return c.Description + "."
	}
	return c.Description + " (" + c.Unit + ")."
}

func validMetricName(n string) bool {
	for i, r := range n {
		if r == '_' || r == ':' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return n != ""
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func unixTime(t *time.Time) (float64, bool) {
	if t == nil || t.IsZero() {
		return 0, false
	}
	return float64(t.Unix()), true
}

// promWriter writes the Prometheus text format (version 0.0.4).
type promWriter struct{ w io.Writer }

var (
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
)

func (m *promWriter) help(name, typ, text string) {
	fmt.Fprintf(m.w, "# HELP %s %s\n# TYPE %s %s\n", name, helpEscaper.Replace(text), name, typ)
}

func (m *promWriter) sample(name string, v float64, labels ...string) {
	var b strings.Builder
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `%s="%s"`, labels[i], labelEscaper.Replace(labels[i+1]))
		}
		b.WriteByte('}')
	}
	// Plain decimal notation: timestamps stay exact and readable.
	fmt.Fprintf(&b, " %s\n", strconv.FormatFloat(v, 'f', -1, 64))
	_, _ = io.WriteString(m.w, b.String())
}

// ts writes a Unix timestamp, skipping unknown times.
func (m *promWriter) ts(name string, t *time.Time, labels ...string) {
	if v, ok := unixTime(t); ok {
		m.sample(name, v, labels...)
	}
}
