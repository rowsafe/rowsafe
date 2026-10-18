# Prometheus and Grafana

A Rowsafe server on its own (installed with `--no-account`) can serve what it knows as
Prometheus metrics: whether each database is protected, its newest backups and Proofs,
continuous backup, the alerts firing, the agent's version, and the database and server readings
the agent collects. It is off by default and listens nowhere until you turn it on.

## Turn it on

On the server, add to `/etc/rowsafe/agent.env`, then `sudo systemctl restart rowsafe-agent`:

```sh
ROWSAFE_METRICS_LISTEN=127.0.0.1:9188
```

`curl -s 127.0.0.1:9188/metrics` shows them. Prometheus on another machine needs an address it
can reach, and then a token too (an address other than loopback is refused without one):

```sh
ROWSAFE_METRICS_LISTEN=10.0.0.5:9188
ROWSAFE_METRICS_TOKEN=...   # at least 16 characters, e.g. the output of: openssl rand -hex 32
```

Prometheus sends it as a bearer token (`authorization: credentials_file:` in the scrape job).
The endpoint speaks plain HTTP: keep it on a private network or a VPN, or put a TLS proxy in front.
In Docker, set the same variables on the agent container, listen on `0.0.0.0:9188` with a token,
and publish the port to the host only (`127.0.0.1:9188:9188`).

If the setting is wrong or the port is taken, the agent logs why (`journalctl -u rowsafe-agent`)
and keeps backing up without metrics.

## Files

- `prometheus.example.yml`: the scrape job.
- `rowsafe.rules.yml`: alert rules (`promtool test rules rowsafe.rules.test.yml`). The server
  already sends its own alerts (`sudo rowsafe channels add`); Prometheus adds the one it can't
  send: that the server or the agent is down (`RowsafeMetricsDown`).
- `grafana-dashboard.json`: a dashboard (Dashboards → New → Import), with server and database
  pickers.

## Metrics

Every series has the labels `database` and `host`. Times are Unix timestamps: the age of a backup
is `time() - rowsafe_backup_last_success_timestamp_seconds`. The names match the hosted control
plane's where they mean the same, so rules work with both.

| Metric | What it is |
| --- | --- |
| `rowsafe_database_protected` | 1 when the database is protected (`rowsafe status NAME`) |
| `rowsafe_database_info{engine,status}` | each database, always 1 |
| `rowsafe_database_status_since_timestamp_seconds{status}` | when it entered its status |
| `rowsafe_backup_last_success_timestamp_seconds{type}` | newest successful backup (`any`, `full`, `diff`, `incr`) |
| `rowsafe_backup_last_size_bytes{type}`, `rowsafe_backup_last_stored_bytes{type}`, `rowsafe_backup_last_duration_seconds{type}` | its size, what it added to the storage, how long it took |
| `rowsafe_recovery_window_start_timestamp_seconds` | the oldest moment it can be restored to |
| `rowsafe_drill_last_run_timestamp_seconds`, `rowsafe_drill_last_success_timestamp_seconds`, `rowsafe_drill_last_passed` | Proof (the weekly restore test) |
| `rowsafe_archiver_up`, `rowsafe_wal_last_archived_timestamp_seconds`, `rowsafe_wal_last_failed_timestamp_seconds`, `rowsafe_wal_archive_failed_total`, `rowsafe_archiver_report_timestamp_seconds` | continuous backup |
| `rowsafe_task_last_failure_timestamp_seconds{type}` | the newest task of a type failed or was lost |
| `rowsafe_alert_firing{rule,severity}` | 1 while one of the server's alert rules fires |
| `rowsafe_agent_info{version,platform}`, `rowsafe_agent_last_seen_timestamp_seconds`, `rowsafe_agent_update_available{version}` | the agent |
| `rowsafe_database_up`, `rowsafe_monitoring_report_timestamp_seconds` | the agent's newest reading |
| `rowsafe_<reading>` | the agent's readings: `rowsafe_connections_active`, `rowsafe_connections_used_pct`, `rowsafe_cache_hit_pct`, `rowsafe_disk_free_pct`, `rowsafe_replication_lag_seconds`, `rowsafe_xid_headroom_pct`, ... (the collect package's catalog; percentages are 0-100) |
| `rowsafe_host_<reading>{host}` | the server: `rowsafe_host_cpu_pct`, `rowsafe_host_mem_used_pct`, `rowsafe_host_load1`, ... |

Readings are dropped when the newest is over 10 minutes old, so a stopped agent doesn't look healthy.
