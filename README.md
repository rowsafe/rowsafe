# Rowsafe

**The database admin you never hired.** Rowsafe looks after the databases you run on your own servers: backups you can restore to any second, a restore test every week, monitoring with one-click fixes, and a safety net for AI coding agents.

This repository is the open-source part of [Rowsafe](https://rowsafe.sh): the agent, the `rowsafe` CLI, the installer and the MCP server. Everything that touches your data is here, under Apache-2.0.

**Docs:** [rowsafe.sh/docs](https://rowsafe.sh/docs)

**Databases**, on Linux servers and in Docker:

- PostgreSQL 13–18, MySQL 8.0/8.4, MariaDB 10.6–11.4, MongoDB 6.0–8.0, ClickHouse 24.8–26.8
- Redis 7.0+ and Valkey 7.2+ (standalone servers)
- SQLite (restore to any second needs WAL mode)

Features per database: `protocol.EngineCapabilities`.

## Get started

```sh
rowsafe login
rowsafe hosts enroll-token                       # prints the install command
curl -fsSL https://rowsafe.sh | sudo sh -s rse_… # on the database server
```

**Rewind**: continuous backups, restore to any second.

```sh
rowsafe mark before-drop                  # a named restore point (a Mark)
rowsafe rewind copy app --at "14:04"      # a copy as of 14:04, next to production
rowsafe rewind compare app                # rows missing or changed in production
rowsafe rewind rows app public.orders     # bring the missing rows back
rowsafe rewind database app --at "14:04"  # rewind in place, with undo
```

**Proof**: a weekly automatic restore test (`rowsafe proof app`).

**Pulse**: a 0–100 health score with fixes you apply (`rowsafe pulse`, `rowsafe fix app`), slow queries (`rowsafe top app`), insights and tuning.

**Guard**: `rowsafe mcp`, the Claude Code and Codex plugins and the GitHub Action save a Mark before migrations, destructive SQL and deploys. AI agents can ask for any change to production; an owner or admin approves it in the dashboard. Agents can never approve.

**Rowsafe Cloud**: PostgreSQL servers Rowsafe runs for you, billed by the hour (never more than the monthly price), with all of the above on from the first minute.

```sh
rowsafe cloud sizes                         # clouds, regions, sizes, prices, what is sold out
rowsafe cloud create shop-db --wait         # the cheapest size free now; only this computer may connect
rowsafe env --on shop-db                    # the app's database and login, DATABASE_URL in .env
rowsafe connect shop-db                     # psql, as a temporary user removed when you quit
rowsafe cloud allow shop-db 203.0.113.4     # let the app's server connect
rowsafe cloud resize shop-db medium         # a Mark first; asks before the restart
rowsafe cloud clone shop-db shop-test --at "10m ago" --delete-after 1d
rowsafe cloud passphrase shop-db --file shop-db-passphrase.txt
rowsafe cloud delete shop-db                # asks you to type the name
```

The first server billed by the hour gives you a link to add a card, once. Database passwords never pass through Rowsafe: `rowsafe env` makes the password on your computer and sends only its SCRAM verifier, and other passwords are made on the database server and encrypted for your terminal. `rowsafe help cloud` has the details.

Full guide: [Quickstart](https://rowsafe.sh/docs/quickstart).

## What's in this repository

| Path | What it is |
|---|---|
| `cmd/rowsafe-agent`, `internal/agent` | The agent: outbound HTTPS only, a fixed set of tasks, no arbitrary commands or SQL. |
| `cmd/rowsafe`, `client` | The CLI. |
| `mcp`, `integrations/` | Guard: the MCP server, Claude Code and Codex plugins, and the GitHub Action (`rowsafe/action`). |
| `collect`, `tune` | Monitoring, and settings recommendations. |
| `protocol` | API types shared by the agent, the CLI and the control plane. |
| `internal/pgbackrest`, `internal/pginspect` | PostgreSQL. |
| `internal/engine` | MySQL/MariaDB, MongoDB, ClickHouse, Redis/Valkey, SQLite. |
| `scripts/install.sh` | The installer served at `https://rowsafe.sh`. |
| `release`, `cmd/rowsafe-release` | Release signing and verification. |

## Safety

- **Never restarts or changes production on its own.** Restarts, fixes, rewinds and settings changes run only when a person confirms them.
- **Fixes come from a fixed list** and are re-checked on the server right before they run.
- **Restore tests and copies are isolated** from production and its backups.
- **Your data and secrets stay on your server.** Backups are encrypted before upload; Rowsafe sees table names and counts, not rows.
- **Signed, reproducible releases** with automatic rollback. See [verifying releases](docs/verifying-releases.md).
- **Monitoring is read-only.** `ROWSAFE_COLLECT_QUERY_TEXT=false` keeps query text on your server; `ROWSAFE_MONITORING=false` turns it off.

## Build

`make build`. Locally built agents never auto-update.

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) · docs in [rowsafe/docs](https://github.com/rowsafe/docs) · report vulnerabilities through [security advisories](https://github.com/rowsafe/rowsafe/security/advisories/new) ([SECURITY.md](SECURITY.md)).

## License

[Apache License 2.0](LICENSE). Copyright 2026 Adraa Labs.
