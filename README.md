# Rowsafe

**The database admin you never hired.** Rowsafe looks after the databases you run on your own servers: backups you can restore to any second, a restore test every week, monitoring with one-click fixes, and a safety net for AI coding agents.

This repository is the open-source part of [Rowsafe](https://rowsafe.sh): the agent, the `rowsafe` CLI, the installer and the MCP server. Everything that touches your data is here, under Apache-2.0.

**Docs:** [rowsafe.sh/docs](https://rowsafe.sh/docs)

**Databases**, on Linux servers and in Docker:

- PostgreSQL 13–18, MySQL 8.0/8.4, MariaDB 10.6–11.4, MongoDB 6.0–8.0, ClickHouse 24.8–26.8
- Redis 7.0+ and Valkey 7.2+ (standalone servers)
- SQLite (restore to any second needs WAL mode)
- OpenSearch 2.x/3.x (single node; snapshots every 5 minutes: restores go back to a snapshot or a Mark, not to any second)
- Qdrant 1.13+ (single servers; snapshots every 15 minutes, only of the collections that changed: restores go back to a snapshot or a Mark, not to any second)
- Meilisearch 1.12+, Community Edition, on Linux servers (snapshots every 15 minutes when something changed: restores go back to a snapshot or a Mark, not to any second)

Features per database: `protocol.EngineCapabilities`.

## Try it now: no account

```sh
curl -fsSL https://rowsafe.sh/cli | sh
rowsafe add shop postgres://user@host:5432/dbname   # once: checks it connects, saves it on this computer
rowsafe pulse shop
```

A 0–100 health score for a PostgreSQL database you can connect to, with what to fix in plain language: cleanup falling behind, transaction ID wraparound, bloat, unused and duplicate indexes, stuck sessions and locks, connections, replication slots and settings. Rowsafe applies the fixes after you confirm. Nothing is sent anywhere.

```sh
rowsafe fix shop                       # apply what pulse found (asks first)
rowsafe insights | top | activity | settings | tune shop
rowsafe schema shop [TABLE…]           # tables, columns, keys, indexes (used or not): compact for an AI agent
rowsafe explain shop "SELECT …"        # why a query is slow, and the index that would likely help
rowsafe preview shop 0042.sql          # check a migration first: locks, rewrites, a verdict (no restore point)
rowsafe mcp shop --allow-writes        # the same as MCP tools for Claude Code, Codex or Cursor
rowsafe use shop                       # in a project: then just `rowsafe pulse`
```

The connection string stays in your config folder, readable only by you; `.rowsafe.json` gets only the name. Pipe it in (`rowsafe add shop < url.txt`) or use `--from-env VAR` to keep the password out of your shell history; in a project, `rowsafe add` alone offers the `DATABASE_URL` from `.env`. `rowsafe databases` lists them, `rowsafe forget shop` removes one.

Once, without saving: `rowsafe pulse postgres://…`, or set `DATABASE_URL` and leave the argument out. Use the direct connection, not a pooler. Backups, restore to any second, the weekly restore test, alerts and history need the agent on your server: see below. `rowsafe help local` has the details.

## Get started

```sh
curl -fsSL https://rowsafe.sh/cli | sh           # the CLI, on your Mac or Linux computer
rowsafe login
rowsafe hosts add root@203.0.113.10              # installs the agent on that server over SSH
# or on the database server itself:  curl -fsSL https://rowsafe.sh | sudo sh
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

**Guard**: `rowsafe mcp`, the Claude Code and Codex plugins and the GitHub Action save a Mark before migrations, destructive SQL and deploys. AI agents act as the person who connected them, right away, with exactly that person's rights, like a CLI token; what that person can't do, Rowsafe refuses and says why. Owners can set a monthly budget for agents (Settings → AI agents). Every agent action is in the audit log.

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

**The CLI does what the dashboard does**, as the person behind the key and with that person's rights: security (`rowsafe security fix app restrict_access --allow 10.0.0.0/16`), the server's security updates and reboots, alert rules, logs and log forwarding, the maintenance window, standbys, moves, upgrades and more. Every change asks first on a terminal; scripts and AI agents pass `--yes`, and `--json` prints JSON. `rowsafe help all` lists everything.

Full guide: [Quickstart](https://rowsafe.sh/docs/quickstart).

## What's in this repository

| Path | What it is |
|---|---|
| `cmd/rowsafe-agent`, `internal/agent` | The agent: outbound HTTPS only, a fixed set of tasks, no arbitrary commands or SQL. |
| `cmd/rowsafe`, `client` | The CLI. |
| `mcp`, `integrations/` | Guard: the MCP server, Claude Code and Codex plugins, and the GitHub Action (`rowsafe/action`). |
| `collect`, `tune` | Monitoring, and settings recommendations. |
| `pulse`, `local` | The health score and its fixes, and Rowsafe without an account (`rowsafe pulse postgres://…`). |
| `protocol` | API types shared by the agent, the CLI and the control plane. |
| `internal/pgbackrest`, `internal/pginspect` | PostgreSQL. |
| `internal/engine` | MySQL/MariaDB, MongoDB, ClickHouse, Redis/Valkey, SQLite, Qdrant, Meilisearch. |
| `scripts/install.sh` | The installer served at `https://rowsafe.sh`. |
| `scripts/cli.sh` | The CLI installer served at `https://rowsafe.sh/cli` (macOS and Linux). |
| `release`, `cmd/rowsafe-release` | Release signing and verification. |

## Safety

- **Never restarts or changes production on its own.** Restarts, fixes, rewinds and settings changes run only when a person confirms them, or when an AI agent they connected asks with their rights (audited; Rowsafe saves a Mark first for risky ones).
- **Fixes come from a fixed list** and are re-checked on the server right before they run.
- **Restore tests and copies are isolated** from production and its backups.
- **Your data and secrets stay on your server.** Backups are encrypted before upload; Rowsafe sees table names and counts, not rows.
- **Signed, reproducible releases** with automatic rollback. See [verifying releases](docs/verifying-releases.md).
- **Monitoring is read-only.** `ROWSAFE_COLLECT_QUERY_TEXT=false` keeps query text on your server; `ROWSAFE_MONITORING=false` turns it off.
- **No usage tracking unless you turn it on.** The CLI sends nothing about how you use it by default. `rowsafe telemetry on` sends, after each command, its name (`cloud create`, never its arguments), the CLI version, OS, exit code, a duration range, whether a terminal or an AI agent ran it, whether you're logged in, and a random ID made on this computer. `rowsafe telemetry status` shows exactly what goes out; `rowsafe telemetry off`, `ROWSAFE_TELEMETRY=0` or `DO_NOT_TRACK=1` stop it. The schema is [`protocol/telemetry.go`](protocol/telemetry.go).

## Build

`make build`. Locally built agents never auto-update.

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) · docs in [rowsafe/docs](https://github.com/rowsafe/docs) · report vulnerabilities through [security advisories](https://github.com/rowsafe/rowsafe/security/advisories/new) ([SECURITY.md](SECURITY.md)).

## License

[Apache License 2.0](LICENSE). Copyright 2026 Adraa Labs.
