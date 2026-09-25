# Rowsafe

**Sleep at night.** Rowsafe backs up the databases you already run, lets you restore to any second, and proves every week that your backups actually restore. This repository is the open-source part of [Rowsafe](https://rowsafe.sh): the agent that runs on your servers, the `rowsafe` CLI, the installer and the MCP server for AI agents.

Everything that touches your data is here, under Apache-2.0, so you can read exactly what runs on your machines.

**Documentation:** [rowsafe.sh/docs](https://rowsafe.sh/docs) · **Status:** PostgreSQL 13–18 on Linux servers and in Docker. MySQL, MariaDB, MongoDB and Redis are planned.

## Get started

```sh
rowsafe login                                          # opens the dashboard to approve this machine
rowsafe hosts enroll-token                             # prints the install command for your server
curl -fsSL https://rowsafe.sh | sudo sh -s rse_…       # on the database server
```

The installer does the rest on the server: it installs the agent, sets up storage, finds PostgreSQL, shows you the plan and asks before turning on backups (and before restarting PostgreSQL, if that is needed). To set up from your workstation instead: `rowsafe adopt app`, then `rowsafe apply app`.

**Rewind**: continuous backups, restore to any second. Deleted rows by mistake? Restore a copy as it was just before, next to production, and bring the rows back.

```sh
rowsafe status                       # is everything protected?
rowsafe mark before-drop             # a named point (a Mark) you can go back to
rowsafe rewind copy app --at "14:04" # a copy as it was at 14:04, on your server; production isn't touched
rowsafe rewind compare app           # which rows are missing or changed in production
rowsafe rewind rows app public.orders  # bring the missing rows back (asks first)
rowsafe rewind database app --at "14:04"  # worst case: the whole database goes back (asks first; undo keeps working)
```

**Proof**: every week Rowsafe restores your latest backup into a scratch copy and checks it.

```sh
rowsafe proof app         # run the restore test now
rowsafe proofs app        # past results
```

**Pulse**: how your databases are doing.

```sh
rowsafe pulse             # a 0-100 score per database, with what to fix in plain language
rowsafe fix app           # let Rowsafe fix what pulse found (clean up tables, end a stuck session...)
rowsafe top app           # the queries that take the most time, and which got slower
rowsafe insights app      # largest tables, unused indexes, wasted space, vacuum
```

**Guard**: the safety net for AI agents and deploys. `rowsafe mcp` and the Claude Code plugin create a restore point before migrations and destructive SQL; the GitHub Action saves one before every deploy.

Full guide: [Quickstart](https://rowsafe.sh/docs/quickstart).

## What's in this repository

| Path | What it is |
|---|---|
| `cmd/rowsafe-agent`, `internal/agent` | The agent. Makes outbound HTTPS requests only and runs a fixed set of tasks: inspect, adopt, check, backup, restore test, restore point, a PostgreSQL restart when you ask for one, Rewind (a copy next to production, compare, bring rows back, rewind in place and undo) when you ask, and health fixes you apply (VACUUM, ANALYZE, rebuilding or removing an index, cancelling a query, ending a session, removing an inactive replication slot). |
| `cmd/rowsafe`, `client` | The CLI. |
| `mcp`, `integrations/claude-code` | Guard: `rowsafe mcp`, an MCP server for AI assistants, and a Claude Code plugin that creates a restore point before migrations. |
| `integrations/github-action` | Guard in CI: a GitHub Action that saves a Mark (restore point) before every deploy, published as `rowsafe/action`. |
| `collect` | What the agent's monitoring reads: database and host metrics, locks, replication, query statistics and table insights. |
| `protocol` | The API types shared by the agent, the CLI and the Rowsafe service. |
| `internal/pgbackrest`, `internal/pginspect` | PostgreSQL backup and inspection. |
| `scripts/install.sh` | The installer served at `https://rowsafe.sh`. |
| `release`, `cmd/rowsafe-release` | Release signing and verification. |

## Safety by design

- **Never restarts your database on its own.** When a change needs a restart, you choose when: the installer asks, or you click Restart in the dashboard or run `rowsafe restart`. AI agents can't restart it.
- **Plan before apply.** You see every change before anything happens.
- **Fixes you choose, checked twice.** Health fixes run only when a person applies one, from a fixed list (no arbitrary SQL). The agent looks every object up again and re-checks the conditions right before it acts: it never removes an index that backs a constraint or has been used since, never ends Rowsafe's own, replication or autovacuum sessions, and only ends the exact session that was found (same process and start time). DDL waits at most 5 seconds for locks, indexes are rebuilt and removed `CONCURRENTLY`, and VACUUM runs gently (`vacuum_cost_delay`). AI agents can't apply fixes.
- **Isolated restore tests and copies** that can't touch production or its backups: a private socket, no network listener, no archiving into your bucket.
- **Rewind only when you ask, and undoable.** Bringing rows back runs in one transaction by primary key (parents first, triggers off, a Mark saved first). Rewinding the whole database keeps the current data aside for undo, and any failure puts the original back and starts it again. Your data stays on your server: Rowsafe only sees table names and counts. AI agents can't restore anything.
- **Signed, verifiable releases** with automatic rollback of a bad update. See [verifying releases](docs/verifying-releases.md).
- **Your secrets stay on your server,** and backups are encrypted before upload.
- **Backups go easy on your server.** Backups and restore tests run at low CPU and disk priority (`nice`, `ionice`), so PostgreSQL comes first. pgBackRest uses one process on servers with up to 4 CPUs and two on bigger ones (`process-max`), and compresses with zstd. Copying each change to your bucket (`archive-push`, run by PostgreSQL) is left at normal priority so it never falls behind.
- **Monitoring is read-only and light.** Short statement and lock timeouts on every query; heavier table checks run every 30 minutes, in the background, and back off when slow. `ROWSAFE_COLLECT_QUERY_TEXT=false` keeps query text on your server; `ROWSAFE_MONITORING=false` turns monitoring off.

## Build from source

```sh
make build   # bin/rowsafe, bin/rowsafe-agent, bin/rowsafe-release
make test
make lint
```

Release builds are reproducible (`make dist`). Locally built agents run but never auto-update.

## Contributing and security

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Documentation lives in [rowsafe/docs](https://github.com/rowsafe/docs). Report vulnerabilities privately through [GitHub security advisories](https://github.com/rowsafe/rowsafe/security/advisories/new) ([SECURITY.md](SECURITY.md)).

## License

[Apache License 2.0](LICENSE). Copyright 2026 Adraa Labs.
