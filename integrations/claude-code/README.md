# Rowsafe Guard for Claude Code

The database safety net for AI agents (PostgreSQL, MySQL, MariaDB, MongoDB, ClickHouse, Redis, Valkey, SQLite, Qdrant, OpenSearch and Meilisearch): before a migration or destructive SQL, check that the database can be recovered and create a named Rowsafe restore point.

- **MCP server** `https://api.rowsafe.sh/mcp`: sign in with Rowsafe once (`/mcp` in Claude Code, or the prompt in Claude Desktop and claude.ai); you choose the organization and what it may do. Always: `safety_check`, `list_restore_points`, read-only health, alerts, live activity, disk, uptime, metrics, security, updates, audit log, backup and restore-test tools, Rowsafe Cloud's catalog and servers (`cloud_catalog`, `list_cloud_servers`, `get_cloud_server`), `describe_change`, and `get_agent_action` / `list_agent_actions` (the changes AI agents made). If you allow Marks: `create_restore_point`. If you allow it to act: backups, restore tests, checks, migration previews, safe copies, acknowledging alerts, `request_change` for a change to production (a Pulse fix, settings, a restart, a rewind, an upgrade, a standby failover, a new Rowsafe Cloud server, ...), the direct `create_cloud_server`, `cloud_firewall` and `apply_fix`, and `create_app_database` for the app's own database and login.
- **Claude acts as you**, right away, with exactly the rights of the person who connected it (at sign-in, or who created its API key), like a CLI token. What you can't do in the dashboard, Claude can't either: Rowsafe refuses it and Claude tells you why (a member's change, a first payment only an owner makes, a standby or a move where a person compares the server's key, a change that can't be undone before there's a backup). Nothing waits for approval. An owner can set a monthly budget for agents (Settings → AI agents). Rowsafe saves a Mark before risky changes, and every action is in the audit log and the owners' digest email. The skills tell Claude to make only changes you asked for or agreed to, and to confirm destructive, disruptive or paid ones with you first.
- **Skill** `rowsafe-safety`: the workflow (check, restore point, preview migrations, proceed; if something breaks, stop and tell the user).
- **Skill** `rowsafe-health`: is the database healthy, why is it slow, what's stuck, how to tune it: `rowsafe pulse`, `insights`, `top`, `activity`, `settings` and `tune`, and fixes only after you agree. Works without a Rowsafe account, on a PostgreSQL connection string.
- **Skill** `rowsafe-new-database`: when the app needs a database: pick the cheapest fitting Rowsafe Cloud size (`cloud_catalog`), tell you the size and price and get your OK, create the server (`create_cloud_server`; with a checkout link if pay as you go isn't on yet), wait until it's ready (`get_cloud_server`), then get the app's own database and login (made in the dashboard, where your browser makes its password, or `create_app_database` from a local `rowsafe mcp`) and put the connection string in `.env`. The password never passes through Rowsafe.
- **Hook** `hooks/guard.sh` on Bash: with the `rowsafe` CLI installed, creates a restore point right before commands like `prisma migrate deploy`, `rails db:migrate`, `alembic upgrade`, `psql -c "DROP TABLE ..."`, `mysql -e "TRUNCATE ..."`, `mongosh --eval "db.orders.drop()"`, `clickhouse-client -q "ALTER TABLE ... DELETE ..."` or `sqlite3 app.db "DROP TABLE ..."`. It never approves a command; without the CLI it does nothing.

Requirements: for restore points, a Rowsafe account with the database connected; health checks need only the CLI (below). For the hook, migration previews (`rowsafe preview`) and safe copies (`rowsafe copies create`): the `rowsafe` CLI on `PATH` (`curl -fsSL https://rowsafe.sh/cli | sh` on macOS and Linux; on Windows, `rowsafe-windows-amd64.exe` from the [latest release](https://github.com/rowsafe/rowsafe/releases/latest)), logged in (`rowsafe login`), and the project's database named in `ROWSAFE_DATABASE` or `.rowsafe.json` (`rowsafe init app`, which also offers to add a short Rowsafe section to `AGENTS.md` and `CLAUDE.md`).

```sh
claude plugin marketplace add rowsafe/rowsafe   # or ./ from a local clone
claude plugin install rowsafe@rowsafe
```

### Without an account

The `rowsafe-health` skill runs the CLI on the connection string your app uses. For MCP tools instead (`database_health`, `database_insights`, `top_queries`, `live_activity`, `database_settings`; `apply_fix` with `--allow-writes`), run the CLI's local server on the database:

```sh
claude mcp add rowsafe-db -- rowsafe mcp "postgres://user@host:5432/app"
```

It runs on your computer, reads with short timeouts, and sends nothing to Rowsafe. Passwords can stay in `~/.pgpass` or `PGPASSWORD`. Backups and restore points need the Rowsafe agent on the database server.

Set `ROWSAFE_REQUIRE_PROTECTION=1` (or `"require_protection": true` in `.rowsafe.json`) to block destructive commands when the database isn't protected or the restore point can't be confirmed.

Details: [rowsafe.sh/docs/guides/ai-agents](https://rowsafe.sh/docs/guides/ai-agents).
