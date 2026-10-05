# Rowsafe Guard for Claude Code

The database safety net for AI agents (PostgreSQL, MySQL, MariaDB, MongoDB, ClickHouse, Redis, Valkey and SQLite): before a migration or destructive SQL, check that the database can be recovered and create a named Rowsafe restore point.

- **MCP server** `https://api.rowsafe.sh/mcp`: sign in with Rowsafe once (`/mcp` in Claude Code, or the prompt in Claude Desktop and claude.ai); you choose the organization and what it may do. Always: `safety_check`, `list_restore_points`, read-only health, alerts, live activity, disk, uptime, metrics, security, updates, audit log, backup and restore-test tools, and `describe_change` / `get_approval` / `list_approvals`. If you allow Marks: `create_restore_point`. If you allow it to act: backups, restore tests, checks, migration previews, safe copies, acknowledging alerts, and `request_change`, which asks you to approve a change to production (a Pulse fix, settings, a restart, a rewind, an upgrade, a standby failover, ...). Nothing changes production until an owner or admin approves the request in the dashboard, and Claude can never approve.
- **Skill** `rowsafe-safety`: the workflow (check, restore point, preview migrations, proceed; if something breaks, stop and tell the user).
- **Hook** `hooks/guard.sh` on Bash: with the `rowsafe` CLI installed, creates a restore point right before commands like `prisma migrate deploy`, `rails db:migrate`, `alembic upgrade`, `psql -c "DROP TABLE ..."`, `mysql -e "TRUNCATE ..."`, `mongosh --eval "db.orders.drop()"`, `clickhouse-client -q "ALTER TABLE ... DELETE ..."` or `sqlite3 app.db "DROP TABLE ..."`. It never approves a command; without the CLI it does nothing.

Requirements: a Rowsafe account with the database connected. For the hook, migration previews (`rowsafe preview`) and safe copies (`rowsafe copies create`): the `rowsafe` CLI on `PATH`, logged in (`rowsafe login`), and the project's database named in `ROWSAFE_DATABASE` or `.rowsafe.json` (`{"database": "app"}`).

```sh
claude plugin marketplace add rowsafe/rowsafe   # or ./ from a local clone
claude plugin install rowsafe@rowsafe
```

Set `ROWSAFE_REQUIRE_PROTECTION=1` (or `"require_protection": true` in `.rowsafe.json`) to block destructive commands when the database isn't protected or the restore point can't be confirmed.

Details: [rowsafe.sh/docs/guides/ai-agents](https://rowsafe.sh/docs/guides/ai-agents).
