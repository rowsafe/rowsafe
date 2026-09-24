# Rowsafe Guard for Claude Code

The PostgreSQL safety net for AI agents: before a migration or destructive SQL, check that the database can be recovered and create a named Rowsafe restore point.

- **MCP server** `rowsafe mcp --allow-restore-points`: `safety_check`, `create_restore_point`, `list_restore_points`, and read-only fleet tools.
- **Skill** `rowsafe-safety`: the workflow (check, restore point, proceed; if something breaks, stop and tell the user).
- **Hook** `rowsafe guard` on Bash: creates a restore point right before commands like `prisma migrate deploy`, `rails db:migrate`, `alembic upgrade` or `psql -c "DROP TABLE ..."`.

Requirements: the `rowsafe` CLI on `PATH`, logged in (`rowsafe login`), and the project's database named in `ROWSAFE_DATABASE` or `.rowsafe.json` (`{"database": "app"}`).

```sh
claude plugin marketplace add rowsafe/rowsafe   # or ./ from a local clone
claude plugin install rowsafe@rowsafe
```

Set `ROWSAFE_REQUIRE_PROTECTION=1` (or `"require_protection": true` in `.rowsafe.json`) to block destructive commands when the database isn't protected or the restore point can't be confirmed.

Details: [rowsafe.sh/docs/guides/ai-agents](https://rowsafe.sh/docs/guides/ai-agents).
