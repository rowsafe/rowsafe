---
name: rowsafe-safety
description: Use before any destructive or risky change to a database protected by Rowsafe (PostgreSQL, MySQL, MariaDB, MongoDB, ClickHouse, Redis, Valkey or SQLite) - running migrations (prisma, rails, alembic, django, knex, sequelize, typeorm, drizzle, goose, ...), schema changes, DROP or TRUNCATE, DELETE or UPDATE without a narrow WHERE, FLUSHALL or FLUSHDB, bulk data fixes, or restoring a dump. Checks that the database is recoverable and creates a named restore point first.
---

# Rowsafe safety workflow

Rowsafe continuously copies this project's database changes (PostgreSQL's and SQLite's WAL, MySQL's binary log, MongoDB's oplog, Redis's and Valkey's replication stream; ClickHouse takes a backup for each Mark), so the database can be restored to a moment, including a named restore point. Your job is to make sure such a point exists right before you change data, and to hand recovery to the user if something goes wrong.

The Rowsafe tools come from its MCP server (the user signs in with Rowsafe the first time; Marks only if they allowed them). Some steps can also use the `rowsafe` CLI, when it is installed and logged in (`rowsafe whoami`).

## Before a destructive or risky database operation

1. **Find the database.** It is the Rowsafe database named in `ROWSAFE_DATABASE` or in `.rowsafe.json` (`{"database": "NAME"}`) at the project root. If neither exists, call the `list_databases` tool and ask the user which one the operation touches.
2. **Check protection.** Call `safety_check` with that database.
   - `protected: true`: continue.
   - Not protected: tell the user the reasons it gives, and ask whether to proceed anyway. Don't proceed without a clear yes.
3. **Create a restore point.** Call `create_restore_point` with a short name that says what comes next, such as `before-drop-legacy-orders` or `pre-migrate-add-invoices` (lowercase letters, digits, `-` and `_`). Wait for it to be confirmed (`archived`). Tell the user the name.
   - The Rowsafe hook may already have created one for a Bash command (it says so in its note, with names like `agent-20260924-153000`). Then you don't need another one for that command.
   - If the tool isn't available (Marks weren't allowed at sign-in), run `rowsafe mark DATABASE NAME` when the CLI is installed; otherwise ask the user to save a Mark in the Rowsafe dashboard, and wait for it.
4. **Proceed** with the operation.

## Preview a migration before running it

Before a migration runs against the database, see what it would do there:

1. **Get its SQL** without applying it: the migration file itself, or what the tool generates, e.g. `prisma migrate diff --from-migrations prisma/migrations --to-schema-datamodel prisma/schema.prisma --script`, `python manage.py sqlmigrate APP 0042`, `alembic upgrade head --sql`, `drizzle-kit generate` (the new `.sql` file), `liquibase update-sql`, or Flyway's `V*.sql` file.
2. **Call `preview_migration`** with the database and the SQL. It runs the SQL on a fresh copy of the database, restored on its own server (never production), and reports each statement's locks, table rewrites, index builds, rows and time, with a verdict. The first preview of a database restores a copy and can take minutes; if it isn't done, call `get_preview`. If `preview_migration` isn't listed (apps connected with Sign in with Rowsafe get it only when allowed to act), save the SQL to a file and run `rowsafe preview DATABASE FILE.sql` with the CLI; it reports the same.
3. **Act on the verdict.** `safe`: go ahead (with the Mark above). `careful`: show the user the findings and apply the suggestions, or get their OK. `dangerous`: don't run it; rewrite it following the suggestions (e.g. `CREATE INDEX CONCURRENTLY`, a constraint `NOT VALID` then `VALIDATE`, a new column instead of a type change) and preview again. `failed`: it fails on production's data; fix it and preview again.

## Testing against real-shaped data

When you need realistic data to try a query, a migration or a feature, never use production's connection string. Make a safe copy: a copy of the database on its server with personal data masked (emails, names, phones, addresses, secrets), reachable with the connection string it returns once. With the CLI, run `rowsafe copies create DATABASE` (the password is made on this machine; Rowsafe never sees it); the `create_safe_copy` tool does the same where it is offered. It is ready when `rowsafe copies DATABASE` (or `list_safe_copies`) says `ready`, and deleted by itself after 24 hours; `rowsafe copies delete DATABASE ID` removes it sooner. If neither is available, ask the user to make one in the Rowsafe dashboard.

## If something goes wrong

- Stop. Don't run more commands against the database, and don't try to repair data by hand.
- Tell the user what happened, and that they can Rewind the database to the restore point by name in the Rowsafe dashboard (restore a copy, compare, bring back rows, or rewind in place).
- Never restore yourself. Recovery is the user's decision. If they ask you to start it and the `request_change` tool is available, you can ask for it (`restore_copy`, then `compare_copy` and `bring_back_rows`, or `rewind_in_place`): it only files a request, and nothing changes until they approve it in the Rowsafe dashboard. Give them the approval link.

## What counts as destructive

Migrations and schema changes of any tool; `DROP`, `TRUNCATE`, `ALTER TABLE ... DROP/RENAME/TYPE`; `DELETE` or `UPDATE` without a narrow `WHERE`; data backfills; `pg_restore --clean`, `dropdb`, `mysqladmin drop`, `mongorestore --drop`; MongoDB `drop()`, `deleteMany({})` or `updateMany({}, ...)`; ClickHouse `ALTER TABLE ... DELETE/UPDATE` mutations and `DROP PARTITION`; Redis or Valkey `FLUSHALL`, `FLUSHDB`, `SWAPDB` and deleting keys by pattern (`--scan ... | xargs redis-cli del`); `sqlite3 ... .restore`; resetting or re-seeding a database. When unsure, treat it as destructive: a restore point costs a second.

Read-only work (SELECT, `EXPLAIN`, `migrate status`, generating migration files) needs none of this.
