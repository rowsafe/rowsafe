---
name: rowsafe-safety
description: Use before any destructive or risky change to a PostgreSQL database protected by Rowsafe - running migrations (prisma, rails, alembic, django, knex, sequelize, typeorm, drizzle, goose, ...), schema changes, DROP or TRUNCATE, DELETE or UPDATE without a narrow WHERE, bulk data fixes, or restoring a dump. Checks that the database is recoverable and creates a named restore point first.
---

# Rowsafe safety workflow

Rowsafe continuously archives this project's PostgreSQL WAL, so the database can be restored to any moment, including a named restore point. Your job is to make sure such a point exists right before you change data, and to hand recovery to the user if something goes wrong.

## Before a destructive or risky database operation

1. **Find the database.** It is the Rowsafe database named in `ROWSAFE_DATABASE` or in `.rowsafe.json` (`{"database": "NAME"}`) at the project root. If neither exists, call the `list_databases` tool and ask the user which one the operation touches.
2. **Check protection.** Call `safety_check` with that database.
   - `protected: true`: continue.
   - Not protected: tell the user the reasons it gives, and ask whether to proceed anyway. Don't proceed without a clear yes.
3. **Create a restore point.** Call `create_restore_point` with a short name that says what comes next, such as `before-drop-legacy-orders` or `pre-migrate-add-invoices` (lowercase letters, digits, `-` and `_`). Wait for it to be confirmed (`archived`). Tell the user the name.
   - The Rowsafe hook may already have created one for a Bash command (it says so in its note, with names like `agent-20260924-153000`). Then you don't need another one for that command.
   - If the tool is unavailable, ask the user to run `rowsafe mark DATABASE NAME`.
4. **Proceed** with the operation.

## If something goes wrong

- Stop. Don't run more commands against the database, and don't try to repair data by hand.
- Tell the user what happened, and that they can restore the database to the restore point by name (pgBackRest `--type=name --target=NAME`; see Rowsafe's restore runbook).
- Never attempt a restore yourself. Restores replace the running cluster and are the user's decision.

## What counts as destructive

Migrations and schema changes of any tool; `DROP`, `TRUNCATE`, `ALTER TABLE ... DROP/RENAME/TYPE`; `DELETE` or `UPDATE` without a narrow `WHERE`; data backfills; `pg_restore --clean`; `dropdb`; resetting or re-seeding a database. When unsure, treat it as destructive: a restore point costs a second.

Read-only work (SELECT, `EXPLAIN`, `migrate status`, generating migration files) needs none of this.
