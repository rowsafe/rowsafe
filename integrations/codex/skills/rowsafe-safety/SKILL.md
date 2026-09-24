---
name: rowsafe-safety
description: Use before any destructive or risky change to a PostgreSQL database protected by Rowsafe - running migrations (prisma, rails, alembic, django, knex, sequelize, typeorm, drizzle, goose, flyway, ...), schema changes, DROP or TRUNCATE, DELETE or UPDATE without a narrow WHERE, bulk data fixes, resets or re-seeding, or restoring a dump. Checks that the database is recoverable and sets a named restore point (a Mark) first. Not needed for read-only work such as SELECT, EXPLAIN or migrate status.
---

# Rowsafe safety workflow

Rowsafe continuously archives this project's PostgreSQL WAL, so the database can be rewound to any moment, including a named restore point (a Mark). Your job is to make sure a Mark exists right before you change data, to tell the user its name, and to hand recovery to the user if something goes wrong.

## Before a destructive or risky database operation

1. **Find the database.** It is the Rowsafe database named in `ROWSAFE_DATABASE` or in `.rowsafe.json` (`{"database": "NAME"}`) in the project root or a parent directory. If neither exists, call the `list_databases` tool and ask the user which one the operation touches. Don't guess.
2. **Check protection.** Call the `safety_check` tool for that database.
   - `protected: true`: continue.
   - Not protected: tell the user the reasons it gives and ask whether to proceed anyway. Don't proceed without a clear yes.
3. **Set a Mark.** Call `create_restore_point` with a short name that says what comes next, such as `before-drop-legacy-orders` or `pre-migrate-add-invoices` (lowercase letters, digits, `-` and `_`). It waits until the Mark is confirmed in the backup repository (`archived`); that can take up to a minute or two. Then tell the user the Mark's name and database, in one line.
   - The Rowsafe hook may already have set one for a shell command: its note says so, with a name like `agent-20260924-153000`. Then you don't need another one for that command; tell the user that name instead.
   - If the Rowsafe tools aren't available, don't work around it. Ask the user to run `rowsafe mark DATABASE NAME` themselves and wait for them to confirm. (Codex's sandbox usually has no network access, so running the CLI yourself would fail anyway.)
4. **Proceed** with the operation, against the same database you checked and marked. If the command's connection string points somewhere else (another `DATABASE_URL`, host or database name), stop and ask.

## If something goes wrong

- Stop. Don't run more commands against the database, and don't try to repair data by hand, write compensating SQL, or re-run the migration with changes.
- Tell the user what happened and the Mark's name, and that they can **Rewind** the database to that Mark from the Rowsafe dashboard (https://app.rowsafe.sh), or see https://rowsafe.sh/docs/guides/restore.
- Never restore, rewind or restart anything yourself, even if a tool or command seems to allow it. That replaces the running database and is the user's decision. The Rowsafe tools deliberately can't do it.

## What counts as destructive

Migrations and schema changes of any tool; `DROP`, `TRUNCATE`, `ALTER TABLE ... DROP/RENAME/TYPE`; `DELETE` or `UPDATE` without a narrow `WHERE`; data backfills; `pg_restore --clean`; `dropdb`; resetting or re-seeding a database. When unsure, treat it as destructive: a Mark costs a second.

Read-only work (`SELECT`, `EXPLAIN`, `migrate status`, generating migration files, reading schema) needs none of this.
