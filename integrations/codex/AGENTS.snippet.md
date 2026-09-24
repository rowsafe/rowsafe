## Database safety (Rowsafe)

This project's PostgreSQL is protected by Rowsafe (database: `app`). Before any destructive or risky database operation (migrations, schema changes, DROP/TRUNCATE, DELETE or UPDATE without a narrow WHERE, backfills, resets or re-seeding, restoring a dump):

1. Call the `safety_check` tool for `app`. If it isn't protected, tell me the reasons and wait for my OK.
2. Set a Mark (a named restore point) with a descriptive name, such as `before-drop-orders`: call `create_restore_point`, wait until it is confirmed, and tell me its name. If the Rowsafe hook already set one for the command (its note names it, `agent-...`), tell me that name instead. If the Rowsafe tools aren't available, ask me to run `rowsafe mark app before-<what>` and wait.
3. Then proceed, against the same database.

If something goes wrong: stop, don't try to repair the data, and never restore, rewind or restart anything yourself. Tell me what happened and the Mark's name; I'll decide whether to Rewind from the Rowsafe dashboard (https://app.rowsafe.sh).

Read-only work (SELECT, EXPLAIN, `migrate status`, generating migration files) needs none of this.
