---
name: rowsafe-new-database
description: Use when the app you are building needs a PostgreSQL database and there is none yet (no DATABASE_URL, or the user asks for one) - a new Rowsafe Cloud server, or a new database and login on a Rowsafe Cloud server the organization already has. Picks the cheapest fitting size, asks for it (a person approves it, unless the owner lets agents do it on their own within a budget), waits until it is ready, and puts the connection string in the app's environment without anyone else seeing the password.
---

# Need a database? (Rowsafe Cloud)

Rowsafe Cloud is PostgreSQL that Rowsafe runs and protects from the first minute (continuous backups, a weekly restore test, monitoring), billed to the user's organization. You can ask for one. If your owner allows it, it happens right away; otherwise give them the approval link: nothing is created, changed or billed until an owner or admin approves your request in the Rowsafe dashboard. `get_org` says which: an owner can let AI agents create servers and app databases on their own within a monthly budget (Settings → AI agents).

The tools come from Rowsafe's MCP server (`codex mcp login rowsafe` signs in). Asking for changes (`request_change`, `create_app_database`) needs the user to have allowed Codex to act at sign-in; if those tools aren't listed, ask the user to create the server in the Rowsafe dashboard (Create a server) and to give you the connection string.

## Steps

1. **Use what exists.** Call `list_cloud_servers`: if the organization already has a ready server the app can use, skip to step 5 with its database.
2. **Pick a size.** Call `cloud_catalog`. Choose a region near where the app runs and the cheapest size that fits; a new or small app fits the smallest size (it names the cheapest one free now, about $10 a month at most). Don't pick a size that is sold out in that region. Tell the user what you picked and what it costs, per hour and at most per month.
3. **Ask for it.** Call `request_change` with action `create_cloud_server`, no database, and params `name` (like `shop-db`), `region`, `size`, and `allowed_ips` (the addresses the app connects from; leave it empty if you don't know them yet). The reason says what it's for, in one or two plain sentences. If it ran right away (approved automatically by the owner's agent setting), tell the user what you created and what it costs. Otherwise give the user the approval link it returns. If pay as you go isn't active yet, the person who approves pays at a checkout right after; the server is created once paid.
4. **Wait.** Unless it already ran, call `get_approval` with `wait_seconds` until it is approved (or denied: then stop and don't ask again unless the user wants to). Once approved it shows the server's ID. Call `get_cloud_server` with that ID and `wait_seconds` until it is `ready` (5 to 10 minutes; it may first wait for payment).
5. **Let the app in.** `get_cloud_server` shows who can connect. If the app's address isn't listed, ask for `request_change` `cloud_firewall` with the server and the whole new `allowed_ips` list.
6. **Get the app its own database and login.** Call `create_app_database` with the server's database (as `get_cloud_server` shows it), a `name` for the app's database, and a reason. A person approves it too, unless your owner lets agents do it on their own.
   - Connected with Sign in with Rowsafe (this plugin's server), Rowsafe never makes or sees the password: when the person approves, the database server makes it and their browser shows them the connection string once. Ask them to paste it into the app's `.env` themselves, or to give it to you.
   - Through a local `rowsafe mcp` (the CLI), the password is made on this machine and Rowsafe only gets its verifier: you get the full connection string at once, shown only once. It works once the request is approved and `get_task` shows the task succeeded.
7. **Store it safely.** Put the connection string in the app's environment, e.g. `DATABASE_URL` in `.env`, and make sure `.env` is in `.gitignore`. Never put it in code, a commit or a log, and don't repeat it back in the chat. Keep `sslmode=require` as given.

## Later

- A bigger size: `request_change` `resize_cloud_server` (the database is offline a few minutes; Rowsafe saves a Mark first).
- A copy to test on: `request_change` `clone_to_new_server` with `delete_after_hours`, or a masked `create_safe_copy` on the same server.
- Deleting a server is `delete_cloud_server`: only when the user asks; the person approving types its name (or, if your owner gave agents full autonomy, Rowsafe does it right away once a backup exists).
- Before migrations and other risky changes, follow the `rowsafe-safety` skill.
