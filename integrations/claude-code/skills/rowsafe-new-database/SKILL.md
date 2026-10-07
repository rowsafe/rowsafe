---
name: rowsafe-new-database
description: Use when the app you are building needs a PostgreSQL database and there is none yet (no DATABASE_URL, or the user asks for one) - a new Rowsafe Cloud server, or a new database and login on a Rowsafe Cloud server the organization already has. Picks the cheapest fitting size, tells the user the price and gets their OK, creates it with the user's rights (or asks a person to approve it when the organization wants that), waits until it is ready, and puts the connection string in the app's environment without anyone else seeing the password.
---

# Need a database? (Rowsafe Cloud)

Rowsafe Cloud is PostgreSQL that Rowsafe runs and protects from the first minute (continuous backups, a weekly restore test, monitoring), billed to the user's organization. You can create one. You act as the person who connected you, with exactly their rights in the Rowsafe dashboard: for an owner or admin it is created right away. It waits for an owner or admin to approve it in the dashboard instead when the user is a member, when an owner chose "Ask me first" for AI agents or set a budget it would go over, or when a first payment is due and the user isn't an owner; nothing is created or billed until then. `get_org` shows the organization's agent setting (Settings → AI agents).

The tools come from Rowsafe's MCP server. Making changes (`create_cloud_server`, `cloud_firewall`, `create_app_database`, `request_change`) needs the user to have allowed you to act; if those tools aren't listed, ask the user to create the server in the Rowsafe dashboard (Create a server) and to give you the connection string.

## Steps

1. **Use what exists.** Call `list_cloud_servers`: if the organization already has a ready server the app can use, skip to step 5 with its database.
2. **Pick a size.** Call `cloud_catalog`. Choose a region near where the app runs and the cheapest size that fits; a new or small app fits the smallest size (it names the cheapest one free now, about $10 a month at most). Don't pick a size that is sold out in that region. Tell the user what you picked and what it costs, per hour and at most per month, and wait for their OK.
3. **Create it.** Once the user agrees, call `create_cloud_server` (or `request_change` with action `create_cloud_server`, no database) with `name` (like `shop-db`), `region`, `size`, and `allowed_ips` (the addresses the app connects from; leave it empty if you don't know them yet). The reason says what it's for, in one or two plain sentences. Then, depending on the result:
   - **Done**: the server is being created. Tell the user what you created and what it costs.
   - **A checkout link**: the organization has no pay as you go yet (or its cloud is billed by the month). The server waits for payment; give the user the link to pay (only an owner can). It is created once paid.
   - **Waiting for a person**: give the user the approval link it returns. Nothing is created or billed until an owner or admin approves it (and an owner pays, if a first payment is due).
4. **Wait.** If it waits for a person, call `get_approval` with `wait_seconds` until it is approved (or denied: then stop and don't ask again unless the user wants to); once approved it shows the server's ID. Call `get_cloud_server` with the server's ID and `wait_seconds` until it is `ready` (5 to 10 minutes; it may first wait for payment).
5. **Let the app in.** `get_cloud_server` shows who can connect. If the app's address isn't listed, call `cloud_firewall` with the server and the whole new `allowed_ips` list.
6. **Get the app its own database and login.** Call `create_app_database` with the server's database (as `get_cloud_server` shows it), a `name` for the app's database, and a reason.
   - Connected with Sign in with Rowsafe (this plugin's server), Rowsafe never makes or sees the password, so this one always waits for a person: give the user the approval link. When they approve, the database server makes the password and their browser shows them the connection string once. Ask them to paste it into the app's `.env` themselves, or to give it to you.
   - Through a local `rowsafe mcp` (the CLI), the password is made on this machine and Rowsafe only gets its verifier, so it runs right away with the user's rights (or once approved): you get the full connection string at once, shown only once. It works once `get_task` shows the task succeeded.
7. **Store it safely.** Put the connection string in the app's environment, e.g. `DATABASE_URL` in `.env`, and make sure `.env` is in `.gitignore`. Never put it in code, a commit or a log, and don't repeat it back in the chat. Keep `sslmode=require` as given.

## Later

- A bigger size: `request_change` `resize_cloud_server` (the database is offline a few minutes; Rowsafe saves a Mark first). Tell the user the new price and the downtime first, and wait for their OK.
- A copy to test on: `request_change` `clone_to_new_server` with `delete_after_hours` (tell the user what it costs first), or a masked `create_safe_copy` on the same server.
- Deleting a server is `request_change` `delete_cloud_server`: only when the user asks, and only after you confirm with them which server it is: the server and anything not backed up are gone, and its bill stops. Rowsafe types the server's name for you and records that it did; its backups stay in Rowsafe Storage. With no backup yet (or no saved backup passphrase), it waits for a person.
- Before migrations and other risky changes, follow the `rowsafe-safety` skill.
