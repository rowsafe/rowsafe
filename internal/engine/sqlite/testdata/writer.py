#!/usr/bin/env python3
# The "app" for the SQLite engine's integration test: C SQLite (Python's
# sqlite3 module, POSIX locks) writing to a WAL database as fast as it can,
# with its own checkpoints racing the agent's. Transaction i inserts event
# i (a payload derived from i, sometimes large enough to span many pages),
# sets state.v = i and, every 10th, deletes event i-5, so any consistent
# moment is fully described by v.
#
#   writer.py DB SECONDS START [truncate_at_seconds]
import hashlib, sqlite3, sys, time

db, seconds, start = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
truncate_at = float(sys.argv[4]) if len(sys.argv) > 4 else -1
c = sqlite3.connect(db, timeout=10, isolation_level=None)
c.execute("PRAGMA journal_mode=WAL")
c.execute("PRAGMA synchronous=NORMAL")
c.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, payload BLOB)")
c.execute("CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v INTEGER) WITHOUT ROWID")
c.execute("INSERT OR IGNORE INTO state VALUES ('v', 0)")

def payload(i):
    h = hashlib.sha256(str(i).encode()).digest()
    n = 64 + (i * 7919) % 3000
    if i % 97 == 0:
        n = 200000  # many pages in one transaction
    return (h * (n // len(h) + 1))[:n]

t0 = time.time()
i = start
truncated = False
while time.time() - t0 < seconds:
    c.execute("BEGIN IMMEDIATE")
    c.execute("INSERT INTO events VALUES (?, ?, ?)", (i, int(time.time() * 1000), payload(i)))
    c.execute("UPDATE state SET v = ? WHERE k = 'v'", (i,))
    if i % 10 == 0:
        c.execute("DELETE FROM events WHERE id = ?", (i - 5,))
    c.execute("COMMIT")
    if i % 150 == 0:
        c.execute("PRAGMA wal_checkpoint(PASSIVE)")
    if truncate_at >= 0 and not truncated and time.time() - t0 >= truncate_at:
        truncated = True
        r = c.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        print("truncate", r, flush=True)
    i += 1
    time.sleep(0.001)
print("last", i - 1, flush=True)
