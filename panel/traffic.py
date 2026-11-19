#!/usr/bin/env python3
"""Per-configuration traffic history.

Every five minutes the timer runs this script: it reads the peer counters
from `awg show <iface> dump`, subtracts the previous reading and stores the
delta in the panel database. Deltas survive a peer that is reissued (its
counters start from zero) and a reboot; a counter that went backwards is
treated as a fresh start.

Two resolutions are kept in one table: five-minute points for a week and
hourly points for 90 days. The panel API reads them by configuration.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("KASKAD_CONFIG", "/etc/kaskad/panel.json"))
DB_PATH = Path(os.environ.get("KASKAD_DB", "/var/lib/kaskad/panel.db"))

STEP = 300
HOUR = 3600
RAW_TTL = 7 * 86400
HOUR_TTL = 90 * 86400

# The panel creates these at startup, but the timer can fire while the panel
# is being restarted: the sampler makes sure its own tables exist.
SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic (
    client_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    step INTEGER NOT NULL,
    rx INTEGER NOT NULL,
    tx INTEGER NOT NULL,
    PRIMARY KEY (client_id, ts, step)
);
CREATE TABLE IF NOT EXISTS traffic_state (
    client_id INTEGER PRIMARY KEY,
    public_key TEXT NOT NULL,
    rx INTEGER NOT NULL,
    tx INTEGER NOT NULL,
    ts INTEGER NOT NULL
);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def dump_peers(iface: str) -> dict:
    """`awg show <iface> dump` → {public_key: {rx, tx}} in bytes."""
    res = subprocess.run(
        ["awg", "show", iface, "dump"], capture_output=True, text=True
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"awg show {iface} dump: {(res.stderr or '').strip() or 'failed'}"
        )
    peers = {}
    lines = [line for line in res.stdout.splitlines() if line.strip()]
    for index, line in enumerate(lines):
        if index == 0:
            continue
        f = line.split("\t")
        if len(f) >= 8:
            peers[f[0]] = {"rx": int(f[5] or 0), "tx": int(f[6] or 0)}
    return peers


def add(conn: sqlite3.Connection, client_id: int, bucket: int, step: int,
        rx: int, tx: int) -> None:
    conn.execute(
        "INSERT INTO traffic (client_id, ts, step, rx, tx) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(client_id, ts, step) DO UPDATE SET "
        "rx = rx + excluded.rx, tx = tx + excluded.tx",
        (client_id, bucket, step, rx, tx),
    )


def sample(conn: sqlite3.Connection, peers: dict, now: int | None = None) -> dict:
    """Stores the deltas since the previous run; returns what was recorded.

    The first run of a configuration only stores its counters as the
    baseline: the traffic that happened before the panel knew the peer is
    not history.
    """
    now = int(time.time()) if now is None else int(now)
    state = {
        r["client_id"]: r for r in conn.execute("SELECT * FROM traffic_state")
    }
    recorded = {"peers": 0, "rx": 0, "tx": 0}
    for cl in conn.execute("SELECT id, public_key FROM clients").fetchall():
        peer = peers.get(cl["public_key"])
        if not peer:
            continue
        rx, tx = int(peer["rx"]), int(peer["tx"])
        prev = state.get(cl["id"])
        if prev is None or prev["public_key"] != cl["public_key"]:
            conn.execute(
                "INSERT INTO traffic_state (client_id, public_key, rx, tx, ts) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(client_id) DO UPDATE SET "
                "public_key = excluded.public_key, rx = excluded.rx, "
                "tx = excluded.tx, ts = excluded.ts",
                (cl["id"], cl["public_key"], rx, tx, now),
            )
            continue
        drx, dtx = rx - prev["rx"], tx - prev["tx"]
        # A reboot or a recreated peer resets the counters: everything the
        # peer reports now happened after that reset.
        if drx < 0:
            drx = rx
        if dtx < 0:
            dtx = tx
        if drx or dtx:
            add(conn, cl["id"], now - now % STEP, STEP, drx, dtx)
            add(conn, cl["id"], now - now % HOUR, HOUR, drx, dtx)
            recorded["peers"] += 1
            recorded["rx"] += drx
            recorded["tx"] += dtx
        conn.execute(
            "UPDATE traffic_state SET rx = ?, tx = ?, ts = ? WHERE client_id = ?",
            (rx, tx, now, cl["id"]),
        )
    prune(conn, now)
    return recorded


def prune(conn: sqlite3.Connection, now: int | None = None) -> None:
    now = int(time.time()) if now is None else int(now)
    conn.execute(
        "DELETE FROM traffic WHERE step = ? AND ts < ?", (STEP, now - RAW_TTL)
    )
    conn.execute(
        "DELETE FROM traffic WHERE step = ? AND ts < ?", (HOUR, now - HOUR_TTL)
    )
    # SQLite reuses the id of a deleted configuration, so an orphan row would
    # become the history of whatever is created next.
    conn.execute("DELETE FROM traffic WHERE client_id NOT IN (SELECT id FROM clients)")
    conn.execute(
        "DELETE FROM traffic_state WHERE client_id NOT IN (SELECT id FROM clients)"
    )


def main() -> int:
    try:
        c = json.loads(CONFIG_PATH.read_text())
        peers = dump_peers(c["iface"])
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"traffic: {exc}", file=sys.stderr)
        return 1
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        ensure_schema(conn)
        with conn:
            recorded = sample(conn, peers)
    finally:
        conn.close()
    print(
        "traffic: {peers} peers, rx {rx} B, tx {tx} B".format(**recorded),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
