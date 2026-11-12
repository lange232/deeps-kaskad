#!/usr/bin/env python3
"""Applies client routing based on the panel database.

Internet clients without granted exits share table 100 (the active exit is
chosen by the failover daemon). Clients with granted internet exits get their
own table and a rule pointing at it, so the failover daemon can follow the
order the client chose. Clients with routed exits get
`from <ip> to <cidr> lookup <exit table>` rules with a higher priority, so
specific subnets always win over the default route.

Rules we installed previously are removed before every apply, so deleting a
client or an exit does not leave stale state behind.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("KASKAD_CONFIG", "/etc/kaskad/panel.json"))
DB_PATH = Path(os.environ.get("KASKAD_DB", "/var/lib/kaskad/panel.db"))

ROUTE_PRIORITY = 10000
INTERNET_PRIORITY = 20000
# 1000+, not 200: the 201..264 range overlaps the system tables
# 253 (default), 254 (main) and 255 (local). A wrong value here once wiped
# the main table and cut the host off the network.
ROUTED_TABLE_BASE = 1000
# Per-client internet tables live above the routed ones; ids are bounded by
# the number of clients, and none of these ranges may touch 253/254/255.
CLIENT_TABLE_BASE = 3000
# A client's own choice must win over the shared automatic table.
CLIENT_PRIORITY = 19000
# These tables must never be flushed.
RESERVED_TABLES = {0, 100, 253, 254, 255}


def cfg() -> dict:
    return json.loads(CONFIG_PATH.read_text())


def rows(db: sqlite3.Connection, sql: str) -> list[dict]:
    return [dict(r) for r in db.execute(sql).fetchall()]


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def routed_table(exit_id: int) -> int:
    return ROUTED_TABLE_BASE + int(exit_id)


def client_table(client_id: int) -> int:
    return CLIENT_TABLE_BASE + int(client_id)


def tables_to_flush(current: set[int], previous: set[int]) -> list[int]:
    """Tables to flush: everything we used now or before, never reserved ones."""
    return sorted(
        t for t in (current | previous)
        if t > ROUTED_TABLE_BASE and t not in RESERVED_TABLES
    )


def get_setting(key: str) -> str:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else ""
    finally:
        conn.close()


def save_setting(key: str, value: str) -> None:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        conn.commit()
    finally:
        conn.close()


def cleanup_rules(internet_table: int) -> None:
    """Removes all rules of ours, no matter who installed them.

    This cleans up leftovers from older versions (the rule for the whole
    client subnet) and does not care whether the panel or the unit applied
    the routing.
    """
    res = run(["ip", "rule", "show"])
    for line in (res.stdout or "").splitlines():
        if ":" not in line:
            continue
        spec = line.split(":", 1)[1].strip().split()
        if "iif" not in spec or "awg0" not in spec or "lookup" not in spec:
            continue
        idx = spec.index("lookup")
        if idx + 1 >= len(spec):
            continue
        table = spec[idx + 1]
        if not table.isdigit():
            continue
        value = int(table)
        if value in RESERVED_TABLES and value != internet_table:
            continue
        if value == internet_table or value > ROUTED_TABLE_BASE:
            run(["ip", "rule", "del"] + spec)


def apply() -> dict:
    c = cfg()
    internet_table = int(c.get("route_table", 100))
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        exits = rows(db, "SELECT * FROM exits WHERE enabled = 1")
        clients = rows(db, "SELECT * FROM clients WHERE enabled = 1")
        links = rows(db, "SELECT * FROM client_exits")
        grants = rows(
            db,
            "SELECT ce.client_id, ce.priority, e.id AS exit_id, e.iface, "
            "e.priority AS exit_priority FROM client_internet_exits ce "
            "JOIN exits e ON e.id = ce.exit_id "
            "WHERE e.enabled = 1 AND e.mode = 'internet' "
            "ORDER BY ce.priority, e.priority, e.id",
        )
        client_by_id = {cl["id"]: cl for cl in clients}
        exit_by_id = {ex["id"]: ex for ex in exits}
    finally:
        db.close()

    client_choices: dict[int, list[str]] = {}
    for grant in grants:
        client_choices.setdefault(grant["client_id"], []).append(grant["iface"])

    cleanup_rules(internet_table)

    # Exit ids grow as exits are added and removed, so the set of tables we
    # own is persisted in the database instead of assuming a fixed range.
    current_tables = {
        routed_table(ex["id"]) for ex in exits
        if ex["mode"] == "routes" and Path(f"/sys/class/net/{ex['iface']}").exists()
    }
    current_tables |= {
        client_table(cl["id"]) for cl in clients
        if cl["internet"] and client_choices.get(cl["id"])
    }
    raw_previous = get_setting("routing_tables")
    if raw_previous:
        try:
            previous_tables = {int(x) for x in json.loads(raw_previous)}
        except (ValueError, TypeError):
            previous_tables = set()
    else:
        # First run on an existing database: clean the legacy range too.
        previous_tables = set(range(ROUTED_TABLE_BASE + 1, ROUTED_TABLE_BASE + 65))
    for table in tables_to_flush(current_tables, previous_tables):
        run(["ip", "route", "flush", "table", str(table)])

    tables: set[int] = set()
    rules: list[tuple[list[str], int]] = []

    # routes of routed exits
    for ex in exits:
        if ex["mode"] != "routes":
            continue
        if not Path(f"/sys/class/net/{ex['iface']}").exists():
            continue
        table = routed_table(ex["id"])
        tables.add(table)
        for cidr in [x.strip() for x in (ex["routes"] or "").split(",") if x.strip()]:
            run(["ip", "route", "replace", cidr, "dev", ex["iface"], "table", str(table)])

    # clients with granted internet exits get their own table; the failover
    # daemon keeps its default route on the first exit that is alive
    try:
        active_exit = Path("/run/kaskad/active-exit").read_text().strip()
    except OSError:
        active_exit = ""
    for cl in clients:
        choices = client_choices.get(cl["id"]) if cl["internet"] else None
        if not choices:
            continue
        table = client_table(cl["id"])
        tables.add(table)
        preferred = active_exit if active_exit in choices else choices[0]
        if Path(f"/sys/class/net/{preferred}").exists():
            run(["ip", "route", "replace", "default", "dev", preferred,
                 "table", str(table)])

    # client rules
    for cl in clients:
        if not cl["internet"]:
            continue
        if client_choices.get(cl["id"]):
            rules.append(
                (["from", cl["ip"], "iif", "awg0", "lookup", str(client_table(cl["id"]))],
                 CLIENT_PRIORITY)
            )
        else:
            rules.append(
                (["from", cl["ip"], "iif", "awg0", "lookup", str(internet_table)],
                 INTERNET_PRIORITY)
            )
    for link in links:
        cl = client_by_id.get(link["client_id"])
        ex = exit_by_id.get(link["exit_id"])
        if not cl or not ex or ex["mode"] != "routes":
            continue
        if not Path(f"/sys/class/net/{ex['iface']}").exists():
            continue
        table = routed_table(ex["id"])
        for cidr in [x.strip() for x in (ex["routes"] or "").split(",") if x.strip()]:
            rules.append(
                (["from", cl["ip"], "to", cidr, "iif", "awg0", "lookup", str(table)],
                 ROUTE_PRIORITY)
            )

    seen: set[tuple] = set()
    unique: list[tuple[list[str], int]] = []
    for spec, prio in rules:
        key = tuple(spec)
        if key in seen:
            continue
        seen.add(key)
        unique.append((spec, prio))

    for spec, prio in unique:
        run(["ip", "rule", "add"] + spec + ["priority", str(prio)])

    save_setting("routing_tables", json.dumps(sorted(tables)))
    return {"rules": len(unique), "tables": sorted(tables)}


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] != "apply":
        sys.exit("usage: routing.py [apply]")
    result = apply()
    print(f"rules: {result['rules']}, tables: {result['tables']}")


if __name__ == "__main__":
    main()
