#!/usr/bin/env python3
"""Applies client routing based on the panel database.

Internet clients get a per-client rule pointing at table 100 (the active exit
is chosen by the failover daemon). Clients with routed exits get
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
        if int(table) in RESERVED_TABLES and int(table) != internet_table:
            continue
        if int(table) == internet_table or ROUTED_TABLE_BASE < int(table) <= ROUTED_TABLE_BASE + 64:
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
        client_by_id = {cl["id"]: cl for cl in clients}
        exit_by_id = {ex["id"]: ex for ex in exits}
    finally:
        db.close()

    cleanup_rules(internet_table)
    # Rebuild routed exit tables from scratch; flushing extra ones is harmless.
    for table in range(ROUTED_TABLE_BASE + 1, ROUTED_TABLE_BASE + 65):
        if table in RESERVED_TABLES:
            continue
        run(["ip", "route", "flush", "table", str(table)])

    tables: set[int] = set()
    rules: list[list[str]] = []

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

    # client rules
    for cl in clients:
        if cl["internet"]:
            rules.append(["from", cl["ip"], "iif", "awg0", "lookup", str(internet_table)])
    for link in links:
        cl = client_by_id.get(link["client_id"])
        ex = exit_by_id.get(link["exit_id"])
        if not cl or not ex or ex["mode"] != "routes":
            continue
        if not Path(f"/sys/class/net/{ex['iface']}").exists():
            continue
        table = routed_table(ex["id"])
        for cidr in [x.strip() for x in (ex["routes"] or "").split(",") if x.strip()]:
            rules.append(["from", cl["ip"], "to", cidr, "iif", "awg0", "lookup", str(table)])

    seen: set[tuple] = set()
    unique: list[list[str]] = []
    for rule in rules:
        key = tuple(rule)
        if key in seen:
            continue
        seen.add(key)
        unique.append(rule)

    for rule in unique:
        prio = ROUTE_PRIORITY if "to" in rule else INTERNET_PRIORITY
        run(["ip", "rule", "add"] + rule + ["priority", str(prio)])

    return {"rules": len(unique), "tables": sorted(tables)}


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] != "apply":
        sys.exit("usage: routing.py [apply]")
    result = apply()
    print(f"rules: {result['rules']}, tables: {result['tables']}")


if __name__ == "__main__":
    main()
