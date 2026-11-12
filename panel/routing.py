#!/usr/bin/env python3
"""Applies client routing based on the panel database.

Internet clients without granted exits share table 100 (the active exit is
chosen by the failover daemon). Clients with granted internet exits get their
own table and a rule pointing at it, so the failover daemon can follow the
order the client chose. Clients with routed exits get
`from <ip> to <cidr> lookup <exit table>` rules with a higher priority, so
specific subnets always win over the default route.

Table numbers are allocated in the database and never computed from row ids:
ids are reused after a delete, and arithmetic ranges eventually collide.
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
# A client's own choice must win over the shared automatic table.
CLIENT_PRIORITY = 19000
# All routing tables we own live above the system ones: 201..264 overlaps the
# main/local tables (253..255) and once cut a host off the network.
TABLE_POOL_BASE = 1001
# These tables must never be flushed or allocated.
RESERVED_TABLES = {0, 100, 253, 254, 255}


def cfg() -> dict:
    return json.loads(CONFIG_PATH.read_text())


def rows(db: sqlite3.Connection, sql: str) -> list[dict]:
    return [dict(r) for r in db.execute(sql).fetchall()]


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def used_tables(conn: sqlite3.Connection) -> set[int]:
    """Table numbers already owned by exits or clients."""
    used: set[int] = set()
    for sql in (
        "SELECT table_num FROM exits WHERE table_num > 0",
        "SELECT table_num FROM clients WHERE table_num > 0",
    ):
        used |= {r[0] for r in conn.execute(sql)}
    return used


def allocate_table(conn: sqlite3.Connection) -> int:
    """Lowest free table number from the shared pool."""
    used = used_tables(conn)
    number = TABLE_POOL_BASE
    while number in used or number in RESERVED_TABLES:
        number += 1
    return number


def tables_to_flush(current: set[int], previous: set[int]) -> list[int]:
    """Tables to flush: everything we used now or before, never reserved ones."""
    return sorted(
        t for t in (current | previous)
        if t >= TABLE_POOL_BASE and t not in RESERVED_TABLES
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


def _is_missing(error: str) -> bool:
    text = error.lower()
    return (
        "no such file" in text
        or "no such process" in text
        or "fib table does not exist" in text
        or "file exists" in text
    )


def cleanup_rules(internet_table: int, errors: list[str]) -> None:
    """Removes all rules of ours, no matter who installed them.

    This cleans up leftovers from older versions (the rule for the whole
    client subnet) and does not care whether the panel or the unit applied
    the routing.
    """
    res = run(["ip", "rule", "show"])
    if res.returncode != 0:
        errors.append(f"ip rule show: {res.stderr.strip()}")
        return
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
        if value == internet_table or value >= TABLE_POOL_BASE:
            result = run(["ip", "rule", "del"] + spec)
            if result.returncode != 0:
                errors.append(f"ip rule del {' '.join(spec)}: {result.stderr.strip()}")


def apply() -> dict:
    c = cfg()
    internet_table = int(c.get("route_table", 100))
    errors: list[str] = []
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
    finally:
        db.close()

    client_choices: dict[int, list[str]] = {}
    for grant in grants:
        client_choices.setdefault(grant["client_id"], []).append(grant["iface"])

    cleanup_rules(internet_table, errors)

    # The set of tables we own is persisted, so tables of deleted objects are
    # flushed even though they are no longer in the database.
    current_tables = {
        ex["table_num"] for ex in exits
        if ex["mode"] == "routes" and ex["table_num"] > 0
        and Path(f"/sys/class/net/{ex['iface']}").exists()
    }
    current_tables |= {
        cl["table_num"] for cl in clients
        if cl["internet"] and cl["table_num"] > 0 and client_choices.get(cl["id"])
    }
    raw_previous = get_setting("routing_tables")
    if raw_previous:
        try:
            previous_tables = {int(x) for x in json.loads(raw_previous)}
        except (ValueError, TypeError):
            previous_tables = set()
    else:
        # First run on an existing database: clean the legacy ranges too.
        previous_tables = set(range(1001, 3065))
    for table in tables_to_flush(current_tables, previous_tables):
        result = run(["ip", "route", "flush", "table", str(table)])
        if result.returncode != 0 and not _is_missing(result.stderr):
            errors.append(f"ip route flush table {table}: {result.stderr.strip()}")

    tables: set[int] = set()
    rules: list[tuple[list[str], int]] = []

    # routes of routed exits
    for ex in exits:
        if ex["mode"] != "routes" or ex["table_num"] <= 0:
            continue
        if not Path(f"/sys/class/net/{ex['iface']}").exists():
            continue
        table = ex["table_num"]
        tables.add(table)
        for cidr in [x.strip() for x in (ex["routes"] or "").split(",") if x.strip()]:
            result = run(["ip", "route", "replace", cidr, "dev", ex["iface"],
                          "table", str(table)])
            if result.returncode != 0:
                errors.append(
                    f"ip route replace {cidr} table {table}: {result.stderr.strip()}"
                )

    # clients with granted internet exits get their own table; the failover
    # daemon keeps its default route on the first exit that is alive
    try:
        active_exit = Path("/run/kaskad/active-exit").read_text().strip()
    except OSError:
        active_exit = ""
    for cl in clients:
        choices = client_choices.get(cl["id"]) if cl["internet"] else None
        if not choices or cl["table_num"] <= 0:
            continue
        table = cl["table_num"]
        tables.add(table)
        preferred = active_exit if active_exit in choices else choices[0]
        if Path(f"/sys/class/net/{preferred}").exists():
            result = run(["ip", "route", "replace", "default", "dev", preferred,
                          "table", str(table)])
            if result.returncode != 0:
                errors.append(
                    f"ip route replace default dev {preferred} table {table}: "
                    f"{result.stderr.strip()}"
                )

    # client rules
    for cl in clients:
        if not cl["internet"]:
            continue
        if client_choices.get(cl["id"]) and cl["table_num"] > 0:
            rules.append(
                (["from", cl["ip"], "iif", "awg0", "lookup", str(cl["table_num"])],
                 CLIENT_PRIORITY)
            )
        else:
            rules.append(
                (["from", cl["ip"], "iif", "awg0", "lookup", str(internet_table)],
                 INTERNET_PRIORITY)
            )
    for link in links:
        cl = next((x for x in clients if x["id"] == link["client_id"]), None)
        ex = next((x for x in exits if x["id"] == link["exit_id"]), None)
        if not cl or not ex or ex["mode"] != "routes" or ex["table_num"] <= 0:
            continue
        if not Path(f"/sys/class/net/{ex['iface']}").exists():
            continue
        table = ex["table_num"]
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

    applied = 0
    for spec, prio in unique:
        result = run(["ip", "rule", "add"] + spec + ["priority", str(prio)])
        if result.returncode != 0:
            errors.append(f"ip rule add {' '.join(spec)}: {result.stderr.strip()}")
        else:
            applied += 1

    save_setting("routing_tables", json.dumps(sorted(tables)))
    return {"rules": applied, "tables": sorted(tables), "errors": errors}


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] != "apply":
        sys.exit("usage: routing.py [apply]")
    result = apply()
    print(f"rules: {result['rules']}, tables: {result['tables']}")
    for error in result["errors"]:
        print(f"error: {error}", file=sys.stderr)
    if result["errors"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
