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

The apply is a diff: the desired state is compared with the kernel, and only
the difference is executed. Tables and rules that stay in use are never
recreated, so a panel change does not interrupt unrelated clients.
"""
from __future__ import annotations

import ipaddress
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

Rule = tuple[int, tuple[str, ...]]  # (priority, spec tokens)
Route = tuple[str, str]  # (prefix, dev)


def cfg() -> dict:
    return json.loads(CONFIG_PATH.read_text())


def rows(db: sqlite3.Connection, sql: str) -> list[dict]:
    return [dict(r) for r in db.execute(sql).fetchall()]


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def used_tables(conn: sqlite3.Connection) -> set[int]:
    """Table numbers already owned by exits, clients or claimed allocations."""
    used: set[int] = set()
    for sql in (
        "SELECT table_num FROM exits WHERE table_num > 0",
        "SELECT table_num FROM clients WHERE table_num > 0",
        "SELECT table_num FROM table_numbers",
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


def claim_table(conn: sqlite3.Connection, kind: str, owner_id: int) -> int:
    """Reserves a number for one object in the same transaction.

    The registry has a PRIMARY KEY, so two concurrent creates cannot end up
    with the same number even when one is a client and the other an exit.
    """
    for _ in range(20):
        number = allocate_table(conn)
        try:
            conn.execute(
                "INSERT INTO table_numbers (table_num, kind, owner_id) "
                "VALUES (?, ?, ?)",
                (number, kind, owner_id),
            )
        except sqlite3.IntegrityError:
            continue
        return number
    raise RuntimeError("no free routing table number")


def release_table(conn: sqlite3.Connection, kind: str, owner_id: int) -> None:
    conn.execute(
        "DELETE FROM table_numbers WHERE kind = ? AND owner_id = ?",
        (kind, owner_id),
    )


def sync_registry(conn: sqlite3.Connection) -> None:
    """Rebuilds the registry and repairs duplicates across both object types."""
    conn.execute("DELETE FROM table_numbers")
    seen: set[int] = set()
    for table, kind in (("exits", "exit"), ("clients", "client")):
        for row in conn.execute(
            f"SELECT id, table_num FROM {table} WHERE table_num > 0 ORDER BY id"
        ).fetchall():
            owner_id, number = row[0], row[1]
            if number in seen:
                # A legacy client and exit can share a number; one of them
                # has to move before the registry can hold a single claim.
                old = number
                number = allocate_table(conn)
                conn.execute(
                    f"UPDATE {table} SET table_num = ? WHERE id = ?",
                    (number, owner_id),
                )
                print(
                    f"routing: {kind} {owner_id} moved from table {old} "
                    f"to {number}",
                    flush=True,
                )
            seen.add(number)
            conn.execute(
                "INSERT INTO table_numbers (table_num, kind, owner_id) "
                "VALUES (?, ?, ?)",
                (number, kind, owner_id),
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


def _owned_table(value: int, internet_table: int) -> bool:
    if value in RESERVED_TABLES:
        return value == internet_table
    return value == internet_table or value >= TABLE_POOL_BASE


def _norm_prefix(value: str) -> str:
    """How the kernel prints a prefix: no host bits, no /32 on addresses."""
    if value == "default":
        return value
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return value
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


def parse_rules(output: str, internet_table: int) -> set[Rule]:
    """Rules of ours from `ip rule show`, as (priority, spec tokens).

    A rule is ours when it has `iif awg0` and looks up the shared internet
    table or a pool table; the system tables are never touched.
    """
    rules: set[Rule] = set()
    for line in output.splitlines():
        head, sep, rest = line.partition(":")
        if not sep or not head.strip().isdigit():
            continue
        spec = tuple(rest.strip().split())
        if "iif" not in spec or "awg0" not in spec or "lookup" not in spec:
            continue
        if "to" in spec:
            at = spec.index("to") + 1
            spec = spec[:at] + (_norm_prefix(spec[at]),) + spec[at + 1:]
        idx = spec.index("lookup")
        if idx + 1 >= len(spec) or not spec[idx + 1].isdigit():
            continue
        if _owned_table(int(spec[idx + 1]), internet_table):
            rules.add((int(head.strip()), spec))
    return rules


def parse_routes(output: str) -> set[Route]:
    """Routes from `ip route show table N`, as (prefix, dev)."""
    routes: set[Route] = set()
    for line in output.splitlines():
        tokens = line.split()
        if len(tokens) >= 3 and tokens[1] == "dev":
            routes.add((_norm_prefix(tokens[0]), tokens[2]))
    return routes


def plan_changes(
    existing_rules: set[Rule],
    desired_rules: set[Rule],
    existing_routes: dict[int, set[Route]],
    desired_routes: dict[int, set[Route]],
    flush_candidates: set[int],
) -> dict:
    """Pure diff between the kernel state and the desired state.

    A table that stays in use is never flushed: its extra routes are removed
    one by one and the missing ones are replaced. Only tables nobody needs
    any more are flushed whole.
    """
    plan = {
        "rules_del": sorted(existing_rules - desired_rules),
        "rules_add": sorted(desired_rules - existing_rules),
        "tables_flush": [],
        "routes_del": [],
        "routes_add": [],
    }
    orphan = set(existing_routes) | flush_candidates
    plan["tables_flush"] = sorted(
        t for t in orphan - set(desired_routes)
        if t >= TABLE_POOL_BASE and t not in RESERVED_TABLES
    )
    for table in sorted(desired_routes):
        wanted = desired_routes[table]
        have = existing_routes.get(table, set())
        for route in sorted(have - wanted):
            plan["routes_del"].append((table,) + route)
        for route in sorted(wanted - have):
            plan["routes_add"].append((table,) + route)
    return plan


def execute_plan(plan: dict, errors: list[str]) -> int:
    """Runs the diff and returns the number of applied changes.

    Rules go first: a stale rule must stop matching before its table is
    flushed, otherwise traffic briefly falls through to the main table.
    """
    changes = 0
    for prio, spec in plan["rules_del"]:
        result = run(["ip", "rule", "del"] + list(spec) + ["priority", str(prio)])
        if result.returncode != 0 and not _is_missing(result.stderr):
            errors.append(f"ip rule del {' '.join(spec)}: {result.stderr.strip()}")
        else:
            changes += 1
    for table in plan["tables_flush"]:
        result = run(["ip", "route", "flush", "table", str(table)])
        if result.returncode != 0 and not _is_missing(result.stderr):
            errors.append(f"ip route flush table {table}: {result.stderr.strip()}")
        else:
            changes += 1
    for table, prefix, dev in plan["routes_del"]:
        result = run(["ip", "route", "del", prefix, "dev", dev, "table", str(table)])
        if result.returncode != 0 and not _is_missing(result.stderr):
            errors.append(
                f"ip route del {prefix} dev {dev} table {table}: "
                f"{result.stderr.strip()}"
            )
        else:
            changes += 1
    for table, prefix, dev in plan["routes_add"]:
        result = run(["ip", "route", "replace", prefix, "dev", dev, "table", str(table)])
        if result.returncode != 0:
            errors.append(
                f"ip route replace {prefix} dev {dev} table {table}: "
                f"{result.stderr.strip()}"
            )
        else:
            changes += 1
    for prio, spec in plan["rules_add"]:
        result = run(["ip", "rule", "add"] + list(spec) + ["priority", str(prio)])
        if result.returncode != 0:
            errors.append(f"ip rule add {' '.join(spec)}: {result.stderr.strip()}")
        else:
            changes += 1
    return changes


def desired_state() -> tuple[set[Rule], dict[int, set[Route]], dict[int, list[str]], int]:
    """The routing state the panel wants, from the database.

    Client tables are returned separately as {table: choices}: which exit the
    table points at is decided by apply(), because the failover daemon owns
    that choice and a kept route must not be fought over.
    """
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
    finally:
        db.close()

    client_choices: dict[int, list[str]] = {}
    for grant in grants:
        client_choices.setdefault(grant["client_id"], []).append(grant["iface"])

    routes: dict[int, set[Route]] = {}

    # routes of routed exits
    for ex in exits:
        if ex["mode"] != "routes" or ex["table_num"] <= 0:
            continue
        if not Path(f"/sys/class/net/{ex['iface']}").exists():
            continue
        table = ex["table_num"]
        for cidr in [x.strip() for x in (ex["routes"] or "").split(",") if x.strip()]:
            routes.setdefault(table, set()).add((_norm_prefix(cidr), ex["iface"]))

    # clients with granted internet exits get their own table; the failover
    # daemon keeps its default route on the first exit that is alive
    client_tables: dict[int, list[str]] = {}
    for cl in clients:
        choices = client_choices.get(cl["id"]) if cl["internet"] else None
        if choices and cl["table_num"] > 0:
            client_tables[cl["table_num"]] = choices

    # client rules
    rules: set[Rule] = set()
    for cl in clients:
        if not cl["internet"]:
            continue
        if client_choices.get(cl["id"]) and cl["table_num"] > 0:
            rules.add(
                (CLIENT_PRIORITY,
                 ("from", cl["ip"], "iif", "awg0", "lookup", str(cl["table_num"])))
            )
        else:
            rules.add(
                (INTERNET_PRIORITY,
                 ("from", cl["ip"], "iif", "awg0", "lookup", str(internet_table)))
            )
    for link in links:
        cl = next((x for x in clients if x["id"] == link["client_id"]), None)
        ex = next((x for x in exits if x["id"] == link["exit_id"]), None)
        if not cl or not ex or ex["mode"] != "routes" or ex["table_num"] <= 0:
            continue
        if not Path(f"/sys/class/net/{ex['iface']}").exists():
            continue
        for cidr in [x.strip() for x in (ex["routes"] or "").split(",") if x.strip()]:
            rules.add(
                (ROUTE_PRIORITY,
                 ("from", cl["ip"], "to", _norm_prefix(cidr), "iif", "awg0",
                  "lookup", str(ex["table_num"])))
            )
    return rules, routes, client_tables, internet_table


def apply() -> dict:
    errors: list[str] = []
    desired_rules, desired_routes, client_tables, internet_table = desired_state()

    res = run(["ip", "rule", "show"])
    if res.returncode != 0:
        errors.append(f"ip rule show: {res.stderr.strip()}")
        existing_rules: set[Rule] = set()
    else:
        existing_rules = parse_rules(res.stdout or "", internet_table)

    # Only desired tables need reading: anything else is flushed whole.
    read_tables = set(desired_routes) | set(client_tables)
    existing_routes: dict[int, set[Route]] = {}
    for table in sorted(read_tables):
        res = run(["ip", "route", "show", "table", str(table)])
        if res.returncode != 0:
            if not _is_missing(res.stderr):
                errors.append(f"ip route show table {table}: {res.stderr.strip()}")
            continue
        routes = parse_routes(res.stdout or "")
        if routes:
            existing_routes[table] = routes

    # The failover daemon owns the exit choice of a client table: keep the
    # route that is already there while it points at a granted exit, so an
    # apply does not fight the daemon over a working client.
    try:
        active_exit = Path("/run/kaskad/active-exit").read_text().strip()
    except OSError:
        active_exit = ""
    for table, choices in client_tables.items():
        current = next(
            (dev for prefix, dev in existing_routes.get(table, set())
             if prefix == "default"),
            None,
        )
        if current in choices:
            preferred = current
        else:
            preferred = active_exit if active_exit in choices else choices[0]
        if Path(f"/sys/class/net/{preferred}").exists():
            desired_routes.setdefault(table, set()).add(("default", preferred))

    # The set of tables we own is persisted, so tables of deleted objects are
    # flushed even though they are no longer in the database.
    raw_previous = get_setting("routing_tables")
    flush_candidates: set[int] = set()
    if raw_previous:
        try:
            flush_candidates = {int(x) for x in json.loads(raw_previous)}
        except (ValueError, TypeError):
            flush_candidates = set()
    else:
        # First run on an existing database: clean the legacy ranges too.
        flush_candidates = set(range(TABLE_POOL_BASE, 3065))
    # Tables referenced by leftover rules are orphans as well.
    flush_candidates |= {
        int(spec[spec.index("lookup") + 1])
        for _, spec in existing_rules
        if int(spec[spec.index("lookup") + 1]) >= TABLE_POOL_BASE
    }

    plan = plan_changes(
        existing_rules, desired_rules, existing_routes, desired_routes,
        flush_candidates,
    )
    changes = execute_plan(plan, errors)

    save_setting("routing_tables", json.dumps(sorted(desired_routes)))
    return {
        "rules": len(desired_rules),
        "tables": sorted(desired_routes),
        "changes": changes,
        "errors": errors,
    }


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] != "apply":
        sys.exit("usage: routing.py [apply]")
    result = apply()
    print(
        f"rules: {result['rules']}, tables: {result['tables']}, "
        f"changes: {result['changes']}"
    )
    for error in result["errors"]:
        print(f"error: {error}", file=sys.stderr)
    if result["errors"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
