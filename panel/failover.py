#!/usr/bin/env python3
"""Failover for exit gateways.

Every INTERVAL seconds each enabled exit is probed through its interface,
the first alive one by priority becomes active and the client route follows.

Strict priority: the best alive exit is always active. Returning to a higher
priority exit only happens after FAILBACK_STABLE seconds of stable operation,
so an unstable link does not cause flapping.

Manual switch: the panel stores an interface name in the settings table and
the daemon keeps that exit active while it is enabled and alive. Clearing the
value returns to automatic selection.

Per-client exits: the administrator grants a set of internet exits to a
client and the client orders them. Every tick each such client gets a default
route in its own table pointing at the first granted exit that is alive. If
none of them is alive the route is removed and that client has no internet.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import routing


CONFIG_PATH = Path(os.environ.get("KASKAD_CONFIG", "/etc/kaskad/panel.json"))
DB_PATH = Path(os.environ.get("KASKAD_DB", "/var/lib/kaskad/panel.db"))
RUN_DIR = Path("/run/kaskad")
ACTIVE_FILE = RUN_DIR / "active-exit"
STATUS_FILE = RUN_DIR / "status.json"
MANUAL_KEY = "manual_exit"

INTERVAL = 10
DEAD_AFTER = 3
ALIVE_AFTER = 2
FAILBACK_STABLE = 60
PROBE_TARGET = "1.1.1.1"
RTT_RE = re.compile(r"time=([0-9.]+)\s*ms")

state: dict[str, dict] = {}
# Tunnels that were present on the previous tick. A change means old routes
# may be stale and new ones were never created: routing is re-applied then,
# because kaskad-routing.service only runs once at boot and cannot know that
# an exit came up later.
known_ifaces: set[str] | None = None
routing_pending = False
routing_retry_at = 0.0
routing_backoff = 10
routing_last_error = ""


def log(msg: str) -> None:
    print(f"{datetime.now(timezone.utc).strftime('%H:%M:%S')} {msg}", flush=True)


def cfg() -> dict:
    return json.loads(CONFIG_PATH.read_text())


def get_setting(key: str) -> str:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else ""
    finally:
        conn.close()


def set_setting(key: str, value: str) -> None:
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


def exits() -> list[dict]:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT id, name, iface, priority, enabled, mode FROM exits ORDER BY priority, id"
            ).fetchall()
        ]
    finally:
        conn.close()


def client_grants() -> list[dict]:
    """Granted internet exits, ordered by the client's own priority."""
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT ce.client_id, ce.priority AS choice, c.ip, "
                "c.table_num AS client_table, e.iface "
                "FROM client_internet_exits ce "
                "JOIN clients c ON c.id = ce.client_id "
                "AND c.enabled = 1 AND c.internet = 1 "
                "JOIN exits e ON e.id = ce.exit_id "
                "AND e.enabled = 1 AND e.mode = 'internet' "
                "ORDER BY ce.client_id, ce.priority, e.priority, e.id"
            ).fetchall()
        ]
    finally:
        conn.close()


def pick_client_exit(choices: list[str], alive) -> str | None:
    """First granted exit that is alive, or None when all are down."""
    for iface in choices:
        if iface in alive:
            return iface
    return None


def current_default(table: int) -> str | None:
    res = run(["ip", "route", "show", "default", "table", str(table)])
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    return None


def apply_client_routes(choices: dict[tuple[int, str], list[str]], alive) -> dict[str, str]:
    """Points each client table at its first alive granted exit.

    The reported mapping comes from the routing table after the change, so a
    failed `ip route` never shows up as a working exit.
    """
    used: dict[str, str] = {}
    for (table, ip), order in choices.items():
        if table <= 0:
            log(f"client {ip}: no routing table allocated")
            continue
        desired = pick_client_exit(order, alive)
        before = current_default(table)
        # When nothing is alive the old route is left in place: it points at
        # a dead exit, so traffic already fails, and a daemon restart does
        # not cut a working client for the two probe rounds it needs.
        if desired and desired != before:
            res = run(["ip", "route", "replace", "default", "dev", desired,
                       "table", str(table)])
            if res.returncode != 0:
                log(f"client {ip}: failed to route via {desired}: "
                    f"{res.stderr.strip()}")
        after = current_default(table)
        if after in alive:
            used[ip] = after
        if after != before:
            # Stale conntrack entries keep the source address of the old exit.
            run(["conntrack", "-D", "-s", f"{ip}/32"], timeout=5)
            log(f"client {ip}: exit {after}")
        if desired and after != desired:
            log(f"client {ip}: wanted {desired}, table {table} has "
                f"{after or 'no default'}")
    return used


def run(cmd: list[str], timeout: int = 5) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def iface_exists(iface: str) -> bool:
    return Path(f"/sys/class/net/{iface}").exists()


def awg_ifaces() -> set[str]:
    try:
        return {p.name for p in Path("/sys/class/net").glob("awg*") if p.is_dir()}
    except OSError:
        return set()


def sync_routing(c: dict) -> None:
    """Re-applies routing when tunnels appeared or disappeared."""
    global known_ifaces, routing_pending, routing_retry_at
    global routing_backoff, routing_last_error
    current = awg_ifaces()
    if known_ifaces is None:
        # The routing unit runs once at boot and may have failed or raced
        # with the exits; a first sync costs one diff and fixes that.
        log(f"initial routing sync: {sorted(current)}")
        routing_pending = True
        routing_retry_at = 0.0
    elif known_ifaces != current:
        appeared = sorted(current - known_ifaces)
        vanished = sorted(known_ifaces - current)
        log(f"interfaces changed: +{appeared or '-'} -{vanished or '-'}")
        routing_pending = True
        routing_retry_at = 0.0
        routing_backoff = 10
    known_ifaces = current
    if not routing_pending or time.time() < routing_retry_at:
        return
    # awg-quick creates the interface before it finishes configuring it, so
    # give it a moment.
    time.sleep(1)
    result = routing.apply()
    errors = result.get("errors", [])
    if errors:
        message = "; ".join(errors)
        if message != routing_last_error:
            # A permanent error must not flood the journal every tick.
            log(f"routing: {message}")
            routing_last_error = message
        routing_backoff = min(max(routing_backoff * 2, 10), 300)
        routing_retry_at = time.time() + routing_backoff
        routing_pending = True
        return
    routing_backoff = 10
    routing_last_error = ""
    routing_pending = False
    log(f"routing re-applied: tables {result.get('tables')}")


def ping_rtt(stdout: str) -> float | None:
    """Round-trip time from ping output, in milliseconds."""
    match = RTT_RE.search(stdout or "")
    return float(match.group(1)) if match else None


def probe(exit: dict) -> tuple[bool, float | None]:
    """(alive, rtt_ms); routed exits have no ICMP latency."""
    iface = exit["iface"]
    if not iface_exists(iface):
        return False, None
    if exit.get("mode") == "routes":
        # A routed exit only allows its own subnets in AllowedIPs, so pinging
        # 1.1.1.1 is pointless: it is alive as long as its handshake is fresh.
        res = run(["awg", "show", iface, "latest-handshakes"])
        if res.returncode != 0:
            return False, None
        now = time.time()
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[-1].isdigit():
                if now - int(parts[-1]) < 180:
                    return True, None
        return False, None
    try:
        res = run(["ping", "-c1", "-W2", "-I", iface, PROBE_TARGET], timeout=4)
    except subprocess.TimeoutExpired:
        return False, None
    if res.returncode != 0:
        return False, None
    return True, ping_rtt(res.stdout)


def client_rows() -> list[dict]:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        return [
            dict(r)
            for r in conn.execute("SELECT ip FROM clients WHERE enabled = 1")
        ]
    finally:
        conn.close()


def probe_client(ip: str) -> float | None:
    """Round-trip from S1 to a client through awg0; None when it does not answer."""
    if not iface_exists("awg0"):
        return None
    try:
        res = run(["ping", "-c1", "-W1", "-I", "awg0", ip], timeout=3)
    except subprocess.TimeoutExpired:
        return None
    if res.returncode != 0:
        return None
    return ping_rtt(res.stdout)


def client_pings() -> dict[str, float | None]:
    ips = [row["ip"] for row in client_rows()]
    if not ips:
        return {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(probe_client, ips))
    return {
        ip: (round(rtt) if rtt is not None else None)
        for ip, rtt in zip(ips, values)
    }


def read_active() -> str | None:
    try:
        value = ACTIVE_FILE.read_text().strip()
    except OSError:
        return None
    # "none" is an explicit "no exit is alive" marker, not an interface.
    return value if value and value != "none" else None


def should_clear_active(desired, active) -> bool:
    """The file is stale when nothing is alive but it still names an exit."""
    return desired is None and bool(active) and active != "none"


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(text)
    tmp.replace(path)


def switch(iface: str, c: dict) -> None:
    result = run(["ip", "route", "replace", "default", "dev", iface, "table", str(c["route_table"])])
    if result.returncode != 0:
        log(f"failed to switch the route to {iface}: {result.stderr.strip()}")
        return
    write_atomic(ACTIVE_FILE, iface + "\n")
    # Stale conntrack entries keep the NAT of the previous exit, so packets
    # leave through the new interface with the wrong source address. Drop
    # the client flows.
    run(["conntrack", "-D", "-s", c["clients_net"]], timeout=5)
    log(f"active exit: {iface}")


def update_state(exit: dict, ok: bool, rtt: float | None = None) -> None:
    iface = exit["iface"]
    st = state.setdefault(
        iface,
        {"fails": 0, "oks": 0, "alive": False, "alive_since": 0,
         "last_ok": 0, "rtt_ms": None, "rtt_ts": 0},
    )
    if ok:
        st["fails"] = 0
        st["oks"] += 1
        st["last_ok"] = int(time.time())
        if rtt is not None:
            st["rtt_ms"] = round(rtt)
            st["rtt_ts"] = int(time.time())
        if not st["alive"] and st["oks"] >= ALIVE_AFTER:
            st["alive"] = True
            st["alive_since"] = int(time.time())
    else:
        st["oks"] = 0
        st["fails"] += 1
        if st["alive"] and st["fails"] >= DEAD_AFTER:
            st["alive"] = False
            st["alive_since"] = 0


def write_status(active, rows: list[dict], manual: str = "", clients=None,
                 client_ping=None) -> None:
    payload = {
        "ts": int(time.time()),
        "active": active,
        "manual": manual,
        "clients": clients or {},
        "client_ping": client_ping or {},
        "exits": {
            e["iface"]: {
                "name": e["name"],
                "enabled": bool(e["enabled"]),
                "mode": e.get("mode", "internet"),
                "priority": e["priority"],
                "alive": state.get(e["iface"], {}).get("alive", False),
                "last_ok": state.get(e["iface"], {}).get("last_ok", 0),
                "alive_since": state.get(e["iface"], {}).get("alive_since", 0),
                "rtt_ms": state.get(e["iface"], {}).get("rtt_ms"),
                "rtt_ts": state.get(e["iface"], {}).get("rtt_ts", 0),
            }
            for e in rows
        },
    }
    write_atomic(STATUS_FILE, json.dumps(payload))


def choose(active, alive, manual, alive_since, now, stable):
    """Pick the active exit.

    alive is a list of interfaces sorted by priority. A manual choice is
    sticky while that exit is alive; if it died the caller is told to clear
    it. Automatic selection keeps the current exit until a higher priority
    one has been stable for `stable` seconds.
    """
    if manual:
        if manual in alive:
            return manual, False
        return _auto(active, alive, alive_since, now, stable), True
    return _auto(active, alive, alive_since, now, stable), False


def _auto(active, alive, alive_since, now, stable):
    if not alive:
        return None
    best = alive[0]
    if best == active:
        return best
    if active not in alive:
        return best
    since = alive_since.get(best, 0)
    if since and now - since >= stable:
        return best
    return active


def tick(c: dict) -> None:
    rows = exits()
    for e in rows:
        if e["enabled"]:
            ok, rtt = probe(e)
            update_state(e, ok, rtt)

    # Exits can come up after kaskad-routing.service already ran; only this
    # loop notices, so it re-applies the tables and rules.
    sync_routing(c)

    alive_rows = [
        e for e in rows
        if e["enabled"] and e.get("mode") == "internet" and state.get(e["iface"], {}).get("alive")
    ]
    alive = [e["iface"] for e in alive_rows]
    active = read_active()
    manual = get_setting(MANUAL_KEY)
    alive_since = {
        e["iface"]: state.get(e["iface"], {}).get("alive_since", 0) for e in alive_rows
    }

    desired, clear_manual = choose(
        active, alive, manual, alive_since, int(time.time()), FAILBACK_STABLE
    )
    if clear_manual:
        set_setting(MANUAL_KEY, "")
        log(f"manual exit {manual} is down, back to automatic")
        manual = ""
    # The active-exit file outlives a service restart, so repairing the route
    # is not optional: after a reboot or a manual flush the table can be
    # empty while the file still names the right exit.
    if desired and (desired != active or current_default(c["route_table"]) != desired):
        log(f"switching to {desired}")
        switch(desired, c)
    elif should_clear_active(desired, active):
        # The panel must not show a dead exit as active.
        write_atomic(ACTIVE_FILE, "none\n")
        log(f"no alive internet exit: {active} is no longer active")

    choices: dict[tuple[int, str], list[str]] = {}
    for grant in client_grants():
        key = (grant["client_table"], grant["ip"])
        choices.setdefault(key, []).append(grant["iface"])
    client_routes = apply_client_routes(choices, alive)

    pings = client_pings()
    write_status(read_active(), rows, manual, client_routes, client_ping=pings)


def main() -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    c = cfg()
    log(f"start: interval {INTERVAL}s, dead after {DEAD_AFTER}, failback after {FAILBACK_STABLE}s")
    while True:
        try:
            tick(c)
        except Exception as exc:  # the daemon must survive a single bad cycle
            log(f"cycle error: {exc}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
