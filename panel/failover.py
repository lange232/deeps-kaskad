#!/usr/bin/env python3
"""Failover for exit gateways.

Every INTERVAL seconds each enabled exit is probed through its interface,
the first alive one by priority becomes active and the client route follows.

Strict priority: the best alive exit is always active. Returning to a higher
priority exit only happens after FAILBACK_STABLE seconds of stable operation,
so an unstable link does not cause flapping.

Manual switch: the panel writes an interface name to
/run/kaskad/requested-exit and the daemon applies it if the exit is enabled
and alive.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("KASKAD_CONFIG", "/etc/kaskad/panel.json"))
DB_PATH = Path(os.environ.get("KASKAD_DB", "/var/lib/kaskad/panel.db"))
RUN_DIR = Path("/run/kaskad")
ACTIVE_FILE = RUN_DIR / "active-exit"
REQUEST_FILE = RUN_DIR / "requested-exit"
STATUS_FILE = RUN_DIR / "status.json"

INTERVAL = 10
DEAD_AFTER = 3
ALIVE_AFTER = 2
FAILBACK_STABLE = 60
PROBE_TARGET = "1.1.1.1"

state: dict[str, dict] = {}


def log(msg: str) -> None:
    print(f"{datetime.now(timezone.utc).strftime('%H:%M:%S')} {msg}", flush=True)


def cfg() -> dict:
    return json.loads(CONFIG_PATH.read_text())


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


def run(cmd: list[str], timeout: int = 5) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def iface_exists(iface: str) -> bool:
    return Path(f"/sys/class/net/{iface}").exists()


def probe(exit: dict) -> bool:
    iface = exit["iface"]
    if not iface_exists(iface):
        return False
    if exit.get("mode") == "routes":
        # A routed exit only allows its own subnets in AllowedIPs, so pinging
        # 1.1.1.1 is pointless: it is alive as long as its handshake is fresh.
        res = run(["awg", "show", iface, "latest-handshakes"])
        if res.returncode != 0:
            return False
        now = time.time()
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[-1].isdigit():
                if now - int(parts[-1]) < 180:
                    return True
        return False
    try:
        return run(["ping", "-c1", "-W2", "-I", iface, PROBE_TARGET], timeout=4).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def read_active() -> str | None:
    try:
        return ACTIVE_FILE.read_text().strip() or None
    except OSError:
        return None


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


def update_state(exit: dict, ok: bool) -> None:
    iface = exit["iface"]
    st = state.setdefault(iface, {"fails": 0, "oks": 0, "alive": False, "alive_since": 0, "last_ok": 0})
    if ok:
        st["fails"] = 0
        st["oks"] += 1
        st["last_ok"] = int(time.time())
        if not st["alive"] and st["oks"] >= ALIVE_AFTER:
            st["alive"] = True
            st["alive_since"] = int(time.time())
    else:
        st["oks"] = 0
        st["fails"] += 1
        if st["alive"] and st["fails"] >= DEAD_AFTER:
            st["alive"] = False
            st["alive_since"] = 0


def write_status(active: str | None, rows: list[dict]) -> None:
    payload = {
        "ts": int(time.time()),
        "active": active,
        "exits": {
            e["iface"]: {
                "name": e["name"],
                "enabled": bool(e["enabled"]),
                "mode": e.get("mode", "internet"),
                "priority": e["priority"],
                "alive": state.get(e["iface"], {}).get("alive", False),
                "last_ok": state.get(e["iface"], {}).get("last_ok", 0),
                "alive_since": state.get(e["iface"], {}).get("alive_since", 0),
            }
            for e in rows
        },
    }
    write_atomic(STATUS_FILE, json.dumps(payload))


def tick(c: dict) -> None:
    rows = exits()
    for e in rows:
        if e["enabled"]:
            update_state(e, probe(e))

    alive = [
        e for e in rows
        if e["enabled"] and e.get("mode") == "internet" and state.get(e["iface"], {}).get("alive")
    ]
    active = read_active()

    desired = alive[0]["iface"] if alive else None

    # A manual request wins over automation when the exit is alive.
    requested = ""
    try:
        requested = REQUEST_FILE.read_text().strip()
    except OSError:
        pass
    if requested:
        try:
            REQUEST_FILE.unlink()
        except OSError:
            pass
        match = next((e for e in alive if e["iface"] == requested), None)
        if match:
            desired = match["iface"]
            log(f"manual switch to {desired}")
        elif requested:
            log(f"manual request {requested} rejected: not enabled or not alive")

    if desired and desired != active:
        active_row = next((e for e in rows if e["iface"] == active), None)
        active_ok = bool(active_row and active_row["enabled"] and state.get(active, {}).get("alive"))
        if not active_ok:
            switch(desired, c)
        else:
            since = state.get(desired, {}).get("alive_since", 0)
            if since and int(time.time()) - since >= FAILBACK_STABLE:
                log(f"failing back to {desired}")
                switch(desired, c)

    write_status(read_active(), rows)


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
