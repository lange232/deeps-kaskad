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

import ipaddress
import json
import os
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

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
# An exit can answer ICMP and still be unusable for some destinations. The
# probes below cover several networks and both ICMP and TCP; a few bad rounds
# make the exit "degraded", so clients move to a healthy one without waiting
# for it to go completely dead.
DEGRADED_AFTER = 3
RECOVER_AFTER = 3
PROBE_TARGET = "1.1.1.1"
# A TCP handshake is the cheapest thing a browser needs; ICMP is only a
# fallback for networks that answer it and filter TCP nowhere.
PROBE_TCP = ("1.1.1.1", 443)
# Three targets in three networks: one unreachable site is visible in the
# diagnosis but does not condemn the exit on its own.
PROBE_HTTP = (
    ("http://connectivitycheck.gstatic.com/generate_204", 204),
    ("http://example.com/", 200),
    ("http://captive.apple.com/hotspot-detect.html", 200),
)
MIN_HEALTHY_TARGETS = 2
# Probing is asynchronous: a probe that outlives the interval keeps running
# and its result is applied when it lands, instead of being dropped and
# started again. The caps keep the queues finite.
CHECK_MAX_INFLIGHT = 8
HTTP_TIMEOUT = 4
# Hostnames are resolved through the exit, exactly as a client does: the
# answer is picked for the exit's network, not for the server's.
DNS_TIMEOUT = 3
DNS_CACHE_SECONDS = 300
# Extra targets are per account: a destination that matters to one user must
# not mark an exit bad for everybody.
CHECK_DEAD_AFTER = 3
CHECK_RECOVER = 3
CHECK_TIMEOUT = 5
# Account checks are advisory: they tune per-account routing but must never
# push the global failover cycle past its ten-second interval. Each tick
# probes a few accounts in turn, so every account is still covered, just not
# on every round when many accounts keep checks.
CHECK_ACCOUNTS_PER_TICK = 4
RTT_RE = re.compile(r"time=([0-9.]+)\s*ms")

probe_pool = ThreadPoolExecutor(max_workers=8)
check_pool = ThreadPoolExecutor(max_workers=CHECK_MAX_INFLIGHT)
# Probe in flight -> the exit it describes. A probe is never started twice for
# the same exit: the result of the running one is applied when it finishes.
probe_inflight: dict = {}
# Account check in flight -> (check id, target, exit). Same rule: one run per
# target and exit, and every finished run is applied, even a slow one.
check_inflight: dict = {}
# Client ip -> the pinned exit it is staying on while degraded. Only a change
# is logged, otherwise a long outage writes a line every tick.
pinned_degraded: dict[str, str] = {}
state: dict[str, dict] = {}
# Last per-target results of every exit, for the panel's diagnosis.
probe_targets: dict[str, dict[str, bool]] = {}
# (iface, host) -> (expires at, addresses)
dns_cache: dict[tuple[str, str], tuple[float, list[str]]] = {}
check_state: dict[tuple[int, str], dict] = {}
# Round-robin position over the accounts that keep checks.
check_cursor = 0
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
    """Granted internet exits, ordered by the client's own priority.

    A configuration owned by an account gets its access from the account; its
    `client_internet_exits` rows are kept in step with the grants, so the same
    query serves both. The legacy `internet` flag only matters for rows that
    predate accounts.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT ce.client_id, ce.priority AS choice, c.ip, "
                "c.table_num AS client_table, c.account_id, c.pinned_iface, "
                "e.iface "
                "FROM client_internet_exits ce "
                "JOIN clients c ON c.id = ce.client_id "
                "AND c.enabled = 1 AND (c.internet = 1 OR c.account_id IS NOT NULL) "
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


def apply_client_routes(
    choices: dict[tuple[int, str], list[str]], alive, avoid=None,
    pins=None, alive_all=None
) -> dict[str, str]:
    """Points each client table at its first usable granted exit.

    ``avoid`` maps a client key to the exits its account's own checks are
    currently failing. They are skipped when another exit remains; when every
    exit is avoided the original order is used, so a bad check never leaves
    the account without a working exit.

    ``pins`` maps a client key to the exit its owner asked for. A pin wins
    over the degraded mark and over the account checks, but only while that
    exit is alive: a dead tunnel is never forced, the order takes over.
    """
    used: dict[str, str] = {}
    avoid = avoid or {}
    pins = pins or {}
    everything = set(alive_all) if alive_all is not None else set(alive)
    for (table, ip), order in choices.items():
        if table <= 0:
            log(f"client {ip}: no routing table allocated")
            continue
        pin = pins.get((table, ip), "")
        if pin and pin in everything and pin in order:
            desired = pin
            if pin not in alive:
                if pinned_degraded.get(ip) != pin:
                    pinned_degraded[ip] = pin
                    log(f"client {ip}: staying on pinned {pin}, degraded")
            else:
                pinned_degraded.pop(ip, None)
        else:
            pinned_degraded.pop(ip, None)
            blocked = avoid.get((table, ip), set())
            allowed = [iface for iface in order if iface not in blocked]
            desired = pick_client_exit(allowed or order, alive)
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
        if after in everything:
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


def dns_servers() -> list[str]:
    """The resolvers clients use, in the same order.

    Only these are tried: falling back to the server's own resolver would
    bring back the answers picked for the wrong network.
    """
    try:
        dns = str(cfg().get("dns") or "")
    except (OSError, ValueError):
        dns = ""
    servers = [part.strip() for part in dns.split(",") if part.strip()]
    return servers or ["1.1.1.1"]


def build_query(host: str, ident: int | None = None) -> bytes:
    """A minimal A query: one question, no EDNS."""
    if ident is None:
        ident = int.from_bytes(os.urandom(2), "big")
    packet = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    for part in host.rstrip(".").split("."):
        packet += bytes([len(part)]) + part.encode()
    return packet + b"\x00\x00\x01\x00\x01"


def parse_a(data: bytes) -> list[tuple[str, int]]:
    """A records with their TTL from a DNS response."""
    if len(data) < 12:
        return []
    ancount = struct.unpack("!H", data[6:8])[0]
    pos = 12
    for _ in range(struct.unpack("!H", data[4:6])[0]):  # skip questions
        while pos < len(data) and data[pos] != 0:
            pos += data[pos] + 1
        pos += 5
    out = []
    for _ in range(ancount):
        if pos + 2 > len(data):
            break
        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while pos < len(data) and data[pos] != 0:
                pos += data[pos] + 1
            pos += 1
        if pos + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 1 and rdlen == 4 and pos + 4 <= len(data):
            out.append((socket.inet_ntoa(data[pos:pos + 4]), ttl))
        pos += rdlen
    return out


def matches_query(data: bytes, ident: int, host: str) -> bool:
    """Is this the answer to our query, for our name?

    The kernel filters by peer (the socket is connected), but a stale or
    mangled datagram must not be cached as an answer either.
    """
    if len(data) < 12:
        return False
    if struct.unpack("!H", data[0:2])[0] != ident:
        return False
    if not struct.unpack("!H", data[2:4])[0] & 0x8000:  # QR bit
        return False
    if struct.unpack("!H", data[4:6])[0] != 1:  # one question
        return False
    pos, labels = 12, []
    while pos < len(data) and data[pos] != 0:
        length = data[pos]
        pos += 1
        if length > len(data) - pos:
            return False
        labels.append(data[pos:pos + length].decode("ascii", "replace").lower())
        pos += length
    return ".".join(labels) == host.rstrip(".").lower()


def dns_lookup(host: str, server: str, iface: str) -> list[tuple[str, int]]:
    """Ask the resolver with the query bound to one exit.

    A client resolves through its exit, so the probe does the same: the
    address chosen for the exit's network is the one a client would get.
    """
    query = build_query(host)
    ident = struct.unpack("!H", query[0:2])[0]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        sock.settimeout(DNS_TIMEOUT)
        # connect() makes the kernel drop datagrams from anybody but this
        # resolver; the check below also verifies the id and the name.
        sock.connect((server, 53))
        sock.send(query)
        data = sock.recv(4096)
    finally:
        sock.close()
    if not matches_query(data, ident, host):
        return []
    return parse_a(data)


def resolve_via(iface: str, host: str) -> list[str]:
    """Addresses of ``host`` as seen from this exit, cached by TTL."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    key = (iface, host)
    now = time.time()
    cached = dns_cache.get(key)
    if cached and cached[0] > now:
        return cached[1]
    answers: list[tuple[str, int]] = []
    for server in dns_servers():
        try:
            answers = dns_lookup(host, server, iface)
        except (OSError, subprocess.TimeoutExpired):
            answers = []
        if answers:
            break
    if not answers:
        return []
    ttl = min(ttl for _ip, ttl in answers) or 1
    addresses = [ip for ip, _ttl in answers]
    dns_cache[key] = (now + min(ttl, DNS_CACHE_SECONDS), addresses)
    return addresses


def public_ip(address: str) -> bool:
    try:
        return ipaddress.ip_address(address.split("%", 1)[0]).is_global
    except ValueError:
        return False


def tcp_ms(iface: str, host: str, port: int, timeout: float = 3.0) -> float | None:
    """Milliseconds to complete a TCP handshake through the exit, or None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    started = time.time()
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        sock.settimeout(timeout)
        return (time.time() - started) * 1000 if sock.connect_ex((host, port)) == 0 else None
    except OSError:
        return None
    finally:
        sock.close()


def http_probe(iface: str) -> tuple[bool, dict[str, bool]]:
    """Fetch every target through this exit, at an address resolved by it."""
    results: dict[str, bool] = {}
    for url, expected in PROBE_HTTP:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        results[url] = False
        for address in resolve_via(iface, host)[:2]:
            if not public_ip(address):
                continue
            try:
                res = run(
                    ["curl", "-4", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "--max-time", str(HTTP_TIMEOUT), "--interface", iface,
                     "--resolve", f"{host}:{port}:{address}", url],
                    timeout=HTTP_TIMEOUT + 2,
                )
            except (subprocess.TimeoutExpired, OSError):
                continue
            code = (res.stdout or "").strip()
            if res.returncode == 0 and code == str(expected):
                results[url] = True
                break
    return sum(1 for ok in results.values() if ok) >= MIN_HEALTHY_TARGETS, results


def probe(exit: dict) -> tuple[bool, float | None, bool]:
    """(alive, rtt_ms, healthy).

    ``alive`` is transport-level: a TCP handshake to a public address through
    the exit, or ICMP as a fallback for hosts that filter TCP. ``healthy``
    additionally means the HTTP targets answer, resolved through the exit
    itself; a live but degraded exit is not offered while a healthy one
    exists.
    """
    iface = exit["iface"]
    if not iface_exists(iface):
        probe_targets.pop(iface, None)
        return False, None, False
    if exit.get("mode") == "routes":
        # A routed exit only allows its own subnets in AllowedIPs, so pinging
        # 1.1.1.1 is pointless: it is alive as long as its handshake is fresh.
        res = run(["awg", "show", iface, "latest-handshakes"])
        if res.returncode != 0:
            return False, None, False
        now = time.time()
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[-1].isdigit():
                if now - int(parts[-1]) < 180:
                    return True, None, True
        return False, None, False
    # A TCP handshake is what browsing needs; ICMP is the fallback for
    # networks that drop TCP probes but answer ping.
    rtt = tcp_ms(iface, *PROBE_TCP)
    if rtt is None:
        try:
            res = run(["ping", "-c1", "-W1", "-I", iface, PROBE_TARGET], timeout=3)
        except subprocess.TimeoutExpired:
            res = None
        if res is not None and res.returncode == 0:
            rtt = ping_rtt(res.stdout)
    alive = rtt is not None
    if not alive:
        probe_targets.pop(iface, None)
        return False, None, False
    healthy, results = http_probe(iface)
    probe_targets[iface] = results
    return True, rtt, healthy


def probe_safe(exit: dict) -> tuple[bool, float | None, bool]:
    try:
        return probe(exit)
    except Exception as exc:  # a probe must never kill the daemon
        log(f"probe {exit['iface']}: {exc}")
        return False, None, False


def account_checks() -> list[dict]:
    """Enabled checks of enabled accounts; empty on an old database."""
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT ch.id, ch.account_id, ch.kind, ch.target "
                "FROM account_checks ch "
                "JOIN accounts a ON a.id = ch.account_id AND a.enabled = 1 "
                "WHERE ch.enabled = 1 ORDER BY ch.account_id, ch.id"
            ).fetchall()
        ]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def account_grants() -> list[dict]:
    """Internet exits each account may use, in the account's order."""
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT ae.account_id, e.iface FROM account_exits ae "
                "JOIN exits e ON e.id = ae.exit_id "
                "AND e.enabled = 1 AND e.mode = 'internet' "
                "JOIN accounts a ON a.id = ae.account_id AND a.enabled = 1 "
                "ORDER BY ae.account_id, ae.priority, e.priority, e.id"
            ).fetchall()
        ]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def target_host(kind: str, target: str) -> str:
    """The host part of a check target: an address, or the URL's host."""
    if kind == "http":
        return urlparse(target).hostname or ""
    return target


def check_ok(kind: str, target: str, iface: str) -> bool:
    """Is this account target reachable through this exit?

    The name is resolved through the exit and every address must be public:
    a name that starts pointing into private space is not followed, and an
    answer picked for another network is not used.
    """
    try:
        parsed = urlparse(target) if kind == "http" else None
        port = parsed.port if parsed else None
    except ValueError:
        return False
    host = target_host(kind, target)
    if not host:
        return False
    addresses = resolve_via(iface, host)
    if not addresses or not all(public_ip(a) for a in addresses):
        return False
    if kind == "http":
        port = port or (443 if parsed.scheme == "https" else 80)
        for address in addresses[:2]:
            try:
                res = run(
                    ["curl", "-4", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "--max-time", str(CHECK_TIMEOUT), "--interface", iface,
                     "--resolve", f"{host}:{port}:{address}", target],
                    timeout=CHECK_TIMEOUT + 2,
                )
            except (subprocess.TimeoutExpired, OSError):
                continue
            code = (res.stdout or "").strip()
            if res.returncode == 0 and code.isdigit() and 200 <= int(code) < 400:
                return True
        return False
    if kind == "icmp":
        for address in addresses[:2]:
            try:
                res = run(["ping", "-c1", "-W2", "-I", iface, address], timeout=4)
            except (subprocess.TimeoutExpired, OSError):
                continue
            if res.returncode == 0:
                return True
    return False


def update_check_state(
    check_id: int, target: str, iface: str, ok: bool
) -> None:
    st = check_state.setdefault(
        (check_id, iface), {"oks": 0, "fails": 0, "bad": False}
    )
    if ok:
        st["fails"] = 0
        st["oks"] += 1
        if st["bad"] and st["oks"] >= CHECK_RECOVER:
            st["bad"] = False
            log(f"check {target}: passing via {iface} again")
    else:
        st["oks"] = 0
        st["fails"] += 1
        if not st["bad"] and st["fails"] >= CHECK_DEAD_AFTER:
            st["bad"] = True
            log(f"check {target}: failing via {iface}")


def start_probes(rows: list[dict]) -> None:
    """Applies finished probes and starts one for every idle exit.

    Nothing waits here: a probe slower than the interval finishes in the
    background, its verdict is applied when it lands, and no second probe is
    queued for the same exit meanwhile.
    """
    for future in list(probe_inflight):
        if not future.done():
            continue
        exit_row = probe_inflight.pop(future)
        try:
            update_state(exit_row, *future.result())
        except Exception as exc:  # a probe must never kill the daemon
            log(f"probe {exit_row['iface']}: {exc}")
    busy = {row["iface"] for row in probe_inflight.values()}
    for exit_row in rows:
        if not exit_row["enabled"] or exit_row["iface"] in busy:
            continue
        probe_inflight[probe_pool.submit(probe_safe, exit_row)] = exit_row


def harvest_checks() -> None:
    """Applies every finished account check, however late it came."""
    for future in list(check_inflight):
        if not future.done():
            continue
        check_id, target, iface = check_inflight.pop(future)
        try:
            ok = future.result()
        except Exception as exc:  # one bad target must not stop the cycle
            log(f"check {target} via {iface}: {exc}")
            continue
        update_check_state(check_id, target, iface, ok)


def run_account_checks(alive=None) -> tuple[dict[int, set[str]], dict]:
    """Probes the accounts' targets through their exits.

    ``alive``, when given, limits the probes to exits the failover currently
    considers alive: probing a dead tunnel only burns the HTTP timeout. A
    rotating slice of accounts is probed per tick, so a host with many
    accounts still keeps its cycle short.

    Returns the exits each account should avoid and a compact report for the
    panel: account -> check -> failing interfaces. A check is reported only
    when the account has at least one exit to try it through; otherwise the
    panel shows it as unknown rather than as passing.
    """
    global check_cursor
    checks = account_checks()
    granted: dict[int, list[str]] = {}
    for grant in account_grants():
        ifaces = granted.setdefault(grant["account_id"], [])
        if grant["iface"] not in ifaces:
            ifaces.append(grant["iface"])

    # Drop state for checks, exits or accounts that no longer exist. This is
    # the full set, not the probed slice: a check skipped this tick keeps its
    # last known result instead of flapping back to unknown.
    known = {
        (ch["id"], iface)
        for ch in checks
        for iface in granted.get(ch["account_id"], [])
    }
    for key in list(check_state):
        if key not in known:
            check_state.pop(key, None)

    accounts = sorted({ch["account_id"] for ch in checks})
    if len(accounts) <= CHECK_ACCOUNTS_PER_TICK:
        selected = accounts
    else:
        start = check_cursor % len(accounts)
        selected = [
            accounts[(start + i) % len(accounts)]
            for i in range(CHECK_ACCOUNTS_PER_TICK)
        ]
        check_cursor = start + CHECK_ACCOUNTS_PER_TICK
    chosen = set(selected)

    live = set(alive) if alive is not None else None
    by_account: dict[int, list[dict]] = {}
    for ch in checks:
        by_account.setdefault(ch["account_id"], []).append(ch)

    harvest_checks()
    queued = {(task[0], task[2]) for task in check_inflight.values()}
    free = CHECK_MAX_INFLIGHT - len(check_inflight)
    for aid in selected:
        if free <= 0:
            break
        for ch in by_account.get(aid, []):
            for iface in granted.get(aid, []):
                if free <= 0:
                    break
                if live is not None and iface not in live:
                    continue
                if (ch["id"], iface) in queued:
                    continue
                future = check_pool.submit(
                    check_ok, ch["kind"], ch["target"], iface
                )
                check_inflight[future] = (ch["id"], ch["target"], iface)
                queued.add((ch["id"], iface))
                free -= 1

    avoid: dict[int, set[str]] = {}
    report: dict = {}
    for ch in checks:
        ifaces = granted.get(ch["account_id"], [])
        # A check nobody has probed yet stays out of the report: the panel
        # then shows it as unknown, not as passing.
        if not any((ch["id"], iface) in check_state for iface in ifaces):
            continue
        failing = []
        for iface in ifaces:
            if check_state.get((ch["id"], iface), {}).get("bad"):
                failing.append(iface)
                avoid.setdefault(ch["account_id"], set()).add(iface)
        report.setdefault(str(ch["account_id"]), {})[str(ch["id"])] = {
            "failing": failing,
        }
    return avoid, report


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


def record_exit_transition(previous, current, manual, alive, degraded=()) -> None:
    if previous == current:
        return
    if not current:
        reason = "No healthy internet exit"
    elif current == manual:
        reason = "Manual selection"
    elif not previous:
        reason = "Internet exit available"
    elif previous in degraded:
        reason = "Previous exit degraded"
    elif previous not in alive:
        reason = "Previous exit unavailable"
    else:
        reason = "Preferred exit recovered"
    detail = f"{previous or 'none'} → {current or 'none'} · {reason}"
    try:
        with closing(sqlite3.connect(DB_PATH, timeout=1)) as conn, conn:
            conn.execute("INSERT INTO audit (ts, action, detail) VALUES (?, ?, ?)",
                         (datetime.now(timezone.utc).isoformat(timespec="seconds"),
                          "exit_failover", detail))
    except sqlite3.Error as exc:
        log(f"cannot record exit transition: {exc}")


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


def update_state(
    exit: dict, ok: bool, rtt: float | None = None, healthy: bool | None = None
) -> None:
    if healthy is None:
        healthy = ok
    iface = exit["iface"]
    now = int(time.time())
    st = state.setdefault(
        iface,
        {"fails": 0, "oks": 0, "alive": False, "alive_since": 0,
         "last_ok": 0, "rtt_ms": None, "rtt_ts": 0,
         "degraded": False, "bad": 0, "good": 0, "healthy_since": 0},
    )
    if ok:
        st["fails"] = 0
        st["oks"] += 1
        st["last_ok"] = now
        if rtt is not None:
            st["rtt_ms"] = round(rtt)
            st["rtt_ts"] = now
        if not st["alive"] and st["oks"] >= ALIVE_AFTER:
            st["alive"] = True
            st["alive_since"] = now
            st["healthy_since"] = 0
        if healthy:
            st["bad"] = 0
            st["good"] += 1
            if st["degraded"] and st["good"] >= RECOVER_AFTER:
                st["degraded"] = False
                st["healthy_since"] = now
                log(f"exit {iface}: healthy again")
            elif not st["degraded"] and not st["healthy_since"]:
                st["healthy_since"] = now
        else:
            st["good"] = 0
            if not st["degraded"]:
                st["healthy_since"] = 0
                st["bad"] += 1
                if st["bad"] >= DEGRADED_AFTER:
                    st["degraded"] = True
                    st["bad"] = 0
                    log(f"exit {iface}: degraded")
    else:
        st["oks"] = 0
        st["good"] = 0
        st["healthy_since"] = 0
        st["fails"] += 1
        if st["alive"] and st["fails"] >= DEAD_AFTER:
            st["alive"] = False
            st["alive_since"] = 0
            st["degraded"] = False


def write_status(active, rows: list[dict], manual: str = "", clients=None,
                 client_ping=None, checks=None) -> None:
    payload = {
        "ts": int(time.time()),
        "active": active,
        "manual": manual,
        "clients": clients or {},
        "client_ping": client_ping or {},
        "checks": checks or {},
        "exits": {
            e["iface"]: {
                "name": e["name"],
                "enabled": bool(e["enabled"]),
                "mode": e.get("mode", "internet"),
                "priority": e["priority"],
                "alive": state.get(e["iface"], {}).get("alive", False),
                "degraded": bool(state.get(e["iface"], {}).get("degraded", False)),
                "healthy": bool(state.get(e["iface"], {}).get("alive")
                                and not state.get(e["iface"], {}).get("degraded", False)),
                "last_ok": state.get(e["iface"], {}).get("last_ok", 0),
                "alive_since": state.get(e["iface"], {}).get("alive_since", 0),
                "rtt_ms": state.get(e["iface"], {}).get("rtt_ms"),
                "rtt_ts": state.get(e["iface"], {}).get("rtt_ts", 0),
                "targets": probe_targets.get(e["iface"], {}),
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
    start_probes(rows)

    # Exits can come up after kaskad-routing.service already ran; only this
    # loop notices, so it re-applies the tables and rules.
    sync_routing(c)

    alive_rows = [
        e for e in rows
        if e["enabled"] and e.get("mode") == "internet" and state.get(e["iface"], {}).get("alive")
    ]
    alive = [e["iface"] for e in alive_rows]
    degraded = {
        e["iface"] for e in rows if state.get(e["iface"], {}).get("degraded")
    }
    usable_rows = [e for e in alive_rows if e["iface"] not in degraded]
    usable = [e["iface"] for e in usable_rows]
    active = read_active()
    manual = get_setting(MANUAL_KEY)
    # If every exit is degraded, keep the current one: moving between two bad
    # links buys nothing and cuts existing connections.
    pool = usable or ([active] if active in alive else [])
    healthy_since = {
        iface: state.get(iface, {}).get("healthy_since", 0) for iface in pool
    }

    desired, clear_manual = choose(
        active, pool, manual, healthy_since, int(time.time()), FAILBACK_STABLE
    )
    if clear_manual:
        set_setting(MANUAL_KEY, "")
        log(f"manual exit {manual} is down or degraded, back to automatic")
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

    record_exit_transition(active, read_active(), manual, alive, degraded)
    avoid, check_report = run_account_checks(alive)
    choices: dict[tuple[int, str], list[str]] = {}
    avoid_by_client: dict[tuple[int, str], set[str]] = {}
    pins: dict[tuple[int, str], str] = {}
    for grant in client_grants():
        key = (grant["client_table"], grant["ip"])
        choices.setdefault(key, []).append(grant["iface"])
        if grant.get("account_id"):
            avoid_by_client.setdefault(key, set()).update(
                avoid.get(int(grant["account_id"]), set())
            )
        if grant.get("pinned_iface"):
            pins[key] = grant["pinned_iface"]
    client_routes = apply_client_routes(
        choices, usable, avoid_by_client, pins, alive
    )

    pings = client_pings()
    write_status(read_active(), rows, manual, client_routes,
                 client_ping=pings, checks=check_report)


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
