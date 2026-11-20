#!/usr/bin/env python3
"""Client management panel for awg0.

Started by the kaskad-panel systemd unit. The source of truth for peers is
the SQLite database at /var/lib/kaskad/panel.db; awg0.conf is rendered from
it and applied with `awg syncconf`, so active tunnels are not interrupted.

CLI:
    app.py serve                 — web interface
    app.py sync                  — re-render awg0.conf and apply it
    app.py seed <file.json>      — import clients and exits (once)
    app.py conf <name>           — print a client config (for tests)
"""
from __future__ import annotations

import base64
import hashlib
from contextlib import contextmanager
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import auth
import awgconf
import routing
import traffic

BASE = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("KASKAD_CONFIG", "/etc/kaskad/panel.json"))
DB_PATH = Path(os.environ.get("KASKAD_DB", "/var/lib/kaskad/panel.db"))
ANDROID_APK = Path(os.environ.get("KASKAD_ANDROID_APK", "/var/lib/kaskad/app.apk"))
COOKIE = "kaskad_session"
SESSION_TTL = auth.SESSION_TTL
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$")
# The app's device identifier: an Android id or a uuid, never shown as a name.
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
# Configurations per account unless the administrator sets a personal value.
DEFAULT_MAX_CONFIGS = 5

def human_ts(value) -> str:
    if not value:
        return "never"
    text = str(value).replace("T", " ").replace("+00:00", "")
    return text[:16] + " UTC"


templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.filters["ts"] = human_ts
app = FastAPI(title="deeps kaskad", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


# A page must never come from the browser cache: the panel changes on deploy,
# the pages no longer reload themselves, and a stale copy looks like the
# change never arrived.
@app.middleware("http")
async def no_store_pages(request, call_next):
    response = await call_next(request)
    if response.headers.get("content-type", "").startswith("text/html"):
        response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------- config / db

def cfg() -> dict:
    return json.loads(CONFIG_PATH.read_text())


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        existing = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        conn.executescript(
            """
            -- A row is one configuration (one WireGuard peer), not a device
            -- or an account: an account can own several of them.
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY,
                account_id INTEGER,
                name TEXT UNIQUE NOT NULL,
                device_id TEXT,
                ip TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                preshared_key TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                internet INTEGER NOT NULL DEFAULT 1,
                table_num INTEGER NOT NULL DEFAULT 0
            );
            -- The account is the email. It owns configurations and the access
            -- to exits; a configuration only keeps its own order.
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                token_version INTEGER NOT NULL DEFAULT 1,
                max_configs INTEGER,
                last_login TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS account_exits (
                account_id INTEGER NOT NULL,
                exit_id INTEGER NOT NULL,
                priority INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (account_id, exit_id)
            );
            CREATE TABLE IF NOT EXISTS client_exits (
                client_id INTEGER NOT NULL,
                exit_id INTEGER NOT NULL,
                PRIMARY KEY (client_id, exit_id)
            );
            CREATE TABLE IF NOT EXISTS client_internet_exits (
                client_id INTEGER NOT NULL,
                exit_id INTEGER NOT NULL,
                priority INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (client_id, exit_id)
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS exits (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                iface TEXT UNIQUE NOT NULL,
                priority INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                conf TEXT NOT NULL,
                created_at TEXT NOT NULL,
                mode TEXT NOT NULL DEFAULT 'internet',
                routes TEXT NOT NULL DEFAULT '',
                dns TEXT NOT NULL DEFAULT '',
                comment TEXT NOT NULL DEFAULT '',
                table_num INTEGER NOT NULL DEFAULT 0,
                nat INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY,
                ts TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions (
                jti TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                uid INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS table_numbers (
                table_num INTEGER PRIMARY KEY,
                kind TEXT NOT NULL,
                owner_id INTEGER NOT NULL
            );
            """
        )
        # The sampler shares the definition: it can fire while the panel is
        # restarting and must not depend on this process having run yet.
        conn.executescript(traffic.SCHEMA)
        migrate(conn, existing)


def migrate(conn: sqlite3.Connection, existing: set[str]) -> None:
    """Brings the schema up to date for databases created by older versions."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(exits)")}
    for name, ddl in (
        ("mode", "ALTER TABLE exits ADD COLUMN mode TEXT NOT NULL DEFAULT 'internet'"),
        ("routes", "ALTER TABLE exits ADD COLUMN routes TEXT NOT NULL DEFAULT ''"),
        ("dns", "ALTER TABLE exits ADD COLUMN dns TEXT NOT NULL DEFAULT ''"),
        ("comment", "ALTER TABLE exits ADD COLUMN comment TEXT NOT NULL DEFAULT ''"),
        ("table_num", "ALTER TABLE exits ADD COLUMN table_num INTEGER NOT NULL DEFAULT 0"),
        ("nat", "ALTER TABLE exits ADD COLUMN nat INTEGER NOT NULL DEFAULT 1"),
    ):
        if name not in cols:
            conn.execute(ddl)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(clients)")}
    if "internet" not in cols:
        conn.execute("ALTER TABLE clients ADD COLUMN internet INTEGER NOT NULL DEFAULT 1")
    if "table_num" not in cols:
        conn.execute("ALTER TABLE clients ADD COLUMN table_num INTEGER NOT NULL DEFAULT 0")
    # Configurations created before accounts existed belong to nobody: the
    # administrator re-creates the accounts and their configurations by hand.
    if "account_id" not in cols:
        conn.execute("ALTER TABLE clients ADD COLUMN account_id INTEGER")
    # The device identifier the app sends on login: kept apart from the name,
    # which is meant for people. One account cannot hold the same device twice.
    if "device_id" not in cols:
        conn.execute("ALTER TABLE clients ADD COLUMN device_id TEXT")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS clients_device ON clients "
        "(account_id, device_id) WHERE device_id IS NOT NULL"
    )
    # First start on an old database: accounts replace users and account ids
    # can collide with old users ids, so a session from before the upgrade
    # must not sign in as a freshly created account.
    if "accounts" not in existing:
        conn.execute("DELETE FROM sessions")
    if setting("default_max_configs", conn) is None:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('default_max_configs', ?)",
            (str(DEFAULT_MAX_CONFIGS),),
        )

    # Table numbers are allocated once and stored: ids are reused after a
    # delete, and computing 1000 + id would eventually collide with the
    # client tables.
    for row in conn.execute(
        "SELECT id FROM exits WHERE table_num = 0 AND mode = 'routes'"
    ).fetchall():
        conn.execute(
            "UPDATE exits SET table_num = ? WHERE id = ?",
            (routing.allocate_table(conn), row["id"]),
        )
    for row in conn.execute("SELECT id FROM clients WHERE table_num = 0").fetchall():
        conn.execute(
            "UPDATE clients SET table_num = ? WHERE id = ?",
            (routing.allocate_table(conn), row["id"]),
        )
    # SQLite reuses the freed id of a deleted row, so links pointing at a
    # deleted client or exit would grant access to the next object created.
    for table in ("client_exits", "client_internet_exits"):
        conn.execute(
            f"DELETE FROM {table} WHERE client_id NOT IN (SELECT id FROM clients) "
            "OR exit_id NOT IN (SELECT id FROM exits)"
        )
    conn.execute(
        "DELETE FROM account_exits WHERE account_id NOT IN (SELECT id FROM accounts) "
        "OR exit_id NOT IN (SELECT id FROM exits)"
    )
    # The subnets a configuration uses are now an explicit choice. The first
    # start on an older database writes the old default — everything the
    # account grants — once; the marker keeps a later opt-out from being
    # undone on every start.
    if setting("routed_selection", conn) is None:
        conn.execute(
            "INSERT INTO client_exits (client_id, exit_id) "
            "SELECT c.id, ae.exit_id FROM clients c "
            "JOIN account_exits ae ON ae.account_id = c.account_id "
            "JOIN exits e ON e.id = ae.exit_id AND e.mode = 'routes' "
            "WHERE c.account_id IS NOT NULL AND NOT EXISTS ("
            "  SELECT 1 FROM client_exits ce "
            "  WHERE ce.client_id = c.id AND ce.exit_id = ae.exit_id)"
        )
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('routed_selection', '1')"
        )

    # One table per object across both kinds: duplicates would make a client
    # and a routed exit fight over the same routes. The registry is rebuilt
    # from the live rows and repairs leftovers of an older database.
    routing.sync_registry(conn)
    for table in ("exits", "clients"):
        conn.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {table}_table_num "
            f"ON {table}(table_num) WHERE table_num > 0"
        )


def audit(action: str, detail: str = "") -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit (ts, action, detail) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), action, detail),
        )


def setting(key: str, conn: sqlite3.Connection | None = None) -> str | None:
    if conn is not None:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None
    with db() as own:
        row = own.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(key: str, value: str, conn: sqlite3.Connection | None = None) -> None:
    owner = conn if conn is not None else db()
    if conn is not None:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        return
    with owner as own:
        own.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


# ---------------------------------------------------------------- wireguard

def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def genkey() -> str:
    return run(["awg", "genkey"]).stdout.strip()


def genpsk() -> str:
    return run(["awg", "genpsk"]).stdout.strip()


def pubkey(private: str) -> str:
    return run(["awg", "pubkey"], input=private + "\n").stdout.strip()


def server_key(c: dict, conn: sqlite3.Connection | None = None) -> str:
    key = setting("awg0_private_key", conn)
    if key:
        return key
    path = Path(c["awg_dir"]) / "awg0.key"
    if path.exists():
        key = path.read_text().strip()
    else:
        key = genkey()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(key + "\n")
        os.chmod(path, 0o600)
    set_setting("awg0_private_key", key, conn)
    return key


def render_conf(c: dict, conn: sqlite3.Connection | None = None) -> str:
    """Renders awg0.conf.

    With a connection the uncommitted rows of the current transaction are
    rendered, so the tunnel is configured from exactly the state that will
    be committed.
    """
    if conn is None:
        with db() as own:
            clients = own.execute(
                "SELECT * FROM clients WHERE enabled = 1 ORDER BY ip"
            ).fetchall()
    else:
        clients = conn.execute(
            "SELECT * FROM clients WHERE enabled = 1 ORDER BY ip"
        ).fetchall()
    return render_conf_rows(c, clients, conn)


def render_conf_rows(c: dict, clients, conn: sqlite3.Connection | None = None) -> str:
    lines = [
        "# Generated by kaskad-panel. Manual edits will be lost.",
        "[Interface]",
        f"PrivateKey = {server_key(c, conn)}",
        f"Address = {c['address']}/{c['net'].split('/')[1]}",
        f"ListenPort = {c['port']}",
        f"MTU = {c['mtu']}",
        "Table = off",
    ]
    for key, value in c["params"].items():
        lines.append(f"{key} = {value}")
    for cl in clients:
        lines += [
            "",
            "[Peer]",
            f"# {cl['name']}",
            f"PublicKey = {cl['public_key']}",
            f"PresharedKey = {cl['preshared_key']}",
            f"AllowedIPs = {cl['ip']}/32",
        ]
    return "\n".join(lines) + "\n"


def expected_peers(conn: sqlite3.Connection | None = None) -> set[str]:
    if conn is None:
        with db() as own:
            return {r[0] for r in own.execute(
                "SELECT public_key FROM clients WHERE enabled = 1"
            )}
    return {r[0] for r in conn.execute(
        "SELECT public_key FROM clients WHERE enabled = 1"
    )}


def applied_peers(iface: str) -> set[str]:
    dump = iface_dump(iface)
    if not dump.get("ok"):
        raise RuntimeError(f"awg show {iface}: the interface does not report")
    return set(dump["peers"])


def verify_conf(c: dict, conn: sqlite3.Connection | None = None) -> None:
    """Checks that the tunnel really carries the peers we just wrote.

    `syncconf` can succeed while the device keeps an old state; only the
    device dump proves the change landed.
    """
    expected = expected_peers(conn)
    actual = applied_peers(c["iface"])
    if expected != actual:
        missing = len(expected - actual)
        extra = len(actual - expected)
        raise RuntimeError(
            f"peers after apply: missing {missing}, unexpected {extra}"
        )


def iface_up(c: dict) -> bool:
    return Path(f"/sys/class/net/{c['iface']}").exists()


def conf_peers(text: str) -> set[str]:
    """Public keys of the peers in a rendered config."""
    return {
        line.split("=", 1)[1].strip()
        for line in text.splitlines()
        if line.strip().startswith("PublicKey = ")
    }


def syncconf(c: dict) -> None:
    res = run(
        ["bash", "-c", f"awg syncconf {c['iface']} <(awg-quick strip {c['iface']})"]
    )
    if res.returncode != 0:
        raise RuntimeError(f"syncconf: {res.stderr.strip()}")


def syncconf_file(c: dict, config_path: Path) -> None:
    """Applies a config file that is not the interface's own awg0.conf."""
    res = run(
        ["bash", "-c",
         f"awg syncconf {c['iface']} "
         f"<(awg-quick strip {shlex.quote(str(config_path))})"]
    )
    if res.returncode != 0:
        raise RuntimeError(f"syncconf {config_path.name}: {res.stderr.strip()}")


class RollbackFailed(RuntimeError):
    """The database change was cancelled, but the live tunnel could not be."""


def showconf(c: dict) -> bytes:
    """The live device configuration, used when there is no file to restore."""
    res = run(["awg", "showconf", c["iface"]])
    if res.returncode != 0 or not res.stdout.strip():
        raise RuntimeError(
            f"awg showconf {c['iface']}: "
            f"{res.stderr.strip() or 'empty output'}"
        )
    return res.stdout.encode()


def rollback_conf(c: dict, previous: bytes | None, snapshot: bytes | None,
                  had_iface: bool, path: Path) -> None:
    """Puts the file and the interface back to the previous configuration.

    Called after a failed apply. Raises when the live state cannot be
    restored, so the caller can report that instead of pretending the change
    did not happen.
    """
    if not had_iface:
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(previous)
            os.chmod(path, 0o600)
        if iface_up(c):
            run(["systemctl", "stop", f"awg-quick@{c['iface']}"])
            for _ in range(10):
                if not iface_up(c):
                    break
                time.sleep(0.3)
            if iface_up(c):
                raise RuntimeError(f"awg-quick@{c['iface']} is still running")
        return

    temp: Path | None = None
    if previous is not None:
        path.write_bytes(previous)
        os.chmod(path, 0o600)
        syncconf(c)
        expected = conf_peers(previous.decode())
    else:
        if snapshot is None:
            raise RuntimeError("no configuration to roll back to")
        # The device dump lacks Address/MTU/Table, so it must not replace
        # awg0.conf; apply it from a temporary file. The file is kept when
        # the restore fails: without it there is nothing to recover from.
        path.unlink(missing_ok=True)
        temp = path.with_name(f"{c['iface']}-rollback.conf")
        temp.write_bytes(snapshot)
        os.chmod(temp, 0o600)
        try:
            syncconf_file(c, temp)
        except Exception as exc:
            raise RuntimeError(
                f"{exc}; snapshot kept at {temp}"
            ) from exc
        expected = conf_peers(snapshot.decode())

    actual = applied_peers(c["iface"])
    if actual != expected:
        kept = f"; snapshot kept at {temp}" if temp is not None else ""
        raise RuntimeError(
            f"device still has {len(actual - expected)} unexpected peers{kept}"
        )
    if temp is not None:
        temp.unlink(missing_ok=True)


def apply_error_message(exc: Exception, action: str) -> str:
    """What the user is told: a failed rollback means the live state is unknown."""
    if isinstance(exc, RollbackFailed):
        return (
            "the WireGuard config could not be applied and the live tunnel "
            "could not be rolled back; awg0 may differ from the database - "
            "inspect it before continuing"
        )
    return f"the WireGuard config could not be applied; {action}"


def apply_conf(c: dict, conn: sqlite3.Connection | None = None) -> None:
    path = Path(c["awg_dir"]) / "awg0.conf"
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = path.read_bytes() if path.exists() else None
    had_iface = iface_up(c)
    snapshot = None
    if had_iface and previous is None:
        # No file to restore from, but the device is live: the snapshot is
        # taken before anything is touched, and a failure here changes nothing.
        snapshot = showconf(c)

    tmp = path.with_suffix(".tmp")
    tmp.write_text(render_conf(c, conn))
    os.chmod(tmp, 0o600)
    tmp.replace(path)

    try:
        if not had_iface:
            res = run(["systemctl", "start", f"awg-quick@{c['iface']}"])
            for _ in range(10):
                if iface_up(c):
                    break
                time.sleep(0.3)
            if not iface_up(c):
                raise RuntimeError(
                    f"awg-quick@{c['iface']}: interface did not come up"
                    + (f": {res.stderr.strip()}" if res.stderr.strip() else "")
                )
        else:
            syncconf(c)
        verify_conf(c, conn)
    except Exception as exc:
        # The database transaction is rolled back by the caller; the file and
        # the device must not keep a change that never happened.
        try:
            rollback_conf(c, previous, snapshot, had_iface, path)
        except Exception as rollback_exc:
            raise RollbackFailed(
                f"{exc}; rollback failed: {rollback_exc}"
            ) from exc
        raise


def iface_dump(name: str) -> dict:
    """awg show <iface> dump → {public_key: {handshake, rx, tx}} + device.

    The first line is always the device and the rest are peers. AmneziaWG
    prints extra device fields (Jc, S*, H*), so the field count cannot tell
    them apart.
    """
    res = run(["awg", "show", name, "dump"])
    if res.returncode != 0:
        return {"peers": {}, "ok": False}
    peers = {}
    device = {}
    lines = [line for line in res.stdout.splitlines() if line.strip()]
    for index, line in enumerate(lines):
        f = line.split("\t")
        if index == 0:
            device = {"private": f[0], "public": f[1], "port": f[2], "fwmark": f[3]}
        elif len(f) >= 8:
            peers[f[0]] = {
                "endpoint": f[2],
                "allowed": f[3],
                "handshake": int(f[4] or 0),
                "rx": int(f[5] or 0),
                "tx": int(f[6] or 0),
            }
    return {"device": device, "peers": peers, "ok": True}


def remote_ip(endpoint: str) -> str:
    """The peer address without the port, as the host sees it.

    An empty string means the peer never connected (awg prints "(none)"):
    there is no address to show, and the client hides the field.
    """
    value = (endpoint or "").strip()
    if not value or value == "(none)":
        return ""
    if value.startswith("["):  # [2001:db8::1]:51820
        return value[1:].split("]", 1)[0]
    return value.rsplit(":", 1)[0] if ":" in value else value


TRAFFIC_RANGES = {"1h": 1, "24h": 24, "7d": 7 * 24, "30d": 30 * 24, "90d": 90 * 24}
CHART_WIDTH = 720
CHART_HEIGHT = 180
CHART_COLUMNS = 240


def human_bytes(value) -> str:
    value = float(value or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return "0 B"


def human_rate(value) -> str:
    return human_bytes(value) + "/s"


def traffic_time_label(ts: int) -> str:
    moment = datetime.fromtimestamp(int(ts))
    if moment.date() == datetime.now().date():
        return moment.strftime("%H:%M")
    return moment.strftime("%d.%m %H:%M")


def config_traffic_rows(cid: int, hours: int):
    """Traffic points of one configuration for the last `hours` hours."""
    step = traffic.STEP if hours <= 7 * 24 else traffic.HOUR
    now = int(time.time())
    since = now - hours * 3600
    with db() as conn:
        rows = conn.execute(
            "SELECT ts, rx, tx FROM traffic WHERE client_id = ? AND step = ? "
            "AND ts >= ? ORDER BY ts",
            (cid, step, since),
        ).fetchall()
    return step, since, now, rows


def build_traffic_chart(step: int, since: int, now: int, rows) -> dict | None:
    """Downsampled series and totals for the cabinet chart.

    The stored buckets are summed into at most CHART_COLUMNS columns and drawn
    as bytes per second, so a five-minute point and an hourly point look the
    same on the time axis.
    """
    span = max(int(now) - int(since), 1)
    bucket = max(step, math.ceil(span / CHART_COLUMNS / step) * step)
    sums: dict[int, list[int]] = {}
    total_rx = total_tx = 0
    for row in rows:
        rx, tx = int(row["rx"]), int(row["tx"])
        total_rx += rx
        total_tx += tx
        key = min((span - 1) // bucket, int((int(row["ts"]) - since) // bucket))
        pair = sums.setdefault(key, [0, 0])
        pair[0] += rx
        pair[1] += tx
    if not sums:
        return None
    peak = max(max(pair) for pair in sums.values()) / bucket
    scale = peak or 1
    # Two adjacent bars per time bucket. Missing buckets stay blank.
    slot = CHART_WIDTH * bucket / span
    bars = []
    for key, (rx, tx) in sorted(sums.items()):
        x = key * slot
        width = min(slot, CHART_WIDTH - x)
        bars.append({"x": round(x, 2),
                     "up_x": round(x + width / 2, 2), "width": round(width * .43, 2),
                     "down": round(tx / bucket / scale * (CHART_HEIGHT - 4), 2),
                     "up": round(rx / bucket / scale * (CHART_HEIGHT - 4), 2)})
    intervals = []
    for key in range(math.ceil(span / bucket)):
        start = since + key * bucket
        end = min(now, start + bucket)
        rx, tx = sums.get(key, (None, None))
        intervals.append({"from": start, "to": end, "rx": rx, "tx": tx})
    return {
        "width": CHART_WIDTH, "height": CHART_HEIGHT,
        "bars": bars, "intervals": intervals, "interval_fraction": bucket / span,
        "from_ts": since, "to_ts": now,
        "total_rx": human_bytes(total_rx),
        "total_tx": human_bytes(total_tx),
        "peak": human_rate(peak),
        "from": traffic_time_label(since),
        "to": traffic_time_label(now),
    }


def traffic_context(cid: int, period: str) -> dict:
    if period not in TRAFFIC_RANGES:
        period = "24h"
    return {"period": period, "ranges": TRAFFIC_RANGES,
            "chart": build_traffic_chart(*config_traffic_rows(cid, TRAFFIC_RANGES[period]))}


def apply_routing() -> None:
    try:
        result = routing.apply()
        for error in result.get("errors", []):
            print(f"routing: {error}", flush=True)
    except Exception as exc:
        print(f"routing: {exc}", flush=True)


def unit_active(name: str) -> str:
    return run(["systemctl", "is-active", name]).stdout.strip() or "unknown"


# ---------------------------------------------------------------- auth

ADMIN_LOGIN = auth.ADMIN_LOGIN
MIN_PASSWORD = auth.MIN_PASSWORD
email_error = auth.email_error
password_error = auth.password_error
normalize_email = auth.normalize_email
hash_password = auth.hash_password
check_password = auth.check_password


def verify_admin_password(password: str) -> bool:
    return auth.check_password(password, os.environ.get("KASKAD_ADMIN_PASSWORD_HASH", ""))


_dummy_hash = ""


def _burn_hash(password: str) -> None:
    """Spend roughly the same time on unknown emails as on known ones."""
    global _dummy_hash
    if not _dummy_hash:
        _dummy_hash = auth.hash_password(secrets.token_urlsafe(16))
    auth.check_password(password, _dummy_hash)


def _session_secret() -> str:
    return os.environ["KASKAD_SESSION_SECRET"]


def make_session(role: str, uid: int = 0, tv: int = 0, ttl: int = 0) -> str:
    if ttl:
        return auth.make_session(_session_secret(), role, uid, tv, ttl)
    return auth.make_session(_session_secret(), role, uid, tv)


def session_data(token: str | None) -> dict | None:
    return auth.session_data(_session_secret(), token)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def start_session(role: str, uid: int = 0, tv: int = 0, ttl: int = 0) -> str:
    """Creates a session that can be revoked server-side on logout."""
    token = make_session(role, uid, tv, ttl)
    data = session_data(token)
    with db() as conn:
        conn.execute(
            "INSERT INTO sessions (jti, role, uid, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (data["jti"], role, uid, _now_iso(), int(data["exp"])),
        )
    return token


def session_alive(data: dict) -> bool:
    """A signed cookie is not enough: the session must not be revoked."""
    jti = data.get("jti")
    if not jti:
        return False
    with db() as conn:
        row = conn.execute(
            "SELECT revoked, expires_at FROM sessions WHERE jti = ?", (jti,)
        ).fetchone()
    return bool(row and not row["revoked"] and row["expires_at"] > int(time.time()))


def revoke_session(token: str | None) -> None:
    data = session_data(token)
    if not data or not data.get("jti"):
        return
    with db() as conn:
        conn.execute("UPDATE sessions SET revoked = 1 WHERE jti = ?", (data["jti"],))


def revoke_user_sessions(uid: int) -> None:
    with db() as conn:
        conn.execute("UPDATE sessions SET revoked = 1 WHERE uid = ?", (uid,))
        conn.execute(
            "UPDATE accounts SET token_version = token_version + 1 WHERE id = ?", (uid,)
        )


def prune_sessions() -> None:
    """Drops sessions that expired more than a day ago."""
    limit = int(time.time()) - 86400
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (limit,))


def csrf(token: str) -> str:
    return hmac.new(token.encode(), b"csrf", hashlib.sha256).hexdigest()[:32]


def _redirect(location: str):
    raise HTTPException(status_code=303, headers={"Location": location})


def require_admin(request: Request) -> str:
    token = request.cookies.get(COOKIE)
    data = session_data(token)
    if not data or not session_alive(data):
        _redirect("/login")
    if data["role"] != "admin":
        _redirect("/me")
    return token


def account_row(aid: int):
    with db() as conn:
        return conn.execute("SELECT * FROM accounts WHERE id = ?", (aid,)).fetchone()


def account_rows(conn: sqlite3.Connection | None = None):
    """Every account, ordered by email: the pickers and the account list."""
    sql = "SELECT * FROM accounts ORDER BY email"
    if conn is not None:
        return conn.execute(sql).fetchall()
    with db() as own:
        return own.execute(sql).fetchall()


def require_user(request: Request) -> tuple[str, object]:
    """Returns (session token, account row)."""
    token = request.cookies.get(COOKIE)
    data = session_data(token)
    if not data or not session_alive(data):
        _redirect("/login")
    if data["role"] != "user":
        _redirect("/")
    row = account_row(int(data.get("uid", 0)))
    if (
        not row
        or not row["enabled"]
        or row["token_version"] != data.get("tv")
    ):
        _redirect("/login")
    return token, row


RATE_WINDOW = 300
# A wrong password blocks that email from that address; one noisy address
# cannot lock an account from the whole internet.
PAIR_LIMIT = 5
IP_LIMIT = 20
# Attempts against one email only add a slowdown. A hard block here would
# let anyone lock the administrator out by guessing his address.
EMAIL_DELAY_AFTER = 3
EMAIL_DELAY_MAX = 3.0

_attempts: dict[str, list[float]] = {}


def _prune_attempts(now: float | None = None) -> None:
    now = now if now is not None else time.time()
    for key in list(_attempts):
        hits = [t for t in _attempts[key] if now - t < RATE_WINDOW]
        if hits:
            _attempts[key] = hits
        else:
            del _attempts[key]


def rate_key(ip: str) -> str:
    """IPv6 addresses rotate within a /64, so the whole prefix is the key."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if address.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return ip


def _count(key: str) -> int:
    _prune_attempts()
    return len(_attempts.get(key, []))


def rate_limited(ip: str, email: str = "") -> bool:
    if _count(f"ip:{ip}") >= IP_LIMIT:
        return True
    return bool(email) and _count(f"pair:{ip}|{email}") >= PAIR_LIMIT


def login_delay(email: str) -> float:
    """Small, growing delay for repeated guesses against one address."""
    hits = _count(f"email:{email}") if email else 0
    if hits < EMAIL_DELAY_AFTER:
        return 0.0
    return min(EMAIL_DELAY_MAX, 0.5 * (hits - EMAIL_DELAY_AFTER + 1))


def note_failure(ip: str, email: str = "") -> None:
    now = time.time()
    keys = [f"ip:{ip}"]
    if email:
        keys += [f"email:{email}", f"pair:{ip}|{email}"]
    for key in keys:
        _attempts.setdefault(key, []).append(now)


def clear_failures(ip: str, email: str = "") -> None:
    """A successful sign-in resets the counters for that account.

    The address counter is kept: otherwise one valid account would reset the
    per-address limit for everybody behind the same NAT.
    """
    if email:
        _attempts.pop(f"email:{email}", None)
        _attempts.pop(f"pair:{ip}|{email}", None)


_flash_secrets: dict[str, tuple[float, str]] = {}


def _prune_secrets(now: float | None = None) -> None:
    now = now if now is not None else time.time()
    for key, (expires, _) in list(_flash_secrets.items()):
        if expires <= now:
            del _flash_secrets[key]


def stash_secret(value: str) -> str:
    """Keep a generated password out of URLs; the panel shows it once."""
    _prune_secrets()
    key = secrets.token_urlsafe(9)
    _flash_secrets[key] = (time.time() + 300, value)
    return key


def pop_secret(key: str | None) -> str:
    _prune_secrets()
    if not key:
        return ""
    item = _flash_secrets.pop(key, None)
    if not item:
        return ""
    expires, value = item
    return value if expires > time.time() else ""


@app.middleware("http")
async def headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


# ---------------------------------------------------------------- routes

def exits_rows():
    with db() as conn:
        return conn.execute("SELECT * FROM exits ORDER BY priority, id").fetchall()


def run_dir(name: str) -> str:
    try:
        return (Path("/run/kaskad") / name).read_text().strip()
    except FileNotFoundError:
        return ""


def read_status() -> dict:
    try:
        return json.loads((Path("/run/kaskad") / "status.json").read_text())
    except Exception:
        return {"exits": {}, "active": None}


def free_iface(conn) -> str:
    used = {r["iface"] for r in conn.execute("SELECT iface FROM exits").fetchall()}
    for n in range(1, 64):
        name = f"awg{n}"
        if name not in used:
            return name
    raise RuntimeError("no free awgN interface left")


def apply_exit(c: dict, row) -> str:
    path = Path(c["awg_dir"]) / f"{row['iface']}.conf"
    routes = [x.strip() for x in (row["routes"] or "").split(",") if x.strip()]
    path.write_text(awgconf.render(row["conf"], c["exit_mtu"], routes or None))
    os.chmod(path, 0o600)
    unit = f"awg-quick@{row['iface']}"
    run(["systemctl", "enable", unit])
    if row["enabled"]:
        res = run(["systemctl", "restart", unit])
        if res.returncode != 0:
            return res.stderr.strip() or "failed to bring the interface up"
    else:
        run(["systemctl", "disable", "--now", unit])
    return ""


def remove_exit(row) -> None:
    run(["systemctl", "disable", "--now", f"awg-quick@{row['iface']}"])
    path = Path(cfg()["awg_dir"]) / f"{row['iface']}.conf"
    path.unlink(missing_ok=True)


def config_rows():
    with db() as conn:
        return conn.execute("SELECT * FROM clients ORDER BY ip").fetchall()


def config_row(cid: int):
    with db() as conn:
        return conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()


def account_configs(aid: int):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM clients WHERE account_id = ? ORDER BY id", (aid,)
        ).fetchall()


def config_by_device(aid: int, device_id: str):
    """The configuration this account already has for the device, if any."""
    with db() as conn:
        return conn.execute(
            "SELECT * FROM clients WHERE account_id = ? AND device_id = ?",
            (aid, device_id),
        ).fetchone()


def drop_traffic(conn, cid: int) -> None:
    """Removes a deleted configuration's history and sampler baseline."""
    conn.execute("DELETE FROM traffic WHERE client_id = ?", (cid,))
    conn.execute("DELETE FROM traffic_state WHERE client_id = ?", (cid,))


def created_config_view(cl) -> dict:
    return {
        "id": cl["id"],
        "name": cl["name"],
        "device_id": (cl["device_id"] if "device_id" in cl.keys() else "") or "",
        "ip": cl["ip"],
        "internet": config_has_internet(cl),
        "enabled": bool(cl["enabled"]),
    }


def max_configs_for(account) -> int:
    """The per-account override, or the server default from settings."""
    value = account["max_configs"]
    if value is not None:
        return max(1, int(value))
    raw = setting("default_max_configs")
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return DEFAULT_MAX_CONFIGS


def ip_free(net_cidr: str, taken: set[str]) -> str:
    net = ipaddress.ip_network(net_cidr)
    for host in net.hosts():
        if str(host).endswith(".1"):
            continue
        if str(host) not in taken:
            return str(host)
    raise RuntimeError("no free addresses left")


def account_exits(aid: int, mode: str | None = None) -> list:
    """Exits granted to an account, in the account's order."""
    sql = (
        "SELECT e.*, ae.priority AS choice FROM account_exits ae "
        "JOIN exits e ON e.id = ae.exit_id "
        "WHERE ae.account_id = ? AND e.enabled = 1"
    )
    params: list = [aid]
    if mode:
        sql += " AND e.mode = ?"
        params.append(mode)
    sql += " ORDER BY ae.priority, e.priority, e.id"
    with db() as conn:
        return conn.execute(sql, params).fetchall()


def config_routed_exits(cl) -> list:
    """Subnet exits this configuration uses.

    The account decides which subnets are allowed; the configuration picks
    the ones it needs (client_exits). Rows from before accounts existed keep
    their own grants.
    """
    if cl["account_id"]:
        with db() as conn:
            return conn.execute(
                "SELECT e.* FROM client_exits ce "
                "JOIN exits e ON e.id = ce.exit_id "
                "AND e.enabled = 1 AND e.mode = 'routes' "
                "JOIN account_exits ae ON ae.account_id = ? "
                "AND ae.exit_id = ce.exit_id "
                "WHERE ce.client_id = ? ORDER BY e.priority, e.id",
                (int(cl["account_id"]), cl["id"]),
            ).fetchall()
    with db() as conn:
        return conn.execute(
            "SELECT e.* FROM client_exits ce "
            "JOIN exits e ON e.id = ce.exit_id "
            "WHERE ce.client_id = ? AND e.enabled = 1 AND e.mode = 'routes' "
            "ORDER BY e.priority, e.id",
            (cl["id"],),
        ).fetchall()


def config_internet_exits(cl) -> list:
    """Internet exits a configuration may use, in the configuration's order.

    Access comes from the account; the order is a per-configuration copy that
    is created with the configuration and can be changed or reset.
    """
    if cl["account_id"]:
        granted = {
            e["id"]: e for e in account_exits(int(cl["account_id"]), "internet")
        }
        with db() as conn:
            order = [
                r["exit_id"] for r in conn.execute(
                    "SELECT exit_id FROM client_internet_exits "
                    "WHERE client_id = ? ORDER BY priority, exit_id",
                    (cl["id"],),
                )
            ]
        items = [granted[eid] for eid in order if eid in granted]
        items += [
            e for e in sorted(granted.values(), key=lambda x: (x["priority"], x["id"]))
            if e["id"] not in order
        ]
        return items
    with db() as conn:
        return conn.execute(
            "SELECT e.*, ce.priority AS choice "
            "FROM client_internet_exits ce "
            "JOIN exits e ON e.id = ce.exit_id "
            "WHERE ce.client_id = ? AND e.enabled = 1 AND e.mode = 'internet' "
            "ORDER BY ce.priority, e.priority, e.id",
            (cl["id"],),
        ).fetchall()


def config_has_internet(cl) -> bool:
    """Account grants decide; an account-less configuration keeps its flag."""
    if cl["account_id"]:
        return bool(config_internet_exits(cl))
    return bool(cl["internet"])


def internet_exits_rows() -> list:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM exits WHERE enabled = 1 AND mode = 'internet' ORDER BY priority, id"
        ).fetchall()


def sync_account_configs(conn, aid: int, reset_order: bool = False) -> None:
    """Keeps per-configuration order rows in step with the account's grants.

    A newly granted exit is appended to every configuration of the account;
    a revoked one disappears. With reset_order the account's order wins
    outright, which is what the "apply to all" button does.
    """
    granted = [
        r["exit_id"] for r in conn.execute(
            "SELECT ae.exit_id FROM account_exits ae "
            "JOIN exits e ON e.id = ae.exit_id "
            "WHERE ae.account_id = ? AND e.mode = 'internet' "
            "ORDER BY ae.priority, e.priority, e.id",
            (aid,),
        )
    ]
    for row in conn.execute(
        "SELECT id FROM clients WHERE account_id = ?", (aid,)
    ).fetchall():
        current = [
            r["exit_id"] for r in conn.execute(
                "SELECT exit_id FROM client_internet_exits WHERE client_id = ? "
                "ORDER BY priority, exit_id",
                (row["id"],),
            )
        ]
        if reset_order:
            order = list(granted)
        else:
            order = [eid for eid in current if eid in granted]
            order += [eid for eid in granted if eid not in order]
        conn.execute(
            "DELETE FROM client_internet_exits WHERE client_id = ?", (row["id"],)
        )
        for position, eid in enumerate(order):
            conn.execute(
                "INSERT INTO client_internet_exits (client_id, exit_id, priority) "
                "VALUES (?, ?, ?)",
                (row["id"], eid, (position + 1) * 10),
            )

    granted_routed = {
        r["exit_id"] for r in conn.execute(
            "SELECT ae.exit_id FROM account_exits ae "
            "JOIN exits e ON e.id = ae.exit_id "
            "WHERE ae.account_id = ? AND e.mode = 'routes'",
            (aid,),
        )
    }
    for row in conn.execute(
        "SELECT id FROM clients WHERE account_id = ?", (aid,)
    ).fetchall():
        cid = row["id"]
        current = {
            r["exit_id"] for r in conn.execute(
                "SELECT exit_id FROM client_exits WHERE client_id = ?", (cid,)
            )
        }
        for eid in current - granted_routed:
            conn.execute(
                "DELETE FROM client_exits WHERE client_id = ? AND exit_id = ?",
                (cid, eid),
            )
        for eid in granted_routed - current:
            conn.execute(
                "INSERT INTO client_exits (client_id, exit_id) VALUES (?, ?)",
                (cid, eid),
            )


def routed_grants(conn, account_id: int) -> list[int]:
    """Routed exits the account allows, in its order."""
    return [
        r["exit_id"] for r in conn.execute(
            "SELECT ae.exit_id FROM account_exits ae "
            "JOIN exits e ON e.id = ae.exit_id "
            "WHERE ae.account_id = ? AND e.mode = 'routes' AND e.enabled = 1 "
            "ORDER BY ae.priority, e.priority, e.id",
            (account_id,),
        )
    ]


def config_routed_choices(account) -> list:
    """The account's routed exits: what a configuration may switch on."""
    with db() as conn:
        return conn.execute(
            "SELECT e.* FROM account_exits ae "
            "JOIN exits e ON e.id = ae.exit_id "
            "WHERE ae.account_id = ? AND e.mode = 'routes' AND e.enabled = 1 "
            "ORDER BY ae.priority, e.priority, e.id",
            (int(account["id"]),),
        ).fetchall()


def write_routed_choice(conn, cl, chosen: set[int]) -> None:
    """Stores which of the account's subnets this configuration uses."""
    conn.execute("DELETE FROM client_exits WHERE client_id = ?", (cl["id"],))
    for eid in chosen:
        conn.execute(
            "INSERT INTO client_exits (client_id, exit_id) VALUES (?, ?)",
            (cl["id"], eid),
        )


def config_access(c: dict, cl) -> tuple[str, list[str]]:
    """AllowedIPs and DNS for the configuration, depending on its class."""
    networks: list[str] = []
    dns: list[str] = []
    for ex in config_routed_exits(cl):
        for cidr in (ex["routes"] or "").split(","):
            cidr = cidr.strip()
            if cidr and cidr not in networks:
                networks.append(cidr)
        for addr in (ex["dns"] or "").split(","):
            addr = addr.strip()
            if addr and addr not in dns:
                dns.append(addr)

    if config_has_internet(cl):
        return "0.0.0.0/0", [d.strip() for d in c["dns"].split(",") if d.strip()]
    if not networks:
        raise ValueError("configuration has neither internet nor subnets assigned")
    return ", ".join(networks), dns[:2]


PLAIN_AWG0_PARAMS = {
    "jc": "0", "jmin": "0", "jmax": "0",
    "s1": "0", "s2": "0", "s3": "0", "s4": "0",
    "h1": "1", "h2": "2", "h3": "3", "h4": "4",
    "contentpaddingaddition": "0",
    "randomtrailers": "off", "disablecookies": "off",
}


def awg0_obfuscated(params: dict) -> bool:
    """True when awg0 is not plain WireGuard and clients need the params too."""
    for key, value in (params or {}).items():
        default = PLAIN_AWG0_PARAMS.get(str(key).lower())
        if default is not None and str(value).strip().lower() != default:
            return True
    return False


def config_conf(c: dict, cl) -> str:
    allowed, dns = config_access(c, cl)
    # 25 s is the WireGuard recommendation behind NAT; an aggressive NAT or a
    # short UDP timeout on the path needs a smaller value, so an installation
    # can set its own (kaskad_client_keepalive).
    keepalive = int(c.get("client_keepalive", 25) or 25)
    lines = [
        "[Interface]",
        f"PrivateKey = {cl['private_key']}",
        f"Address = {cl['ip']}/32",
    ]
    if dns:
        lines.append(f"DNS = {', '.join(dns)}")
    lines.append(f"MTU = {c['mtu']}")
    # With obfuscation on awg0 a plain WireGuard client cannot connect any
    # more, and the app needs the parameters in its own config: they go into
    # [Interface] next to the keys. Plain installs keep the file readable by
    # stock WireGuard.
    if awg0_obfuscated(c.get("params") or {}):
        for key, value in c["params"].items():
            lines.append(f"{key} = {value}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {pubkey(server_key(c))}",
        f"PresharedKey = {cl['preshared_key']}",
        f"Endpoint = {c['endpoint']}:{c['port']}",
        f"AllowedIPs = {allowed}",
        f"PersistentKeepalive = {keepalive}",
    ]
    return "\n".join(lines) + "\n"


def mask_conf(text: str) -> str:
    out = []
    for line in text.splitlines():
        low = line.strip().lower()
        if low.startswith(("privatekey", "presharedkey")):
            key = line.split("=")[0].strip()
            out.append(f"{key} = ••••••••")
        else:
            out.append(line)
    return "\n".join(out)


def config_view(cl, live: dict, assigned=None) -> dict:
    st = live.get(cl["public_key"], {})
    if assigned is None:
        assigned = config_routed_exits(cl)
    return {
        "id": cl["id"],
        "account_id": cl["account_id"],
        "name": cl["name"],
        "device_id": (cl["device_id"] if "device_id" in cl.keys() else "") or "",
        "ip": cl["ip"],
        "enabled": bool(cl["enabled"]),
        "internet": config_has_internet(cl),
        "exits": [e["name"] for e in assigned],
        "remote_ip": remote_ip(st.get("endpoint", "")),
        "handshake": st.get("handshake", 0),
        "rx": st.get("rx", 0),
        "tx": st.get("tx", 0),
    }


def fresh_routing_status(status: dict, now: int) -> bool:
    ts = status.get("ts")
    return isinstance(ts, (int, float)) and 0 <= now - ts <= 60


def routing_status(now: int | None = None) -> tuple[dict, bool]:
    """Failover status, emptied when it is too old to describe anything.

    The daemon writes it every ten seconds. A stale file outlives a crash, so
    every page must treat its exits as unknown rather than as healthy.
    """
    status = read_status()
    fresh = fresh_routing_status(status, int(time.time()) if now is None else now)
    return (status if fresh else {}), fresh


def selected_internet_iface(view: dict, status: dict, shared: bool = False) -> str:
    return ((status.get("active") if shared else (status.get("clients") or {}).get(view["ip"]))
            or "")


def configuration_diagnosis(view: dict, status: dict, now: int, shared: bool = False) -> dict:
    if not view["enabled"]:
        return {"state": "Disabled", "warning": ""}
    if not view["internet"] and not view["exits"]:
        return {"state": "No access assigned", "warning": ""}
    handshake = view["handshake"]
    if not handshake:
        return {"state": "No handshake recorded", "warning": ""}
    if now - handshake >= 180:
        return {"state": "Last handshake", "warning": ""}
    warning = ""
    if view["internet"]:
        if not fresh_routing_status(status, now):
            warning = "Exit status unavailable"
        else:
            iface = selected_internet_iface(view, status, shared)
            if not (status.get("exits") or {}).get(iface, {}).get("alive"):
                warning = "No working internet exit"
    return {"state": "Online", "warning": warning}


def exit_view(e, status: dict, active, manual: str = "") -> dict:
    st = status.get("exits", {}).get(e["iface"], {})
    return {
        "id": e["id"],
        "name": e["name"],
        "iface": e["iface"],
        "priority": e["priority"],
        "enabled": bool(e["enabled"]),
        "mode": e["mode"],
        "routes": e["routes"],
        "dns": e["dns"],
        "comment": e["comment"],
        "nat": bool(e["nat"]) if "nat" in e.keys() else True,
        "endpoint": awgconf.endpoint(e["conf"]),
        "alive": st.get("alive"),
        "last_ok": st.get("last_ok", 0),
        "rtt_ms": st.get("rtt_ms"),
        "rtt_ts": st.get("rtt_ts", 0),
        "active": e["iface"] == active,
        "pinned": bool(manual) and e["iface"] == manual,
    }


def services() -> dict:
    return {
        "awg0": unit_active("awg-quick@awg0"),
        "routing": unit_active("kaskad-routing"),
        "firewall": unit_active("kaskad-firewall"),
        "failover": unit_active("kaskad-failover"),
    }


def render_page(request: Request, template: str, nav: str, **ctx):
    c = cfg()
    ctx.setdefault("hide_nav", False)
    ctx.setdefault("role", "admin")
    ctx.setdefault("version", c.get("version", "dev"))
    ctx.setdefault("commit", c.get("commit", ""))
    ctx["nav"] = nav
    return templates.TemplateResponse(request, template, ctx)


# ---------------------------------------------------------------- auth

def login_context(error=None, email=""):
    c = cfg()
    return {
        "error": error,
        "email": email,
        "hide_nav": True,
        "version": c.get("version", "dev"),
        "commit": c.get("commit", ""),
    }


def login_response(request: Request, error=None, email="", status: int = 200):
    """The sign-in page, or its standalone anonymous form.

    The anonymous variant shares nothing with the panel template: its source
    must not mention the product, its stack or its features, so it has no
    inherited scripts, styles or navigation.
    """
    anonymous = setting("login_anonymous") == "1"
    template = "login_anon.html" if anonymous else "login.html"
    return templates.TemplateResponse(
        request, template, login_context(error, email), status_code=status
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return login_response(request)


@app.post("/login")
def login(request: Request, email: str = Form(""), password: str = Form(...)):
    ip = request.client.host if request.client else "?"
    ip_key = rate_key(ip)
    email = normalize_email(email)

    def fail(message: str, status: int = 401):
        return login_response(request, message, email, status)

    if rate_limited(ip_key, email):
        return fail("too many attempts, wait 5 minutes", 429)

    token = ""
    location = ""
    role = ""
    uid = 0
    tv = 0
    if email == ADMIN_LOGIN:
        if verify_admin_password(password):
            location = "/"
            role = "admin"
    elif email:
        row = None
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE email = ?", (email,)
            ).fetchone()
        ok = bool(
            row
            and check_password(password, row["password_hash"])
            and row["enabled"]
        )
        if not row:
            _burn_hash(password)
        if ok:
            uid = int(row["id"])
            tv = int(row["token_version"])
            with db() as conn:
                conn.execute(
                    "UPDATE accounts SET last_login = ? WHERE id = ?",
                    (_now_iso(), uid),
                )
            location = "/me"
            role = "user"

    if not role:
        delay = login_delay(email)
        if delay:
            # Slows down guessing against one address without locking it: a
            # correct password never sleeps, only wrong ones do.
            time.sleep(delay)
        note_failure(ip_key, email)
        # Read by fail2ban through journald; never log the password, and keep
        # control characters out of the line.
        safe_email = re.sub(r"[\x00-\x1f\x7f]", "", email)[:254] or "-"
        print(f"KASKAD_AUTH_FAIL ip={ip} email={safe_email}", flush=True)
        audit("login_failed", f"{ip} {safe_email}")
        return fail("wrong email or password")

    token = start_session(role, uid, tv)
    clear_failures(ip_key, email)
    prune_sessions()
    response = RedirectResponse(location, status_code=303)
    response.set_cookie(
        COOKIE, token, httponly=True, secure=True, samesite="strict", max_age=SESSION_TTL
    )
    audit("login", f"{role} {email} {ip}")
    return response


@app.post("/logout")
def logout(request: Request):
    revoke_session(request.cookies.get(COOKIE))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE)
    return response


@app.get("/ping")
def ping():
    """Tiny target for the browser to measure its round-trip to the panel."""
    return PlainTextResponse(
        "pong", headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    )


@app.get("/healthz")
def healthz():
    """Liveness for monitoring: database readable and failover reporting.

    Deliberately says nothing about the product or its version: this endpoint
    is public, and the signed-out page can be configured to stay anonymous.
    """
    try:
        with db() as conn:
            conn.execute("SELECT 1").fetchone()
    except Exception as exc:
        print(f"healthz: {exc}", flush=True)
        return JSONResponse({"ok": False, "error": "database"}, status_code=503)
    status = read_status()
    ts = int(status.get("ts") or 0)
    now = int(time.time())
    age = now - ts if ts else None
    fresh = fresh_routing_status(status, now)
    return JSONResponse(
        {"ok": fresh, "failover_age": age},
        status_code=200 if fresh else 503,
    )


# ---------------------------------------------------------------- overview

@app.get("/", response_class=HTMLResponse)
def overview(request: Request, err: str | None = None, ok: str | None = None):
    token = require_admin(request)
    c = cfg()
    live = iface_dump(c["iface"])["peers"]
    configs = [config_view(cl, live) for cl in config_rows()]
    status, fresh = routing_status()
    active = run_dir("active-exit") if fresh else None
    manual = setting("manual_exit") or ""
    exits = [exit_view(e, status, active, manual) for e in exits_rows()]
    with db() as conn:
        events = conn.execute(
            "SELECT ts, action, detail FROM audit ORDER BY id DESC LIMIT 6"
        ).fetchall()
    now = int(time.time())
    online = sum(1 for cl in configs if cl["handshake"] and now - cl["handshake"] < 180)
    rx = sum(cl["rx"] for cl in configs)
    tx = sum(cl["tx"] for cl in configs)
    health = overview_health(exits, fresh)
    return render_page(
        request, "overview.html", "overview",
        csrf=csrf(token), err=err, ok=ok,
        clients=configs, exits=exits, health=health, status_fresh=fresh,
        online=online, rx=rx, tx=tx,
        events=events,
    )


def overview_health(exits: list[dict], status_fresh: bool) -> dict:
    active = next((e for e in exits if e["active"] and e["enabled"]
                   and e["mode"] == "internet"), None)
    issues = []
    if not status_fresh:
        issues.append({"url": "/settings#services", "text": "Exit status unavailable → System"})
    elif not active or not active["alive"]:
        issues.append({"url": "/exits", "text": "No healthy active internet exit → Exits"})
    for e in exits:
        if e["enabled"] and e["alive"] is False:
            issues.append({"url": f"/exits/{e['id']}", "text": f"{e['name']} is down → Exit details"})
    for name, state in services().items():
        if state != "active":
            issues.append({"url": "/settings#services", "text": f"{name}: {state} → System"})
    return {"active": {key: active[key] for key in ("id", "name", "iface")} if active else None,
            "issues": issues}


# ---------------------------------------------------------------- exits

EXIT_DEFAULTS = {"name": "", "mode": "internet", "priority": "", "routes": "", "dns": "", "conf": ""}


@app.get("/exits", response_class=HTMLResponse)
def exits_page(request: Request, mode: str | None = None):
    token = require_admin(request)
    status, fresh = routing_status()
    active = run_dir("active-exit") if fresh else None
    manual = setting("manual_exit") or ""
    items = [exit_view(e, status, active, manual) for e in exits_rows()]
    if mode in ("internet", "routes"):
        items = [e for e in items if e["mode"] == mode]
    return render_page(
        request, "exits.html", "exits",
        csrf=csrf(token), exits=items, mode=mode or "", manual_exit=manual,
        routing_fresh=fresh,
        counts={
            "all": len(exits_rows()),
            "internet": sum(1 for e in exits_rows() if e["mode"] == "internet"),
            "routes": sum(1 for e in exits_rows() if e["mode"] == "routes"),
        },
    )


@app.get("/exits/new", response_class=HTMLResponse)
def exit_new_page(request: Request, err: str | None = None):
    token = require_admin(request)
    return render_page(
        request, "exit_new.html", "exits",
        csrf=csrf(token), err=err, form=EXIT_DEFAULTS,
        clients_net=cfg()["clients_net"],
    )


@app.get("/exits/{eid}", response_class=HTMLResponse)
def exit_page(request: Request, eid: int, err: str | None = None, ok: str | None = None):
    token = require_admin(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM exits WHERE id = ?", (eid,)).fetchone()
        configs = conn.execute("SELECT * FROM clients WHERE enabled = 1 ORDER BY name").fetchall()
    if not row:
        raise HTTPException(status_code=404)
    status, fresh = routing_status()
    active = run_dir("active-exit") if fresh else None
    manual = setting("manual_exit") or ""
    current, reserve = [], []
    if row["enabled"]:
        for cl in configs:
            if row["mode"] == "routes":
                if any(e["id"] == eid for e in config_routed_exits(cl)):
                    current.append(cl)
                continue
            choices = config_internet_exits(cl)
            shared = not cl["account_id"] and bool(cl["internet"]) and not choices
            if not cl["account_id"] and not cl["internet"]:
                continue
            if not shared and not any(e["id"] == eid for e in choices):
                continue
            if fresh and selected_internet_iface(cl, status, shared) == row["iface"]:
                current.append(cl)
            else:
                reserve.append(cl)
    return render_page(
        request, "exit_detail.html", "exits",
        csrf=csrf(token), err=err, ok=ok,
        exit=exit_view(row, status, active, manual),
        conf=mask_conf(awgconf.render(row["conf"], cfg()["exit_mtu"],
                                      [x.strip() for x in (row["routes"] or "").split(",") if x.strip()] or None)),
        current_configs=current, reserve_configs=reserve, routing_fresh=fresh,
        clients_net=cfg()["clients_net"],
    )


def parse_routes(value: str) -> list[str]:
    nets = []
    for chunk in value.replace("\n", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        net = ipaddress.ip_network(chunk, strict=False)
        if net.prefixlen == 0:
            raise ValueError("0.0.0.0/0 is not needed here — use the internet mode")
        nets.append(str(net))
    return list(dict.fromkeys(nets))


@app.post("/exits")
def create_exit(
    request: Request,
    name: str = Form(...),
    priority: str = Form(""),
    mode: str = Form("internet"),
    routes: str = Form(""),
    dns: str = Form(""),
    comment: str = Form(""),
    nat: str = Form(""),
    conf: str = Form(...),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    name = name.strip()
    comment = comment.strip()

    def fail(msg: str):
        return RedirectResponse("/exits/new?err=" + quote(msg), status_code=303)

    if not NAME_RE.match(name):
        return fail("name: latin letters, digits, dot, dash; up to 32 characters")
    if len(comment) > 120:
        return fail("comment: up to 120 characters")
    errors = awgconf.validate(conf)
    if errors:
        return fail("; ".join(errors))

    c = cfg()
    try:
        prio = int(priority) if priority.strip() else (
            max([e["priority"] for e in exits_rows()] or [0]) + 10
        )
    except ValueError:
        return fail("priority must be a number")

    if mode not in ("internet", "routes"):
        return fail("unknown exit mode")
    if mode == "routes" and not routes.strip():
        # The provider config names the networks this peer can reach; when
        # AllowedIPs is the default route, the Address network is the guess.
        routes = ", ".join(awgconf.guess_routes(conf))
    try:
        nets = parse_routes(routes) if mode == "routes" else []
    except ValueError as exc:
        return fail(str(exc))
    if mode == "routes" and not nets:
        return fail("an exit with subnets needs at least one CIDR")

    if mode == "routes":
        for ex in exits_rows():
            if ex["mode"] != "routes":
                continue
            for old in [x.strip() for x in (ex["routes"] or "").split(",") if x.strip()]:
                for new in nets:
                    if ipaddress.ip_network(old).overlaps(ipaddress.ip_network(new)):
                        return fail(f"subnet {new} overlaps {old} of exit \"{ex['name']}\"")

    def ident(text: str) -> tuple[str, str]:
        d = awgconf.parse_text(text)
        addr = d["iface"].get("Address", "").split(",")[0].strip().split("/")[0]
        key = ""
        for k, v in d["iface"].items():
            if k.lower() == "privatekey":
                key = v.strip()
        return addr, key

    new_addr, new_key = ident(conf)
    for ex in exits_rows():
        old_addr, old_key = ident(ex["conf"])
        if (new_addr and new_addr == old_addr) or (new_key and new_key == old_key):
            return fail(
                f"this config is already used by exit \"{ex['name']}\" (address {new_addr or '—'}). "
                "Providers issue a separate config per device"
            )

    with db() as conn:
        if conn.execute("SELECT 1 FROM exits WHERE name = ?", (name,)).fetchone():
            return fail("an exit with this name already exists")
        iface = free_iface(conn)
        cur = conn.execute(
            "INSERT INTO exits (name, iface, priority, enabled, conf, created_at, mode, routes, dns, comment, table_num, nat) "
            "VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 0, ?)",
            (name, iface, prio, conf, datetime.now(timezone.utc).isoformat(timespec="seconds"),
             mode, ", ".join(nets), dns.strip(), comment,
             1 if mode == "internet" or nat else 0),
        )
        eid = cur.lastrowid
        if mode == "routes":
            conn.execute(
                "UPDATE exits SET table_num = ? WHERE id = ?",
                (routing.claim_table(conn, "exit", eid), eid),
            )
        row = conn.execute("SELECT * FROM exits WHERE id = ?", (eid,)).fetchone()

    error = apply_exit(c, row)
    apply_routing()
    audit("exit_added", f"{name} {iface} {mode}")
    if error:
        with db() as conn:
            conn.execute("UPDATE exits SET enabled = 0 WHERE id = ?", (row["id"],))
        return fail(f"{name}: {error}. Exit disabled, check the config")
    return RedirectResponse(f"/exits/{row['id']}?ok=exit+added", status_code=303)


@app.post("/exits/{eid}/comment")
def update_exit_comment(
    request: Request, eid: int, comment: str = Form(""), csrf_token: str = Form(...)
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    comment = comment.strip()
    if len(comment) > 120:
        return RedirectResponse(
            f"/exits/{eid}?err=" + quote("comment: up to 120 characters"), status_code=303
        )
    with db() as conn:
        row = conn.execute("SELECT * FROM exits WHERE id = ?", (eid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404)
        conn.execute("UPDATE exits SET comment = ? WHERE id = ?", (comment, eid))
    audit("exit_comment", f"{row['name']}: {comment}")
    return RedirectResponse(f"/exits/{eid}?ok=comment+saved", status_code=303)


@app.post("/exits/{eid}/nat")
def update_exit_nat(
    request: Request,
    eid: int,
    nat: str = Form(""),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    with db() as conn:
        row = conn.execute("SELECT * FROM exits WHERE id = ?", (eid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404)
        if row["mode"] != "routes":
            return RedirectResponse(
                f"/exits/{eid}?err={quote('internet exits always use NAT')}",
                status_code=303,
            )
        wanted = 1 if nat else 0
        changed = int(row["nat"]) != wanted
        conn.execute("UPDATE exits SET nat = ? WHERE id = ?", (wanted, eid))
    audit("exit_nat", f"{row['name']} nat={wanted}")
    apply_routing()
    if changed:
        # Existing flows keep the old mapping until their conntrack entry
        # expires; drop them only once the new rules are in place.
        res = run(["conntrack", "-D", "-s", cfg()["clients_net"]], timeout=5)
        if res.returncode != 0 and "0 flow entries" not in res.stderr.lower():
            print(f"conntrack: {res.stderr.strip()}", flush=True)
    return RedirectResponse(f"/exits/{eid}?ok=nat+updated", status_code=303)


@app.post("/exits/{eid}/toggle")
def toggle_exit(request: Request, eid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    with db() as conn:
        row = conn.execute("SELECT * FROM exits WHERE id = ?", (eid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404)
        conn.execute("UPDATE exits SET enabled = ? WHERE id = ?", (0 if row["enabled"] else 1, eid))
        row = conn.execute("SELECT * FROM exits WHERE id = ?", (eid,)).fetchone()
    apply_exit(cfg(), row)
    apply_routing()
    audit("exit_toggle", f"{row['name']} -> {row['enabled']}")
    return RedirectResponse(f"/exits/{eid}", status_code=303)


@app.post("/exits/{eid}/delete")
def delete_exit(request: Request, eid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    with db() as conn:
        row = conn.execute("SELECT * FROM exits WHERE id = ?", (eid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404)
        conn.execute("DELETE FROM exits WHERE id = ?", (eid,))
        conn.execute("DELETE FROM client_exits WHERE exit_id = ?", (eid,))
        conn.execute("DELETE FROM client_internet_exits WHERE exit_id = ?", (eid,))
        routing.release_table(conn, "exit", eid)
    remove_exit(row)
    apply_routing()
    audit("exit_deleted", row["name"])
    return RedirectResponse("/exits?ok=exit+deleted", status_code=303)


@app.post("/exits/{eid}/activate")
def activate_exit(request: Request, eid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    with db() as conn:
        row = conn.execute("SELECT * FROM exits WHERE id = ?", (eid,)).fetchone()
    if not row:
        raise HTTPException(status_code=404)
    set_setting("manual_exit", row["iface"])
    audit("exit_pinned", f"{row['name']} {row['iface']}")
    return RedirectResponse("/exits?ok=exit+pinned", status_code=303)


@app.post("/exits/auto")
def exit_auto(request: Request, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    set_setting("manual_exit", "")
    audit("exit_auto", "")
    return RedirectResponse("/exits?ok=automatic+selection", status_code=303)


# ---------------------------------------------------------------- configurations

def config_limit_error(account) -> str:
    """Empty string when the account may get another configuration."""
    n = len(account_configs(int(account["id"])))
    limit = max_configs_for(account)
    if n >= limit:
        return (
            f"this account already has {n} of {limit} allowed configurations"
        )
    return ""


def spawn_config(
    conn, account, name: str = "", device_id: str = "", uniquify: bool = False
) -> int:
    """Creates one configuration with server-generated keys in this transaction.

    The caller commits: the peer must exist in awg0.conf by the time the row
    is visible, so a failed apply rolls the configuration back.
    """
    c = cfg()
    rows = conn.execute("SELECT ip, name FROM clients").fetchall()
    taken_ips = {r["ip"] for r in rows}
    taken_names = {r["name"] for r in rows}
    device_id = device_id.strip()
    if device_id and not DEVICE_ID_RE.match(device_id):
        raise ValueError(
            "device_id: latin letters, digits, dash; 8 to 64 characters"
        )
    name = name.strip()
    if name:
        if not NAME_RE.match(name):
            raise ValueError(
                "name: latin letters, digits, dot, dash; up to 32 characters"
            )
        if name in taken_names:
            if not uniquify:
                raise ValueError("a configuration with this name already exists")
            # Two phones of one model would otherwise fight over the name the
            # app sends; the response carries the name that was actually used.
            base, n = name, 2
            while True:
                suffix = f"-{n}"
                candidate = base[: 32 - len(suffix)] + suffix
                if candidate not in taken_names:
                    break
                n += 1
            name = candidate
    else:
        local = re.sub(r"[^a-z0-9]+", "-", account["email"].split("@")[0].lower())
        local = local.strip("-") or "config"
        n = 1
        while f"{local}-{n}" in taken_names:
            n += 1
        name = f"{local}-{n}"
    ip = ip_free(c["net"], taken_ips)
    private = genkey()
    cur = conn.execute(
        "INSERT INTO clients (account_id, name, device_id, ip, public_key, "
        "private_key, preshared_key, enabled, created_at, internet, table_num) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 1, 0)",
        (account["id"], name, device_id or None, ip, pubkey(private), private,
         genpsk(), _now_iso()),
    )
    cid = cur.lastrowid
    conn.execute(
        "UPDATE clients SET table_num = ? WHERE id = ?",
        (routing.claim_table(conn, "client", cid), cid),
    )
    # A new configuration starts with the account's order at this moment.
    granted = [
        r["exit_id"] for r in conn.execute(
            "SELECT ae.exit_id FROM account_exits ae "
            "JOIN exits e ON e.id = ae.exit_id "
            "WHERE ae.account_id = ? AND e.mode = 'internet' "
            "ORDER BY ae.priority, e.priority, e.id",
            (account["id"],),
        )
    ]
    for position, eid in enumerate(granted):
        conn.execute(
            "INSERT INTO client_internet_exits (client_id, exit_id, priority) "
            "VALUES (?, ?, ?)",
            (cid, eid, (position + 1) * 10),
        )
    # Subnets are picked per configuration; a new one starts with all of them.
    for row in conn.execute(
        "SELECT ae.exit_id FROM account_exits ae "
        "JOIN exits e ON e.id = ae.exit_id "
        "WHERE ae.account_id = ? AND e.mode = 'routes'",
        (account["id"],),
    ).fetchall():
        conn.execute(
            "INSERT INTO client_exits (client_id, exit_id) VALUES (?, ?)",
            (cid, row["exit_id"]),
        )
    apply_conf(c, conn)
    return cid


def reissue_keys(conn, cl) -> None:
    """New keys for one configuration; the old config stops working."""
    private = genkey()
    conn.execute(
        "UPDATE clients SET private_key = ?, public_key = ?, preshared_key = ? "
        "WHERE id = ?",
        (private, pubkey(private), genpsk(), cl["id"]),
    )
    apply_conf(cfg(), conn)


def move_in_order(order: list[int], exit_id: int, direction: str) -> list[int]:
    """Swaps one entry with its neighbour; a foreign exit is a 404."""
    if exit_id not in order:
        raise HTTPException(status_code=404)
    index = order.index(exit_id)
    target = index - 1 if direction == "up" else index + 1
    if 0 <= target < len(order):
        order[index], order[target] = order[target], order[index]
    return order


def write_config_order(conn, cid: int, order: list[int]) -> None:
    conn.execute(
        "DELETE FROM client_internet_exits WHERE client_id = ?", (cid,)
    )
    for position, eid in enumerate(order):
        conn.execute(
            "INSERT INTO client_internet_exits (client_id, exit_id, priority) "
            "VALUES (?, ?, ?)",
            (cid, eid, (position + 1) * 10),
        )


def reset_config_order(conn, cl) -> None:
    """Puts one configuration back on the account's order."""
    if not cl["account_id"]:
        return
    granted = [
        r["exit_id"] for r in conn.execute(
            "SELECT ae.exit_id FROM account_exits ae "
            "JOIN exits e ON e.id = ae.exit_id "
            "WHERE ae.account_id = ? AND e.mode = 'internet' "
            "ORDER BY ae.priority, e.priority, e.id",
            (cl["account_id"],),
        )
    ]
    write_config_order(conn, cl["id"], granted)


@app.get("/configs", response_class=HTMLResponse)
def configs_page(request: Request, q: str | None = None, state: str = ""):
    token = require_admin(request)
    live = iface_dump(cfg()["iface"])["peers"]
    with db() as conn:
        accounts = {
            r["id"]: r
            for r in conn.execute("SELECT id, email, enabled FROM accounts")
        }
    items = [config_view(cl, live) for cl in config_rows()]
    for c in items:
        account = accounts.get(c["account_id"])
        c["account_email"] = account["email"] if account else ""
        c["account_enabled"] = bool(account["enabled"]) if account else False
    if q:
        needle = q.strip().lower()
        items = [
            c for c in items
            if needle in c["name"].lower()
            or needle in c["ip"]
            or needle in c["account_email"].lower()
        ]
    filters = {"": "All", "recent": "Recent handshake", "disabled": "Disabled",
               "unassigned": "Unassigned"}
    if state not in filters:
        state = ""
    now = int(time.time())
    if state == "recent":
        items = [c for c in items if c["enabled"] and c["handshake"]
                 and now - c["handshake"] < 180]
    elif state == "disabled":
        items = [c for c in items if not c["enabled"]]
    elif state == "unassigned":
        items = [c for c in items if not c["account_email"]]
    return render_page(
        request, "configs.html", "configs",
        csrf=csrf(token), configs=items, q=q or "", state=state, filters=filters,
    )


@app.get("/configs/new", response_class=HTMLResponse)
def config_new_page(request: Request, err: str | None = None):
    token = require_admin(request)
    with db() as conn:
        rows = account_rows(conn)
        counts = {
            r["account_id"]: r["n"] for r in conn.execute(
                "SELECT account_id, count(*) AS n FROM clients "
                "WHERE account_id IS NOT NULL GROUP BY account_id"
            )
        }
    accounts = [
        {
            "id": a["id"],
            "email": a["email"],
            "limit": max_configs_for(a),
            "n": counts.get(a["id"], 0),
        }
        for a in rows
    ]
    return render_page(
        request, "config_new.html", "configs",
        csrf=csrf(token), err=err, accounts=accounts,
    )


@app.post("/configs")
def create_config(
    request: Request,
    account_id: int = Form(...),
    name: str = Form(""),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    account = account_row(account_id)
    if not account:
        raise HTTPException(status_code=404)
    problem = config_limit_error(account)
    if problem:
        return RedirectResponse("/configs/new?err=" + quote(problem), status_code=303)
    try:
        with db() as conn:
            cid = spawn_config(conn, account, name)
    except (RuntimeError, ValueError) as exc:
        message = (
            apply_error_message(exc, "nothing was saved")
            if isinstance(exc, RuntimeError) else str(exc)
        )
        return RedirectResponse("/configs/new?err=" + quote(message), status_code=303)
    audit("config_added", f"{account['email']} {name or cid}")
    apply_routing()
    return RedirectResponse(f"/configs/{cid}?ok=configuration+created", status_code=303)


@app.post("/configs/{cid}/name")
def config_rename(
    request: Request, cid: int, name: str = Form(""),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    cl = config_row(cid)
    if not cl:
        raise HTTPException(status_code=404)
    name = name.strip()
    if not NAME_RE.match(name):
        problem = "name: latin letters, digits, dot, dash; up to 32 characters"
        return RedirectResponse(f"/configs/{cid}?err=" + quote(problem), status_code=303)
    with db() as conn:
        taken = conn.execute(
            "SELECT id FROM clients WHERE name = ? AND id != ?", (name, cid)
        ).fetchone()
        if taken:
            problem = "a configuration with this name already exists"
            return RedirectResponse(
                f"/configs/{cid}?err=" + quote(problem), status_code=303
            )
        conn.execute("UPDATE clients SET name = ? WHERE id = ?", (name, cid))
    audit("config_renamed", f"{cl['name']} -> {name}")
    return RedirectResponse(f"/configs/{cid}?ok=name+updated", status_code=303)


@app.get("/configs/{cid}", response_class=HTMLResponse)
def config_page(
    request: Request,
    cid: int,
    period: str = Query("24h", alias="range"),
    err: str | None = None,
    ok: str | None = None,
):
    token = require_admin(request)
    c = cfg()
    cl = config_row(cid)
    if not cl:
        raise HTTPException(status_code=404)
    account = account_row(int(cl["account_id"])) if cl["account_id"] else None
    live = iface_dump(c["iface"])["peers"]
    view = config_view(cl, live)
    status, routing_fresh = routing_status()
    client_rtt = (status.get("client_ping") or {}).get(cl["ip"])
    states = status.get("exits") or {}
    known = exits_rows()
    latency = {
        e["iface"]: (states.get(e["iface"], {}).get("rtt_ms") if routing_fresh else None)
        for e in known
    }
    alive = {
        e["iface"]: (bool(states.get(e["iface"], {}).get("alive")) if routing_fresh else None)
        for e in known
    }
    try:
        conf = mask_conf(config_conf(c, cl))
    except ValueError:
        conf = None
    accounts = []
    if not account:
        accounts = account_rows()
    chosen_routed = {e["id"] for e in config_routed_exits(cl)}
    allowed_routed = config_routed_choices(account) if account else []
    allowed_ids = {e["id"] for e in allowed_routed}
    return render_page(
        request, "config_detail.html", "configs",
        csrf=csrf(token), err=err, ok=ok, config=view, **traffic_context(cid, period),
        account=account, routed=config_routed_exits(cl),
        diagnosis=configuration_diagnosis(view, status, int(time.time()),
                                           not cl["account_id"] and not config_internet_exits(cl)),
        internet_exits=config_internet_exits(cl),
        latency=latency, alive=alive, client_rtt=client_rtt, conf=conf,
        routing_fresh=routing_fresh,
        accounts=accounts,
        routed_choices=[
            {"id": r["id"], "name": r["comment"] or r["name"], "routes": r["routes"],
             "chosen": r["id"] in chosen_routed}
            for r in allowed_routed
        ],
        ungranted_subnets=[
            e for e in exits_rows()
            if e["mode"] == "routes" and e["enabled"] and e["id"] not in allowed_ids
        ] if account else [],
    )


@app.post("/configs/{cid}/routed")
def config_routed_update(
    request: Request, cid: int, exits: list[int] = Form([]),
    csrf_token: str = Form(...),
):
    """Which of the account's subnets this configuration uses."""
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    cl = config_row(cid)
    if not cl:
        raise HTTPException(status_code=404)
    if not cl["account_id"]:
        return RedirectResponse(
            f"/configs/{cid}?err={quote('a configuration without an account cannot pick subnets')}",
            status_code=303,
        )
    with db() as conn:
        allowed = set(routed_grants(conn, int(cl["account_id"])))
        wanted = {int(e) for e in exits} & allowed
        write_routed_choice(conn, cl, wanted)
    audit("config_routed", f"{cl['name']} {sorted(wanted)}")
    apply_routing()
    return RedirectResponse(f"/configs/{cid}?ok=subnets+updated", status_code=303)


@app.post("/configs/{cid}/toggle")
def toggle_config(request: Request, cid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    try:
        with db() as conn:
            row = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
            if not row:
                raise HTTPException(status_code=404)
            conn.execute(
                "UPDATE clients SET enabled = ? WHERE id = ?",
                (0 if row["enabled"] else 1, cid),
            )
            apply_conf(cfg(), conn)
    except RuntimeError as exc:
        print(f"config {cid}: {exc}", flush=True)
        return RedirectResponse(
            f"/configs/{cid}?err={quote(apply_error_message(exc, 'nothing changed'))}",
            status_code=303,
        )
    audit("config_toggle", f"{row['name']} -> {0 if row['enabled'] else 1}")
    apply_routing()
    return RedirectResponse(f"/configs/{cid}", status_code=303)


@app.post("/configs/{cid}/account")
def assign_config(
    request: Request, cid: int, account_id: int = Form(...),
    csrf_token: str = Form(...),
):
    """Attaches a configuration created before accounts existed to an account.

    The keys and the address stay, so the device keeps its tunnel. Only the
    source of the grants changes: the account's exits and their order replace
    the legacy per-client rows. If the access class differs (for example the
    account has subnets only), the generated `.conf` changes AllowedIPs and
    DNS, so the device needs the file again.
    """
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    cl = config_row(cid)
    if not cl:
        raise HTTPException(status_code=404)
    if cl["account_id"]:
        return RedirectResponse(
            f"/configs/{cid}?err={quote('this configuration already belongs to an account')}",
            status_code=303,
        )
    account = account_row(account_id)
    if not account:
        raise HTTPException(status_code=404)
    problem = config_limit_error(account)
    if problem:
        return RedirectResponse(
            f"/configs/{cid}?err={quote(problem)}", status_code=303
        )
    with db() as conn:
        conn.execute(
            "UPDATE clients SET account_id = ? WHERE id = ?", (account["id"], cid)
        )
        order = [
            r["exit_id"] for r in conn.execute(
                "SELECT ae.exit_id FROM account_exits ae "
                "JOIN exits e ON e.id = ae.exit_id "
                "WHERE ae.account_id = ? AND e.mode = 'internet' "
                "ORDER BY ae.priority, e.priority, e.id",
                (account["id"],),
            )
        ]
        write_config_order(conn, cid, order)
        # The legacy routed rows are replaced by the account's grants.
        conn.execute("DELETE FROM client_exits WHERE client_id = ?", (cid,))
        for row in conn.execute(
            "SELECT ae.exit_id FROM account_exits ae "
            "JOIN exits e ON e.id = ae.exit_id "
            "WHERE ae.account_id = ? AND e.mode = 'routes'",
            (account["id"],),
        ).fetchall():
            conn.execute(
                "INSERT INTO client_exits (client_id, exit_id) VALUES (?, ?)",
                (cid, row["exit_id"]),
            )
    apply_routing()
    audit("config_assigned", f"{cl['name']} -> {account['email']}")
    return RedirectResponse(
        f"/configs/{cid}?ok={quote('assigned to ' + account['email'])}", status_code=303
    )


@app.post("/configs/{cid}/delete")
def delete_config(request: Request, cid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    try:
        with db() as conn:
            row = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
            if not row:
                raise HTTPException(status_code=404)
            routing.release_table(conn, "client", cid)
            conn.execute("DELETE FROM clients WHERE id = ?", (cid,))
            conn.execute("DELETE FROM client_exits WHERE client_id = ?", (cid,))
            conn.execute("DELETE FROM client_internet_exits WHERE client_id = ?", (cid,))
            drop_traffic(conn, cid)
            apply_conf(cfg(), conn)
    except RuntimeError as exc:
        print(f"config {cid}: {exc}", flush=True)
        return RedirectResponse(
            f"/configs/{cid}?err={quote(apply_error_message(exc, 'nothing was deleted'))}",
            status_code=303,
        )
    audit("config_deleted", row["name"])
    apply_routing()
    return RedirectResponse("/configs?ok=configuration+deleted", status_code=303)


@app.post("/configs/{cid}/reissue")
def reissue_config(request: Request, cid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    cl = config_row(cid)
    if not cl:
        raise HTTPException(status_code=404)
    try:
        with db() as conn:
            reissue_keys(conn, cl)
    except RuntimeError as exc:
        print(f"config {cid}: {exc}", flush=True)
        return RedirectResponse(
            f"/configs/{cid}?err={quote(apply_error_message(exc, 'the key was not changed'))}",
            status_code=303,
        )
    audit("config_key_reissued", cl["name"])
    apply_routing()
    return RedirectResponse(f"/configs/{cid}?ok=key+reissued", status_code=303)


@app.post("/configs/{cid}/order")
def config_order_move(
    request: Request,
    cid: int,
    exit_id: int = Form(...),
    direction: str = Form(...),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    if direction not in ("up", "down"):
        raise HTTPException(status_code=400, detail="direction")
    cl = config_row(cid)
    if not cl:
        raise HTTPException(status_code=404)
    order = [e["id"] for e in config_internet_exits(cl)]
    with db() as conn:
        write_config_order(conn, cid, move_in_order(order, exit_id, direction))
    audit("config_exit_order", f"{cl['name']} {' '.join(str(e) for e in order)}")
    apply_routing()
    return RedirectResponse(f"/configs/{cid}?ok=exit+order+updated", status_code=303)


@app.post("/configs/{cid}/order/reset")
def config_order_reset(request: Request, cid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    cl = config_row(cid)
    if not cl:
        raise HTTPException(status_code=404)
    with db() as conn:
        reset_config_order(conn, cl)
    audit("config_exit_order_reset", cl["name"])
    apply_routing()
    return RedirectResponse(f"/configs/{cid}?ok=order+reset+to+account", status_code=303)


def conf_response(cl, download: bool = True) -> Response:
    """The client config as a download, or as text for the mobile API.

    A browser download must not be text/plain: Android Chrome then ignores the
    .conf extension and saves the file as .txt. The API keeps text/plain, so
    the app reads the body exactly as before.
    """
    try:
        body = config_conf(cfg(), cl)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not download:
        return PlainTextResponse(body)
    return Response(
        body,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{cl["name"]}.conf"'},
    )


def qr_response(cl) -> Response:
    try:
        body = config_conf(cfg(), cl)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
        fh.write(body)
        tmp = fh.name
    os.chmod(tmp, 0o600)
    try:
        res = subprocess.run(
            ["qrencode", "-t", "PNG", "-s", "6", "-o", "-", "-r", tmp],
            capture_output=True,
        )
    finally:
        os.unlink(tmp)
    if res.returncode != 0:
        raise HTTPException(status_code=500, detail="qrencode")
    return Response(res.stdout, media_type="image/png")


@app.get("/configs/{cid}/conf")
def download_conf(request: Request, cid: int):
    require_admin(request)
    cl = config_row(cid)
    if not cl:
        raise HTTPException(status_code=404)
    return conf_response(cl)


@app.get("/configs/{cid}/qr.png")
def qr(request: Request, cid: int):
    require_admin(request)
    cl = config_row(cid)
    if not cl:
        raise HTTPException(status_code=404)
    return qr_response(cl)


# ---------------------------------------------------------------- accounts

@app.get("/accounts", response_class=HTMLResponse)
def accounts_page(request: Request, q: str | None = None):
    token = require_admin(request)
    with db() as conn:
        rows = account_rows(conn)
        counts = {
            r["account_id"]: r["n"] for r in conn.execute(
                "SELECT account_id, count(*) AS n FROM clients "
                "WHERE account_id IS NOT NULL GROUP BY account_id"
            )
        }
    items = [
        {
            "id": a["id"],
            "email": a["email"],
            "enabled": bool(a["enabled"]),
            "limit": max_configs_for(a),
            "max_configs": a["max_configs"],
            "configs_n": counts.get(a["id"], 0),
            "internet": bool(account_exits(int(a["id"]), "internet")),
            "exits": [e["name"] for e in account_exits(int(a["id"]))],
            "last_login": a["last_login"],
        }
        for a in rows
    ]
    if q:
        needle = q.strip().lower()
        items = [a for a in items if needle in a["email"].lower()]
    return render_page(
        request, "accounts.html", "accounts",
        csrf=csrf(token), accounts=items, q=q or "",
    )


@app.get("/accounts/new", response_class=HTMLResponse)
def account_new_page(request: Request, err: str | None = None):
    token = require_admin(request)
    return render_page(
        request, "account_new.html", "accounts",
        csrf=csrf(token), err=err, default_limit=setting("default_max_configs"),
    )


@app.post("/accounts")
def create_account(
    request: Request,
    email: str = Form(...),
    password: str = Form(""),
    max_configs: str = Form(""),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")

    def fail(msg: str):
        return RedirectResponse("/accounts/new?err=" + quote(msg), status_code=303)

    email = normalize_email(email)
    problem = email_error(email)
    if problem:
        return fail(problem)
    password = password or secrets.token_urlsafe(12)
    problem = password_error(password)
    if problem:
        return fail(problem)
    limit = None
    if max_configs.strip():
        try:
            limit = int(max_configs)
        except ValueError:
            return fail("configurations limit must be a number")
        if limit < 1:
            return fail("configurations limit must be at least 1")
    try:
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO accounts (email, password_hash, enabled, "
                "token_version, max_configs, created_at) "
                "VALUES (?, ?, 1, 1, ?, ?)",
                (email, hash_password(password), limit, _now_iso()),
            )
            aid = cur.lastrowid
    except sqlite3.IntegrityError:
        return fail("email is already used by another account")
    audit("account_created", email)
    return RedirectResponse(
        f"/accounts/{aid}?ok=account+created&newpw={quote(stash_secret(password))}",
        status_code=303,
    )


@app.get("/accounts/{aid}", response_class=HTMLResponse)
def account_page(
    request: Request,
    aid: int,
    err: str | None = None,
    ok: str | None = None,
    newpw: str | None = None,
):
    token = require_admin(request)
    account = account_row(aid)
    if not account:
        raise HTTPException(status_code=404)
    live = iface_dump(cfg()["iface"])["peers"]
    configs = [config_view(cl, live) for cl in account_configs(aid)]
    routed = [
        e for e in exits_rows() if e["mode"] == "routes" and e["enabled"]
    ]
    granted = {e["id"] for e in account_exits(aid)}
    return render_page(
        request, "account_detail.html", "accounts",
        csrf=csrf(token), err=err, ok=ok, account=account,
        configs=configs, routed=routed, granted=granted,
        internet_exits=internet_exits_rows(),
        order=account_exits(aid, "internet"),
        limit=max_configs_for(account),
        default_limit=setting("default_max_configs"),
        newpw=pop_secret(newpw),
    )


@app.post("/accounts/{aid}/exits")
def account_exits_update(
    request: Request,
    aid: int,
    exits: list[int] = Form([]),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    account = account_row(aid)
    if not account:
        raise HTTPException(status_code=404)
    with db() as conn:
        allowed = {
            r["id"] for r in conn.execute(
                "SELECT id FROM exits WHERE enabled = 1"
            )
        }
        wanted = {int(e) for e in exits if int(e) in allowed}
        current = {
            r["exit_id"]: r["priority"] for r in conn.execute(
                "SELECT exit_id, priority FROM account_exits WHERE account_id = ?",
                (aid,),
            )
        }
        for exit_id in list(current):
            if exit_id not in wanted:
                conn.execute(
                    "DELETE FROM account_exits WHERE account_id = ? AND exit_id = ?",
                    (aid, exit_id),
                )
        next_priority = max(current.values(), default=0) + 10
        for row in conn.execute(
            "SELECT id FROM exits WHERE enabled = 1 ORDER BY priority, id"
        ).fetchall():
            eid = row["id"]
            if eid in wanted and eid not in current:
                conn.execute(
                    "INSERT INTO account_exits (account_id, exit_id, priority) "
                    "VALUES (?, ?, ?)",
                    (aid, eid, next_priority),
                )
                next_priority += 10
        # Granted exits appear on every configuration; revoked ones go away.
        sync_account_configs(conn, aid)
    audit("account_exits", f"{account['email']} exits={sorted(wanted)}")
    apply_routing()
    return RedirectResponse(f"/accounts/{aid}?ok=access+updated", status_code=303)


@app.post("/accounts/{aid}/order")
def account_order_move(
    request: Request,
    aid: int,
    exit_id: int = Form(...),
    direction: str = Form(...),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    if direction not in ("up", "down"):
        raise HTTPException(status_code=400, detail="direction")
    account = account_row(aid)
    if not account:
        raise HTTPException(status_code=404)
    with db() as conn:
        # Only the internet exits have a user-visible order; routed exits keep
        # their own priority and are never swapped with them.
        order = [
            r["exit_id"] for r in conn.execute(
                "SELECT ae.exit_id FROM account_exits ae "
                "JOIN exits e ON e.id = ae.exit_id "
                "WHERE ae.account_id = ? AND e.mode = 'internet' "
                "ORDER BY ae.priority, e.priority, e.id",
                (aid,),
            )
        ]
        order = move_in_order(order, exit_id, direction)
        for position, eid in enumerate(order):
            conn.execute(
                "UPDATE account_exits SET priority = ? "
                "WHERE account_id = ? AND exit_id = ?",
                ((position + 1) * 10, aid, eid),
            )
    audit("account_exit_order", f"{account['email']} {' '.join(str(e) for e in order)}")
    return RedirectResponse(f"/accounts/{aid}?ok=order+updated", status_code=303)


@app.post("/accounts/{aid}/order/apply")
def account_order_apply(request: Request, aid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    account = account_row(aid)
    if not account:
        raise HTTPException(status_code=404)
    with db() as conn:
        sync_account_configs(conn, aid, reset_order=True)
    audit("account_exit_order_applied", account["email"])
    apply_routing()
    return RedirectResponse(
        f"/accounts/{aid}?ok=order+applied+to+all+configurations", status_code=303
    )


@app.post("/accounts/{aid}/max-configs")
def account_max_configs(
    request: Request,
    aid: int,
    max_configs: str = Form(""),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    account = account_row(aid)
    if not account:
        raise HTTPException(status_code=404)
    value = None
    if max_configs.strip():
        try:
            value = int(max_configs)
        except ValueError:
            return RedirectResponse(
                f"/accounts/{aid}?err=" + quote("limit must be a number"),
                status_code=303,
            )
        if value < 1:
            return RedirectResponse(
                f"/accounts/{aid}?err=" + quote("limit must be at least 1"),
                status_code=303,
            )
        have = len(account_configs(aid))
        if value < have:
            return RedirectResponse(
                f"/accounts/{aid}?err="
                + quote(f"the account already has {have} configurations"),
                status_code=303,
            )
    with db() as conn:
        conn.execute(
            "UPDATE accounts SET max_configs = ? WHERE id = ?", (value, aid)
        )
    audit(
        "account_max_configs",
        f"{account['email']} {'default' if value is None else value}",
    )
    return RedirectResponse(f"/accounts/{aid}?ok=limit+updated", status_code=303)


@app.post("/accounts/{aid}/configs")
def account_create_config(
    request: Request,
    aid: int,
    name: str = Form(""),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    account = account_row(aid)
    if not account:
        raise HTTPException(status_code=404)
    problem = config_limit_error(account)
    if problem:
        return RedirectResponse(f"/accounts/{aid}?err=" + quote(problem), status_code=303)
    try:
        with db() as conn:
            cid = spawn_config(conn, account, name)
    except (RuntimeError, ValueError) as exc:
        message = (
            apply_error_message(exc, "nothing was saved")
            if isinstance(exc, RuntimeError) else str(exc)
        )
        return RedirectResponse(f"/accounts/{aid}?err=" + quote(message), status_code=303)
    audit("config_added", f"{account['email']} {name or cid}")
    apply_routing()
    return RedirectResponse(f"/configs/{cid}?ok=configuration+created", status_code=303)


@app.post("/accounts/{aid}/password")
def account_reset(request: Request, aid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    account = account_row(aid)
    if not account:
        raise HTTPException(status_code=404)
    password = secrets.token_urlsafe(12)
    with db() as conn:
        conn.execute(
            "UPDATE accounts SET password_hash = ?, "
            "token_version = token_version + 1 WHERE id = ?",
            (hash_password(password), aid),
        )
        conn.execute("UPDATE sessions SET revoked = 1 WHERE uid = ?", (aid,))
    audit("account_password_reset", account["email"])
    return RedirectResponse(
        f"/accounts/{aid}?ok=password+reset&newpw={quote(stash_secret(password))}",
        status_code=303,
    )


@app.post("/accounts/{aid}/toggle")
def account_toggle(request: Request, aid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    account = account_row(aid)
    if not account:
        raise HTTPException(status_code=404)
    enabled = 0 if account["enabled"] else 1
    with db() as conn:
        conn.execute(
            "UPDATE accounts SET enabled = ?, token_version = token_version + 1 "
            "WHERE id = ?",
            (enabled, aid),
        )
        conn.execute("UPDATE sessions SET revoked = 1 WHERE uid = ?", (aid,))
    audit("account_toggle", f"{account['email']} -> {enabled}")
    return RedirectResponse(
        f"/accounts/{aid}?ok=" + ("account+enabled" if enabled else "account+disabled"),
        status_code=303,
    )


@app.post("/accounts/{aid}/delete")
def account_delete(request: Request, aid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    account = account_row(aid)
    if not account:
        raise HTTPException(status_code=404)
    try:
        with db() as conn:
            configs = [
                r["id"] for r in conn.execute(
                    "SELECT id FROM clients WHERE account_id = ?", (aid,)
                )
            ]
            conn.execute("UPDATE sessions SET revoked = 1 WHERE uid = ?", (aid,))
            for cid in configs:
                routing.release_table(conn, "client", cid)
                conn.execute("DELETE FROM clients WHERE id = ?", (cid,))
                conn.execute("DELETE FROM client_exits WHERE client_id = ?", (cid,))
                conn.execute(
                    "DELETE FROM client_internet_exits WHERE client_id = ?", (cid,)
                )
                drop_traffic(conn, cid)
            conn.execute("DELETE FROM account_exits WHERE account_id = ?", (aid,))
            conn.execute("DELETE FROM accounts WHERE id = ?", (aid,))
            apply_conf(cfg(), conn)
    except RuntimeError as exc:
        print(f"account {aid}: {exc}", flush=True)
        return RedirectResponse(
            f"/accounts/{aid}?err={quote(apply_error_message(exc, 'nothing was deleted'))}",
            status_code=303,
        )
    audit("account_deleted", f"{account['email']} {len(configs)} configurations")
    apply_routing()
    return RedirectResponse("/accounts?ok=account+deleted", status_code=303)


# ---------------------------------------------------------------- self service

def account_first_config(account):
    configs = account_configs(int(account["id"]))
    return configs[0] if configs else None


def user_config(account, cid: int):
    """A configuration of this account, or 404 — never another account's."""
    cl = config_row(cid)
    if not cl or cl["account_id"] != account["id"]:
        raise HTTPException(status_code=404)
    return cl


@app.get("/me", response_class=HTMLResponse)
def me_page(request: Request, err: str | None = None, ok: str | None = None):
    token, account = require_user(request)
    live = iface_dump(cfg()["iface"])["peers"]
    configs = [config_view(cl, live) for cl in account_configs(int(account["id"]))]
    return render_page(
        request, "me.html", "me", role="user",
        csrf=csrf(token), err=err, ok=ok, configs=configs,
        email=account["email"], last_login=human_ts(account["last_login"]),
        limit=max_configs_for(account),
        has_app=ANDROID_APK.exists(),
    )


@app.get("/me/account", response_class=HTMLResponse)
def me_account(request: Request, err: str | None = None, ok: str | None = None):
    token, account = require_user(request)
    return render_page(request, "me_account.html", "account", role="user",
                       csrf=csrf(token), email=account["email"], err=err, ok=ok)


@app.get("/me/configs/new", response_class=HTMLResponse)
def me_config_new_page(request: Request, err: str | None = None):
    token, account = require_user(request)
    configs = account_configs(int(account["id"]))
    return render_page(
        request, "me_config_new.html", "me", role="user",
        csrf=csrf(token), err=err, have=len(configs),
        limit=max_configs_for(account),
    )


@app.post("/me/configs")
def me_create_config(
    request: Request,
    name: str = Form(""),
    csrf_token: str = Form(...),
):
    token, account = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    problem = config_limit_error(account)
    if problem:
        return RedirectResponse(
            "/me/configs/new?err=" + quote(problem), status_code=303
        )
    try:
        with db() as conn:
            cid = spawn_config(conn, account, name)
    except (RuntimeError, ValueError) as exc:
        message = (
            apply_error_message(exc, "nothing was saved")
            if isinstance(exc, RuntimeError) else str(exc)
        )
        return RedirectResponse(
            "/me/configs/new?err=" + quote(message), status_code=303
        )
    audit("user_config_added", f"{account['email']} {name or cid}")
    apply_routing()
    return RedirectResponse(
        f"/me/configs/{cid}?ok=configuration+created", status_code=303
    )


@app.post("/me/configs/{cid}/name")
def me_config_rename(
    request: Request, cid: int, name: str = Form(""),
    csrf_token: str = Form(...),
):
    token, account = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    cl = user_config(account, cid)
    name = name.strip()
    if not NAME_RE.match(name):
        problem = "name: latin letters, digits, dot, dash; up to 32 characters"
        return RedirectResponse(
            f"/me/configs/{cid}?err=" + quote(problem), status_code=303
        )
    with db() as conn:
        taken = conn.execute(
            "SELECT id FROM clients WHERE name = ? AND id != ?", (name, cid)
        ).fetchone()
        if taken:
            problem = "a configuration with this name already exists"
            return RedirectResponse(
                f"/me/configs/{cid}?err=" + quote(problem), status_code=303
            )
        conn.execute("UPDATE clients SET name = ? WHERE id = ?", (name, cid))
    audit("user_config_renamed", f"{account['email']} {cl['name']} -> {name}")
    return RedirectResponse(
        f"/me/configs/{cid}?ok=name+updated", status_code=303
    )


@app.get("/me/configs/{cid}", response_class=HTMLResponse)
def me_config_page(
    request: Request,
    cid: int,
    period: str = Query("24h", alias="range"),
    err: str | None = None,
    ok: str | None = None,
):
    token, account = require_user(request)
    cl = user_config(account, cid)
    c = cfg()
    live = iface_dump(c["iface"])["peers"]
    status, routing_fresh = routing_status()
    granted = config_internet_exits(cl)
    current_iface = (status.get("clients") or {}).get(cl["ip"]) or ""
    current = next((e for e in granted if e["iface"] == current_iface), None)
    states = status.get("exits") or {}
    known = exits_rows()
    alive = {
        e["iface"]: (bool(states.get(e["iface"], {}).get("alive")) if routing_fresh else None)
        for e in known
    }
    latency = {
        e["iface"]: (states.get(e["iface"], {}).get("rtt_ms") if routing_fresh else None)
        for e in known
    }
    try:
        conf = mask_conf(config_conf(c, cl))
    except ValueError:
        conf = None
    chosen_routed = {e["id"] for e in config_routed_exits(cl)}
    view = config_view(cl, live)
    return render_page(
        request, "me_config.html", "me", role="user",
        csrf=csrf(token), err=err, ok=ok, email=account["email"],
        cl=view, diagnosis=configuration_diagnosis(view, status, int(time.time())),
        conf=conf, internet_exits=granted, current_exit=current,
        alive=alive, latency=latency, has_app=ANDROID_APK.exists(),
        routing_fresh=routing_fresh,
        **traffic_context(cid, period),
        routed_choices=[
            {"id": r["id"], "name": r["comment"] or r["name"], "routes": r["routes"],
             "chosen": r["id"] in chosen_routed}
            for r in config_routed_choices(account)
        ],
    )


@app.post("/me/configs/{cid}/routed")
def me_config_routed(
    request: Request, cid: int, exits: list[int] = Form([]),
    csrf_token: str = Form(...),
):
    token, account = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    cl = user_config(account, cid)
    with db() as conn:
        allowed = set(routed_grants(conn, int(account["id"])))
        wanted = {int(e) for e in exits} & allowed
        write_routed_choice(conn, cl, wanted)
    audit("user_config_routed", f"{account['email']} {cl['name']} {sorted(wanted)}")
    apply_routing()
    return RedirectResponse(f"/me/configs/{cid}?ok=subnets+updated", status_code=303)


@app.get("/me/configs/{cid}/conf")
def me_config_conf(request: Request, cid: int):
    _, account = require_user(request)
    cl = user_config(account, cid)
    audit("config_downloaded", f"{account['email']} {cl['name']}")
    return conf_response(cl)


@app.get("/me/configs/{cid}/qr.png")
def me_config_qr(request: Request, cid: int):
    _, account = require_user(request)
    return qr_response(user_config(account, cid))


@app.post("/me/configs/{cid}/order")
def me_config_order(request: Request, cid: int, exit_id: int = Form(...),
                    direction: str = Form(...), csrf_token: str = Form(...)):
    token, account = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    if direction not in ("up", "down"):
        raise HTTPException(status_code=400, detail="direction")
    cl = user_config(account, cid)
    order = [e["id"] for e in config_internet_exits(cl)]
    with db() as conn:
        write_config_order(conn, cid, move_in_order(order, exit_id, direction))
    audit("user_exit_order", f"{account['email']} {cl['name']} {' '.join(str(e) for e in order)}")
    apply_routing()
    return RedirectResponse(
        f"/me/configs/{cid}?ok=exit+order+updated", status_code=303
    )


@app.post("/me/configs/{cid}/order/reset")
def me_config_order_reset(request: Request, cid: int, csrf_token: str = Form(...)):
    token, account = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    cl = user_config(account, cid)
    with db() as conn:
        reset_config_order(conn, cl)
    audit("user_exit_order_reset", f"{account['email']} {cl['name']}")
    apply_routing()
    return RedirectResponse(
        f"/me/configs/{cid}?ok=order+reset+to+account", status_code=303
    )


@app.post("/me/configs/{cid}/toggle")
def me_config_toggle(request: Request, cid: int, csrf_token: str = Form(...)):
    token, account = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    cl = user_config(account, cid)
    try:
        with db() as conn:
            conn.execute(
                "UPDATE clients SET enabled = ? WHERE id = ?",
                (0 if cl["enabled"] else 1, cid),
            )
            apply_conf(cfg(), conn)
    except RuntimeError as exc:
        print(f"config {cid}: {exc}", flush=True)
        return RedirectResponse(
            f"/me/configs/{cid}?err="
            + quote(apply_error_message(exc, "nothing changed")),
            status_code=303,
        )
    audit("user_config_toggle", f"{account['email']} {cl['name']}")
    apply_routing()
    return RedirectResponse(f"/me/configs/{cid}", status_code=303)


@app.post("/me/configs/{cid}/delete")
def me_config_delete(request: Request, cid: int, csrf_token: str = Form(...)):
    token, account = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    cl = user_config(account, cid)
    try:
        with db() as conn:
            routing.release_table(conn, "client", cid)
            conn.execute("DELETE FROM clients WHERE id = ?", (cid,))
            conn.execute("DELETE FROM client_exits WHERE client_id = ?", (cid,))
            conn.execute("DELETE FROM client_internet_exits WHERE client_id = ?", (cid,))
            drop_traffic(conn, cid)
            apply_conf(cfg(), conn)
    except RuntimeError as exc:
        print(f"config {cid}: {exc}", flush=True)
        return RedirectResponse(
            f"/me/configs/{cid}?err="
            + quote(apply_error_message(exc, "nothing was deleted")),
            status_code=303,
        )
    audit("user_config_deleted", f"{account['email']} {cl['name']}")
    apply_routing()
    return RedirectResponse("/me?ok=configuration+deleted", status_code=303)


@app.post("/me/configs/{cid}/reissue")
def me_config_reissue(request: Request, cid: int, csrf_token: str = Form(...)):
    token, account = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    cl = user_config(account, cid)
    try:
        with db() as conn:
            reissue_keys(conn, cl)
    except RuntimeError as exc:
        print(f"config {cid}: {exc}", flush=True)
        return RedirectResponse(
            f"/me/configs/{cid}?err="
            + quote(apply_error_message(exc, "your key was not changed")),
            status_code=303,
        )
    audit("user_key_reissued", f"{account['email']} {cl['name']}")
    apply_routing()
    return RedirectResponse(f"/me/configs/{cid}?ok=key+reissued", status_code=303)


@app.get("/download/android")
def download_android():
    """The Android client APK, served from a file the deploy drops next to
    the database; 404 until the administrator uploads one."""
    if not ANDROID_APK.exists():
        raise HTTPException(status_code=404, detail="no app uploaded yet")
    return FileResponse(
        ANDROID_APK,
        media_type="application/vnd.android.package-archive",
        filename="deepskaskad.apk",
    )


@app.get("/me/conf")
def me_conf(request: Request):
    """Compatibility: the first configuration, for the released app."""
    _, account = require_user(request)
    cl = account_first_config(account)
    if not cl:
        raise HTTPException(status_code=409, detail="no configuration yet")
    audit("config_downloaded", f"{account['email']} {cl['name']}")
    return conf_response(cl)


@app.get("/me/qr.png")
def me_qr(request: Request):
    _, account = require_user(request)
    cl = account_first_config(account)
    if not cl:
        raise HTTPException(status_code=409, detail="no configuration yet")
    return qr_response(cl)


@app.post("/me/exits/move")
def me_exit_move(
    request: Request,
    exit_id: int = Form(...),
    direction: str = Form(...),
    csrf_token: str = Form(...),
):
    """Compatibility: reorders the first configuration, like /me/conf."""
    token, account = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    if direction not in ("up", "down"):
        raise HTTPException(status_code=400, detail="direction")
    cl = account_first_config(account)
    if not cl:
        raise HTTPException(status_code=404)
    order = [e["id"] for e in config_internet_exits(cl)]
    with db() as conn:
        write_config_order(conn, cl["id"], move_in_order(order, exit_id, direction))
    audit("user_exit_order", f"{account['email']} {' '.join(str(e) for e in order)}")
    apply_routing()
    return RedirectResponse("/me?ok=exit+order+updated", status_code=303)


@app.post("/me/password")
def me_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    csrf_token: str = Form(...),
):
    token, account = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    if not check_password(current_password, account["password_hash"]):
        return RedirectResponse("/me/account?err=" + quote("current password is wrong"), status_code=303)
    problem = password_error(new_password, "new password")
    if problem:
        return RedirectResponse("/me/account?err=" + quote(problem), status_code=303)
    new_hash = hash_password(new_password)
    with db() as conn:
        conn.execute(
            "UPDATE accounts SET password_hash = ?, "
            "token_version = token_version + 1 WHERE id = ?",
            (new_hash, account["id"]),
        )
        # Every other session of this account dies with the password change.
        conn.execute("UPDATE sessions SET revoked = 1 WHERE uid = ?", (account["id"],))
        tv = conn.execute(
            "SELECT token_version FROM accounts WHERE id = ?", (account["id"],)
        ).fetchone()[0]
    audit("user_password_changed", account["email"])
    response = RedirectResponse("/me/account?ok=password+changed", status_code=303)
    response.set_cookie(
        COOKIE, start_session("user", int(account["id"]), int(tv)),
        httponly=True, secure=True, samesite="strict", max_age=SESSION_TTL,
    )
    return response


@app.post("/me/logout-all")
def me_logout_all(request: Request, csrf_token: str = Form(...)):
    token, account = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    revoke_user_sessions(int(account["id"]))
    audit("user_sessions_revoked", account["email"])
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE)
    return response


# ------------------------------------------------------------- mobile API
#
# Bearer-token API for the mobile app (a WireGuard Android fork). The app
# signs in with the same email/password as the /me page, gets a long-lived
# token, and manages its own configurations. Admin accounts are not accepted
# here: the app only ever needs client configurations.

API_SESSION_TTL = 30 * 86400


def api_user(request: Request):
    """Bearer auth for the app: the account row or a JSON 401, never a redirect."""
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    data = session_data(token)
    if not data or data["role"] != "user" or not session_alive(data):
        raise HTTPException(status_code=401, detail="sign in again")
    row = account_row(int(data.get("uid", 0)))
    if not row or not row["enabled"] or row["token_version"] != data.get("tv"):
        raise HTTPException(status_code=401, detail="account disabled")
    return token, row


def api_configs(account) -> list[dict]:
    live = iface_dump(cfg()["iface"])["peers"]
    return [config_view(cl, live) for cl in account_configs(int(account["id"]))]


def api_config(account, config_id: int | None):
    """The requested configuration of this account, or its first one."""
    configs = account_configs(int(account["id"]))
    if not configs:
        raise HTTPException(
            status_code=409, detail="no configuration yet; create one first"
        )
    if config_id is None or config_id == 0:
        return configs[0]
    for cl in configs:
        if cl["id"] == config_id:
            return cl
    raise HTTPException(status_code=404, detail="configuration not found")


@app.post("/api/login")
def api_login(request: Request, email: str = Form(""), password: str = Form(...)):
    ip = request.client.host if request.client else "?"
    ip_key = rate_key(ip)
    email = normalize_email(email)
    if rate_limited(ip_key, email):
        raise HTTPException(status_code=429, detail="too many attempts, wait 5 minutes")

    row = None
    if email and email != ADMIN_LOGIN:
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE email = ?", (email,)
            ).fetchone()
    ok = bool(
        row
        and check_password(password, row["password_hash"])
        and row["enabled"]
    )
    if not row:
        _burn_hash(password)
    if not ok:
        delay = login_delay(email)
        if delay:
            time.sleep(delay)
        note_failure(ip_key, email)
        safe_email = re.sub(r"[\x00-\x1f\x7f]", "", email)[:254] or "-"
        print(f"KASKAD_AUTH_FAIL ip={ip} email={safe_email} via=api", flush=True)
        audit("api_login_failed", f"{ip} {safe_email}")
        raise HTTPException(status_code=401, detail="wrong email or password")

    uid, tv = int(row["id"]), int(row["token_version"])
    token = start_session("user", uid, tv, ttl=API_SESSION_TTL)
    with db() as conn:
        conn.execute("UPDATE accounts SET last_login = ? WHERE id = ?", (_now_iso(), uid))
    clear_failures(ip_key, email)
    prune_sessions()
    audit("api_login", f"{email} {ip}")
    configs = api_configs(row)
    return {
        "token": token,
        "expires_at": session_data(token)["exp"],
        "email": email,
        "client": configs[0] if configs else None,
        "configs": configs,
    }


@app.get("/api/me")
def api_me(request: Request):
    _, account = api_user(request)
    configs = api_configs(account)
    return {
        "email": account["email"],
        "client": configs[0] if configs else None,
        "configs": configs,
    }


@app.post("/api/me/configs")
def api_create_config(
    request: Request, name: str = Form(""), device_id: str = Form("")
):
    """Creates a configuration, or returns the one this device already has.

    The app sends the device identifier on every first connect, so a reinstall
    must not leave the account with a second configuration of the same phone.
    """
    _, account = api_user(request)
    device_id = device_id.strip()
    if device_id:
        if not DEVICE_ID_RE.match(device_id):
            raise HTTPException(
                status_code=400,
                detail="device_id: latin letters, digits, dash; 8 to 64 characters",
            )
        known = config_by_device(int(account["id"]), device_id)
        if known:
            audit("user_config_reused", f"{account['email']} {known['name']} via=api")
            return {
                "config": created_config_view(known),
                "configs": api_configs(account),
            }
    problem = config_limit_error(account)
    if problem:
        raise HTTPException(status_code=409, detail=problem)
    try:
        with db() as conn:
            cid = spawn_config(conn, account, name, device_id, uniquify=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except sqlite3.IntegrityError:
        # Two first connects of one device raced: the unique index kept one
        # row, and the loser answers with it instead of an error.
        known = config_by_device(int(account["id"]), device_id) if device_id else None
        if not known:
            raise HTTPException(status_code=409, detail="configuration already exists")
        audit("user_config_reused", f"{account['email']} {known['name']} via=api")
        return {
            "config": created_config_view(known),
            "configs": api_configs(account),
        }
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=apply_error_message(exc, "not saved"))
    audit("user_config_added", f"{account['email']} {name or cid} via=api")
    apply_routing()
    return {
        "config": created_config_view(config_row(cid)),
        "configs": api_configs(account),
    }


@app.post("/api/me/configs/{cid}/toggle")
def api_toggle_config(request: Request, cid: int):
    _, account = api_user(request)
    cl = api_config(account, cid)
    try:
        with db() as conn:
            conn.execute(
                "UPDATE clients SET enabled = ? WHERE id = ?",
                (0 if cl["enabled"] else 1, cid),
            )
            apply_conf(cfg(), conn)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=apply_error_message(exc, "not changed"))
    audit("user_config_toggle", f"{account['email']} {cl['name']} via=api")
    apply_routing()
    return {"ok": True, "enabled": not bool(cl["enabled"])}


@app.delete("/api/me/configs/{cid}")
def api_delete_config(request: Request, cid: int):
    _, account = api_user(request)
    cl = api_config(account, cid)
    try:
        with db() as conn:
            routing.release_table(conn, "client", cid)
            conn.execute("DELETE FROM clients WHERE id = ?", (cid,))
            conn.execute("DELETE FROM client_exits WHERE client_id = ?", (cid,))
            conn.execute("DELETE FROM client_internet_exits WHERE client_id = ?", (cid,))
            drop_traffic(conn, cid)
            apply_conf(cfg(), conn)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=apply_error_message(exc, "not deleted"))
    audit("user_config_deleted", f"{account['email']} {cl['name']} via=api")
    apply_routing()
    return {"ok": True}


@app.get("/api/me/conf")
def api_conf(request: Request, config_id: int | None = None):
    """The awg0 client config, ready to import into a WireGuard client."""
    _, account = api_user(request)
    cl = api_config(account, config_id)
    audit("config_downloaded", f"{account['email']} {cl['name']} via=api")
    return conf_response(cl, download=False)


@app.get("/api/me/configs/{cid}/conf")
def api_config_conf(request: Request, cid: int):
    _, account = api_user(request)
    cl = api_config(account, cid)
    audit("config_downloaded", f"{account['email']} {cl['name']} via=api")
    return conf_response(cl, download=False)


@app.get("/api/me/configs/{cid}/traffic")
def api_config_traffic(request: Request, cid: int, hours: int = 24):
    """Traffic deltas of one configuration.

    Five-minute points for a week, hourly beyond that; a gap means the
    sampler was not running, an empty list means there is no history yet.
    """
    _, account = api_user(request)
    cl = api_config(account, cid)
    hours = max(1, min(hours, 2160))
    step, since, now, rows = config_traffic_rows(cl["id"], hours)
    return {
        "config_id": cl["id"],
        "step_seconds": step,
        "points": [
            {"ts": r["ts"], "rx": r["rx"], "tx": r["tx"]} for r in rows
        ],
    }


@app.post("/api/logout")
def api_logout(request: Request):
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    revoke_session(token)
    return {"ok": True}


@app.get("/api/me/exits")
def api_exits(request: Request, config_id: int | None = None):
    """Internet exits of one configuration, in its order.

    An empty list means the administrator granted none: the client then rides
    the automatic active exit and has nothing to switch.
    """
    _, account = api_user(request)
    cl = api_config(account, config_id)
    status, fresh = routing_status()
    known = status.get("exits", {})
    return [
        {
            "id": e["id"],
            "name": e["name"],
            "comment": e["comment"],
            # null while the failover daemon has not reported: the panel has
            # not observed this exit and must not claim that it is up.
            "alive": bool(known.get(e["iface"], {}).get("alive")) if fresh else None,
            "rtt_ms": known.get(e["iface"], {}).get("rtt_ms") if fresh else None,
            "status_fresh": fresh,
        }
        for e in config_internet_exits(cl)
    ]


@app.post("/api/me/exits/order")
def api_exits_order(
    request: Request,
    exit_id: list[int] = Form(...),
    config_id: int = Form(0),
):
    """Sets one configuration's exit order; every granted exit must be
    present exactly once, so a partial or foreign list is rejected."""
    _, account = api_user(request)
    cl = api_config(account, config_id)
    granted = [e["id"] for e in config_internet_exits(cl)]
    if sorted(exit_id) != sorted(granted):
        raise HTTPException(
            status_code=400, detail="the order must list every granted exit once"
        )
    with db() as conn:
        write_config_order(conn, cl["id"], exit_id)
    audit(
        "user_exit_order",
        f"{account['email']} {cl['name']} {' '.join(str(e) for e in exit_id)} via=api",
    )
    apply_routing()
    return {"ok": True}


@app.get("/api/me/subnets")
def api_subnets(request: Request, config_id: int | None = None):
    """Subnet exits the account allows, with the choice of this configuration.

    A configuration uses only the subnets switched on here: they end up in the
    AllowedIPs of its .conf, and routing installs a rule for each of them.
    """
    _, account = api_user(request)
    cl = api_config(account, config_id)
    chosen = {e["id"] for e in config_routed_exits(cl)}
    return [
        {
            "id": e["id"],
            "name": e["name"],
            "comment": e["comment"],
            "routes": e["routes"],
            "enabled": e["id"] in chosen,
        }
        for e in config_routed_choices(account)
    ]


@app.post("/api/me/subnets")
def api_subnets_update(
    request: Request,
    subnet_id: list[int] = Form([]),
    config_id: int = Form(0),
):
    """Switches subnets on for one configuration.

    A subset of the account's grants is enough (unlike the exit order, a
    subnet is simply on or off); an empty list turns all of them off.
    """
    _, account = api_user(request)
    cl = api_config(account, config_id)
    with db() as conn:
        allowed = set(routed_grants(conn, int(account["id"])))
        wanted = {int(s) for s in subnet_id}
        if not wanted <= allowed:
            raise HTTPException(
                status_code=400,
                detail="the account does not grant all of these subnets",
            )
        write_routed_choice(conn, cl, wanted)
    audit(
        "user_subnets",
        f"{account['email']} {cl['name']} {' '.join(str(s) for s in sorted(wanted))} via=api",
    )
    apply_routing()
    chosen = {e["id"] for e in config_routed_exits(cl)}
    return {
        "ok": True,
        "subnets": [
            {"id": e["id"], "name": e["name"], "enabled": e["id"] in chosen}
            for e in config_routed_choices(account)
        ],
    }


@app.get("/status.json")
def status_json(request: Request, overview: bool = False):
    """Live numbers for the page scripts.

    The pages render everything server-side; this endpoint only feeds the
    ticker that updates handshakes, traffic and exit health in place, so the
    browse does not reload and lose scroll, focus or an open <details>.
    """
    token = request.cookies.get(COOKIE)
    data = session_data(token)
    if not data or not session_alive(data):
        raise HTTPException(status_code=401, detail="sign in again")
    role = data.get("role")
    account = None
    if role == "user":
        account = account_row(int(data.get("uid", 0)))
        if (not account or not account["enabled"]
                or account["token_version"] != data.get("tv")):
            raise HTTPException(status_code=401, detail="account disabled")
    elif role != "admin":
        raise HTTPException(status_code=401, detail="sign in again")

    c = cfg()
    status, status_fresh = routing_status()
    live = iface_dump(c["iface"])["peers"]
    now = int(time.time())
    rows = account_configs(int(account["id"])) if account else config_rows()
    views = [config_view(cl, live) for cl in rows]
    shared = {cl["id"] for cl in rows if not cl["account_id"] and cl["internet"]
              and not config_internet_exits(cl)}
    exits = {
        e["iface"]: {
            "name": e["name"],
            "enabled": bool(e["enabled"]),
            "mode": e["mode"],
            "alive": (status.get("exits") or {}).get(e["iface"], {}).get("alive"),
            "rtt_ms": (status.get("exits") or {}).get(e["iface"], {}).get("rtt_ms"),
            "last_ok": (status.get("exits") or {}).get(e["iface"], {}).get("last_ok", 0),
        }
        for e in exits_rows()
    }
    current = status.get("clients") or {}
    health = {}
    if overview and role == "admin":
        active = run_dir("active-exit") if status_fresh else None
        health["overview"] = overview_health(
            [exit_view(e, status, active) for e in exits_rows()], status_fresh
        )
    return {
        **health,
        "ts": now,
        "status_fresh": status_fresh,
        "active": status.get("active"),
        "online": sum(1 for v in views if v["handshake"] and now - v["handshake"] < 180),
        "rx": sum(v["rx"] for v in views),
        "tx": sum(v["tx"] for v in views),
        "exits_alive": sum(1 for e in exits.values() if e["alive"]),
        "exits_total": len(exits),
        "configs_total": len(views),
        "exits": exits,
        "configs": {
            v["ip"]: {
                "name": v["name"],
                "enabled": v["enabled"],
                "handshake": v["handshake"],
                "rx": v["rx"],
                "tx": v["tx"],
                "iface": current.get(v["ip"], ""),
                "diagnosis": configuration_diagnosis(
                    v, status, now, v["id"] in shared
                ),
            }
            for v in views
        },
    }


# ---------------------------------------------------------------- journal

@app.get("/journal", response_class=HTMLResponse)
def journal_page(request: Request, action: str | None = None, page: int = 1):
    token = require_admin(request)
    per = 50
    page = max(1, page)
    where, params = "", []
    if action:
        where, params = "WHERE action = ?", [action]
    with db() as conn:
        total = conn.execute(f"SELECT count(*) FROM audit {where}", params).fetchone()[0]
        events = conn.execute(
            f"SELECT ts, action, detail FROM audit {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [per, (page - 1) * per],
        ).fetchall()
        actions = [r[0] for r in conn.execute(
            "SELECT action, count(*) c FROM audit GROUP BY action ORDER BY c DESC"
        ).fetchall()]
    pages = max(1, (total + per - 1) // per)
    return render_page(
        request, "journal.html", "journal",
        events=events, actions=actions, action=action or "",
        page=page, pages=pages, total=total,
    )


# ---------------------------------------------------------------- settings

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, ok: str | None = None, err: str | None = None):
    token = require_admin(request)
    c = cfg()
    with db() as conn:
        accounts_n = conn.execute("SELECT count(*) FROM accounts").fetchone()[0]
        configs_n = conn.execute("SELECT count(*) FROM clients").fetchone()[0]
        exits_n = conn.execute("SELECT count(*) FROM exits").fetchone()[0]
        audits_n = conn.execute("SELECT count(*) FROM audit").fetchone()[0]
    db_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    return render_page(
        request, "settings.html", "settings",
        cfg=c, csrf=csrf(token), ok=ok, err=err,
        accounts_n=accounts_n, configs_n=configs_n, exits_n=exits_n,
        audits_n=audits_n, default_max_configs=setting("default_max_configs"),
        login_anonymous=setting("login_anonymous") == "1",
        db_size=db_size, status=services(),
    )


@app.post("/settings/max-configs")
def settings_max_configs(
    request: Request,
    default_max_configs: str = Form(...),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    try:
        value = int(default_max_configs)
    except ValueError:
        value = 0
    if value < 1:
        return RedirectResponse(
            "/settings?err=" + quote("the default limit must be at least 1"),
            status_code=303,
        )
    set_setting("default_max_configs", str(value))
    audit("settings_max_configs", str(value))
    return RedirectResponse("/settings?ok=default+limit+updated", status_code=303)


@app.post("/settings/login-anonymous")
def settings_login_anonymous(
    request: Request,
    csrf_token: str = Form(...),
    enabled: str = Form(""),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    value = "1" if enabled else "0"
    set_setting("login_anonymous", value)
    audit("settings_login_anonymous", value)
    return RedirectResponse("/settings?ok=sign-in+page+updated", status_code=303)


# ---------------------------------------------------------------- cli

def cli_seed(path: str) -> None:
    init_db()
    c = cfg()
    server_key(c)
    data = json.loads(Path(path).read_text())
    clients_in = data if isinstance(data, list) else data.get("clients", [])
    exits_in = [] if isinstance(data, list) else data.get("exits", [])

    imported_exits = []
    with db() as conn:
        for item in exits_in:
            if conn.execute("SELECT 1 FROM exits WHERE name = ?", (item["name"],)).fetchone():
                continue
            iface = item.get("iface") or free_iface(conn)
            conn.execute(
                "INSERT INTO exits (name, iface, priority, enabled, conf, created_at, mode, routes, dns) "
                "VALUES (?, ?, ?, 1, ?, ?, 'internet', '', '')",
                (item["name"], iface, int(item.get("priority", 10)), item["conf"],
                 datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
            imported_exits.append({"name": item["name"], "iface": iface})

    for item in imported_exits:
        audit("exit_imported", f"{item['name']} {item['iface']}")
        row = next((r for r in exits_rows() if r["name"] == item["name"]), None)
        if row:
            apply_exit(c, row)

    imported = []
    with db() as conn:
        for item in clients_in:
            if conn.execute("SELECT 1 FROM clients WHERE name = ?", (item["name"],)).fetchone():
                continue
            conn.execute(
                "INSERT INTO clients (name, ip, public_key, private_key, preshared_key, enabled, created_at) "
                "VALUES (?, ?, ?, ?, ?, 1, ?)",
                (
                    item["name"], item["ip"], item["public_key"], item["private_key"],
                    item.get("preshared_key") or genpsk(),
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ),
            )
            imported.append(item)
    for item in imported:
        audit("client_imported", f"{item['name']} {item['ip']}")
    apply_conf(c)
    print(f"imported {len(imported)} clients, {len(imported_exits)} exits")


def cli_conf(name: str) -> None:
    init_db()
    c = cfg()
    with db() as conn:
        cl = conn.execute("SELECT * FROM clients WHERE name = ?", (name,)).fetchone()
    if not cl:
        sys.exit("no such client")
    print(config_conf(c, cl), end="")


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] == "serve":
        import uvicorn
        init_db()
        c = cfg()
        server_key(c)
        # On a fresh install awg0.conf does not exist yet — render and start it.
        try:
            apply_conf(c)
        except Exception as exc:
            print(f"awg0: {exc}", flush=True)
        apply_routing()
        uvicorn.run(
            "app:app",
            host=c["listen"]["host"],
            port=c["listen"]["port"],
            ssl_certfile=c["tls"]["cert"],
            ssl_keyfile=c["tls"]["key"],
            access_log=False,
            server_header=False,
            app_dir=str(BASE),
        )
    elif sys.argv[1] == "sync":
        init_db()
        apply_conf(cfg())
        print("awg0 updated")
    elif sys.argv[1] == "seed" and len(sys.argv) == 3:
        cli_seed(sys.argv[2])
    elif sys.argv[1] == "conf" and len(sys.argv) == 3:
        cli_conf(sys.argv[2])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
