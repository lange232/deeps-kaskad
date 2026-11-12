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
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import (
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

BASE = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("KASKAD_CONFIG", "/etc/kaskad/panel.json"))
DB_PATH = Path(os.environ.get("KASKAD_DB", "/var/lib/kaskad/panel.db"))
COOKIE = "kaskad_session"
SESSION_TTL = auth.SESSION_TTL
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$")

def human_ts(value) -> str:
    if not value:
        return "never"
    text = str(value).replace("T", " ").replace("+00:00", "")
    return text[:16] + " UTC"


templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.filters["ts"] = human_ts
app = FastAPI(title="deeps kaskad", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


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
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                ip TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                preshared_key TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                internet INTEGER NOT NULL DEFAULT 1,
                table_num INTEGER NOT NULL DEFAULT 0
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
                table_num INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY,
                ts TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                client_id INTEGER NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                token_version INTEGER NOT NULL DEFAULT 1,
                last_login TEXT,
                created_at TEXT NOT NULL
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
        migrate(conn)


def migrate(conn: sqlite3.Connection) -> None:
    """Brings the schema up to date for databases created by older versions."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(exits)")}
    for name, ddl in (
        ("mode", "ALTER TABLE exits ADD COLUMN mode TEXT NOT NULL DEFAULT 'internet'"),
        ("routes", "ALTER TABLE exits ADD COLUMN routes TEXT NOT NULL DEFAULT ''"),
        ("dns", "ALTER TABLE exits ADD COLUMN dns TEXT NOT NULL DEFAULT ''"),
        ("comment", "ALTER TABLE exits ADD COLUMN comment TEXT NOT NULL DEFAULT ''"),
        ("table_num", "ALTER TABLE exits ADD COLUMN table_num INTEGER NOT NULL DEFAULT 0"),
    ):
        if name not in cols:
            conn.execute(ddl)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(clients)")}
    if "internet" not in cols:
        conn.execute("ALTER TABLE clients ADD COLUMN internet INTEGER NOT NULL DEFAULT 1")
    if "table_num" not in cols:
        conn.execute("ALTER TABLE clients ADD COLUMN table_num INTEGER NOT NULL DEFAULT 0")

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


def rollback_conf(c: dict, previous: bytes | None, had_iface: bool) -> None:
    """Puts the interface back to the configuration of the restored file.

    Called after a failed apply. Raises when the live state cannot be
    restored, so the caller can report that instead of pretending the change
    did not happen.
    """
    if had_iface:
        if previous is None:
            # The old config is unknown; touching the device could be worse
            # than leaving it, and the caller reports the original failure.
            print(f"{c['iface']}: rollback without a previous config file",
                  flush=True)
            return
        syncconf(c)
        expected = conf_peers(previous.decode())
        actual = applied_peers(c["iface"])
        if actual != expected:
            raise RuntimeError(
                f"device still has {len(actual - expected)} unexpected peers"
            )
        return
    if iface_up(c):
        run(["systemctl", "stop", f"awg-quick@{c['iface']}"])
        for _ in range(10):
            if not iface_up(c):
                break
            time.sleep(0.3)
        if iface_up(c):
            raise RuntimeError(f"awg-quick@{c['iface']} is still running")


def apply_conf(c: dict, conn: sqlite3.Connection | None = None) -> None:
    path = Path(c["awg_dir"]) / "awg0.conf"
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = path.read_bytes() if path.exists() else None
    had_iface = iface_up(c)
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
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(previous)
            os.chmod(path, 0o600)
        try:
            rollback_conf(c, previous, had_iface)
        except Exception as rollback_exc:
            raise RuntimeError(
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


def make_session(role: str, uid: int = 0, tv: int = 0) -> str:
    return auth.make_session(_session_secret(), role, uid, tv)


def session_data(token: str | None) -> dict | None:
    return auth.session_data(_session_secret(), token)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def start_session(role: str, uid: int = 0, tv: int = 0) -> str:
    """Creates a session that can be revoked server-side on logout."""
    token = make_session(role, uid, tv)
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
            "UPDATE users SET token_version = token_version + 1 WHERE id = ?", (uid,)
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


def user_row(uid: int):
    with db() as conn:
        return conn.execute(
            "SELECT u.id AS uid, u.email, u.password_hash, u.enabled AS account_enabled, "
            "u.token_version, u.last_login, u.client_id, "
            "c.name AS client_name, c.ip AS client_ip, c.enabled AS client_enabled, "
            "c.internet, c.public_key, c.private_key, c.preshared_key "
            "FROM users u JOIN clients c ON c.id = u.client_id WHERE u.id = ?",
            (uid,),
        ).fetchone()


def require_user(request: Request) -> tuple[str, object]:
    """Returns (session token, row with the user account and its client)."""
    token = request.cookies.get(COOKIE)
    data = session_data(token)
    if not data or not session_alive(data):
        _redirect("/login")
    if data["role"] != "user":
        _redirect("/")
    row = user_row(int(data.get("uid", 0)))
    if (
        not row
        or not row["account_enabled"]
        or not row["client_enabled"]
        or row["token_version"] != data.get("tv")
    ):
        _redirect("/login")
    return token, row


def user_client(row) -> dict:
    """Client row shaped like the one from the clients table, for /me."""
    return {
        "id": row["client_id"],
        "name": row["client_name"],
        "ip": row["client_ip"],
        "enabled": row["client_enabled"],
        "internet": row["internet"],
        "public_key": row["public_key"],
        "private_key": row["private_key"],
        "preshared_key": row["preshared_key"],
    }


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


def client_rows():
    with db() as conn:
        return conn.execute("SELECT * FROM clients ORDER BY ip").fetchall()


def ip_free(net_cidr: str, taken: set[str]) -> str:
    net = ipaddress.ip_network(net_cidr)
    for host in net.hosts():
        if str(host).endswith(".1"):
            continue
        if str(host) not in taken:
            return str(host)
    raise RuntimeError("no free addresses left")


def client_exits(cl) -> list:
    with db() as conn:
        return conn.execute(
            "SELECT e.* FROM client_exits ce "
            "JOIN exits e ON e.id = ce.exit_id "
            "WHERE ce.client_id = ? AND e.enabled = 1 AND e.mode = 'routes' "
            "ORDER BY e.priority, e.id",
            (cl["id"],),
        ).fetchall()


def client_internet_exits(cl) -> list:
    """Internet exits granted to the client, in the order the user chose."""
    with db() as conn:
        return conn.execute(
            "SELECT e.*, ce.priority AS choice "
            "FROM client_internet_exits ce "
            "JOIN exits e ON e.id = ce.exit_id "
            "WHERE ce.client_id = ? AND e.enabled = 1 AND e.mode = 'internet' "
            "ORDER BY ce.priority, e.priority, e.id",
            (cl["id"],),
        ).fetchall()


def internet_exits_rows() -> list:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM exits WHERE enabled = 1 AND mode = 'internet' ORDER BY priority, id"
        ).fetchall()


def client_access(c: dict, cl) -> tuple[str, list[str]]:
    """AllowedIPs and DNS for the client, depending on its class."""
    networks: list[str] = []
    dns: list[str] = []
    for ex in client_exits(cl):
        for cidr in (ex["routes"] or "").split(","):
            cidr = cidr.strip()
            if cidr and cidr not in networks:
                networks.append(cidr)
        for addr in (ex["dns"] or "").split(","):
            addr = addr.strip()
            if addr and addr not in dns:
                dns.append(addr)

    if cl["internet"]:
        return "0.0.0.0/0", [d.strip() for d in c["dns"].split(",") if d.strip()]
    if not networks:
        raise ValueError("client has neither internet nor subnets assigned")
    return ", ".join(networks), dns[:2]


def client_conf(c: dict, cl) -> str:
    allowed, dns = client_access(c, cl)
    lines = [
        "[Interface]",
        f"PrivateKey = {cl['private_key']}",
        f"Address = {cl['ip']}/32",
    ]
    if dns:
        lines.append(f"DNS = {', '.join(dns)}")
    lines += [
        f"MTU = {c['mtu']}",
        "",
        "[Peer]",
        f"PublicKey = {pubkey(server_key(c))}",
        f"PresharedKey = {cl['preshared_key']}",
        f"Endpoint = {c['endpoint']}:{c['port']}",
        f"AllowedIPs = {allowed}",
        "PersistentKeepalive = 25",
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


def client_view(cl, live: dict, assigned=None) -> dict:
    st = live.get(cl["public_key"], {})
    if assigned is None:
        assigned = client_exits(cl)
    return {
        "id": cl["id"],
        "name": cl["name"],
        "ip": cl["ip"],
        "enabled": bool(cl["enabled"]),
        "internet": bool(cl["internet"]),
        "exits": [e["name"] for e in assigned],
        "handshake": st.get("handshake", 0),
        "rx": st.get("rx", 0),
        "tx": st.get("tx", 0),
    }


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
        "endpoint": awgconf.endpoint(e["conf"]),
        "alive": st.get("alive"),
        "last_ok": st.get("last_ok", 0),
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


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", login_context())


@app.post("/login")
def login(request: Request, email: str = Form(""), password: str = Form(...)):
    ip = request.client.host if request.client else "?"
    ip_key = rate_key(ip)
    email = normalize_email(email)

    def fail(message: str, status: int = 401):
        return templates.TemplateResponse(
            request, "login.html", login_context(message, email), status_code=status
        )

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
                "SELECT u.*, c.enabled AS client_enabled FROM users u "
                "JOIN clients c ON c.id = u.client_id WHERE u.email = ?",
                (email,),
            ).fetchone()
        ok = bool(
            row
            and check_password(password, row["password_hash"])
            and row["enabled"]
            and row["client_enabled"]
        )
        if not row:
            _burn_hash(password)
        if ok:
            uid = int(row["id"])
            tv = int(row["token_version"])
            with db() as conn:
                conn.execute(
                    "UPDATE users SET last_login = ? WHERE id = ?", (_now_iso(), uid)
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


@app.get("/healthz")
def healthz():
    """Liveness for monitoring: database readable and failover reporting."""
    try:
        with db() as conn:
            conn.execute("SELECT 1").fetchone()
        c = cfg()
    except Exception as exc:
        print(f"healthz: {exc}", flush=True)
        return JSONResponse({"ok": False, "error": "database"}, status_code=503)
    status = read_status()
    ts = int(status.get("ts") or 0)
    age = int(time.time()) - ts if ts else None
    fresh = age is not None and age <= 120
    active = run_dir("active-exit")
    return JSONResponse({
        "ok": fresh,
        "version": c.get("version", ""),
        "commit": c.get("commit", ""),
        "active": None if active in ("", "none") else active,
        "failover_age": age,
    }, status_code=200 if fresh else 503)


# ---------------------------------------------------------------- overview

@app.get("/", response_class=HTMLResponse)
def overview(request: Request, err: str | None = None, ok: str | None = None):
    token = require_admin(request)
    c = cfg()
    live = iface_dump(c["iface"])["peers"]
    clients = [client_view(cl, live) for cl in client_rows()]
    status = read_status()
    active = run_dir("active-exit")
    manual = setting("manual_exit") or ""
    exits = [exit_view(e, status, active, manual) for e in exits_rows()]
    with db() as conn:
        events = conn.execute(
            "SELECT ts, action, detail FROM audit ORDER BY id DESC LIMIT 6"
        ).fetchall()
    now = int(time.time())
    online = sum(1 for cl in clients if cl["handshake"] and now - cl["handshake"] < 180)
    rx = sum(cl["rx"] for cl in clients)
    tx = sum(cl["tx"] for cl in clients)
    active_exit = next((e for e in exits if e["active"]), None)
    return render_page(
        request, "overview.html", "overview",
        csrf=csrf(token), err=err, ok=ok,
        clients=clients, exits=exits, active_exit=active, manual_exit=manual,
        active_row=active_exit, online=online, rx=rx, tx=tx,
        status=services(), events=events, net=c["net"],
    )


# ---------------------------------------------------------------- exits

EXIT_DEFAULTS = {"name": "", "mode": "internet", "priority": "", "routes": "", "dns": "", "conf": ""}


@app.get("/exits", response_class=HTMLResponse)
def exits_page(request: Request, mode: str | None = None):
    token = require_admin(request)
    status = read_status()
    active = run_dir("active-exit")
    manual = setting("manual_exit") or ""
    items = [exit_view(e, status, active, manual) for e in exits_rows()]
    if mode in ("internet", "routes"):
        items = [e for e in items if e["mode"] == mode]
    return render_page(
        request, "exits.html", "exits",
        csrf=csrf(token), exits=items, mode=mode or "", manual_exit=manual,
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
    )


@app.get("/exits/{eid}", response_class=HTMLResponse)
def exit_page(request: Request, eid: int, err: str | None = None, ok: str | None = None):
    token = require_admin(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM exits WHERE id = ?", (eid,)).fetchone()
        assigned = conn.execute(
            "SELECT c.* FROM client_exits ce JOIN clients c ON c.id = ce.client_id "
            "WHERE ce.exit_id = ? ORDER BY c.name",
            (eid,),
        ).fetchall()
    if not row:
        raise HTTPException(status_code=404)
    status = read_status()
    active = run_dir("active-exit")
    manual = setting("manual_exit") or ""
    return render_page(
        request, "exit_detail.html", "exits",
        csrf=csrf(token), err=err, ok=ok,
        exit=exit_view(row, status, active, manual),
        conf=mask_conf(awgconf.render(row["conf"], cfg()["exit_mtu"],
                                      [x.strip() for x in (row["routes"] or "").split(",") if x.strip()] or None)),
        clients=assigned,
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
            "INSERT INTO exits (name, iface, priority, enabled, conf, created_at, mode, routes, dns, comment, table_num) "
            "VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 0)",
            (name, iface, prio, conf, datetime.now(timezone.utc).isoformat(timespec="seconds"),
             mode, ", ".join(nets), dns.strip(), comment),
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


# ---------------------------------------------------------------- clients

@app.get("/clients", response_class=HTMLResponse)
def clients_page(request: Request, q: str | None = None):
    token = require_admin(request)
    live = iface_dump(cfg()["iface"])["peers"]
    with db() as conn:
        accounts = {
            r["client_id"]: r
            for r in conn.execute("SELECT client_id, email, enabled FROM users")
        }
    items = [client_view(cl, live) for cl in client_rows()]
    for c in items:
        account = accounts.get(c["id"])
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
    return render_page(
        request, "clients.html", "clients",
        csrf=csrf(token), clients=items, q=q or "",
    )


@app.get("/clients/new", response_class=HTMLResponse)
def client_new_page(request: Request, err: str | None = None):
    token = require_admin(request)
    routed = [e for e in exits_rows() if e["mode"] == "routes" and e["enabled"]]
    return render_page(
        request, "client_new.html", "clients",
        csrf=csrf(token), err=err, routed=routed,
    )


@app.get("/clients/{cid}", response_class=HTMLResponse)
def client_page(
    request: Request,
    cid: int,
    err: str | None = None,
    ok: str | None = None,
    newpw: str | None = None,
):
    token = require_admin(request)
    c = cfg()
    with db() as conn:
        cl = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
    if not cl:
        raise HTTPException(status_code=404)
    assigned = {e["id"]: e for e in client_exits(cl)}
    routed = [e for e in exits_rows() if e["mode"] == "routes" and e["enabled"]]
    granted = {e["id"] for e in client_internet_exits(cl)}
    live = iface_dump(c["iface"])["peers"]
    view = client_view(cl, live, list(assigned.values()))
    try:
        conf = mask_conf(client_conf(c, cl))
    except ValueError:
        conf = None
    return render_page(
        request, "client_detail.html", "clients",
        csrf=csrf(token), err=err, ok=ok, cl=view, raw=cl,
        routed=routed, assigned=set(assigned.keys()), conf=conf,
        internet_exits=internet_exits_rows(), granted=granted,
        account=client_account(cid), newpw=pop_secret(newpw),
    )


@app.post("/clients")
def create_client(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(""),
    internet: str = Form(""),
    exits: list[int] = Form([]),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    name = name.strip()

    def fail(msg: str):
        return RedirectResponse("/clients/new?err=" + quote(msg), status_code=303)

    if not NAME_RE.match(name):
        return fail("name: latin letters, digits, dot, dash; up to 32 characters")

    email = normalize_email(email)
    problem = email_error(email)
    if problem:
        return fail(problem)
    password = password or secrets.token_urlsafe(12)
    problem = password_error(password)
    if problem:
        return fail(problem)
    with db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            return fail("email is already used by another account")

    c = cfg()
    rows = client_rows()
    if any(r["name"] == name for r in rows):
        return fail("a client with this name already exists")
    try:
        ip = ip_free(c["net"], {r["ip"] for r in rows})
    except RuntimeError as exc:
        return fail(str(exc))

    private = genkey()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO clients (name, ip, public_key, private_key, preshared_key, enabled, created_at, internet, table_num) "
                "VALUES (?, ?, ?, ?, ?, 1, ?, ?, 0)",
                (name, ip, pubkey(private), private, genpsk(), now, 1 if internet else 0),
            )
            cid = cur.lastrowid
            table_num = routing.claim_table(conn, "client", cid)
            conn.execute(
                "UPDATE clients SET table_num = ? WHERE id = ?", (table_num, cid)
            )
            for eid in exits:
                conn.execute("INSERT OR IGNORE INTO client_exits (client_id, exit_id) VALUES (?, ?)", (cid, eid))
            conn.execute(
                "INSERT INTO users (client_id, email, password_hash, enabled, token_version, created_at) "
                "VALUES (?, ?, ?, 1, 1, ?)",
                (cid, email, hash_password(password), now),
            )
            # The tunnel must carry the new peer before the rows are committed;
            # a failed apply rolls the client, its account and its grants back.
            apply_conf(c, conn)
    except RuntimeError as exc:
        print(f"client {name}: {exc}", flush=True)
        return fail("the WireGuard config could not be applied; nothing was saved")
    audit("client_added", f"{name} {ip}")
    audit("account_created", f"{name} {email}")
    apply_routing()
    return RedirectResponse(
        f"/clients/{cid}?ok=client+created&newpw={quote(stash_secret(password))}",
        status_code=303,
    )


@app.post("/clients/{cid}/access")
def client_access_update(
    request: Request,
    cid: int,
    internet: str = Form(""),
    exits: list[int] = Form([]),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    with db() as conn:
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404)
        conn.execute("UPDATE clients SET internet = ? WHERE id = ?", (1 if internet else 0, cid))
        conn.execute("DELETE FROM client_exits WHERE client_id = ?", (cid,))
        for eid in exits:
            conn.execute("INSERT OR IGNORE INTO client_exits (client_id, exit_id) VALUES (?, ?)", (cid, eid))
    audit("client_updated", row["name"])
    apply_routing()
    return RedirectResponse(f"/clients/{cid}?ok=access+updated", status_code=303)


@app.post("/clients/{cid}/internet")
def client_internet_update(
    request: Request,
    cid: int,
    exits: list[int] = Form([]),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    with db() as conn:
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404)
        allowed = {
            r["id"] for r in conn.execute(
                "SELECT id FROM exits WHERE enabled = 1 AND mode = 'internet'"
            )
        }
        wanted = {int(e) for e in exits if int(e) in allowed}
        current = {
            r["exit_id"]: r["priority"] for r in conn.execute(
                "SELECT exit_id, priority FROM client_internet_exits WHERE client_id = ?",
                (cid,),
            )
        }
        for exit_id in list(current):
            if exit_id not in wanted:
                conn.execute(
                    "DELETE FROM client_internet_exits WHERE client_id = ? AND exit_id = ?",
                    (cid, exit_id),
                )
        next_priority = max(current.values(), default=0) + 10
        for exit_id in sorted(wanted):
            if exit_id in current:
                continue
            conn.execute(
                "INSERT INTO client_internet_exits (client_id, exit_id, priority) VALUES (?, ?, ?)",
                (cid, exit_id, next_priority),
            )
            next_priority += 10
    audit("client_internet_access", f"{row['name']} exits={sorted(wanted)}")
    apply_routing()
    return RedirectResponse(f"/clients/{cid}?ok=internet+exits+updated", status_code=303)


@app.post("/clients/{cid}/toggle")
def toggle_client(request: Request, cid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    try:
        with db() as conn:
            row = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
            if not row:
                raise HTTPException(status_code=404)
            conn.execute(
                "UPDATE clients SET enabled = ? WHERE id = ?", (0 if row["enabled"] else 1, cid)
            )
            apply_conf(cfg(), conn)
    except RuntimeError as exc:
        print(f"client {cid}: {exc}", flush=True)
        return RedirectResponse(
            f"/clients/{cid}?err={quote('the WireGuard config could not be applied; nothing changed')}",
            status_code=303,
        )
    audit("client_toggle", f"{row['name']} -> {0 if row['enabled'] else 1}")
    apply_routing()
    return RedirectResponse(f"/clients/{cid}", status_code=303)


@app.post("/clients/{cid}/delete")
def delete_client(request: Request, cid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    try:
        with db() as conn:
            row = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
            if not row:
                raise HTTPException(status_code=404)
            conn.execute(
                "UPDATE sessions SET revoked = 1 WHERE uid IN "
                "(SELECT id FROM users WHERE client_id = ?)", (cid,)
            )
            routing.release_table(conn, "client", cid)
            conn.execute("DELETE FROM users WHERE client_id = ?", (cid,))
            conn.execute("DELETE FROM clients WHERE id = ?", (cid,))
            conn.execute("DELETE FROM client_exits WHERE client_id = ?", (cid,))
            conn.execute("DELETE FROM client_internet_exits WHERE client_id = ?", (cid,))
            apply_conf(cfg(), conn)
    except RuntimeError as exc:
        print(f"client {cid}: {exc}", flush=True)
        return RedirectResponse(
            f"/clients/{cid}?err={quote('the WireGuard config could not be applied; nothing was deleted')}",
            status_code=303,
        )
    audit("client_deleted", row["name"])
    apply_routing()
    return RedirectResponse("/clients?ok=client+deleted", status_code=303)


def conf_response(cl) -> PlainTextResponse:
    try:
        body = client_conf(cfg(), cl)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return PlainTextResponse(
        body,
        headers={"Content-Disposition": f'attachment; filename="{cl["name"]}.conf"'},
    )


def qr_response(cl) -> Response:
    try:
        body = client_conf(cfg(), cl)
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


@app.get("/clients/{cid}/conf")
def download_conf(request: Request, cid: int):
    require_admin(request)
    with db() as conn:
        cl = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
    if not cl:
        raise HTTPException(status_code=404)
    return conf_response(cl)


@app.get("/clients/{cid}/qr.png")
def qr(request: Request, cid: int):
    require_admin(request)
    with db() as conn:
        cl = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
    if not cl:
        raise HTTPException(status_code=404)
    return qr_response(cl)


# ---------------------------------------------------------------- accounts

def client_account(cid: int):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE client_id = ?", (cid,)
        ).fetchone()


def account_redirect(cid: int, ok: str = "", err: str = "", secret: str = "") -> RedirectResponse:
    params = []
    if ok:
        params.append("ok=" + quote(ok))
    if err:
        params.append("err=" + quote(err))
    if secret:
        params.append("newpw=" + quote(secret))
    query = "?" + "&".join(params) if params else ""
    return RedirectResponse(f"/clients/{cid}{query}", status_code=303)


@app.post("/clients/{cid}/account")
def account_create(
    request: Request,
    cid: int,
    email: str = Form(...),
    password: str = Form(""),
    csrf_token: str = Form(...),
):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    with db() as conn:
        cl = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
    if not cl:
        raise HTTPException(status_code=404)
    if client_account(cid):
        return account_redirect(cid, err="this client already has an account")

    email = normalize_email(email)
    problem = email_error(email)
    if problem:
        return account_redirect(cid, err=problem)
    password = password or secrets.token_urlsafe(12)
    problem = password_error(password)
    if problem:
        return account_redirect(cid, err=problem)

    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO users (client_id, email, password_hash, enabled, token_version, created_at) "
                "VALUES (?, ?, ?, 1, 1, ?)",
                (cid, email, hash_password(password),
                 datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
    except sqlite3.IntegrityError:
        return account_redirect(cid, err="email is already used by another account")
    audit("account_created", f"{cl['name']} {email}")
    return account_redirect(cid, ok="account created", secret=stash_secret(password))


@app.post("/clients/{cid}/account/password")
def account_reset(request: Request, cid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    account = client_account(cid)
    if not account:
        raise HTTPException(status_code=404)
    password = secrets.token_urlsafe(12)
    with db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, token_version = token_version + 1 "
            "WHERE id = ?",
            (hash_password(password), account["id"]),
        )
        conn.execute(
            "UPDATE sessions SET revoked = 1 WHERE uid = ?", (account["id"],)
        )
    audit("account_password_reset", account["email"])
    return account_redirect(cid, ok="password reset", secret=stash_secret(password))


@app.post("/clients/{cid}/account/toggle")
def account_toggle(request: Request, cid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    account = client_account(cid)
    if not account:
        raise HTTPException(status_code=404)
    enabled = 0 if account["enabled"] else 1
    with db() as conn:
        conn.execute(
            "UPDATE users SET enabled = ?, token_version = token_version + 1 "
            "WHERE id = ?",
            (enabled, account["id"]),
        )
        conn.execute(
            "UPDATE sessions SET revoked = 1 WHERE uid = ?", (account["id"],)
        )
    audit("account_toggle", f"{account['email']} -> {enabled}")
    return account_redirect(cid, ok="account enabled" if enabled else "account disabled")


@app.post("/clients/{cid}/account/delete")
def account_delete(request: Request, cid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    account = client_account(cid)
    if not account:
        raise HTTPException(status_code=404)
    with db() as conn:
        conn.execute("UPDATE sessions SET revoked = 1 WHERE uid = ?", (account["id"],))
        conn.execute("DELETE FROM users WHERE id = ?", (account["id"],))
    audit("account_deleted", account["email"])
    return account_redirect(cid, ok="account deleted")


# ---------------------------------------------------------------- self service

@app.get("/me", response_class=HTMLResponse)
def me_page(request: Request, err: str | None = None, ok: str | None = None):
    token, row = require_user(request)
    cl = user_client(row)
    c = cfg()
    live = iface_dump(c["iface"])["peers"]
    try:
        conf = mask_conf(client_conf(c, cl))
    except ValueError:
        conf = None
    status = read_status()
    granted = client_internet_exits(cl)
    current_iface = (status.get("clients") or {}).get(cl["ip"]) or ""
    current = next((e for e in granted if e["iface"] == current_iface), None)
    alive = {
        iface: bool(info.get("alive"))
        for iface, info in (status.get("exits") or {}).items()
    }
    return render_page(
        request, "me.html", "me", role="user",
        csrf=csrf(token), err=err, ok=ok, cl=client_view(cl, live),
        email=row["email"], last_login=human_ts(row["last_login"]), conf=conf,
        internet_exits=granted, current_exit=current, alive=alive,
    )


@app.get("/me/conf")
def me_conf(request: Request):
    _, row = require_user(request)
    cl = user_client(row)
    audit("config_downloaded", row["email"])
    return conf_response(cl)


@app.get("/me/qr.png")
def me_qr(request: Request):
    _, row = require_user(request)
    return qr_response(user_client(row))


@app.post("/me/exits/move")
def me_exit_move(
    request: Request,
    exit_id: int = Form(...),
    direction: str = Form(...),
    csrf_token: str = Form(...),
):
    token, row = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    if direction not in ("up", "down"):
        raise HTTPException(status_code=400, detail="direction")
    with db() as conn:
        order = [
            r["exit_id"] for r in conn.execute(
                "SELECT exit_id FROM client_internet_exits "
                "WHERE client_id = ? ORDER BY priority, exit_id",
                (row["client_id"],),
            )
        ]
        if exit_id not in order:
            raise HTTPException(status_code=404)
        index = order.index(exit_id)
        target = index - 1 if direction == "up" else index + 1
        if 0 <= target < len(order):
            order[index], order[target] = order[target], order[index]
            for position, eid in enumerate(order):
                conn.execute(
                    "UPDATE client_internet_exits SET priority = ? "
                    "WHERE client_id = ? AND exit_id = ?",
                    ((position + 1) * 10, row["client_id"], eid),
                )
    audit("user_exit_order", f"{row['email']} {' '.join(str(e) for e in order)}")
    return RedirectResponse("/me?ok=exit+order+updated", status_code=303)


@app.post("/me/password")
def me_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    csrf_token: str = Form(...),
):
    token, row = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    if not check_password(current_password, row["password_hash"]):
        return RedirectResponse("/me?err=" + quote("current password is wrong"), status_code=303)
    problem = password_error(new_password, "new password")
    if problem:
        return RedirectResponse("/me?err=" + quote(problem), status_code=303)
    new_hash = hash_password(new_password)
    with db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, token_version = token_version + 1 "
            "WHERE id = ?",
            (new_hash, row["uid"]),
        )
        # Every other session of this account dies with the password change.
        conn.execute("UPDATE sessions SET revoked = 1 WHERE uid = ?", (row["uid"],))
        tv = conn.execute(
            "SELECT token_version FROM users WHERE id = ?", (row["uid"],)
        ).fetchone()[0]
    audit("user_password_changed", row["email"])
    response = RedirectResponse("/me?ok=password+changed", status_code=303)
    response.set_cookie(
        COOKIE, start_session("user", int(row["uid"]), int(tv)),
        httponly=True, secure=True, samesite="strict", max_age=SESSION_TTL,
    )
    return response


@app.post("/me/logout-all")
def me_logout_all(request: Request, csrf_token: str = Form(...)):
    token, row = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    revoke_user_sessions(int(row["uid"]))
    audit("user_sessions_revoked", row["email"])
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE)
    return response


@app.post("/me/reissue")
def me_reissue(request: Request, csrf_token: str = Form(...)):
    token, row = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    private = genkey()
    try:
        with db() as conn:
            conn.execute(
                "UPDATE clients SET private_key = ?, public_key = ?, preshared_key = ? WHERE id = ?",
                (private, pubkey(private), genpsk(), row["client_id"]),
            )
            apply_conf(cfg(), conn)
    except RuntimeError as exc:
        print(f"client {row['client_id']}: {exc}", flush=True)
        return RedirectResponse(
            f"/me?err={quote('the WireGuard config could not be applied; your key was not changed')}",
            status_code=303,
        )
    apply_routing()
    audit("user_key_reissued", row["email"])
    return RedirectResponse("/me?ok=key+reissued", status_code=303)


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
def settings_page(request: Request):
    require_admin(request)
    c = cfg()
    with db() as conn:
        clients_n = conn.execute("SELECT count(*) FROM clients").fetchone()[0]
        exits_n = conn.execute("SELECT count(*) FROM exits").fetchone()[0]
        audits_n = conn.execute("SELECT count(*) FROM audit").fetchone()[0]
    db_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    return render_page(
        request, "settings.html", "settings",
        cfg=c, clients_n=clients_n, exits_n=exits_n, audits_n=audits_n,
        db_size=db_size, status=services(),
    )


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
    print(client_conf(c, cl), end="")


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
