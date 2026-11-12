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
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import auth
import awgconf

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
                internet INTEGER NOT NULL DEFAULT 1
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
                comment TEXT NOT NULL DEFAULT ''
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
    ):
        if name not in cols:
            conn.execute(ddl)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(clients)")}
    if "internet" not in cols:
        conn.execute("ALTER TABLE clients ADD COLUMN internet INTEGER NOT NULL DEFAULT 1")


def audit(action: str, detail: str = "") -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit (ts, action, detail) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), action, detail),
        )


def setting(key: str) -> str | None:
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
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


def server_key(c: dict) -> str:
    key = setting("awg0_private_key")
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
    set_setting("awg0_private_key", key)
    return key


def render_conf(c: dict) -> str:
    with db() as conn:
        clients = conn.execute(
            "SELECT * FROM clients WHERE enabled = 1 ORDER BY ip"
        ).fetchall()

    lines = [
        "# Generated by kaskad-panel. Manual edits will be lost.",
        "[Interface]",
        f"PrivateKey = {server_key(c)}",
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


def apply_conf(c: dict) -> None:
    path = Path(c["awg_dir"]) / "awg0.conf"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(render_conf(c))
    os.chmod(tmp, 0o600)
    tmp.replace(path)

    if not Path(f"/sys/class/net/{c['iface']}").exists():
        run(["systemctl", "start", f"awg-quick@{c['iface']}"])
        return
    res = run(
        ["bash", "-c", f"awg syncconf {c['iface']} <(awg-quick strip {c['iface']})"]
    )
    if res.returncode != 0:
        raise RuntimeError(f"syncconf: {res.stderr.strip()}")


def iface_dump(name: str) -> dict:
    """awg show <iface> dump → {public_key: {handshake, rx, tx}} + device."""
    res = run(["awg", "show", name, "dump"])
    if res.returncode != 0:
        return {"peers": {}, "ok": False}
    peers = {}
    device = {}
    for line in res.stdout.splitlines():
        f = line.split("\t")
        if len(f) == 4:
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
        import routing
        routing.apply()
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


def csrf(token: str) -> str:
    return hmac.new(token.encode(), b"csrf", hashlib.sha256).hexdigest()[:32]


def _redirect(location: str):
    raise HTTPException(status_code=303, headers={"Location": location})


def require_admin(request: Request) -> str:
    token = request.cookies.get(COOKIE)
    data = session_data(token)
    if not data:
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
    if not data:
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


_attempts: dict[str, list[float]] = {}


def rate_limited(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _attempts.get(ip, []) if now - t < 300]
    _attempts[ip] = hits
    return len(hits) >= 5


def note_failure(ip: str) -> None:
    _attempts.setdefault(ip, []).append(time.time())


_flash_secrets: dict[str, tuple[float, str]] = {}


def stash_secret(value: str) -> str:
    """Keep a generated password out of URLs; the panel shows it once."""
    key = secrets.token_urlsafe(9)
    _flash_secrets[key] = (time.time() + 300, value)
    return key


def pop_secret(key: str | None) -> str:
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
    email = normalize_email(email)
    limit_key = f"email:{email}"

    def fail(message: str, status: int = 401):
        return templates.TemplateResponse(
            request, "login.html", login_context(message, email), status_code=status
        )

    if rate_limited(ip) or (email and rate_limited(limit_key)):
        return fail("too many attempts, wait 5 minutes", 429)

    token = ""
    location = ""
    role = ""
    if email == ADMIN_LOGIN:
        if verify_admin_password(password):
            token = make_session("admin")
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
            with db() as conn:
                conn.execute(
                    "UPDATE users SET last_login = ? WHERE id = ?",
                    (datetime.now(timezone.utc).isoformat(timespec="seconds"), row["id"]),
                )
            token = make_session("user", int(row["id"]), int(row["token_version"]))
            location = "/me"
            role = "user"

    if not token:
        note_failure(ip)
        if email:
            note_failure(limit_key)
        audit("login_failed", f"{ip} {email or '-'}")
        return fail("wrong email or password")

    response = RedirectResponse(location, status_code=303)
    response.set_cookie(
        COOKIE, token, httponly=True, secure=True, samesite="strict", max_age=SESSION_TTL
    )
    audit("login", f"{role} {email} {ip}")
    return response


@app.post("/logout")
def logout(request: Request):
    session_data(request.cookies.get(COOKIE))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE)
    return response


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
        conn.execute(
            "INSERT INTO exits (name, iface, priority, enabled, conf, created_at, mode, routes, dns, comment) "
            "VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?)",
            (name, iface, prio, conf, datetime.now(timezone.utc).isoformat(timespec="seconds"),
             mode, ", ".join(nets), dns.strip(), comment),
        )
        row = conn.execute("SELECT * FROM exits WHERE name = ?", (name,)).fetchone()

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
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO clients (name, ip, public_key, private_key, preshared_key, enabled, created_at, internet) "
            "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
            (name, ip, pubkey(private), private, genpsk(), now, 1 if internet else 0),
        )
        cid = cur.lastrowid
        for eid in exits:
            conn.execute("INSERT OR IGNORE INTO client_exits (client_id, exit_id) VALUES (?, ?)", (cid, eid))
        conn.execute(
            "INSERT INTO users (client_id, email, password_hash, enabled, token_version, created_at) "
            "VALUES (?, ?, ?, 1, 1, ?)",
            (cid, email, hash_password(password), now),
        )
    audit("client_added", f"{name} {ip}")
    audit("account_created", f"{name} {email}")
    apply_conf(c)
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
    apply_conf(cfg())
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
    with db() as conn:
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404)
        conn.execute(
            "UPDATE clients SET enabled = ? WHERE id = ?", (0 if row["enabled"] else 1, cid)
        )
    audit("client_toggle", f"{row['name']} -> {0 if row['enabled'] else 1}")
    apply_conf(cfg())
    apply_routing()
    return RedirectResponse(f"/clients/{cid}", status_code=303)


@app.post("/clients/{cid}/delete")
def delete_client(request: Request, cid: int, csrf_token: str = Form(...)):
    token = require_admin(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    with db() as conn:
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404)
        conn.execute("DELETE FROM users WHERE client_id = ?", (cid,))
        conn.execute("DELETE FROM clients WHERE id = ?", (cid,))
        conn.execute("DELETE FROM client_exits WHERE client_id = ?", (cid,))
    audit("client_deleted", row["name"])
    apply_conf(cfg())
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
            "UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?",
            (hash_password(password), account["id"]),
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
            "UPDATE users SET enabled = ?, token_version = token_version + 1 WHERE id = ?",
            (enabled, account["id"]),
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
    with db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?",
            (hash_password(new_password), row["uid"]),
        )
        tv = conn.execute(
            "SELECT token_version FROM users WHERE id = ?", (row["uid"],)
        ).fetchone()[0]
    audit("user_password_changed", row["email"])
    response = RedirectResponse("/me?ok=password+changed", status_code=303)
    response.set_cookie(
        COOKIE, make_session("user", int(row["uid"]), int(tv)),
        httponly=True, secure=True, samesite="strict", max_age=SESSION_TTL,
    )
    return response


@app.post("/me/reissue")
def me_reissue(request: Request, csrf_token: str = Form(...)):
    token, row = require_user(request)
    if not hmac.compare_digest(csrf_token, csrf(token)):
        raise HTTPException(status_code=400, detail="csrf")
    private = genkey()
    with db() as conn:
        conn.execute(
            "UPDATE clients SET private_key = ?, public_key = ?, preshared_key = ? WHERE id = ?",
            (private, pubkey(private), genpsk(), row["client_id"]),
        )
    apply_conf(cfg())
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
