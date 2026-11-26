#!/usr/bin/env python3
"""Local preview of the panel with disposable demo data.

This is not a second panel: it runs the real FastAPI app over a separate
SQLite database, signs the browser in as the administrator, and replaces the
system calls (awg, ip, systemctl, failover status) with stubs. Use it to look
at pages and click through forms while working on the interface.

    scripts/dev-ui.py                 # http://127.0.0.1:8081
    scripts/dev-ui.py --scenario down # exits down, one route moved
    scripts/dev-ui.py --reset         # rebuild the demo database
    scripts/dev-ui.py --port 8085 --no-reload

Templates and static files are re-read on every request. Python changes
restart the server automatically unless --no-reload is given.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
STATE = Path(os.environ.get("KASKAD_DEV_STATE",
                            Path.home() / ".local" / "share" / "kaskad-dev"))
ADMIN_PASSWORD = "dev-panel"
SCENARIOS = ("healthy", "degraded", "down", "stale")
PNG_PIXEL = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000a49444154789c6300010000050001"
    "0d0a2db40000000049454e44ae426082"
)
# Bumped when the demo dataset changes, so an old database is not silently
# missing rows the UI is expected to show.
SEED_VERSION = "4"


def write_config(port: int) -> dict:
    config = {
        "listen": {"host": "127.0.0.1", "port": port},
        "tls": {"cert": str(STATE / "panel.crt"), "key": str(STATE / "panel.key")},
        "version": (ROOT / "VERSION").read_text().strip(),
        "commit": "dev",
        "awg_dir": str(STATE / "awg"),
        "iface": "awg0",
        "address": "10.80.0.1",
        "net": "10.80.0.0/24",
        "clients_net": "10.80.0.0/24",
        "route_table": 100,
        "exit_mtu": 1340,
        "port": 51820,
        "mtu": 1280,
        "dns": "1.1.1.1, 1.0.0.1",
        "endpoint": "dev.example.com",
        "params": {"Jc": 0, "Jmin": 0, "Jmax": 0, "S1": 0, "S2": 0,
                   "H1": 1, "H2": 2, "H3": 3, "H4": 4},
    }
    (STATE / "panel.json").write_text(json.dumps(config, indent=2))
    return config


def seed_traffic(conn, configs) -> None:
    """Ninety days of hourly points and a week of five-minute points."""
    import math
    import time as _time

    step, hour = 300, 3600
    now = int(_time.time())
    plans = ((step, 7 * 86400), (hour, 90 * 86400))
    for index, cid in enumerate(configs):
        base = 1_800_000 + index * 700_000
        for size, span in plans:
            for ts in range(now - span, now, size):
                point = ts - ts % size
                night = 0.25 if 2 <= (point // hour) % 24 < 7 else 1.0
                wave = 1 + 0.55 * math.sin(point / 2600.0 + index)
                tx = int(base * night * wave)
                rx = int(tx * 0.22)
                conn.execute(
                    "INSERT OR REPLACE INTO traffic (client_id, ts, step, rx, tx) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (cid, point, size, rx, tx),
                )


def top_up_traffic(conn, configs) -> None:
    """Extends the demo history to now, so a database made yesterday still charts."""
    import math
    import time as _time

    now = int(_time.time())
    hour = 3600
    for index, cid in enumerate(configs):
        base = 1_800_000 + index * 700_000
        for size, span in ((300, 7 * 86400), (3600, 90 * 86400)):
            last = conn.execute(
                "SELECT max(ts) FROM traffic WHERE client_id = ? AND step = ?",
                (cid, size),
            ).fetchone()[0]
            if last is None:
                continue
            for ts in range(max(last + size, now - span), now, size):
                point = ts - ts % size
                night = 0.25 if 2 <= (point // hour) % 24 < 7 else 1.0
                wave = 1 + 0.55 * math.sin(point / 2600.0 + index)
                tx = int(base * night * wave)
                rx = int(tx * 0.22)
                conn.execute(
                    "INSERT OR REPLACE INTO traffic (client_id, ts, step, rx, tx) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (cid, point, size, rx, tx),
                )


def seed(app) -> None:
    """A small but varied dataset: three configs, four exits, one orphan."""
    with app.db() as conn:
        account = conn.execute(
            "INSERT INTO accounts (email, password_hash, enabled, token_version, "
            "max_configs, created_at) VALUES (?, ?, 1, 1, NULL, 'now')",
            ("demo@example.com", app.auth.hash_password("demo-password-123")),
        ).lastrowid
        configs = []
        for name, ip in (("phone", "10.80.0.2"), ("laptop", "10.80.0.3"),
                         ("tablet", "10.80.0.4")):
            table = app.routing.allocate_table(conn)
            configs.append(conn.execute(
                "INSERT INTO clients (account_id, name, ip, public_key, private_key, "
                "preshared_key, enabled, created_at, internet, table_num) "
                "VALUES (?, ?, ?, ?, ?, 'psk', 1, 'now', 1, ?)",
                (account, name, ip, "pub-" + name, "priv-" + name, table),
            ).lastrowid)
        conn.execute(
            "INSERT INTO clients (name, ip, public_key, private_key, preshared_key, "
            "enabled, created_at, internet, table_num) "
            "VALUES ('legacy', '10.80.0.9', 'pub-legacy', 'priv-legacy', 'psk', 1, 'now', 1, 0)"
        )
        exits = []
        for name, iface, country, priority in (
            ("tucana", "awg1", "Netherlands", 10),
            ("sauga-dude", "awg2", "Finland", 20),
            ("koit", "awg3", "Estonia", 30),
        ):
            exits.append(conn.execute(
                "INSERT INTO exits (name, iface, priority, enabled, conf, created_at, "
                "mode, routes, table_num, country) "
                "VALUES (?, ?, ?, 1, 'conf', 'now', 'internet', '', 0, ?)",
                (name, iface, priority, country),
            ).lastrowid)
        subnet = conn.execute(
            "INSERT INTO exits (name, iface, priority, enabled, conf, created_at, "
            "mode, routes, table_num, country) "
            "VALUES ('test-subnet', 'awg9', 40, 1, 'conf', 'now', 'routes', "
            "'10.90.0.0/24', ?, '')",
            (app.routing.allocate_table(conn),),
        ).lastrowid
        # A disabled exit has a lower priority than the live ones on purpose:
        # it must still appear last and dimmed.
        conn.execute(
            "INSERT INTO exits (name, iface, priority, enabled, conf, created_at, "
            "mode, routes, table_num, country) "
            "VALUES ('retired', 'awg8', 5, 0, 'conf', 'now', 'internet', '', 0, 'Germany')"
        )
        conn.execute(
            "INSERT INTO exits (name, iface, priority, enabled, conf, created_at, "
            "mode, routes, table_num, country) "
            "VALUES ('lab-subnet', 'awg7', 10, 0, 'conf', 'now', 'routes', "
            "'10.77.0.0/24', ?, '')",
            (app.routing.allocate_table(conn),),
        )
        for index, exit_id in enumerate(exits):
            conn.execute("INSERT INTO account_exits VALUES (?, ?, ?)",
                         (account, exit_id, (index + 1) * 10))
            for cid in configs:
                conn.execute("INSERT INTO client_internet_exits VALUES (?, ?, ?)",
                             (cid, exit_id, (index + 1) * 10))
        # One subnet is granted to the account and chosen by the first config.
        conn.execute("INSERT INTO account_exits VALUES (?, ?, 40)",
                     (account, subnet))
        conn.execute("INSERT INTO client_exits VALUES (?, ?)",
                     (configs[0], subnet))
        app.traffic.ensure_schema(conn)
        seed_traffic(conn, configs)
        conn.execute("INSERT INTO audit (ts, action, detail) VALUES "
                     "('2026-01-01T10:00:00+00:00', 'exit_added', 'tucana awg1 internet')")
        conn.execute("INSERT INTO audit (ts, action, detail) VALUES "
                     "('2026-01-01T10:05:00+00:00', 'exit_failover', "
                     "'awg2 → awg1 · Preferred exit recovered')")


def peers(app) -> dict:
    """Traffic and handshake numbers for the configurations in the demo DB."""
    now = int(time.time())
    with app.db() as conn:
        rows = conn.execute("SELECT public_key, name FROM clients").fetchall()
    result = {}
    for index, row in enumerate(rows):
        result[row["public_key"]] = {
            "handshake": now - 20 - index * 30,
            "rx": (index + 1) * 7340032,
            "tx": (index + 1) * 2097152,
            "endpoint": f"203.0.113.{10 + index}:51820",
        }
    return result


def failover_status(scenario: str) -> dict:
    now = int(time.time())
    if scenario == "stale":
        return {"ts": now - 600, "active": "awg1",
                "exits": {"awg1": {"alive": True, "rtt_ms": 55}}}
    exits = {
        "awg1": {"alive": True, "degraded": False, "rtt_ms": 55, "last_ok": now,
                 "targets": {"https://example.com/": True, "https://1.1.1.1/": True}},
        "awg2": {"alive": True, "degraded": False, "rtt_ms": 44, "last_ok": now,
                 "targets": {"https://example.com/": True, "https://1.1.1.1/": True}},
        "awg3": {"alive": True, "degraded": False, "rtt_ms": 133, "last_ok": now,
                 "targets": {"https://example.com/": True, "https://1.1.1.1/": True}},
        "awg9": {"alive": True, "degraded": False, "rtt_ms": None, "last_ok": now},
    }
    clients = {"10.80.0.2": "awg1", "10.80.0.3": "awg2",
               "10.80.0.4": "awg1", "10.80.0.9": "awg1"}
    active = "awg1"
    if scenario == "degraded":
        exits["awg2"].update(degraded=True,
                             targets={"https://example.com/": False,
                                      "https://1.1.1.1/": True})
        clients["10.80.0.3"] = "awg1"
    elif scenario == "down":
        exits["awg1"].update(alive=False)
        active = "awg2"
        clients.update({"10.80.0.2": "awg2", "10.80.0.3": "awg2",
                        "10.80.0.4": "awg2", "10.80.0.9": "awg2"})
    return {"ts": now, "active": active, "manual": "", "clients": clients,
            "client_ping": {"10.80.0.2": 12, "10.80.0.3": 18},
            "exits": exits}


def fake_run(cmd, **_kwargs):
    if cmd[:2] == ["awg", "genkey"]:
        return subprocess.CompletedProcess(cmd, 0, "dev-private\n", "")
    if cmd[:2] == ["awg", "pubkey"]:
        return subprocess.CompletedProcess(cmd, 0, "dev-public\n", "")
    if cmd[:2] == ["awg", "genpsk"]:
        return subprocess.CompletedProcess(cmd, 0, "dev-psk\n", "")
    return subprocess.CompletedProcess(cmd, 0, "", "")


def build_app(port: int, scenario: str, reset: bool):
    """Prepare the state directory, patch the system edges, sign in."""
    sys.path.insert(0, str(PANEL))
    import auth  # noqa: F401 - imported before app patches the environment
    import app as panel

    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / "awg").mkdir(exist_ok=True)
    if reset:
        for suffix in ("", "-wal", "-shm"):
            (STATE / f"panel.db{suffix}").unlink(missing_ok=True)
    config = write_config(port)
    panel.CONFIG_PATH = STATE / "panel.json"
    panel.DB_PATH = STATE / "panel.db"
    panel.ANDROID_APK = STATE / "app.apk"
    # The cabinet hides the client-apps block when no APK is published. The
    # preview has no real build, so an empty placeholder keeps the block (and
    # the "for android" button) visible; a real APK placed here is left alone.
    if not panel.ANDROID_APK.exists():
        panel.ANDROID_APK.write_bytes(b"")
    panel.WINDOWS_MSI = STATE / "app.msi"
    # Same for the Windows installer: an empty placeholder keeps its button.
    if not panel.WINDOWS_MSI.exists():
        panel.WINDOWS_MSI.write_bytes(b"")
    os.environ["KASKAD_SESSION_SECRET"] = "dev-session-secret"
    os.environ["KASKAD_ADMIN_PASSWORD_HASH"] = auth.hash_password(ADMIN_PASSWORD)

    marker = STATE / "seed-version"
    fresh = not panel.DB_PATH.exists()
    stale_seed = not fresh and (not marker.exists()
                                or marker.read_text().strip() != SEED_VERSION)
    panel.init_db()
    if fresh:
        seed(panel)
        marker.write_text(SEED_VERSION + "\n")
    elif stale_seed:
        print("dev-ui: demo data is from an older seed; run with --reset "
              "to add the newer exits", flush=True)
    with panel.db() as conn:
        ids = [row[0] for row in conn.execute("SELECT id FROM clients ORDER BY id")]
        if ids:
            panel.traffic.ensure_schema(conn)
            top_up_traffic(conn, ids)

    status = failover_status(scenario)
    live = peers(panel)
    services = {"awg0": "active", "routing": "active",
                "firewall": "active", "failover": "active"}
    patches = [
        mock.patch.object(panel, "run", side_effect=fake_run),
        mock.patch.object(panel, "apply_conf", mock.Mock()),
        mock.patch.object(panel, "apply_routing", mock.Mock()),
        mock.patch.object(panel, "apply_exit", mock.Mock(return_value="")),
        mock.patch.object(panel, "iface_dump", lambda _iface: {"peers": live}),
        mock.patch.object(panel, "read_status", lambda: dict(status)),
        mock.patch.object(panel, "services", lambda: services),
        mock.patch.object(panel, "run_dir", lambda _name: status.get("active", "")),
        # qrencode is not installed everywhere; the preview only needs a square.
        mock.patch.object(panel, "qr_response",
                          lambda _cl: panel.Response(content=PNG_PIXEL,
                                                     media_type="image/png")),
    ]
    for patch in patches:
        patch.start()

    from fastapi.testclient import TestClient
    client = TestClient(panel.app, base_url="https://testserver",
                        follow_redirects=False)
    login = client.post("/login", data={"email": "admin", "password": ADMIN_PASSWORD})
    if login.status_code != 303:
        raise SystemExit(f"dev-ui: cannot sign in ({login.status_code})")
    return client, config, patches


def serve(port: int, scenario: str, reset: bool) -> None:
    client, config, patches = build_app(port, scenario, reset)
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def forward(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
            headers = {
                name: value for name, value in self.headers.items()
                if name.lower() not in ("host", "content-length", "connection",
                                        "accept-encoding")
            }
            with lock:
                if method == "GET":
                    response = client.get(self.path)
                else:
                    response = client.post(self.path, content=body, headers=headers)
            payload = response.content
            self.send_response(response.status_code)
            for name, value in response.headers.items():
                if name.lower() in ("content-length", "transfer-encoding", "connection"):
                    continue
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            self.forward("GET")

        def do_POST(self):
            self.forward("POST")

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"dev panel: http://127.0.0.1:{port}  (admin, scenario {scenario})", flush=True)
    print(f"state: {STATE}  |  Ctrl+C to stop", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        for patch in patches:
            patch.stop()


def python_mtimes() -> dict[str, float]:
    return {path.name: path.stat().st_mtime
            for path in sorted(PANEL.glob("*.py"))}


def supervise(port: int, scenario: str, reset: bool) -> None:
    child_args = [sys.executable, "-B", str(Path(__file__).resolve()),
                  "--child", "--port", str(port), "--scenario", scenario]
    if reset:
        child_args.append("--reset")
    # A restart must not wipe the data the user just changed in the browser.
    restart_args = [arg for arg in child_args if arg != "--reset"]
    changes = python_mtimes()
    child = subprocess.Popen(child_args)
    try:
        while child.poll() is None:
            time.sleep(1.0)
            current = python_mtimes()
            if current != changes:
                print("dev-ui: panel code changed, restarting", flush=True)
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                child = subprocess.Popen(restart_args)
                changes = current
    except KeyboardInterrupt:
        pass
    finally:
        if child.poll() is None:
            child.send_signal(signal.SIGINT)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
    if child.returncode not in (0, None):
        sys.exit(child.returncode)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local panel preview")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--scenario", choices=SCENARIOS, default="healthy")
    parser.add_argument("--reset", action="store_true", help="rebuild demo data")
    parser.add_argument("--no-reload", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        serve(args.port, args.scenario, args.reset)
    elif args.no_reload:
        serve(args.port, args.scenario, args.reset)
    else:
        supervise(args.port, args.scenario, args.reset)


if __name__ == "__main__":
    main()
