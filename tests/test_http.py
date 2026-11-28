"""HTTP and database tests for the panel.

They need FastAPI and the panel venv:

    /opt/kaskad/venv/bin/python -m unittest discover -s tests

The system side (awg, systemctl, ip) is mocked: these tests only check the
request handling, the database state and the transaction boundaries.
"""
import hashlib
import json
import os
import re
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))

try:
    from fastapi.testclient import TestClient

    import apkmeta
    import app
    import auth
    import presets
except ImportError:  # pragma: no cover - local python without fastapi
    apkmeta = None
    app = None
    TestClient = None
    auth = None
    presets = None

ADMIN_PASSWORD = "admin-password-123"
USER_PASSWORD = "client-password-123"
SECRET = "test-session-secret"

# A valid 1x1 PNG: enough to pass the magic-byte check the panel makes.
PNG_ICON = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00"
    b"\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


@unittest.skipUnless(app, "fastapi is not installed")
class PanelTestCase(unittest.TestCase):
    counter = 0

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.old_db = app.DB_PATH
        self.old_cfg = app.CONFIG_PATH
        app.DB_PATH = root / "panel.db"
        app.CONFIG_PATH = root / "panel.json"
        self.config = {
            "listen": {"host": "127.0.0.1", "port": 8080},
            "tls": {"cert": str(root / "panel.crt"), "key": str(root / "panel.key")},
            "version": "test",
            "commit": "test",
            "awg_dir": str(root / "awg"),
            "iface": "awg0",
            "address": "10.80.0.1",
            "net": "10.80.0.0/24",
            "clients_net": "10.80.0.0/24",
            "route_table": 100,
            "exit_mtu": 1340,
            "port": 51820,
            "mtu": 1280,
            "dns": "1.1.1.1",
            "endpoint": "vpn.example.com",
            "params": {},
        }
        app.CONFIG_PATH.write_text(json.dumps(self.config))
        os.environ["KASKAD_SESSION_SECRET"] = SECRET
        os.environ["KASKAD_ADMIN_PASSWORD_HASH"] = auth.hash_password(ADMIN_PASSWORD)
        app.init_db()
        app._attempts.clear()
        app._flash_secrets.clear()

        self.patches = [
            mock.patch.object(app, "apply_conf", mock.Mock()),
            mock.patch.object(app, "apply_routing", mock.Mock()),
            mock.patch.object(app, "apply_exit", mock.Mock(return_value="")),
            mock.patch.object(app, "run", side_effect=self.fake_run),
        ]
        for patch in self.patches:
            patch.start()
        self.client = TestClient(app.app, base_url="https://testserver",
                                 follow_redirects=False)

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        app.DB_PATH = self.old_db
        app.CONFIG_PATH = self.old_cfg
        self.tmp.cleanup()

    def fake_run(self, cmd, **kw):
        PanelTestCase.counter += 1
        n = PanelTestCase.counter
        if cmd[:2] == ["awg", "genkey"]:
            return subprocess.CompletedProcess(cmd, 0, f"private-{n}\n", "")
        if cmd[:2] == ["awg", "pubkey"]:
            return subprocess.CompletedProcess(cmd, 0, f"public-{n}\n", "")
        if cmd[:2] == ["awg", "genpsk"]:
            return subprocess.CompletedProcess(cmd, 0, f"psk-{n}\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    # -------------------------------------------------------------- helpers

    def csrf(self, path):
        response = self.client.get(path)
        match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
        self.assertIsNotNone(match, f"no csrf token on {path}")
        return match.group(1)

    def login(self, email, password):
        return self.client.post("/login", data={"email": email, "password": password})

    def login_admin(self):
        response = self.login("admin", ADMIN_PASSWORD)
        self.assertEqual(response.status_code, 303)
        return response

    def seed_account(self, email="c1@example.com", password=USER_PASSWORD,
                     enabled=1, max_configs=None):
        with app.db() as conn:
            cur = conn.execute(
                "INSERT INTO accounts (email, password_hash, enabled, "
                "token_version, max_configs, created_at) "
                "VALUES (?, ?, ?, 1, ?, 'now')",
                (email, auth.hash_password(password), enabled, max_configs),
            )
            return cur.lastrowid

    def seed_client(self, name="c1", ip="10.80.0.2", email="c1@example.com",
                    password=USER_PASSWORD, internet=1, enabled=1,
                    max_configs=None):
        """An account with its first configuration; returns (account, config)."""
        aid = self.seed_account(email, password, max_configs=max_configs)
        with app.db() as conn:
            table = app.routing.allocate_table(conn)
            cur = conn.execute(
                "INSERT INTO clients (account_id, name, ip, public_key, "
                "private_key, preshared_key, enabled, created_at, internet, "
                "table_num) VALUES (?, ?, ?, 'pubkey', 'privkey', 'psk', ?, "
                "'now', ?, ?)",
                (aid, name, ip, enabled, internet, table),
            )
            return aid, cur.lastrowid

    def seed_exit(self, name="e1", iface="awg1", mode="internet", routes="",
                  enabled=1, priority=10):
        with app.db() as conn:
            table = app.routing.allocate_table(conn) if mode == "routes" else 0
            cur = conn.execute(
                "INSERT INTO exits (name, iface, priority, enabled, conf, "
                "created_at, mode, routes, table_num) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name, iface, priority, enabled, "conf", "now", mode, routes, table),
            )
            return cur.lastrowid

    def grant(self, aid, cid, exit_id, priority=10):
        """Access for the account plus the configuration's own order row."""
        with app.db() as conn:
            conn.execute(
                "INSERT INTO account_exits (account_id, exit_id, priority) "
                "VALUES (?, ?, ?)", (aid, exit_id, priority),
            )
            conn.execute(
                "INSERT INTO client_internet_exits (client_id, exit_id, priority) "
                "VALUES (?, ?, ?)", (cid, exit_id, priority),
            )

    def grants(self, cid):
        with app.db() as conn:
            return [tuple(r) for r in conn.execute(
                "SELECT exit_id, priority FROM client_internet_exits "
                "WHERE client_id = ? ORDER BY priority", (cid,))]

    def account_grants(self, aid):
        with app.db() as conn:
            return [tuple(r) for r in conn.execute(
                "SELECT exit_id, priority FROM account_exits "
                "WHERE account_id = ? ORDER BY priority", (aid,))]

    def client_count(self):
        with app.db() as conn:
            return conn.execute("SELECT count(*) FROM clients").fetchone()[0]

    def account_count(self):
        with app.db() as conn:
            return conn.execute("SELECT count(*) FROM accounts").fetchone()[0]


class LoginTests(PanelTestCase):
    def test_bad_password_is_rejected(self):
        response = self.login("admin", "wrong-password")
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(app.COOKIE, response.cookies)

    def test_admin_login_redirects_home(self):
        response = self.login_admin()
        self.assertEqual(response.headers["location"], "/")
        self.assertIn(app.COOKIE, response.cookies)

    def test_bad_csrf_is_rejected(self):
        self.login_admin()
        response = self.client.post("/accounts", data={
            "email": "c1@example.com", "password": USER_PASSWORD,
            "csrf_token": "wrong",
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.account_count(), 0)


class RateLimitTests(PanelTestCase):
    def test_login_is_blocked_after_five_failures(self):
        for _ in range(5):
            self.assertEqual(self.login("admin", "wrong-password").status_code, 401)
        self.assertEqual(self.login("admin", "wrong-password").status_code, 429)


class RoleTests(PanelTestCase):
    def test_user_cannot_open_admin_pages(self):
        self.seed_client(email="c1@example.com")
        self.login("c1@example.com", USER_PASSWORD)
        for path in ("/accounts", "/configs", "/exits", "/journal"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 303, path)
            self.assertEqual(response.headers["location"], "/me")

    def test_user_cannot_change_grants(self):
        aid, _ = self.seed_client(email="c1@example.com")
        exit_id = self.seed_exit()
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf("/me/account")
        response = self.client.post(f"/accounts/{aid}/exits",
                                    data={"exits": [exit_id], "csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/me")
        self.assertEqual(self.account_grants(aid), [])

    def test_anonymous_is_redirected_to_login(self):
        response = self.client.get("/me")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")


class ThrottleTests(PanelTestCase):
    def test_pair_limit_blocks_only_that_pair(self):
        for _ in range(app.PAIR_LIMIT):
            app.note_failure("1.2.3.4", "a@example.com")
        self.assertTrue(app.rate_limited("1.2.3.4", "a@example.com"))
        self.assertFalse(app.rate_limited("1.2.3.4", "b@example.com"))
        self.assertFalse(app.rate_limited("5.6.7.8", "a@example.com"))

    def test_ip_limit_blocks_every_email(self):
        for n in range(app.IP_LIMIT):
            app.note_failure("1.2.3.4", f"user{n}@example.com")
        self.assertTrue(app.rate_limited("1.2.3.4", "else@example.com"))

    def test_email_attempts_only_add_a_delay(self):
        for n in range(10):
            app.note_failure(f"10.0.0.{n}", "admin")
        self.assertFalse(app.rate_limited("9.9.9.9", "admin"))
        self.assertGreater(app.login_delay("admin"), 0)
        self.assertLessEqual(app.login_delay("admin"), app.EMAIL_DELAY_MAX)

    def test_old_attempts_are_forgotten(self):
        app._attempts["ip:1.1.1.1"] = [time.time() - app.RATE_WINDOW - 10]
        self.assertFalse(app.rate_limited("1.1.1.1"))
        self.assertNotIn("ip:1.1.1.1", app._attempts)

    def test_ipv6_is_keyed_by_prefix(self):
        one = app.rate_key("2001:db8:1:2::1")
        two = app.rate_key("2001:db8:1:2::ffff")
        self.assertEqual(one, two)
        self.assertEqual(app.rate_key("10.0.0.1"), "10.0.0.1")

    def test_success_keeps_the_address_counter(self):
        for n in range(app.IP_LIMIT):
            app.note_failure("1.1.1.1", f"user{n}@example.com")
        app.clear_failures("1.1.1.1", "user0@example.com")
        self.assertTrue(app.rate_limited("1.1.1.1", "fresh@example.com"))

    def test_expired_flash_secrets_are_dropped(self):
        app._flash_secrets["stale"] = (time.time() - 1, "password")
        app._prune_secrets()
        self.assertNotIn("stale", app._flash_secrets)


class SessionTests(PanelTestCase):
    def stale_client(self, cookie):
        return TestClient(app.app, base_url="https://testserver",
                           follow_redirects=False,
                           cookies={app.COOKIE: cookie})

    def test_logout_revokes_the_cookie(self):
        self.login_admin()
        cookie = self.client.cookies.get(app.COOKIE)
        response = self.client.post("/logout")
        self.assertEqual(response.status_code, 303)
        stale = self.stale_client(cookie)
        self.assertEqual(stale.get("/").headers["location"], "/login")

    def test_sign_out_everywhere(self):
        self.seed_client(email="c1@example.com")
        self.login("c1@example.com", USER_PASSWORD)
        cookie = self.client.cookies.get(app.COOKIE)
        csrf = self.csrf("/me/account")
        response = self.client.post("/me/logout-all", data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")
        self.assertEqual(self.stale_client(cookie).get("/me").headers["location"],
                         "/login")
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT token_version FROM accounts").fetchone()[0], 2)

    def test_account_reset_revokes_user_sessions(self):
        aid, _ = self.seed_client(email="c1@example.com")
        self.login("c1@example.com", USER_PASSWORD)
        cookie = self.client.cookies.get(app.COOKIE)
        self.client.post("/logout")

        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        response = self.client.post(f"/accounts/{aid}/password",
                                    data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.stale_client(cookie).get("/me").headers["location"],
                         "/login")

    def test_upgrade_drops_sessions_from_before_accounts(self):
        """Account ids can collide with old users ids, so old cookies die."""
        app.start_session("user", 1, 1)
        with app.db() as conn:
            conn.execute("DROP TABLE accounts")
        app.init_db()
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM sessions").fetchone()[0], 0)

    def test_pages_are_not_cached_by_the_browser(self):
        # The pages do not reload themselves, so a cached copy would hide a
        # deploy until the user clears it.
        self.login_admin()
        response = self.client.get("/configs")
        self.assertEqual(response.headers.get("cache-control"), "no-store")

    def test_responses_carry_security_headers(self):
        self.login_admin()
        response = self.client.get("/configs")
        self.assertEqual(response.headers.get("x-frame-options"), "DENY")
        self.assertEqual(response.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(response.headers.get("referrer-policy"), "no-referrer")
        self.assertEqual(response.headers.get("strict-transport-security"),
                         "max-age=31536000")

    def test_the_theme_switch_is_an_icon(self):
        self.login_admin()
        page = self.client.get("/configs").text
        self.assertIn('id="theme-toggle"', page)
        self.assertIn('aria-label="switch to light theme"', page)
        self.assertNotIn(">light theme<", page)

    def test_healthz_is_public(self):
        fresh = {"ts": int(time.time())}
        with mock.patch.object(app, "read_status", return_value=fresh):
            response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        # A public endpoint must not describe the product or its release.
        self.assertEqual(set(response.json()), {"ok", "failover_age"})

    def test_ping_is_a_tiny_public_target(self):
        response = self.client.get("/ping")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "pong")
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_healthz_reports_a_stale_failover(self):
        old = {"ts": int(time.time()) - 600}
        with mock.patch.object(app, "read_status", return_value=old):
            response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.json()["ok"])
        self.assertEqual(set(response.json()), {"ok", "failover_age"})

    def test_healthz_fails_without_a_database(self):
        with mock.patch.object(app, "db", side_effect=RuntimeError("boom")):
            response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 503)


class AnonymousLoginTests(PanelTestCase):
    def set_anonymous(self, enabled):
        self.login_admin()
        data = {"csrf_token": self.csrf("/settings")}
        if enabled:
            data["enabled"] = "1"
        response = self.client.post("/settings/login-anonymous", data=data)
        self.assertEqual(response.status_code, 303)

    def test_the_signed_out_page_can_hide_the_project(self):
        self.assertIn("deeps", self.client.get("/login").text)
        self.set_anonymous(True)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT value FROM settings WHERE key = 'login_anonymous'"
            ).fetchone()[0], "1")
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM audit "
                "WHERE action = 'settings_login_anonymous'"
            ).fetchone()[0], 1)
        self.client.post("/logout")
        page = self.client.get("/login").text
        self.assertIn("<title>Sign in</title>", page)
        self.assertIn(">Sign in</h1>", page)
        self.assertIn('action="/login"', page)
        # The whole source, not just the visible text: no product name, no
        # stack, no panel scripts or styles, no hint of what is behind it.
        lowered = page.lower()
        for token in ("deeps", "kaskad", "deffhost", "github", "amnezia", "awg",
                      "wireguard", "vpn", "tunnel", "peer", "exit", "handshake",
                      "traffic", "status.json", "config", "client", "panel",
                      "oc-", "/static/", "vtest"):
            self.assertNotIn(token, lowered, token)

    def test_a_failed_sign_in_stays_anonymous(self):
        self.set_anonymous(True)
        self.client.post("/logout")
        response = self.client.post(
            "/login", data={"email": "admin", "password": "wrong-password"}
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn(">Sign in</h1>", response.text)
        self.assertNotIn("kaskad", response.text.lower())
        self.assertNotIn("/static/", response.text)

    def test_turning_it_off_restores_the_brand(self):
        self.set_anonymous(True)
        self.client.post("/logout")
        self.assertNotIn("kaskad", self.client.get("/login").text.lower())
        self.set_anonymous(False)
        self.client.post("/logout")
        page = self.client.get("/login").text
        self.assertIn('class="oc-brand"', page)
        self.assertIn('class="site-footer"', page)
        self.assertIn("deeps", page)

    def test_authenticated_pages_keep_the_brand(self):
        self.set_anonymous(True)
        page = self.client.get("/configs").text
        self.assertIn('class="oc-brand"', page)
        self.assertIn('class="site-footer"', page)

    def test_the_setting_rejects_a_bad_csrf_token(self):
        self.login_admin()
        response = self.client.post(
            "/settings/login-anonymous",
            data={"csrf_token": "nope", "enabled": "1"},
        )
        self.assertEqual(response.status_code, 400)
        with app.db() as conn:
            self.assertIsNone(conn.execute(
                "SELECT value FROM settings WHERE key = 'login_anonymous'"
            ).fetchone())


class ErrorSurfaceTests(PanelTestCase):
    def test_browser_errors_do_not_describe_the_framework(self):
        self.assertEqual(self.client.get("/").status_code, 303)
        root = self.client.get("/")
        self.assertEqual(root.headers["location"], "/login")
        self.assertEqual(root.content, b"")
        missing = self.client.get("/nope")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.content, b"")
        slash = self.client.get("/login/")
        self.assertEqual(slash.status_code, 404)
        self.assertEqual(slash.content, b"")
        status = self.client.get("/status.json")
        self.assertEqual(status.status_code, 401)
        self.assertEqual(status.content, b"")

    def test_the_mobile_api_keeps_its_json_errors(self):
        response = self.client.get("/api/me")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "sign in again")

    def test_a_malformed_form_gets_an_empty_422(self):
        response = self.client.post("/login", data={"email": "x"})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.content, b"")

    def test_the_mobile_api_keeps_its_json_validation_errors(self):
        response = self.client.post("/api/login", data={"email": "x"})
        self.assertEqual(response.status_code, 422)
        self.assertIn("detail", response.json())

    def test_static_is_hidden_only_while_sign_in_is_anonymous(self):
        self.assertEqual(self.client.get("/static/theme.css").status_code, 200)
        app.set_setting("login_anonymous", "1")
        hidden = self.client.get("/static/theme.css")
        self.assertEqual(hidden.status_code, 404)
        self.assertEqual(hidden.content, b"")
        self.login_admin()
        self.assertEqual(self.client.get("/static/theme.css").status_code, 200)


class PublicAssetTests(unittest.TestCase):
    def test_stylesheets_do_not_name_their_origin(self):
        static = Path(__file__).resolve().parents[1] / "panel" / "static"
        for name in ("theme.css", "components.css"):
            text = (static / name).read_text().lower()
            for token in ("opencode", "traffic history", "brand accent"):
                self.assertNotIn(token, text, f"{name}: {token}")


class AccountCheckTests(PanelTestCase):
    def start(self, email="c1@example.com", password=USER_PASSWORD):
        aid, cid = self.seed_client(email=email)
        self.login(email, password)
        return aid, cid

    def add(self, target="http://1.1.1.1/", kind="http", label=""):
        return self.client.post("/me/checks", data={
            "kind": kind, "target": target, "label": label,
            "csrf_token": self.csrf("/me/checks"),
        })

    def test_add_list_toggle_and_delete(self):
        aid, _ = self.start()
        response = self.add(label="public dns")
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            row = conn.execute(
                "SELECT * FROM account_checks WHERE account_id = ?", (aid,)
            ).fetchone()
        self.assertEqual(row["target"], "http://1.1.1.1/")
        page = self.client.get("/me/checks").text
        self.assertIn("http://1.1.1.1/", page)
        self.assertIn("public dns", page)
        toggle = self.client.post(f"/me/checks/{row['id']}/toggle", data={
            "csrf_token": self.csrf("/me/checks")})
        self.assertEqual(toggle.status_code, 303)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT enabled FROM account_checks WHERE id = ?", (row["id"],)
            ).fetchone()[0], 0)
        delete = self.client.post(f"/me/checks/{row['id']}/delete", data={
            "csrf_token": self.csrf("/me/checks")})
        self.assertEqual(delete.status_code, 303)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM account_checks").fetchone()[0], 0)

    def test_the_limit_is_three(self):
        self.start()
        for _ in range(3):
            self.assertEqual(self.add().status_code, 303)
        response = self.add()
        self.assertEqual(response.status_code, 303)
        self.assertIn("at%20most%203", response.headers["location"])
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM account_checks").fetchone()[0], 3)

    def test_private_targets_are_refused(self):
        self.start()
        for target, kind in (
            ("http://127.0.0.1/", "http"),
            ("http://10.0.0.1/", "http"),
            ("192.168.1.1", "icmp"),
            ("127.0.0.1", "icmp"),
            ("file:///etc/passwd", "http"),
        ):
            response = self.add(target=target, kind=kind)
            self.assertIn("err=", response.headers["location"])
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM account_checks").fetchone()[0], 0)

    def test_another_account_cannot_touch_the_check(self):
        aid, _ = self.start()
        self.add()
        with app.db() as conn:
            cid = conn.execute(
                "SELECT id FROM account_checks WHERE account_id = ?", (aid,)
            ).fetchone()[0]
        self.seed_client(name="other", ip="10.80.0.9", email="c2@example.com")
        self.login("c2@example.com", USER_PASSWORD)
        for action in ("toggle", "delete"):
            response = self.client.post(f"/me/checks/{cid}/{action}", data={
                "csrf_token": self.csrf("/me/checks")})
            self.assertEqual(response.status_code, 404)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM account_checks WHERE id = ?", (cid,)
            ).fetchone()[0], 1)

    def test_the_admin_sees_the_checks(self):
        aid, _ = self.start()
        self.add(label="corp")
        self.login_admin()
        page = self.client.get(f"/accounts/{aid}").text
        self.assertIn("corp", page)
        self.assertIn("http://1.1.1.1/", page)

    def test_the_cabinet_shows_a_failing_exit(self):
        import time as _time
        aid, _ = self.start()
        self.add()
        with app.db() as conn:
            cid = conn.execute(
                "SELECT id FROM account_checks WHERE account_id = ?", (aid,)
            ).fetchone()[0]
        status = {"ts": int(_time.time()),
                  "checks": {str(aid): {str(cid): {"failing": ["awg1"]}}}}
        with mock.patch.object(app, "read_status", return_value=status):
            page = self.client.get("/me/checks").text
        self.assertIn("failing via awg1", page)

    def test_the_cabinet_names_the_exit_country(self):
        aid, _ = self.start()
        self.add()
        self.seed_exit(name="nl-1", iface="awg1")
        with app.db() as conn:
            conn.execute("UPDATE exits SET country = 'Netherlands' WHERE iface = 'awg1'")
            cid = conn.execute(
                "SELECT id FROM account_checks WHERE account_id = ?", (aid,)
            ).fetchone()[0]
        status = {"ts": int(time.time()),
                  "checks": {str(aid): {str(cid): {"failing": ["awg1"]}}}}
        with mock.patch.object(app, "read_status", return_value=status):
            page = self.client.get("/me/checks").text
        self.assertIn("failing via Netherlands", page)
        self.assertNotIn("failing via awg1", page)

    def test_an_unreported_check_reads_unknown(self):
        aid, _ = self.start()
        self.add()
        status = {"ts": int(time.time()), "checks": {str(aid): {}}}
        with mock.patch.object(app, "read_status", return_value=status):
            page = self.client.get("/me/checks").text
        self.assertIn("unknown", page)

    def test_target_validation(self):
        self.assertIsNone(app.check_target_error("http", "http://1.1.1.1/"))
        self.assertIsNone(app.check_target_error("icmp", "1.1.1.1"))
        for kind, target in (
            ("http", "http://127.0.0.1/"), ("http", "http://10.0.0.1/"),
            ("http", "http://192.168.0.1/"), ("icmp", "127.0.0.1"),
            ("icmp", "10.0.0.1"), ("http", "file:///etc/passwd"),
            ("http", "http://user:pass@1.1.1.1/"),
            ("http", "http://1.1.1.1:notaport/"),
            ("http", "http://1.1.1.1:70000/"),
        ):
            self.assertIsNotNone(app.check_target_error(kind, target), target)



class ExitPinTests(PanelTestCase):
    def setUp(self):
        super().setUp()
        self.aid, self.cid = self.seed_client()
        self.first = self.seed_exit("nl-1", "awg1", priority=10)
        self.second = self.seed_exit("us-1", "awg2", priority=20)
        self.grant(self.aid, self.cid, self.first, 10)
        self.grant(self.aid, self.cid, self.second, 20)
        self.login("c1@example.com", USER_PASSWORD)

    def pinned(self):
        with app.db() as conn:
            return conn.execute(
                "SELECT pinned_iface FROM clients WHERE id = ?", (self.cid,)
            ).fetchone()[0]

    def post(self, action, exit_id=0):
        return self.client.post(
            f"/me/configs/{self.cid}/pin",
            data={"exit_id": exit_id, "action": action,
                  "csrf_token": self.csrf(f"/me/configs/{self.cid}")},
        )

    def test_pinning_a_degraded_exit_and_going_back(self):
        self.assertEqual(self.post("pin", self.second).status_code, 303)
        self.assertEqual(self.pinned(), "awg2")
        page = self.client.get(f"/me/configs/{self.cid}").text
        self.assertIn("Pinned", page)
        self.assertEqual(self.post("auto").status_code, 303)
        self.assertEqual(self.pinned(), "")

    def order(self):
        with app.db() as conn:
            return [r[0] for r in conn.execute(
                "SELECT exit_id FROM client_internet_exits "
                "WHERE client_id = ? ORDER BY priority, exit_id", (self.cid,))]

    def test_the_cabinet_saves_a_full_order(self):
        csrf = self.csrf(f"/me/configs/{self.cid}")
        response = self.client.post(f"/me/configs/{self.cid}/order/set", data={
            "order": [self.second, self.first], "csrf_token": csrf,
        }, headers={"X-Requested-With": "fetch"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})
        self.assertEqual(self.order(), [self.second, self.first])

    def test_the_cabinet_rejects_a_partial_or_foreign_order(self):
        csrf = self.csrf(f"/me/configs/{self.cid}")
        partial = self.client.post(f"/me/configs/{self.cid}/order/set", data={
            "order": [self.first], "csrf_token": csrf,
        })
        self.assertEqual(partial.status_code, 400)
        foreign = self.seed_exit("spare", "awg3", priority=30)
        bad = self.client.post(f"/me/configs/{self.cid}/order/set", data={
            "order": [self.first, foreign], "csrf_token": csrf,
        })
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(self.order(), [self.first, self.second])

    def test_the_cabinet_offers_a_grip_and_one_apply(self):
        with mock.patch.object(app, "read_status", return_value={"ts": int(time.time())}):
            page = self.client.get(f"/me/configs/{self.cid}").text
        self.assertIn('class="oc-table console-table me-exits-table"', page)
        self.assertIn('class="exit-grip"', page)
        self.assertIn('id="me-apply"', page)
        self.assertIn('id="me-pin"', page)
        self.assertIn('id="me-order-inputs"', page)
        self.assertIn('id="me-apply-button"', page)
        self.assertIn('disabled>apply</button>', page)
        self.assertNotIn('>save order</button>', page)
        self.assertNotIn('>save subnets</button>', page)

    def test_the_cabinet_applies_order_and_pin_together(self):
        csrf = self.csrf(f"/me/configs/{self.cid}")
        response = self.client.post(f"/me/configs/{self.cid}/apply", data={
            "order": [self.second, self.first], "exit_id": self.second,
            "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.order(), [self.second, self.first])
        self.assertEqual(self.pinned(), "awg2")

    def test_the_cabinet_apply_refuses_a_foreign_pin(self):
        foreign = self.seed_exit("spare", "awg3", priority=30)
        csrf = self.csrf(f"/me/configs/{self.cid}")
        response = self.client.post(f"/me/configs/{self.cid}/apply", data={
            "order": [self.first, self.second], "exit_id": foreign,
            "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.pinned(), "")

    def test_only_a_granted_exit_can_be_pinned(self):
        foreign = self.seed_exit("spare", "awg3", priority=30)
        self.assertEqual(self.post("pin", foreign).status_code, 404)
        self.assertEqual(self.pinned(), "")

    def test_an_exit_delete_clears_the_pin(self):
        self.post("pin", self.second)
        self.login_admin()
        self.client.post(f"/exits/{self.second}/delete", data={
            "csrf_token": self.csrf(f"/exits/{self.second}")})
        self.assertEqual(self.pinned(), "")

    def test_the_api_pins_and_reports_it(self):
        response = self.client.post("/api/login", data={
            "email": "c1@example.com", "password": USER_PASSWORD})
        headers = {"Authorization": "Bearer " + response.json()["token"]}
        pin = self.client.post("/api/me/exits/pin", headers=headers, data={
            "exit_id": self.second, "action": "pin"})
        self.assertEqual(pin.status_code, 200)
        self.assertEqual(pin.json()["pinned"], "awg2")
        with mock.patch.object(app, "read_status",
                               return_value={"ts": int(time.time())}):
            exits = self.client.get("/api/me/exits", headers=headers).json()
        self.assertEqual([e["pinned"] for e in exits], [False, True])
        auto = self.client.post("/api/me/exits/pin", headers=headers, data={
            "action": "auto"})
        self.assertEqual(auto.json()["pinned"], "")


class BodyLimitTests(PanelTestCase):
    def test_an_oversized_form_is_rejected(self):
        response = self.client.post(
            "/login",
            content=b"email=a%40b.c&password=" + b"x" * (app.MAX_BODY_BYTES + 1),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(response.status_code, 413)

    def test_a_chunked_body_over_the_limit_is_rejected(self):
        chunk = b"x" * (app.MAX_BODY_BYTES // 2 + 1)
        response = self.client.post(
            "/login",
            content=iter([chunk, chunk]),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(response.status_code, 413)

    def test_a_normal_form_still_works(self):
        response = self.client.post(
            "/login", data={"email": "admin", "password": "wrong-password"})
        self.assertEqual(response.status_code, 401)


class CabinetExitStateTests(PanelTestCase):
    def test_me_shows_the_exit_in_use_without_its_state(self):
        aid, cid = self.seed_client()
        eid = self.seed_exit(name="nl-1", iface="awg1")
        self.grant(aid, cid, eid)
        self.login("c1@example.com", USER_PASSWORD)
        status = {
            "ts": int(time.time()),
            "clients": {"10.80.0.2": "awg1"},
            "exits": {"awg1": {"alive": True, "degraded": True, "rtt_ms": 30}},
        }
        with mock.patch.object(app, "read_status", return_value=status):
            page = self.client.get("/me").text
        self.assertIn("nl-1", page)
        # The list names where the traffic leaves, but the exit state lives on
        # the configuration page: rows stay flush without a badge to stagger.
        self.assertNotIn('data-live="current-state|10.80.0.2"', page)

    def test_me_marks_a_configuration_online_with_a_green_dot(self):
        aid, cid = self.seed_client()
        self.login("c1@example.com", USER_PASSWORD)
        now = int(time.time())
        live = {"ok": True, "device": {}, "peers": {"pubkey": {
            "endpoint": "77.88.99.3:51820", "handshake": now - 20,
            "rx": 1, "tx": 1}}}
        with mock.patch.object(app, "iface_dump", return_value=live):
            page = self.client.get("/me").text
        self.assertIn('data-live="config-online|10.80.0.2"', page)
        self.assertIn("config-state config-state--up", page)
        self.assertNotIn(">online<", page)

    def test_me_marks_a_silent_configuration_with_a_red_dot(self):
        aid, cid = self.seed_client()
        self.login("c1@example.com", USER_PASSWORD)
        live = {"ok": True, "device": {}, "peers": {"pubkey": {
            "endpoint": "", "handshake": 1, "rx": 0, "tx": 0}}}
        with mock.patch.object(app, "iface_dump", return_value=live):
            page = self.client.get("/me").text
        self.assertIn("config-state config-state--down", page)

    def test_me_prefers_the_exit_comment_over_its_name(self):
        aid, cid = self.seed_client()
        eid = self.seed_exit(name="nl-1", iface="awg1")
        with app.db() as conn:
            conn.execute(
                "UPDATE exits SET comment = 'Amsterdam' WHERE id = ?", (eid,))
        self.grant(aid, cid, eid)
        self.login("c1@example.com", USER_PASSWORD)
        status = {
            "ts": int(time.time()),
            "clients": {"10.80.0.2": "awg1"},
            "exits": {"awg1": {"alive": True, "degraded": False, "rtt_ms": 30}},
        }
        with mock.patch.object(app, "read_status", return_value=status):
            page = self.client.get("/me").text
        self.assertIn("Amsterdam", page)
        self.assertNotIn(">nl-1<", page)

    def test_me_claims_no_state_when_the_failover_is_silent(self):
        aid, cid = self.seed_client()
        eid = self.seed_exit(name="nl-1", iface="awg1")
        self.grant(aid, cid, eid)
        self.login("c1@example.com", USER_PASSWORD)
        status = {
            "ts": int(time.time()) - 3600,
            "clients": {"10.80.0.2": "awg1"},
            "exits": {"awg1": {"alive": True, "degraded": False, "rtt_ms": 30}},
        }
        with mock.patch.object(app, "read_status", return_value=status):
            page = self.client.get("/me").text
        # A stale status is dropped entirely: the cabinet must not name an
        # exit as the one in use when the failover stopped reporting.
        self.assertNotIn("nl-1", page)

    def test_me_shows_the_country_before_the_comment(self):
        aid, cid = self.seed_client()
        eid = self.seed_exit(name="nl-1", iface="awg1")
        with app.db() as conn:
            conn.execute(
                "UPDATE exits SET country = 'Netherlands', comment = 'Amsterdam' "
                "WHERE id = ?", (eid,))
        self.grant(aid, cid, eid)
        self.login("c1@example.com", USER_PASSWORD)
        status = {
            "ts": int(time.time()),
            "clients": {"10.80.0.2": "awg1"},
            "exits": {"awg1": {"alive": True, "degraded": False, "rtt_ms": 30}},
        }
        with mock.patch.object(app, "read_status", return_value=status):
            page = self.client.get("/me").text
        self.assertIn("Netherlands", page)
        self.assertNotIn("Amsterdam", page)

    def test_admin_saves_the_exit_country(self):
        self.login_admin()
        eid = self.seed_exit(name="nl-1", iface="awg1")
        response = self.client.post(f"/exits/{eid}/details", data={
            "country": "Netherlands", "comment": "Amsterdam",
            "csrf_token": self.csrf(f"/exits/{eid}"),
        })
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            row = conn.execute(
                "SELECT country, comment FROM exits WHERE id = ?", (eid,)
            ).fetchone()
        self.assertEqual(row["country"], "Netherlands")
        self.assertEqual(row["comment"], "Amsterdam")
        page = self.client.get(f"/exits/{eid}").text
        self.assertIn("Netherlands", page)

    def test_a_long_country_is_refused(self):
        self.login_admin()
        eid = self.seed_exit(name="nl-1", iface="awg1")
        response = self.client.post(f"/exits/{eid}/details", data={
            "country": "x" * 41, "comment": "",
            "csrf_token": self.csrf(f"/exits/{eid}"),
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT country FROM exits WHERE id = ?", (eid,)).fetchone()[0], "")

    def test_account_shows_the_default_exit_order(self):
        aid, cid = self.seed_client()
        first = self.seed_exit(name="nl-1", iface="awg1", priority=10)
        second = self.seed_exit(name="us-1", iface="awg2", priority=20)
        self.grant(aid, cid, first, 10)
        self.grant(aid, cid, second, 20)
        self.login("c1@example.com", USER_PASSWORD)
        status = {
            "ts": int(time.time()),
            "clients": {},
            "exits": {
                "awg1": {"alive": True, "degraded": False, "rtt_ms": 20},
                "awg2": {"alive": True, "degraded": True, "rtt_ms": 90},
            },
        }
        with mock.patch.object(app, "read_status", return_value=status):
            page = self.client.get("/me/account").text
        self.assertIn("exit order", page)
        self.assertLess(page.index("nl-1"), page.index("us-1"))
        self.assertIn("degraded", page)
        self.assertIn("up", page)

    def test_account_order_lists_only_granted_exits(self):
        aid, cid = self.seed_client()
        first = self.seed_exit(name="nl-1", iface="awg1")
        self.seed_exit(name="spare", iface="awg2", priority=20)
        self.grant(aid, cid, first)
        self.login("c1@example.com", USER_PASSWORD)
        with mock.patch.object(app, "read_status", return_value={"ts": int(time.time())}):
            page = self.client.get("/me/account").text
        self.assertIn("nl-1", page)
        self.assertNotIn("spare", page)


class ConfigOnlineDotTests(PanelTestCase):
    def online_peers(self, seconds_ago):
        now = int(time.time())
        return {"ok": True, "device": {}, "peers": {"pubkey": {
            "endpoint": "", "handshake": now - seconds_ago, "rx": 0, "tx": 0}}}

    def test_the_configuration_list_marks_an_online_configuration(self):
        aid, cid = self.seed_client()
        self.login_admin()
        with mock.patch.object(app, "iface_dump",
                               return_value=self.online_peers(20)):
            page = self.client.get("/configs").text
        self.assertIn("config-state config-state--up", page)

    def test_the_account_page_marks_a_silent_configuration(self):
        aid, cid = self.seed_client()
        self.login_admin()
        with mock.patch.object(app, "iface_dump",
                               return_value=self.online_peers(600)):
            page = self.client.get(f"/accounts/{aid}").text
        self.assertIn("config-state config-state--down", page)

    def test_a_disabled_configuration_gets_a_grey_dot(self):
        aid, cid = self.seed_client(enabled=0)
        self.login_admin()
        # Even a fresh handshake does not make a disabled row look online.
        with mock.patch.object(app, "iface_dump",
                               return_value=self.online_peers(20)):
            page = self.client.get("/configs").text
        self.assertIn("config-state config-state--disabled", page)


class RollbackMessageTests(PanelTestCase):
    """A failed device rollback must not be reported as 'nothing changed'."""

    def error_text(self, response):
        from urllib.parse import parse_qs, urlparse
        location = response.headers["location"]
        return parse_qs(urlparse(location).query).get("err", [""])[0]

    def rollback_error(self):
        return app.RollbackFailed(
            "syncconf: boom; rollback failed: device still has 1 unexpected peer"
        )

    def assert_warns(self, response):
        self.assertEqual(response.status_code, 303)
        text = self.error_text(response)
        self.assertIn("could not be rolled back", text)
        self.assertIn("inspect", text)
        self.assertNotIn("nothing", text)

    def make_account(self, email="rb@example.com"):
        self.login_admin()
        csrf = self.csrf("/accounts/new")
        response = self.client.post("/accounts", data={
            "email": email, "password": USER_PASSWORD, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        location = response.headers["location"]
        return int(location.split("/accounts/")[1].split("?")[0])

    def test_create_config(self):
        aid = self.make_account()
        csrf = self.csrf(f"/accounts/{aid}")
        app.apply_conf.side_effect = self.rollback_error()
        response = self.client.post(f"/accounts/{aid}/configs", data={
            "name": "rb", "csrf_token": csrf,
        })
        self.assert_warns(response)

    def test_toggle_config(self):
        _, cid = self.seed_client()
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        app.apply_conf.side_effect = self.rollback_error()
        self.assert_warns(self.client.post(f"/configs/{cid}/toggle",
                                           data={"csrf_token": csrf}))

    def test_delete_config(self):
        _, cid = self.seed_client()
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        app.apply_conf.side_effect = self.rollback_error()
        self.assert_warns(self.client.post(f"/configs/{cid}/delete",
                                           data={"csrf_token": csrf}))

    def test_reissue(self):
        _, cid = self.seed_client(email="rb@example.com")
        self.login("rb@example.com", USER_PASSWORD)
        csrf = self.csrf(f"/me/configs/{cid}")
        app.apply_conf.side_effect = self.rollback_error()
        self.assert_warns(self.client.post(f"/me/configs/{cid}/reissue",
                                           data={"csrf_token": csrf}))


class NatHttpTests(PanelTestCase):
    def test_routed_exit_nat_can_be_switched_off(self):
        exit_id = self.seed_exit("sub", "awg2", mode="routes", routes="10.9.0.0/24")
        self.login_admin()
        csrf = self.csrf(f"/exits/{exit_id}")
        response = self.client.post(f"/exits/{exit_id}/nat",
                                    data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT nat FROM exits WHERE id = ?", (exit_id,)).fetchone()[0], 0)
        calls = [" ".join(call.args[0]) for call in app.run.call_args_list]
        self.assertTrue(any("conntrack -D -s" in call for call in calls))
        response = self.client.post(f"/exits/{exit_id}/nat",
                                    data={"nat": "on", "csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT nat FROM exits WHERE id = ?", (exit_id,)).fetchone()[0], 1)

    def test_internet_exit_nat_cannot_be_switched_off(self):
        exit_id = self.seed_exit("net", "awg1", mode="internet")
        self.login_admin()
        csrf = self.csrf(f"/exits/{exit_id}")
        response = self.client.post(f"/exits/{exit_id}/nat",
                                    data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT nat FROM exits WHERE id = ?", (exit_id,)).fetchone()[0], 1)


class ExitCreationTests(PanelTestCase):
    conf = (
        "[Interface]\nAddress = 10.90.0.2/30\nPrivateKey = exit-private\n\n"
        "[Peer]\nPublicKey = exit-public\nEndpoint = host:51820\n"
        "AllowedIPs = 10.90.0.0/30\n"
    )

    def create(self, mode="routes", routes="", conf=None):
        self.login_admin()
        csrf = self.csrf("/exits/new")
        return self.client.post("/exits", data={
            "name": "routed1", "mode": mode, "priority": "20",
            "routes": routes, "dns": "", "comment": "", "nat": "on",
            "conf": conf or self.conf, "csrf_token": csrf,
        })

    def stored_exit(self):
        with app.db() as conn:
            return conn.execute("SELECT * FROM exits").fetchone()

    def test_subnets_are_taken_from_allowed_ips(self):
        response = self.create(routes="")
        self.assertEqual(response.status_code, 303)
        self.assertIn("ok=exit+added", response.headers["location"])
        row = self.stored_exit()
        self.assertEqual(row["mode"], "routes")
        self.assertEqual(row["routes"], "10.90.0.0/30")
        self.assertGreater(row["table_num"], 0)

    def test_subnets_fall_back_to_the_address_network(self):
        conf = self.conf.replace("AllowedIPs = 10.90.0.0/30",
                                 "AllowedIPs = 0.0.0.0/0")
        response = self.create(routes="", conf=conf)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.stored_exit()["routes"], "10.90.0.0/30")

    def test_manual_subnets_win(self):
        response = self.create(routes="192.168.77.0/24")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.stored_exit()["routes"], "192.168.77.0/24")

    def test_internet_exit_ignores_allowed_ips(self):
        response = self.create(mode="internet")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.stored_exit()["routes"], "")


class AdminPingTests(PanelTestCase):
    def test_configuration_diagnosis_distinguishes_tunnel_and_internet(self):
        now = 1000
        view = {"enabled": True, "internet": True, "exits": [], "ip": "10.80.0.2",
                "handshake": now - 10}
        status = {"ts": now, "clients": {view["ip"]: "awg1"},
                  "exits": {"awg1": {"alive": False}}}
        self.assertEqual(app.configuration_diagnosis(view, status, now),
                         {"state": "Online", "warning": "No working internet exit"})
        self.assertEqual(app.configuration_diagnosis(view, {}, now)["warning"],
                         "Exit status unavailable")
        for fields, expected in (({"enabled": False}, "Disabled"),
                                 ({"internet": False}, "No access assigned"),
                                 ({"handshake": 0}, "No handshake recorded"),
                                 ({"handshake": now - 200}, "Last handshake")):
            self.assertEqual(app.configuration_diagnosis(view | fields, status, now)["state"],
                             expected)

    def test_overview_measures_the_device_round_trip(self):
        self.seed_exit("e1", "awg1", mode="internet")
        status = {"exits": {"awg1": {"alive": True, "rtt_ms": 40}},
                  "active": "awg1", "clients": {}, "ts": int(time.time())}
        self.login_admin()
        with mock.patch.object(app, "read_status", return_value=status), mock.patch.object(app, "run_dir", return_value="awg1"):
            response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn('data-live="ping|awg1"', response.text)
        self.assertIn('id="client-rtt"', response.text)
        self.assertIn("fetch('/ping'", response.text)
        self.assertIn("kaskadLive = function", response.text)
        self.assertNotIn("location.reload", response.text)


class AccountTests(PanelTestCase):
    def create_account(self, email="new@example.com", max_configs=""):
        self.login_admin()
        csrf = self.csrf("/accounts/new")
        response = self.client.post("/accounts", data={
            "email": email, "password": USER_PASSWORD,
            "max_configs": max_configs, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        location = response.headers["location"]
        return int(location.split("/accounts/")[1].split("?")[0])

    def seed_orphan(self, name="old", ip="10.80.0.9"):
        """A configuration from before accounts existed: no account_id."""
        with app.db() as conn:
            cid = conn.execute(
                "INSERT INTO clients (name, ip, public_key, private_key, "
                "preshared_key, enabled, created_at, internet, table_num) "
                "VALUES (?, ?, 'pub', 'priv', 'psk', 1, 'now', 1, 0)",
                (name, ip),
            ).lastrowid
            conn.execute("UPDATE clients SET table_num = ? WHERE id = ?",
                         (app.routing.allocate_table(conn), cid))
            return cid

    def test_orphan_config_is_assigned_keeping_its_keys(self):
        aid = self.seed_account(email="owner@example.com")
        cid = self.seed_orphan()
        first = self.seed_exit("e1", "awg1", priority=10)
        second = self.seed_exit("e2", "awg2", priority=20)
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        self.client.post(f"/accounts/{aid}/exits", data={
            "exits": [second, first], "csrf_token": csrf,
        })
        with app.db() as conn:
            before = conn.execute(
                "SELECT public_key, ip FROM clients WHERE id = ?", (cid,)).fetchone()
        response = self.client.post(f"/configs/{cid}/account", data={
            "account_id": aid, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("ok=", response.headers["location"])
        with app.db() as conn:
            row = conn.execute(
                "SELECT account_id, public_key, ip FROM clients WHERE id = ?",
                (cid,)).fetchone()
        self.assertEqual(row["account_id"], aid)
        self.assertEqual(row["public_key"], before["public_key"])
        self.assertEqual(row["ip"], before["ip"])
        # The account order replaces the legacy per-client rows.
        self.assertEqual([e for e, _ in self.grants(cid)], [first, second])

    def test_assigned_config_is_refused_a_second_time(self):
        aid, cid = self.seed_client()
        other = self.seed_account(email="other@example.com")
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/account", data={
            "account_id": other, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT account_id FROM clients WHERE id = ?", (cid,)).fetchone()[0], aid)

    def test_assignment_rejects_a_missing_account(self):
        cid = self.seed_orphan()
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/account", data={
            "account_id": 999999, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 404)
        with app.db() as conn:
            self.assertIsNone(conn.execute(
                "SELECT account_id FROM clients WHERE id = ?", (cid,)).fetchone()[0])

    def test_assignment_of_a_missing_config_is_404(self):
        aid = self.seed_account(email="owner@example.com")
        self.login_admin()
        csrf = self.csrf("/configs/new")
        response = self.client.post("/configs/999999/account", data={
            "account_id": aid, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 404)

    def test_assignment_respects_the_limit(self):
        aid, _ = self.seed_client(email="full@example.com", max_configs=1)
        cid = self.seed_orphan()
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/account", data={
            "account_id": aid, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        with app.db() as conn:
            self.assertIsNone(conn.execute(
                "SELECT account_id FROM clients WHERE id = ?", (cid,)).fetchone()[0])

    def test_create_account_and_config(self):
        aid = self.create_account()
        with app.db() as conn:
            account = conn.execute("SELECT * FROM accounts").fetchone()
        self.assertEqual(account["email"], "new@example.com")
        self.assertIsNone(account["max_configs"])

        csrf = self.csrf("/configs/new")
        response = self.client.post("/configs", data={
            "account_id": aid, "name": "new-client", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("/configs/", response.headers["location"])
        with app.db() as conn:
            config = conn.execute("SELECT * FROM clients").fetchone()
            claims = [tuple(r) for r in conn.execute(
                "SELECT table_num, kind, owner_id FROM table_numbers")]
        self.assertEqual(config["account_id"], aid)
        self.assertEqual(config["name"], "new-client")
        self.assertEqual(config["ip"], "10.80.0.2")
        self.assertGreaterEqual(config["table_num"], app.routing.TABLE_POOL_BASE)
        self.assertEqual(claims,
                         [(config["table_num"], "client", config["id"])])
        app.apply_conf.assert_called()
        # The tunnel must be configured from the uncommitted transaction.
        self.assertIsNotNone(app.apply_conf.call_args.args[1])

    def test_duplicate_email_creates_nothing(self):
        self.seed_account(email="taken@example.com")
        self.login_admin()
        csrf = self.csrf("/accounts/new")
        response = self.client.post("/accounts", data={
            "email": "taken@example.com", "password": USER_PASSWORD,
            "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        self.assertEqual(self.account_count(), 1)

    def test_failed_apply_leaves_no_rows(self):
        self.seed_account(email="broken@example.com")
        with app.db() as conn:
            aid = conn.execute("SELECT id FROM accounts").fetchone()[0]
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        app.apply_conf.side_effect = RuntimeError("syncconf: boom")
        response = self.client.post(f"/accounts/{aid}/configs", data={
            "name": "broken", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        self.assertEqual(self.client_count(), 0)

    def test_delete_config_removes_grants_and_table(self):
        aid, cid = self.seed_client()
        exit_id = self.seed_exit()
        self.grant(aid, cid, exit_id)
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/delete",
                                    data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM clients").fetchone()[0], 0)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM client_internet_exits").fetchone()[0], 0)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM table_numbers").fetchone()[0], 0)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM accounts").fetchone()[0], 1)

    def test_exits_and_subnets_are_separate_tables(self):
        aid, _ = self.seed_client()
        self.seed_exit("north", "awg1")
        self.seed_exit("subnet-lab", "awg2", mode="routes",
                       routes="10.5.0.0/24")
        self.login_admin()
        page = self.client.get(f"/accounts/{aid}").text
        self.assertIn('class="oc-table console-table account-access-table"', page)
        self.assertIn('class="oc-table console-table account-subnets-table"', page)
        self.assertIn(">Exits</h3>", page)
        self.assertIn(">Subnets</h3>", page)
        self.assertNotIn("?access=", page)

    def test_unchecked_rows_sink_and_lose_the_grip(self):
        aid, cid = self.seed_client()
        wanted = self.seed_exit("wanted", "awg1", priority=50)
        spare = self.seed_exit("spare", "awg2", priority=1)
        self.grant(aid, cid, wanted)
        self.login_admin()
        with mock.patch.object(app, "read_status", return_value={"ts": int(time.time())}):
            page = self.client.get(f"/accounts/{aid}").text
        # The granted exit comes first even though its priority is higher.
        self.assertLess(page.index(">wanted<"), page.index(">spare<"))
        spare_row = re.search(
            rf'<tr data-exit-id="{spare}"[^>]*>(.*?)</tr>', page, re.S).group(1)
        self.assertIn("is-disabled", re.search(
            rf'<tr data-exit-id="{spare}"[^>]*>', page).group(0))
        self.assertRegex(spare_row, r'class="exit-grip"[^>]*hidden')

    def test_exit_order_is_replaced_in_one_request(self):
        aid, cid = self.seed_client()
        first = self.seed_exit("first", "awg1", priority=10)
        second = self.seed_exit("second", "awg2", priority=20)
        third = self.seed_exit("third", "awg3", priority=30)
        for exit_id, priority in ((first, 10), (second, 20), (third, 30)):
            self.grant(aid, cid, exit_id, priority)
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        response = self.client.post(f"/accounts/{aid}/order/set", data={
            "order": [third, first, second], "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual([e for e, _ in self.account_grants(aid)],
                         [third, first, second])
        # Existing configurations keep their own order until "apply order".
        self.assertEqual([e for e, _ in self.grants(cid)], [first, second, third])
        # The table lists the granted exits in that same order.
        page = self.client.get(f"/accounts/{aid}").text
        self.assertLess(page.index(">third<"), page.index(">first<"))
        self.assertLess(page.index(">first<"), page.index(">second<"))

    def test_exit_order_must_list_every_granted_exit_once(self):
        aid, cid = self.seed_client()
        first = self.seed_exit("first", "awg1")
        second = self.seed_exit("second", "awg2")
        stranger = self.seed_exit("stranger", "awg3")
        self.grant(aid, cid, first, 10)
        self.grant(aid, cid, second, 20)
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        for order in ([first], [first, second, stranger], [first, first]):
            with self.subTest(order=order):
                response = self.client.post(f"/accounts/{aid}/order/set", data={
                    "order": order, "csrf_token": csrf,
                })
                self.assertEqual(response.status_code, 400)
        self.assertEqual([e for e, _ in self.account_grants(aid)], [first, second])
        self.assertEqual([e for e, _ in self.grants(cid)], [first, second])

    def test_exit_order_answers_the_drag_script_with_json(self):
        aid, cid = self.seed_client()
        first = self.seed_exit("first", "awg1")
        second = self.seed_exit("second", "awg2")
        self.grant(aid, cid, first, 10)
        self.grant(aid, cid, second, 20)
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        response = self.client.post(
            f"/accounts/{aid}/order/set",
            data={"order": [second, first], "csrf_token": csrf},
            headers={"X-Requested-With": "fetch"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})
        self.assertEqual([e for e, _ in self.account_grants(aid)], [second, first])

    def test_admin_account_offers_a_grip_instead_of_move_buttons(self):
        aid, cid = self.seed_client()
        granted = self.seed_exit("granted", "awg1")
        self.seed_exit("spare", "awg2")
        self.grant(aid, cid, granted)
        self.login_admin()
        with mock.patch.object(app, "read_status", return_value={"ts": int(time.time())}):
            page = self.client.get(f"/accounts/{aid}").text
        self.assertIn('class="exit-grip"', page)
        self.assertIn(f'data-exit-id="{granted}"', page)
        self.assertNotIn('>up</button>', page)
        self.assertNotIn('>down</button>', page)
        self.assertIn('id="order-status"', page)
        self.assertIn('id="account-save"', page)
        self.assertIn('disabled>save</button>', page)
        self.assertIn("aria-live=\"polite\"", page)

    def test_saving_access_then_order_together_keeps_both(self):
        aid, cid = self.seed_client()
        first = self.seed_exit("first", "awg1")
        second = self.seed_exit("second", "awg2")
        subnet = self.seed_exit("subnet", "awg5", mode="routes",
                                routes="192.168.70.0/24")
        self.grant(aid, cid, first, 10)
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        # The combined button saves the switches first, sending the subnets as
        # well, then posts the internet order.
        response = self.client.post(f"/accounts/{aid}/exits", data={
            "exits": [second, first, subnet], "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        response = self.client.post(f"/accounts/{aid}/order/set", data={
            "order": [second, first], "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual([e for e, _ in self.account_grants(aid)],
                         [second, first, subnet])

    def test_rows_without_access_are_dimmed_like_the_console(self):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("granted", "awg1"))
        self.seed_exit("spare", "awg2")
        self.login_admin()
        with mock.patch.object(app, "read_status", return_value={"ts": int(time.time())}):
            page = self.client.get(f"/accounts/{aid}").text
        self.assertEqual(page.count('class="is-disabled"'), 1)
        self.assertRegex(page, rf'<tr data-exit-id="\d+" class="is-disabled">[\s\S]*?hidden')

    def test_admin_account_lists_disabled_exits_last_and_dimmed(self):
        aid, cid = self.seed_client()
        live = self.seed_exit("live", "awg2", priority=50)
        retired = self.seed_exit("retired", "awg1", priority=1, enabled=0)
        self.grant(aid, cid, live)
        self.login_admin()
        with mock.patch.object(app, "read_status", return_value={"ts": int(time.time())}):
            page = self.client.get(f"/accounts/{aid}").text
        self.assertIn('class="is-disabled"', page)
        self.assertIn('aria-label="Access to retired"', page)
        self.assertLess(page.index(">live<"), page.index(">retired<"))
        with app.db() as conn:
            disabled_input = re.search(
                rf'<input form="account-access"[^>]*name="exits" value="{retired}"[^>]*>',
                page).group(0)
        self.assertIn("disabled", disabled_input)
        self.assertNotIn("checked", disabled_input)

    def test_delete_account_removes_its_configs(self):
        aid, _ = self.seed_client()
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        response = self.client.post(f"/accounts/{aid}/delete",
                                    data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM clients").fetchone()[0], 0)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM accounts").fetchone()[0], 0)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM table_numbers").fetchone()[0], 0)

    def test_failed_apply_keeps_the_config(self):
        _, cid = self.seed_client()
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        app.apply_conf.side_effect = RuntimeError("syncconf: boom")
        response = self.client.post(f"/configs/{cid}/delete",
                                    data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        self.assertEqual(self.client_count(), 1)


class ConfigLimitTests(PanelTestCase):
    def test_personal_limit_blocks_another_config(self):
        aid, _ = self.seed_client(max_configs=1)
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        response = self.client.post(f"/accounts/{aid}/configs", data={
            "name": "second", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        self.assertEqual(self.client_count(), 1)

    def test_limit_below_the_current_count_is_rejected(self):
        aid, _ = self.seed_client()
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        response = self.client.post(f"/accounts/{aid}/max-configs", data={
            "max_configs": "0", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])

    def test_default_limit_is_editable(self):
        self.login_admin()
        response = self.client.get("/settings")
        self.assertIn("default configurations per account", response.text)
        csrf = self.csrf("/settings")
        response = self.client.post("/settings/max-configs", data={
            "default_max_configs": "2", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual(app.setting("default_max_configs"), "2")


class AdminActivitySystemTests(PanelTestCase):
    def test_activity_labels_and_filter_survive_pagination(self):
        self.login_admin()
        app.audit("login_failed", "unrelated detail")
        for i in range(51):
            app.audit("exit_failover", f"Switch #{i}.")
        app.audit("legacy_event", "<old detail>")

        overview = self.client.get("/").text
        self.assertIn("Global exit switched automatically", overview)
        self.assertIn("Legacy event", overview)
        self.assertIn("&lt;old detail&gt;", overview)
        first = self.client.get("/journal?action=exit_failover").text
        self.assertIn('value="exit_failover" selected>Global exit switched automatically', first)
        self.assertIn('href="/journal?page=2&amp;action=exit_failover"', first)
        self.assertNotIn("unrelated detail", first)
        last = self.client.get("/journal?action=exit_failover&page=999").text
        self.assertIn("Page 2 of 2", last)
        self.assertIn("Switch #0.", last)
        self.assertNotIn("Switch #50.", last)
        empty = self.client.get("/journal?action=unrecorded_event").text
        self.assertIn("No events match this filter", empty)
        self.assertIn('value="unrecorded_event" selected', empty)

    def test_system_service_health_is_independent_of_exit_status(self):
        self.login_admin()
        states = {"awg0": "active", "routing": "failed", "firewall": "unknown",
                  "failover": "activating"}
        with mock.patch.object(app, "services", return_value=states), \
                mock.patch.object(app, "read_status", return_value={}):
            page = self.client.get("/settings").text
            data = self.client.get("/status.json?overview=true").json()
        self.assertLess(page.index('id="services"'), page.index("Panel and network"))
        self.assertIn('data-live="service|routing">Failed</span>', page)
        self.assertIn('data-live="service|firewall">Unknown</span>', page)
        self.assertFalse(data["status_fresh"])
        self.assertEqual(data["overview"]["services"]["failover"],
                         {"label": "Starting", "tone": "warning"})
        self.seed_account()
        self.login("c1@example.com", USER_PASSWORD)
        denied = self.client.get("/settings")
        self.assertEqual(denied.status_code, 303)
        self.assertEqual(denied.headers["location"], "/me")
        self.assertNotIn("overview", self.client.get("/status.json?overview=true").json())


class RoutedChoiceTests(PanelTestCase):
    def test_admin_hides_subnets_not_granted_to_the_account(self):
        aid, cid, routed = self.account_with_routed()
        self.seed_exit("ungranted-subnet", "awg9", mode="routes",
                       routes="10.9.0.0/24")
        with app.db() as conn:
            conn.execute("DELETE FROM client_exits WHERE client_id = ?", (cid,))
        self.login_admin()
        text = self.client.get(f"/configs/{cid}").text
        self.assertNotIn(f'/accounts/{aid}#access', text)
        self.assertNotIn("selected</span>", text)
        self.assertIn("Only subnets granted to the account can be enabled here", text)
        self.assertNotIn("ungranted-subnet", text)
        self.assertNotIn("Not allowed for this account", text)
        self.login("c1@example.com", USER_PASSWORD)
        text = self.client.get(f"/me/configs/{cid}").text
        self.assertIn("Only subnets granted to the account can be enabled here", text)
        self.assertIn('class="oc-table console-table me-subnets-table"', text)
        self.assertNotIn("allowed subnets included", text)
        self.assertNotIn("ungranted-subnet", text)

    """Subnets are granted to the account and chosen per configuration."""

    def account_with_routed(self):
        aid, cid = self.seed_client(internet=0)
        routed = self.seed_exit("sub", "awg2", mode="routes",
                                routes="192.168.50.0/24")
        with app.db() as conn:
            conn.execute(
                "INSERT INTO account_exits (account_id, exit_id, priority) "
                "VALUES (?, ?, 10)", (aid, routed))
            conn.execute(
                "INSERT INTO client_exits (client_id, exit_id) VALUES (?, ?)",
                (cid, routed))
        return aid, cid, routed

    def chosen(self, cid):
        with app.db() as conn:
            return [r[0] for r in conn.execute(
                "SELECT exit_id FROM client_exits WHERE client_id = ?", (cid,))]

    def test_conf_follows_the_chosen_subnets(self):
        aid, cid, routed = self.account_with_routed()
        self.login_admin()
        text = self.conf_text(cid)
        self.assertIn("AllowedIPs = 192.168.50.0/24", text)
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/routed",
                                    data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.chosen(cid), [])
        # Nothing left to route: no config can be issued any more.
        self.assertEqual(self.client.get(f"/configs/{cid}/conf").status_code, 400)

    def conf_text(self, cid):
        response = self.client.get(f"/configs/{cid}/conf")
        self.assertEqual(response.status_code, 200)
        return response.text

    def test_the_download_keeps_the_conf_extension(self):
        # Android Chrome turns a text/plain download into .txt, so the panel
        # hands the file over as a generic binary stream.
        aid, cid, routed = self.account_with_routed()
        self.login_admin()
        response = self.client.get(f"/configs/{cid}/conf")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/octet-stream")
        self.assertEqual(response.headers["content-disposition"],
                         'attachment; filename="c1.conf"')

    def test_a_foreign_subnet_is_ignored(self):
        aid, cid, routed = self.account_with_routed()
        stranger = self.seed_exit("other", "awg9", mode="routes",
                                  routes="10.9.0.0/24")
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        self.client.post(f"/configs/{cid}/routed", data={
            "exits": [routed, stranger], "csrf_token": csrf,
        })
        self.assertEqual(self.chosen(cid), [routed])

    def test_a_new_config_starts_with_every_granted_subnet(self):
        aid, cid, routed = self.account_with_routed()
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        response = self.client.post(f"/accounts/{aid}/configs", data={
            "name": "second", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        new_cid = int(response.headers["location"].split("/configs/")[1].split("?")[0])
        self.assertEqual(self.chosen(new_cid), [routed])

    def test_revoking_a_grant_drops_the_row(self):
        aid, cid, routed = self.account_with_routed()
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        self.client.post(f"/accounts/{aid}/exits", data={"csrf_token": csrf})
        self.assertEqual(self.chosen(cid), [])
        self.client.post(f"/accounts/{aid}/exits", data={
            "exits": [routed], "csrf_token": csrf,
        })
        self.assertEqual(self.chosen(cid), [routed])

    def test_the_user_can_choose_its_subnets(self):
        aid, cid, routed = self.account_with_routed()
        other = self.seed_exit("lab2", "awg3", mode="routes",
                               routes="10.77.0.0/24")
        with app.db() as conn:
            conn.execute(
                "INSERT INTO account_exits (account_id, exit_id, priority) "
                "VALUES (?, ?, 20)", (aid, other))
            conn.execute(
                "INSERT INTO client_exits (client_id, exit_id) VALUES (?, ?)",
                (cid, other))
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf(f"/me/configs/{cid}")
        response = self.client.post(f"/me/configs/{cid}/routed", data={
            "exits": [routed], "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("ok=", response.headers["location"])
        self.assertEqual(self.chosen(cid), [routed])

    def test_the_default_is_written_once(self):
        aid, cid, routed = self.account_with_routed()
        with app.db() as conn:
            conn.execute("DELETE FROM client_exits")
            conn.execute("DELETE FROM settings WHERE key = 'routed_selection'")
        app.init_db()
        self.assertEqual(self.chosen(cid), [routed])
        # A deliberate opt-out must survive the next start.
        with app.db() as conn:
            conn.execute("DELETE FROM client_exits")
        app.init_db()
        self.assertEqual(self.chosen(cid), [])


class SubnetApiTests(PanelTestCase):
    def api_login(self, email="c1@example.com"):
        response = self.client.post("/api/login", data={
            "email": email, "password": USER_PASSWORD,
        })
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": "Bearer " + response.json()["token"]}

    def account_with_subnets(self):
        aid, cid = self.seed_client(internet=0)
        first = self.seed_exit("sub1", "awg2", mode="routes", routes="192.168.50.0/24")
        second = self.seed_exit("sub2", "awg3", mode="routes", routes="10.77.0.0/24")
        with app.db() as conn:
            conn.execute("INSERT INTO account_exits VALUES (?, ?, 10)", (aid, first))
            conn.execute("INSERT INTO account_exits VALUES (?, ?, 20)", (aid, second))
            conn.execute("INSERT INTO client_exits VALUES (?, ?)", (cid, first))
        return aid, cid, first, second

    def test_list_shows_the_choice(self):
        aid, cid, first, second = self.account_with_subnets()
        headers = self.api_login()
        response = self.client.get(f"/api/me/subnets?config_id={cid}", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        body = {row["id"]: row["enabled"] for row in response.json()}
        self.assertEqual(body, {first: True, second: False})
        self.assertEqual(response.json()[0]["routes"], "192.168.50.0/24")

    def test_switch_on_and_off(self):
        aid, cid, first, second = self.account_with_subnets()
        headers = self.api_login()
        response = self.client.post("/api/me/subnets", data={
            "config_id": str(cid), "subnet_id": [str(first), str(second)],
        }, headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual({r["id"]: r["enabled"] for r in response.json()["subnets"]},
                         {first: True, second: True})
        response = self.client.post("/api/me/subnets", data={
            "config_id": str(cid),
        }, headers=headers)
        self.assertEqual(response.status_code, 200)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM client_exits WHERE client_id = ?",
                (cid,)).fetchone()[0], 0)

    def test_a_subnet_the_account_does_not_grant_is_rejected(self):
        aid, cid, first, second = self.account_with_subnets()
        stranger = self.seed_exit("other", "awg9", mode="routes", routes="10.9.0.0/24")
        headers = self.api_login()
        response = self.client.post("/api/me/subnets", data={
            "config_id": str(cid), "subnet_id": [str(stranger)],
        }, headers=headers)
        self.assertEqual(response.status_code, 400)
        with app.db() as conn:
            self.assertEqual([r[0] for r in conn.execute(
                "SELECT exit_id FROM client_exits WHERE client_id = ?", (cid,))], [first])

    def test_another_accounts_config_is_404(self):
        self.seed_client("mine", "10.80.0.2", "mine@example.com")
        _, other = self.seed_client("other", "10.80.0.3", "other@example.com")
        headers = self.api_login("mine@example.com")
        response = self.client.get(f"/api/me/subnets?config_id={other}", headers=headers)
        self.assertEqual(response.status_code, 404)


class StatusJsonTests(PanelTestCase):
    def test_admin_sees_every_configuration(self):
        aid, cid = self.seed_client("one", "10.80.0.2", "one@example.com")
        self.seed_client("two", "10.80.0.3", "two@example.com")
        self.login_admin()
        response = self.client.get("/status.json")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(sorted(body["configs"]), ["10.80.0.2", "10.80.0.3"])
        self.assertIn("exits", body)
        self.assertNotIn("private_key", response.text)

    def test_account_sees_only_its_own(self):
        self.seed_client("mine", "10.80.0.2", "mine@example.com")
        self.seed_client("other", "10.80.0.3", "other@example.com")
        self.login("mine@example.com", USER_PASSWORD)
        body = self.client.get("/status.json").json()
        self.assertEqual(sorted(body["configs"]), ["10.80.0.2"])

    def test_anonymous_is_rejected(self):
        self.assertEqual(self.client.get("/status.json").status_code, 401)


class AdminRouteConsistencyTests(PanelTestCase):
    def test_reported_route_stays_visible_when_access_or_exit_is_disabled(self):
        aid, cid = self.seed_client(name="phone")
        eid = self.seed_exit("stopped", "awg1", enabled=0)
        status = {"ts": int(time.time()), "clients": {"10.80.0.2": "awg1"}}
        self.login_admin()
        with mock.patch.object(app, "read_status", return_value=status), \
                mock.patch.object(app.awgconf, "render", return_value=""):
            live = self.client.get("/status.json").json()
            detail = self.client.get(f"/exits/{eid}").text
        self.assertEqual(live["exit_usage"]["awg1"], 1)
        self.assertEqual(live["configs"]["10.80.0.2"]["admin_route"]["current"]["id"], eid)
        self.assertIn('data-live="admin-exit|awg1">Disabled</span>', detail)

    def test_global_pin_fallback_and_shared_routes_are_consistent(self):
        aid, cid = self.seed_client(name="phone")
        global_id = self.seed_exit("global", "awg1")
        pinned_id = self.seed_exit("pinned", "awg2")
        fallback_id = self.seed_exit("fallback", "awg3")
        self.grant(aid, cid, pinned_id)
        self.grant(aid, cid, fallback_id, 20)
        with app.db() as conn:
            conn.execute("UPDATE clients SET pinned_iface = 'awg2' WHERE id = ?", (cid,))
            conn.execute(
                "INSERT INTO clients (name, ip, public_key, private_key, preshared_key, "
                "enabled, created_at, internet, table_num) "
                "VALUES ('shared', '10.80.0.9', 'pub2', 'priv', 'psk', 1, 'now', 1, 0)"
            ).lastrowid
        self.login_admin()
        status = {"ts": int(time.time()), "active": "awg1",
                  "clients": {"10.80.0.2": "awg3"},
                  "exits": {"awg1": {"alive": True}, "awg2": {"alive": False},
                            "awg3": {"alive": True, "degraded": True}}}
        with mock.patch.object(app, "read_status", return_value=status), \
                mock.patch.object(app, "run_dir", return_value="awg1"), \
                mock.patch.object(app, "services", return_value={}), \
                mock.patch.object(app.awgconf, "render", return_value=""):
            global_data = self.client.get("/status.json").json()
            fallback_data = self.client.get("/status.json?overview=true").json()
            listing = self.client.get("/exits").text
            overview = self.client.get("/").text
        self.assertEqual(global_data["exit_usage"], {"awg1": 1, "awg3": 1})
        # A legacy shared configuration is absent from status["clients"]; the
        # live payload must still report the global active exit for its badge.
        self.assertEqual(global_data["configs"]["10.80.0.9"]["iface"], "awg1")
        route = fallback_data["configs"]["10.80.0.2"]["admin_route"]
        self.assertEqual((global_data["global_exit"], route["pinned"]["id"], route["current"]["id"]),
                         ("awg1", pinned_id, fallback_id))
        self.assertIn('data-live="exit-usage|awg3">1</span>', listing)
        self.assertIn("fallback is degraded", overview)
        self.assertNotIn("#exit-configurations", overview)
        self.assertEqual(global_id, fallback_data["overview"]["active"]["id"])

        stale = dict(status, ts=int(time.time()) - 300)
        with mock.patch.object(app, "read_status", return_value=stale):
            data = self.client.get("/status.json").json()
            listing = self.client.get("/exits").text
        self.assertFalse(data["status_fresh"])
        self.assertIn('data-live="exit-usage|awg3">—</span>', listing)
        self.login("c1@example.com", USER_PASSWORD)
        user_data = self.client.get("/status.json").json()
        self.assertNotIn("exit_usage", user_data)
        self.assertNotIn("admin_route", user_data["configs"]["10.80.0.2"])


def _axml_strings(strings):
    body = b""
    offsets = []
    for text in strings:
        offsets.append(len(body))
        raw = text.encode()
        body += bytes([len(text), len(raw)]) + raw + b"\x00"
    start = 28 + 4 * len(strings)
    size = start + len(body)
    return (struct.pack("<HHI", 0x0001, 28, size)
            + struct.pack("<IIIII", len(strings), 0, 0x0100, start, 0)
            + b"".join(struct.pack("<I", offset) for offset in offsets) + body)


def _axml_attribute(name_index, value=None, string_index=None):
    if string_index is None:
        typed = struct.pack("<HBBI", 8, 0, 0x10, value)
        raw = 0xFFFFFFFF
    else:
        typed = struct.pack("<HBBI", 8, 0, 0x03, string_index)
        raw = string_index
    return struct.pack("<III", 0xFFFFFFFF, name_index, raw) + typed


def _axml_element(name_index, attributes):
    body = struct.pack("<II", 0, 0xFFFFFFFF)
    body += struct.pack("<II", 0xFFFFFFFF, name_index)
    body += struct.pack("<HHHHHH", 20, 20, len(attributes), 0, 0, 0)
    body += b"".join(attributes)
    return struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body


def build_apk(package, version_name, version_code, min_sdk=26):
    """A minimal APK whose binary manifest carries the fields apkmeta reads."""
    strings = ["versionName", "versionCode", "manifest", version_name, package,
               "uses-sdk", "minSdkVersion", "package"]
    resource_map = [0x0101021C, 0x0101021B, 0, 0, 0, 0, 0x0101020C, 0]
    manifest = _axml_element(2, [
        _axml_attribute(7, string_index=4),
        _axml_attribute(0, string_index=3),
        _axml_attribute(1, version_code),
    ])
    content = manifest
    if min_sdk is not None:
        content += _axml_element(5, [_axml_attribute(6, min_sdk)])
    resources = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(resource_map))
    resources += b"".join(struct.pack("<I", item) for item in resource_map)
    pool = _axml_strings(strings)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(pool + resources + content)) + pool + resources + content


class ApkMetaTests(unittest.TestCase):
    @unittest.skipUnless(apkmeta, "panel modules are not importable")
    def test_reads_package_and_versions_from_the_binary_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.apk"
            with zipfile.ZipFile(path, "w") as apk:
                apk.writestr("AndroidManifest.xml",
                             build_apk("ru.deffhost.kaskad", "0.4.11", 411))
            expected_size = path.stat().st_size
            expected_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            meta = apkmeta.read_meta(path)
        self.assertEqual(meta["package"], "ru.deffhost.kaskad")
        self.assertEqual(meta["versionName"], "0.4.11")
        self.assertEqual(meta["versionCode"], 411)
        self.assertEqual(meta["minSdk"], 26)
        self.assertEqual(meta["size"], expected_size)
        self.assertEqual(meta["sha256"], expected_digest)

    @unittest.skipUnless(apkmeta, "panel modules are not importable")
    def test_rejects_a_file_without_a_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.apk"
            with zipfile.ZipFile(path, "w") as apk:
                apk.writestr("classes.dex", b"dex")
            with self.assertRaises(apkmeta.ApkError):
                apkmeta.read_meta(path)

    @unittest.skipUnless(apkmeta, "panel modules are not importable")
    def test_encrypted_or_unsupported_archive_is_an_apk_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.apk"
            path.write_bytes(b"PK\x03\x04")
            for error in (RuntimeError("encrypted"), NotImplementedError("compression")):
                with self.subTest(error=error), \
                        mock.patch.object(apkmeta.zipfile, "ZipFile", side_effect=error):
                    with self.assertRaises(apkmeta.ApkError):
                        apkmeta.read_meta(path)

    @unittest.skipUnless(apkmeta, "panel modules are not importable")
    def test_manifest_and_digest_use_same_open_file_during_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.apk"
            replacement = Path(tmp) / "new.apk"
            for filename, version in ((path, 411), (replacement, 412)):
                with zipfile.ZipFile(filename, "w") as apk:
                    apk.writestr("AndroidManifest.xml",
                                 build_apk("ru.deffhost.kaskad", str(version), version))
            old_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            open_zip = zipfile.ZipFile

            def replace_then_open(handle, *args, **kwargs):
                replacement.replace(path)
                return open_zip(handle, *args, **kwargs)

            with mock.patch.object(apkmeta.zipfile, "ZipFile", side_effect=replace_then_open):
                result = apkmeta.read_meta(path)
            self.assertEqual(result["versionCode"], 411)
            self.assertEqual(result["sha256"], old_digest)


class AndroidInfoTests(PanelTestCase):
    def setUp(self):
        super().setUp()
        self.apk = Path(self.tmp.name) / "app.apk"
        self.apk_patch = mock.patch.object(app, "ANDROID_APK", self.apk)
        self.apk_patch.start()
        app._apk_meta = None

    def tearDown(self):
        app._apk_meta = None
        self.apk_patch.stop()
        super().tearDown()

    def publish(self, version_name="0.4.11", version_code=411, min_sdk=26):
        with zipfile.ZipFile(self.apk, "w") as apk:
            apk.writestr("AndroidManifest.xml", build_apk(
                "ru.deffhost.kaskad", version_name, version_code, min_sdk))
        return hashlib.sha256(self.apk.read_bytes()).hexdigest()

    def test_anonymous_client_gets_version_and_digest(self):
        digest = self.publish()
        response = self.client.get("/api/android")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["package"], "ru.deffhost.kaskad")
        self.assertEqual(body["versionCode"], 411)
        self.assertEqual(body["versionName"], "0.4.11")
        self.assertEqual(body["minSdk"], 26)
        self.assertEqual(body["sha256"], digest)
        self.assertEqual(body["size"], self.apk.stat().st_size)
        self.assertEqual(body["url"], "https://testserver/download/android")
        self.assertRegex(body["published"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(response.headers["cache-control"], "public, max-age=300")

    def test_no_apk_is_404_and_min_sdk_is_optional(self):
        self.assertEqual(self.client.get("/api/android").status_code, 404)
        self.publish(min_sdk=None)
        body = self.client.get("/api/android").json()
        self.assertNotIn("minSdk", body)
        self.assertEqual(body["versionCode"], 411)

    def test_replacing_the_file_changes_the_answer_without_a_restart(self):
        self.publish(version_name="0.4.11", version_code=411)
        self.assertEqual(self.client.get("/api/android").json()["versionCode"], 411)
        self.publish(version_name="0.4.12", version_code=412)
        body = self.client.get("/api/android").json()
        self.assertEqual(body["versionCode"], 412)
        self.assertEqual(body["versionName"], "0.4.12")

    def test_a_file_that_is_not_an_apk_is_not_advertised(self):
        self.apk.write_bytes(b"not a zip archive")
        response = self.client.get("/api/android")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "app metadata is unreadable")
        self.assertNotIn("versionCode", response.text)

    def test_truncated_binary_manifest_returns_503(self):
        for manifest in (b"", b"\x03\x00", b"\x03\x00\x08\x00\x10\x00\x00\x00\x01\x00"):
            with self.subTest(manifest=manifest):
                with zipfile.ZipFile(self.apk, "w") as apk:
                    apk.writestr("AndroidManifest.xml", manifest)
                self.assertEqual(self.client.get("/api/android").status_code, 503)

    def test_file_replaced_during_read_is_not_cached(self):
        self.publish()
        original = app.apkmeta.read_meta_stream

        def replace_during_read(handle):
            meta = original(handle)
            replacement = self.apk.with_name("replacement.apk")
            with zipfile.ZipFile(replacement, "w") as apk:
                apk.writestr("AndroidManifest.xml", build_apk("ru.deffhost.kaskad", "0.4.12", 412))
            replacement.replace(self.apk)
            return meta

        with mock.patch.object(app.apkmeta, "read_meta_stream", side_effect=replace_during_read):
            self.assertEqual(self.client.get("/api/android").status_code, 503)
        self.assertEqual(self.client.get("/api/android").json()["versionCode"], 412)

    def test_download_endpoint_serves_the_same_file_it_describes(self):
        digest = self.publish()
        info = self.client.get("/api/android").json()
        download = self.client.get("/download/android")
        self.assertEqual(download.status_code, 200)
        self.assertEqual(hashlib.sha256(download.content).hexdigest(), info["sha256"])
        self.assertEqual(digest, info["sha256"])
        self.assertEqual(len(download.content), info["size"])


class WindowsDownloadTests(PanelTestCase):
    def setUp(self):
        super().setUp()
        self.msi = Path(self.tmp.name) / "app.msi"
        self.msi_patch = mock.patch.object(app, "WINDOWS_MSI", self.msi)
        self.msi_patch.start()

    def tearDown(self):
        self.msi_patch.stop()
        super().tearDown()

    def test_no_msi_is_404(self):
        self.assertEqual(self.client.get("/download/windows").status_code, 404)

    def test_download_serves_the_published_file(self):
        self.msi.write_bytes(b"msi bytes")
        response = self.client.get("/download/windows")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"msi bytes")
        self.assertEqual(response.headers["content-type"], "application/x-msi")

    def test_the_cabinet_shows_the_windows_button_only_when_published(self):
        aid, cid = self.seed_client()
        self.login("c1@example.com", USER_PASSWORD)
        self.assertNotIn('href="/download/windows"', self.client.get("/me").text)
        self.msi.write_bytes(b"msi")
        self.assertIn('href="/download/windows"', self.client.get("/me").text)

    def test_the_config_page_offers_windows(self):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("e1", "awg1"))
        self.msi.write_bytes(b"msi")
        self.login_admin()
        page = self.client.get(f"/configs/{cid}").text
        self.assertIn('href="/download/windows"', page)


class ConfigPingTests(PanelTestCase):
    def card(self, status):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("e1", "awg1"))
        self.login_admin()
        with mock.patch.object(app, "read_status", return_value=status):
            response = self.client.get(f"/configs/{cid}")
        self.assertEqual(response.status_code, 200)
        return response.text

    def test_card_shows_only_the_server_to_exit_latency(self):
        text = self.card({
            "ts": int(time.time()),
            "exits": {"awg1": {"alive": True, "rtt_ms": 40}},
            "client_ping": {"10.80.0.2": 10},
        })
        self.assertIn('data-live="exit-rtt|awg1">40 ms</span>', text)
        self.assertNotIn("50 ms", text)
        self.assertNotIn("client 10 + exit", text)

    def test_card_shows_exit_latency_without_client_ping(self):
        text = self.card({
            "ts": int(time.time()),
            "exits": {"awg1": {"alive": True, "rtt_ms": 40}},
            "client_ping": {},
        })
        self.assertIn('data-live="exit-rtt|awg1">40 ms</span>', text)
        self.assertNotIn("S1 to exit only", text)

    def test_card_does_not_claim_a_stale_exit_is_up(self):
        text = self.card({
            "ts": int(time.time()) - 300,
            "exits": {"awg1": {"alive": True, "rtt_ms": 40}},
        })
        self.assertIn('data-live="admin-exit|awg1">No data</span>', text)
        self.assertIn('data-iface="awg1" hidden>Active</span>', text)
        self.assertNotIn(">Up</span>", text)
        self.assertNotIn("40 ms", text)

    def test_admin_pages_distinguish_current_exit_from_saved_pin(self):
        aid, cid = self.seed_client()
        pinned = self.seed_exit("preferred", "awg1")
        current = self.seed_exit("fallback", "awg2")
        self.grant(aid, cid, pinned)
        self.grant(aid, cid, current, 20)
        with app.db() as conn:
            conn.execute("UPDATE clients SET pinned_iface = ? WHERE id = ?", ("awg1", cid))
        self.login_admin()
        status = {"ts": int(time.time()), "active": "awg1",
                  "clients": {"10.80.0.2": "awg2"}}
        with mock.patch.object(app, "read_status", return_value=status):
            routes = self.client.get("/status.json").json()["configs"]
            for path in ("/configs", f"/accounts/{aid}"):
                with self.subTest(path=path):
                    page = self.client.get(path)
                    self.assertEqual(page.status_code, 200)
                    self.assertIn(f'data-route-current href="/exits/{current}">fallback', page.text)
                    self.assertIn(f'Pinned · <a class="oc-link" href="/exits/{pinned}">preferred', page.text)
            detail = self.client.get(f"/configs/{cid}").text
            self.assertIn(f'data-iface="awg2">Active', detail)
            self.assertIn('oc-badge--subtle">Pinned', detail)
        self.assertEqual(routes["10.80.0.2"]["admin_route"]["current"]["id"], current)
        self.assertEqual(routes["10.80.0.2"]["admin_route"]["pinned"]["id"], pinned)


class NavigationTests(PanelTestCase):
    def test_config_filters_combine_with_search(self):
        _, disabled = self.seed_client(name="phone", enabled=0)
        _, orphan = self.seed_client(name="tablet", ip="10.80.0.9", email="other@example.com")
        with app.db() as conn:
            conn.execute("UPDATE clients SET account_id = NULL WHERE id = ?", (orphan,))
        self.login_admin()
        for query, expected in (("state=disabled&q=phone", [disabled]),
                                ("state=unassigned", [orphan]),
                                ("state=disabled&q=tablet", [])):
            response = self.client.get("/configs?" + query)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(re.findall(r'data-href="/configs/(\d+)"', response.text),
                             [str(cid) for cid in expected])

    def test_overview_status_tracks_failover_and_is_admin_only(self):
        first = self.seed_exit("first", "awg1")
        second = self.seed_exit("second", "awg2")
        status = {"ts": int(time.time()),
                  "exits": {"awg1": {"alive": False}, "awg2": {"alive": True}}}
        self.login_admin()
        with mock.patch.object(app, "read_status", return_value=status), \
                mock.patch.object(app, "run_dir", return_value="awg2"), \
                mock.patch.object(app, "services", return_value={"routing": "failed"}):
            view = self.client.get("/status.json?overview=true").json()["overview"]
        self.assertEqual(view["active"]["id"], second)
        self.assertEqual([item["url"] for item in view["issues"]],
                         [f"/exits/{first}", "/settings#services"])
        self.seed_account()
        self.login("c1@example.com", USER_PASSWORD)
        self.assertNotIn("overview", self.client.get("/status.json?overview=true").json())

    def test_expired_failover_status_is_not_reported_as_healthy(self):
        self.seed_exit("first", "awg1")
        self.login_admin()
        status = {"ts": int(time.time()) - 120, "active": "awg1",
                  "exits": {"awg1": {"alive": True, "rtt_ms": 23}}}
        with mock.patch.object(app, "read_status", return_value=status), \
                mock.patch.object(app, "run_dir", return_value="awg1"), \
                mock.patch.object(app, "services", return_value={}):
            response = self.client.get("/status.json?overview=true")
            page = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data["status_fresh"])
        self.assertIsNone(data["active"])
        self.assertIsNone(data["exits"]["awg1"]["alive"])
        self.assertIsNone(data["overview"]["active"])
        self.assertIn("Exit status unavailable", data["overview"]["issues"][0]["text"])
        self.assertIn('role="status">Stale · exit status unavailable', page.text)
        self.assertNotIn('href="/exits/1">first</a>', page.text)

    def test_the_exit_list_does_not_claim_a_stale_status(self):
        self.seed_exit("first", "awg1")
        self.login_admin()
        status = {"ts": int(time.time()) - 300, "active": "awg1",
                  "exits": {"awg1": {"alive": True, "rtt_ms": 23}}}
        with mock.patch.object(app, "read_status", return_value=status), \
                mock.patch.object(app, "run_dir", return_value="awg1"):
            page = self.client.get("/exits")
        self.assertEqual(page.status_code, 200)
        self.assertIn('role="status">Stale · exit status unavailable', page.text)
        self.assertIn('data-live="admin-exit|awg1">No data</span>', page.text)
        self.assertIn('data-live="exit-usage|awg1">—</span>', page.text)
        self.assertIn('data-live="global-exit|awg1" hidden', page.text)

    def test_admin_exit_usage_and_health_follow_the_reported_routes(self):
        aid, cid = self.seed_client()
        self.seed_client(name="disabled", ip="10.80.0.9",
                         email="other@example.com", enabled=0)
        first = self.seed_exit("first", "awg1")
        second = self.seed_exit("second", "awg2")
        self.grant(aid, cid, first)
        self.grant(aid, cid, second, 20)
        self.login_admin()
        probe = "https://example.com/"
        status = {
            "ts": int(time.time()), "active": "awg1",
            "clients": {"10.80.0.2": "awg2", "10.80.0.9": "awg2"},
            "exits": {"awg1": {"alive": True},
                      "awg2": {"alive": True, "targets": {probe: False}}},
        }
        with mock.patch.object(app, "read_status", return_value=status), \
                mock.patch.object(app, "run_dir", return_value="awg1"), \
                mock.patch.object(app, "services", return_value={}):
            data = self.client.get("/status.json?overview=true").json()
            exits = self.client.get("/exits").text
            overview = self.client.get("/").text
        self.assertEqual(data["global_exit"], "awg1")
        self.assertEqual(data["exit_usage"], {"awg2": 1})
        self.assertEqual(data["exit_targets"]["awg2"], {probe: False})
        self.assertIn('data-live="exit-usage|awg1">0</span>', exits)
        self.assertIn('data-live="exit-usage|awg2">1</span>', exits)
        self.assertIn("second has a failed check", overview)
        self.assertNotIn("#exit-configurations", overview)

    def test_exit_list_shows_latency_and_subnet_mode_without_internet_badges(self):
        self.seed_exit("online", "awg1")
        self.seed_exit("subnet", "awg2", mode="routes", routes="10.1.0.0/24")
        self.login_admin()
        status = {"ts": int(time.time()), "exits": {
            "awg1": {"alive": True, "rtt_ms": 0},
            "awg2": {"alive": True},
        }}
        with mock.patch.object(app, "read_status", return_value=status):
            all_exits = self.client.get("/exits").text
            internet = self.client.get("/exits?mode=internet").text
            subnet = self.client.get("/exits?mode=routes").text
        self.assertIn('data-live="exit-rtt|awg1">0 ms</span>', all_exits)
        self.assertIn('aria-label="Handshake only">—</span>', all_exits)
        self.assertIn(">Subnets</span>", all_exits)
        self.assertIn("2 of 2 shown enabled", all_exits)
        self.assertIn("1 of 1 shown enabled", internet)
        self.assertIn("1 of 1 shown enabled", subnet)
        self.assertNotIn('>internet</span>', all_exits)

    def test_current_page_is_marked_for_screen_readers(self):
        self.login_admin()
        text = self.client.get("/accounts").text
        self.assertIn('aria-current="page"', text)
        self.assertEqual(text.count('aria-current="page"'), 1)

    def test_account_controls_have_a_separate_authenticated_page(self):
        self.assertEqual(self.client.get("/me/account").headers["location"], "/login")
        self.seed_client()
        self.login("c1@example.com", USER_PASSWORD)
        home = self.client.get("/me").text
        self.assertIn('href="/me/account"', home)
        self.assertNotIn('action="/me/password"', home)
        account = self.client.get("/me/account").text
        self.assertIn('action="/me/password"', account)
        self.assertIn('action="/me/logout-all"', account)

    def test_cabinet_has_no_sidebar(self):
        self.seed_client(email="c1@example.com")
        self.login("c1@example.com", USER_PASSWORD)
        text = self.client.get("/me").text
        self.assertNotIn('<aside class="side">', text)


class GrantTests(PanelTestCase):
    def test_grants_are_saved_in_order_for_every_config(self):
        aid, cid = self.seed_client()
        first = self.seed_exit("e1", "awg1", priority=10)
        second = self.seed_exit("e2", "awg2", priority=20)
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        response = self.client.post(f"/accounts/{aid}/exits", data={
            "exits": [second, first], "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        expected = {first: 10, second: 20}
        self.assertEqual(dict(self.account_grants(aid)), expected)
        self.assertEqual(dict(self.grants(cid)), expected)

    def test_config_exit_order_is_replaced_in_one_request(self):
        aid, cid = self.seed_client()
        first = self.seed_exit("e1", "awg1", priority=10)
        second = self.seed_exit("e2", "awg2", priority=20)
        third = self.seed_exit("e3", "awg3", priority=30)
        for exit_id, priority in ((first, 10), (second, 20), (third, 30)):
            self.grant(aid, cid, exit_id, priority)
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/order/set", data={
            "order": [third, second, first], "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual([e for e, _ in self.grants(cid)], [third, second, first])
        # The account order is untouched until "apply to all".
        self.assertEqual([e for e, _ in self.account_grants(aid)],
                         [first, second, third])

    def test_config_apply_saves_order_and_pin_together(self):
        aid, cid = self.seed_client()
        first = self.seed_exit("e1", "awg1", priority=10)
        second = self.seed_exit("e2", "awg2", priority=20)
        self.grant(aid, cid, first, 10)
        self.grant(aid, cid, second, 20)
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/apply", data={
            "order": [second, first], "exit_id": second, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual([e for e, _ in self.grants(cid)], [second, first])
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT pinned_iface FROM clients WHERE id = ?", (cid,)).fetchone()[0],
                "awg2")

    def test_config_apply_refuses_a_foreign_pin(self):
        aid, cid = self.seed_client()
        first = self.seed_exit("e1", "awg1")
        self.grant(aid, cid, first)
        stranger = self.seed_exit("spare", "awg3")
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/apply", data={
            "order": [first], "exit_id": stranger, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 400)

    def test_config_exit_order_rejects_a_partial_or_foreign_list(self):
        aid, cid = self.seed_client()
        first = self.seed_exit("e1", "awg1")
        second = self.seed_exit("e2", "awg2")
        stranger = self.seed_exit("e3", "awg3")
        self.grant(aid, cid, first, 10)
        self.grant(aid, cid, second, 20)
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        for order in ([first], [second, first, stranger], [first, first]):
            with self.subTest(order=order):
                response = self.client.post(f"/configs/{cid}/order/set", data={
                    "order": order, "csrf_token": csrf,
                })
                self.assertEqual(response.status_code, 400)
        self.assertEqual([e for e, _ in self.grants(cid)], [first, second])

    def test_admin_can_pin_and_unpin_a_configuration_exit(self):
        aid, cid = self.seed_client()
        first = self.seed_exit("e1", "awg1")
        second = self.seed_exit("e2", "awg2")
        self.grant(aid, cid, first, 10)
        self.grant(aid, cid, second, 20)
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/pin", data={
            "exit_id": second, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT pinned_iface FROM clients WHERE id = ?", (cid,)).fetchone()[0],
                "awg2")
        page = self.client.get(f"/configs/{cid}").text
        self.assertIn(f'value="{second}" selected', page)
        self.assertIn('oc-badge--subtle">Pinned', page)
        self.client.post(f"/configs/{cid}/pin", data={
            "exit_id": 0, "csrf_token": csrf,
        })
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT pinned_iface FROM clients WHERE id = ?", (cid,)).fetchone()[0],
                "")

    def test_admin_cannot_pin_an_exit_the_configuration_lacks(self):
        aid, cid = self.seed_client()
        granted = self.seed_exit("e1", "awg1")
        stranger = self.seed_exit("e2", "awg2")
        self.grant(aid, cid, granted, 10)
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/pin", data={
            "exit_id": stranger, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 400)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT pinned_iface FROM clients WHERE id = ?", (cid,)).fetchone()[0],
                "")

    def test_config_page_marks_the_exit_the_traffic_uses(self):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("e1", "awg1"), 10)
        self.grant(aid, cid, self.seed_exit("e2", "awg2"), 20)
        self.login_admin()
        status = {"ts": int(time.time()), "clients": {"10.80.0.2": "awg2"}}
        with mock.patch.object(app, "read_status", return_value=status):
            page = self.client.get(f"/configs/{cid}").text
        self.assertRegex(page, r'data-iface="awg2">Active</span>')
        self.assertRegex(page, r'data-iface="awg1"\s+hidden>Active</span>')

    def test_config_page_uses_grips_and_switches(self):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("e1", "awg1"))
        routed = self.seed_exit("sub", "awg2", mode="routes",
                                routes="10.5.0.0/24")
        with app.db() as conn:
            conn.execute("INSERT INTO account_exits VALUES (?, ?, 20)",
                         (aid, routed))
            conn.execute("INSERT INTO client_exits VALUES (?, ?)",
                         (cid, routed))
        self.login_admin()
        with mock.patch.object(app, "read_status", return_value={"ts": int(time.time())}):
            page = self.client.get(f"/configs/{cid}").text
        self.assertIn('class="oc-table console-table config-exits-table"', page)
        self.assertIn('class="exit-grip"', page)
        self.assertIn('id="config-apply"', page)
        self.assertIn('id="config-pin"', page)
        self.assertIn('id="config-apply-button"', page)
        self.assertIn('disabled>apply</button>', page)
        self.assertIn('class="oc-switch"', page)
        self.assertNotIn('>up</button>', page)
        self.assertNotIn('>down</button>', page)

    def test_config_preview_shows_the_keys_unmasked(self):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("e1", "awg1"))
        self.login_admin()
        with mock.patch.object(app, "read_status", return_value={"ts": int(time.time())}):
            page = self.client.get(f"/configs/{cid}").text
        self.assertIn("PrivateKey = privkey", page)
        self.assertIn("PresharedKey = psk", page)
        self.assertNotIn("••••", page)
        self.login("c1@example.com", USER_PASSWORD)
        with mock.patch.object(app, "read_status", return_value={"ts": int(time.time())}):
            page = self.client.get(f"/me/configs/{cid}").text
        self.assertIn("PrivateKey = privkey", page)
        self.assertNotIn("••••", page)

    def test_disabled_exit_cannot_be_granted(self):
        aid, cid = self.seed_client()
        dead = self.seed_exit("dead", "awg5", enabled=0)
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        self.client.post(f"/accounts/{aid}/exits",
                         data={"exits": [dead], "csrf_token": csrf})
        self.assertEqual(self.account_grants(aid), [])
        self.assertEqual(self.grants(cid), [])

    def test_routed_exit_is_not_an_internet_order(self):
        aid, cid = self.seed_client()
        routed = self.seed_exit("sub", "awg2", mode="routes", routes="10.9.0.0/24")
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        self.client.post(f"/accounts/{aid}/exits",
                         data={"exits": [routed], "csrf_token": csrf})
        self.assertEqual([exit_id for exit_id, _ in self.account_grants(aid)],
                         [routed])
        self.assertEqual(self.grants(cid), [])

    def test_routed_grant_does_not_block_internet_order(self):
        aid, cid = self.seed_client()
        routed = self.seed_exit("sub", "awg9", mode="routes",
                                routes="10.9.0.0/24", priority=1)
        first = self.seed_exit("e1", "awg1", priority=10)
        second = self.seed_exit("e2", "awg2", priority=20)
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        self.client.post(f"/accounts/{aid}/exits", data={
            "exits": [routed, first, second], "csrf_token": csrf,
        })
        self.client.post(f"/accounts/{aid}/order", data={
            "exit_id": first, "direction": "down", "csrf_token": csrf,
        })
        with app.db() as conn:
            internet = [r["exit_id"] for r in conn.execute(
                "SELECT ae.exit_id FROM account_exits ae "
                "JOIN exits e ON e.id = ae.exit_id "
                "WHERE ae.account_id = ? AND e.mode = 'internet' "
                "ORDER BY ae.priority, e.priority, e.id", (aid,))]
        self.assertEqual(internet, [second, first])
        self.assertEqual([e for e, _ in self.grants(cid)], [first, second])

    def test_order_swap_and_apply_to_all(self):
        aid, cid = self.seed_client()
        first = self.seed_exit("e1", "awg1", priority=10)
        second = self.seed_exit("e2", "awg2", priority=20)
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        self.client.post(f"/accounts/{aid}/exits", data={
            "exits": [first, second], "csrf_token": csrf,
        })
        # One configuration gets its own order...
        self.client.post(f"/configs/{cid}/order", data={
            "exit_id": second, "direction": "up", "csrf_token": csrf,
        })
        self.assertEqual([e for e, _ in self.grants(cid)], [second, first])
        # ...and "apply to all" puts it back on the account order.
        self.client.post(f"/accounts/{aid}/order/apply",
                         data={"csrf_token": csrf})
        self.assertEqual([e for e, _ in self.grants(cid)], [first, second])
        # The account order can change without reordering the configurations.
        self.client.post(f"/accounts/{aid}/order", data={
            "exit_id": second, "direction": "up", "csrf_token": csrf,
        })
        self.assertEqual([e for e, _ in self.account_grants(aid)], [second, first])
        self.assertEqual([e for e, _ in self.grants(cid)], [first, second])
        self.client.post(f"/accounts/{aid}/order/apply",
                         data={"csrf_token": csrf})
        self.assertEqual([e for e, _ in self.grants(cid)], [second, first])

    def test_new_config_copies_the_account_order(self):
        aid, cid = self.seed_client()
        first = self.seed_exit("e1", "awg1", priority=10)
        second = self.seed_exit("e2", "awg2", priority=20)
        self.login_admin()
        csrf = self.csrf(f"/accounts/{aid}")
        self.client.post(f"/accounts/{aid}/exits", data={
            "exits": [second, first], "csrf_token": csrf,
        })
        response = self.client.post(f"/accounts/{aid}/configs", data={
            "name": "second-config", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        new_cid = int(response.headers["location"].split("/configs/")[1].split("?")[0])
        self.assertEqual([e for e, _ in self.grants(new_cid)], [first, second])


class UserPageTests(PanelTestCase):
    def test_me_shows_only_own_configs(self):
        self.seed_client("mine", "10.80.0.2", "mine@example.com")
        self.seed_client("other", "10.80.0.3", "other@example.com")
        self.login("mine@example.com", USER_PASSWORD)
        response = self.client.get("/me")
        self.assertEqual(response.status_code, 200)
        self.assertIn("10.80.0.2", response.text)
        self.assertNotIn("10.80.0.3", response.text)

    def test_user_creates_a_config(self):
        aid, _ = self.seed_client(email="c1@example.com", max_configs=2)
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf("/me/configs/new")
        response = self.client.post("/me/configs", data={
            "name": "phone", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("/me/configs/", response.headers["location"])
        with app.db() as conn:
            row = conn.execute(
                "SELECT account_id, name FROM clients WHERE name = 'phone'"
            ).fetchone()
        self.assertEqual(row["account_id"], aid)

    def test_user_cannot_open_another_accounts_config(self):
        self.seed_client("mine", "10.80.0.2", "mine@example.com")
        _, other = self.seed_client("other", "10.80.0.3", "other@example.com")
        self.login("mine@example.com", USER_PASSWORD)
        response = self.client.get(f"/me/configs/{other}")
        self.assertEqual(response.status_code, 404)

    def test_reissue_changes_the_keys(self):
        _, cid = self.seed_client(email="c1@example.com")
        with app.db() as conn:
            before = conn.execute(
                "SELECT public_key FROM clients WHERE id = ?", (cid,)).fetchone()[0]
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf(f"/me/configs/{cid}")
        response = self.client.post(f"/me/configs/{cid}/reissue",
                                    data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            after = conn.execute(
                "SELECT public_key FROM clients WHERE id = ?", (cid,)).fetchone()[0]
        self.assertNotEqual(before, after)
        app.apply_conf.assert_called()

    def test_reissue_failure_keeps_the_old_key(self):
        _, cid = self.seed_client(email="c1@example.com")
        with app.db() as conn:
            before = conn.execute(
                "SELECT public_key FROM clients WHERE id = ?", (cid,)).fetchone()[0]
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf(f"/me/configs/{cid}")
        app.apply_conf.side_effect = RuntimeError("syncconf: boom")
        response = self.client.post(f"/me/configs/{cid}/reissue",
                                    data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        with app.db() as conn:
            after = conn.execute(
                "SELECT public_key FROM clients WHERE id = ?", (cid,)).fetchone()[0]
        self.assertEqual(before, after)

    def test_password_change_invalidates_the_old_session(self):
        self.seed_client(email="c1@example.com")
        self.login("c1@example.com", USER_PASSWORD)
        old_cookie = self.client.cookies.get(app.COOKIE)
        csrf = self.csrf("/me/account")
        response = self.client.post("/me/password", data={
            "current_password": USER_PASSWORD,
            "new_password": "another-password-456",
            "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("ok=", response.headers["location"])
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT token_version FROM accounts").fetchone()[0], 2)

        stale = TestClient(app.app, base_url="https://testserver",
                           follow_redirects=False,
                           cookies={app.COOKIE: old_cookie})
        response = stale.get("/me")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")
        # The response installed a fresh session for this device.
        self.assertEqual(self.client.get("/me").status_code, 200)

    def test_wrong_current_password_changes_nothing(self):
        self.seed_client(email="c1@example.com")
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf("/me/account")
        response = self.client.post("/me/password", data={
            "current_password": "not-the-password",
            "new_password": "another-password-456",
            "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT token_version FROM accounts").fetchone()[0], 1)


class DeviceIdTests(PanelTestCase):
    def api_login(self, email="c1@example.com", password=USER_PASSWORD):
        response = self.client.post("/api/login", data={
            "email": email, "password": password,
        })
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": "Bearer " + response.json()["token"]}, response.json()

    def create(self, headers, **data):
        return self.client.post("/api/me/configs", data=data, headers=headers)

    def test_device_is_stored_and_listed(self):
        self.seed_client(max_configs=5)
        headers, _ = self.api_login()
        response = self.create(headers, name="pixel", device_id="a1b2c3d4e5f6")
        self.assertEqual(response.status_code, 200, response.text)
        config = response.json()["config"]
        self.assertEqual(config["name"], "pixel")
        self.assertEqual(config["device_id"], "a1b2c3d4e5f6")
        # A fresh login must tell the app which configuration is its own.
        _, payload = self.api_login()
        self.assertEqual(payload["configs"][1]["device_id"], "a1b2c3d4e5f6")

    def test_same_device_does_not_create_a_second_config(self):
        self.seed_client(max_configs=5)
        headers, _ = self.api_login()
        first = self.create(headers, name="pixel", device_id="device-aaaa1111")
        again = self.create(headers, name="other", device_id="device-aaaa1111")
        self.assertEqual(again.status_code, 200, again.text)
        self.assertEqual(again.json()["config"]["id"], first.json()["config"]["id"])
        self.assertEqual(self.client_count(), 2)  # the seeded one plus this one

    def test_known_device_is_returned_when_the_limit_is_reached(self):
        self.seed_client(max_configs=2)
        headers, _ = self.api_login()
        first = self.create(headers, name="pixel", device_id="device-limit-0001")
        self.assertEqual(first.status_code, 200, first.text)
        blocked = self.create(headers, name="third")
        self.assertEqual(blocked.status_code, 409)
        again = self.create(headers, device_id="device-limit-0001")
        self.assertEqual(again.status_code, 200, again.text)
        self.assertEqual(again.json()["config"]["id"], first.json()["config"]["id"])

    def test_two_devices_with_one_model_get_distinct_names(self):
        self.seed_client(max_configs=5)
        headers, _ = self.api_login()
        first = self.create(headers, name="pixel-8", device_id="device-model-0001")
        second = self.create(headers, name="pixel-8", device_id="device-model-0002")
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(second.json()["config"]["name"], "pixel-8-2")

    def test_bad_device_id_is_rejected(self):
        self.seed_client(max_configs=5)
        headers, _ = self.api_login()
        for value in ("short", "x" * 65, "has space here"):
            response = self.create(headers, device_id=value)
            self.assertEqual(response.status_code, 400, value)

    def test_the_same_device_id_belongs_to_each_account(self):
        self.seed_client(max_configs=2)
        self.seed_client(name="c2", ip="10.80.0.9", email="c2@example.com")
        first, _ = self.api_login()
        mine = self.create(first, name="pixel", device_id="shared-device-1")
        self.assertEqual(mine.status_code, 200, mine.text)
        second, _ = self.api_login("c2@example.com")
        other = self.create(second, name="pixel2", device_id="shared-device-1")
        self.assertEqual(other.status_code, 200, other.text)
        self.assertNotEqual(other.json()["config"]["id"], mine.json()["config"]["id"])


class DeviceMigrationTests(PanelTestCase):
    def test_old_database_gains_the_device_column(self):
        with app.db() as conn:
            conn.execute("DROP TABLE clients")
            conn.execute(
                "CREATE TABLE clients (id INTEGER PRIMARY KEY, account_id INTEGER, "
                "name TEXT UNIQUE NOT NULL, ip TEXT UNIQUE NOT NULL, "
                "public_key TEXT NOT NULL, private_key TEXT NOT NULL, "
                "preshared_key TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, "
                "created_at TEXT NOT NULL, internet INTEGER NOT NULL DEFAULT 1, "
                "table_num INTEGER NOT NULL DEFAULT 0)"
            )
        app.init_db()
        with app.db() as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(clients)")}
            self.assertIn("device_id", cols)
            index = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' "
                "AND name = 'clients_device'"
            ).fetchone()
            self.assertIsNotNone(index)


class RenameTests(PanelTestCase):
    def second_config(self, aid, name="taken", ip="10.80.0.9"):
        with app.db() as conn:
            table = app.routing.allocate_table(conn)
            cur = conn.execute(
                "INSERT INTO clients (account_id, name, ip, public_key, "
                "private_key, preshared_key, enabled, created_at, internet, "
                "table_num) VALUES (?, ?, ?, 'pubkey2', 'privkey2', 'psk2', 1, "
                "'now', 1, ?)", (aid, name, ip, table),
            )
            return cur.lastrowid

    def test_admin_renames_a_configuration(self):
        aid, cid = self.seed_client()
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/name", data={
            "name": "pixel-8", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual(app.config_row(cid)["name"], "pixel-8")

    def test_admin_cannot_take_a_name_of_another_configuration(self):
        aid, cid = self.seed_client()
        other = self.second_config(aid)
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/name", data={
            "name": "taken", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        self.assertEqual(app.config_row(cid)["name"], "c1")
        self.assertEqual(app.config_row(other)["name"], "taken")

    def test_bad_name_is_rejected(self):
        aid, cid = self.seed_client()
        self.login_admin()
        csrf = self.csrf(f"/configs/{cid}")
        response = self.client.post(f"/configs/{cid}/name", data={
            "name": "with space", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        self.assertEqual(app.config_row(cid)["name"], "c1")

    def test_user_renames_own_configuration(self):
        aid, cid = self.seed_client()
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf(f"/me/configs/{cid}")
        response = self.client.post(f"/me/configs/{cid}/name", data={
            "name": "my-phone", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual(app.config_row(cid)["name"], "my-phone")

    def test_user_cannot_rename_a_foreign_configuration(self):
        aid, cid = self.seed_client()
        aid2, cid2 = self.seed_client(name="c2", ip="10.80.0.9",
                                      email="c2@example.com")
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf(f"/me/configs/{cid}")
        response = self.client.post(f"/me/configs/{cid2}/name", data={
            "name": "stolen", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 404)
        self.assertEqual(app.config_row(cid2)["name"], "c2")


class CabinetTrafficTests(PanelTestCase):
    def seed_traffic(self, cid):
        now = int(time.time())
        with app.db() as conn:
            conn.execute(
                "INSERT INTO traffic (client_id, ts, step, rx, tx) "
                "VALUES (?, ?, 300, 1000, 200000)",
                (cid, now - 600),
            )
        return now

    def assert_history_removed(self, cid):
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM traffic WHERE client_id = ?", (cid,)
            ).fetchone()[0], 0)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM traffic_state WHERE client_id = ?", (cid,)
            ).fetchone()[0], 0)

    def test_admin_delete_clears_history_and_baseline(self):
        _, cid = self.seed_client()
        self.seed_traffic(cid)
        with app.db() as conn:
            conn.execute("INSERT INTO traffic_state VALUES (?, ?, 1, 2, ?)",
                         (cid, app.config_row(cid)["public_key"], int(time.time())))
        self.login_admin()
        response = self.client.post(f"/configs/{cid}/delete", data={
            "csrf_token": self.csrf(f"/configs/{cid}"),
        })
        self.assertEqual(response.status_code, 303)
        self.assert_history_removed(cid)

    def test_stale_status_does_not_claim_an_exit_is_in_use(self):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("first", "awg1"))
        self.login("c1@example.com", USER_PASSWORD)
        stale = {"ts": int(time.time()) - 300,
                 "clients": {"10.80.0.2": "awg1"},
                 "exits": {"awg1": {"alive": True, "rtt_ms": 23}}}
        with mock.patch.object(app, "read_status", return_value=stale):
            text = self.client.get(f"/me/configs/{cid}").text
        self.assertIn('data-live="admin-exit|awg1">No data</span>', text)
        self.assertIn('data-live="active-row|10.80.0.2"', text)
        self.assertIn('data-iface="awg1" hidden>Active</span>', text)
        self.assertNotIn("in use now", text)
        self.assertNotIn('data-live="exit|awg1">up', text)

    def test_cabinet_delete_clears_history_and_baseline(self):
        _, cid = self.seed_client()
        self.seed_traffic(cid)
        with app.db() as conn:
            conn.execute("INSERT INTO traffic_state VALUES (?, ?, 1, 2, ?)",
                         (cid, app.config_row(cid)["public_key"], int(time.time())))
        self.login("c1@example.com", USER_PASSWORD)
        response = self.client.post(f"/me/configs/{cid}/delete", data={
            "csrf_token": self.csrf(f"/me/configs/{cid}"),
        })
        self.assertEqual(response.status_code, 303)
        self.assert_history_removed(cid)

    def test_the_cabinet_draws_the_chart(self):
        aid, cid = self.seed_client()
        self.seed_traffic(cid)
        self.login("c1@example.com", USER_PASSWORD)
        response = self.client.get(f"/me/configs/{cid}?range=24h")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("traffic-chart", response.text)
        self.assertIn("traffic-line--down", response.text)
        self.assertIn("traffic-line--up", response.text)
        self.assertIn("downloaded", response.text)
        self.assertIn(
            f'href="/me/configs/{cid}?range=7d#traffic"', response.text
        )
        self.assertIn(
            f'href="/me/configs/{cid}?range=6h#traffic"', response.text
        )

    def test_the_six_hour_range_draws_five_minute_points(self):
        aid, cid = self.seed_client()
        self.seed_traffic(cid)
        self.login("c1@example.com", USER_PASSWORD)
        response = self.client.get(f"/me/configs/{cid}?range=6h")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("traffic-chart", response.text)
        self.assertIn("traffic-line--down", response.text)
        self.assertIn("const bucket = 300;", response.text)

    def test_the_state_badge_is_green_only_while_online(self):
        aid, cid = self.seed_client()
        eid = self.seed_exit(name="nl-1", iface="awg1")
        self.grant(aid, cid, eid)
        self.login("c1@example.com", USER_PASSWORD)
        now = int(time.time())
        live = {"ok": True, "device": {}, "peers": {"pubkey": {
            "endpoint": "", "handshake": now - 20, "rx": 0, "tx": 0}}}
        status = {"ts": now, "active": "awg1", "clients": {"10.80.0.2": "awg1"},
                  "exits": {"awg1": {"alive": True, "degraded": False, "rtt_ms": 20}}}
        with mock.patch.object(app, "iface_dump", return_value=live), \
                mock.patch.object(app, "read_status", return_value=status):
            page = self.client.get(f"/me/configs/{cid}").text
        self.assertIn(">Online<", page)
        self.assertIn("oc-badge--success\" data-diagnosis-badge", page)

        live["peers"]["pubkey"]["handshake"] = now - 600
        with mock.patch.object(app, "iface_dump", return_value=live), \
                mock.patch.object(app, "read_status", return_value=status):
            page = self.client.get(f"/me/configs/{cid}").text
        self.assertIn("Last handshake", page)
        self.assertIn("oc-badge--subtle\" data-diagnosis-badge", page)

    def test_an_unknown_range_falls_back_to_24h(self):
        aid, cid = self.seed_client()
        self.login("c1@example.com", USER_PASSWORD)
        response = self.client.get(f"/me/configs/{cid}?range=bogus")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("no traffic recorded yet", response.text)

    def test_a_foreign_configuration_is_not_found(self):
        self.seed_client()
        aid2, cid2 = self.seed_client(name="c2", ip="10.80.0.9",
                                      email="c2@example.com")
        self.login("c1@example.com", USER_PASSWORD)
        response = self.client.get(f"/me/configs/{cid2}")
        self.assertEqual(response.status_code, 404)


class PresetsApiTests(PanelTestCase):
    def api_login(self, email="c1@example.com"):
        response = self.client.post("/api/login", data={
            "email": email, "password": USER_PASSWORD,
        })
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": "Bearer " + response.json()["token"]}

    def fill(self, slug="telegram", cidrs="91.108.4.0/22",
             fetched=None, enabled=1):
        now = int(time.time()) if fetched is None else fetched
        with app.db() as conn:
            conn.execute(
                "UPDATE route_presets SET cidrs = ?, fetched_at = ?, enabled = ? "
                "WHERE slug = ?", (cidrs, now, enabled, slug),
            )

    def test_the_catalogue_needs_a_token(self):
        self.seed_client()
        self.assertEqual(self.client.get("/api/me/presets").status_code, 401)

    def test_the_catalogue_serves_enabled_presets(self):
        self.seed_client()
        headers = self.api_login()
        self.fill("telegram")
        self.fill("claude", cidrs="", enabled=0)
        response = self.client.get("/api/me/presets", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual([p["id"] for p in body["presets"]], ["telegram"])
        self.assertFalse(body["stale"])
        self.assertTrue(body["version"])
        self.assertTrue(body["presets"][0]["icon"].startswith("/static/presets/"))
        self.assertTrue(body["presets"][0]["icon_png"].endswith(".png"))
        self.assertEqual(headers["Authorization"][:7], "Bearer ")
        self.assertIn("etag", response.headers)
        self.assertEqual(response.headers["cache-control"], "no-cache")

    def test_the_etag_short_circuits_the_body(self):
        self.seed_client()
        headers = self.api_login()
        self.fill("telegram")
        first = self.client.get("/api/me/presets", headers=headers)
        second = self.client.get(
            "/api/me/presets",
            headers=dict(headers, **{"If-None-Match": first.headers["etag"]}),
        )
        self.assertEqual(second.status_code, 304)
        self.assertEqual(second.content, b"")

    def test_an_old_catalogue_is_marked_stale(self):
        self.seed_client()
        headers = self.api_login()
        self.fill("telegram", fetched=int(time.time()) - presets.STALE_AFTER - 60)
        response = self.client.get("/api/me/presets", headers=headers)
        self.assertTrue(response.json()["stale"])

    def test_an_empty_catalogue_is_an_empty_list(self):
        self.seed_client()
        headers = self.api_login()
        response = self.client.get("/api/me/presets", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["presets"], [])

    def create_personal(self, headers, name="Mine", cidrs="10.90.0.0/24"):
        return self.client.post("/api/me/presets", data={
            "name": name, "description": "d", "cidrs": cidrs,
        }, headers=headers)

    def test_a_personal_preset_is_private_to_its_account(self):
        self.seed_client()
        self.fill("telegram")
        headers = self.api_login()
        created = self.create_personal(headers)
        self.assertEqual(created.status_code, 201, created.text)
        preset = created.json()
        self.assertTrue(preset["id"].startswith("u1-"))
        self.assertNotIn("icon", preset)
        self.assertNotIn("icon_png", preset)
        mine = {p["id"] for p in self.client.get(
            "/api/me/presets", headers=headers).json()["presets"]}
        self.assertIn("telegram", mine)
        self.assertIn(preset["id"], mine)

        self.seed_client(name="c2", ip="10.80.0.9", email="c2@example.com")
        headers2 = self.api_login("c2@example.com")
        theirs = {p["id"] for p in self.client.get(
            "/api/me/presets", headers=headers2).json()["presets"]}
        self.assertNotIn(preset["id"], theirs)
        self.assertIn("telegram", theirs)

    def test_a_personal_preset_can_be_deleted(self):
        self.seed_client()
        headers = self.api_login()
        preset = self.create_personal(headers).json()
        response = self.client.delete(f"/api/me/presets/{preset['id']}",
                                      headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.client.get(
            "/api/me/presets", headers=headers).json()["presets"], [])

    def test_global_and_foreign_presets_cannot_be_deleted(self):
        self.seed_client()
        self.fill("telegram")
        headers = self.api_login()
        self.assertEqual(
            self.client.delete("/api/me/presets/telegram", headers=headers).status_code,
            404,
        )
        self.seed_client(name="c2", ip="10.80.0.9", email="c2@example.com")
        headers2 = self.api_login("c2@example.com")
        foreign = self.create_personal(headers2, name="Theirs").json()
        self.assertEqual(
            self.client.delete(f"/api/me/presets/{foreign['id']}",
                               headers=headers).status_code,
            404,
        )

    def test_the_personal_limit_is_enforced(self):
        self.seed_client()
        headers = self.api_login()
        with app.db() as conn:
            for index in range(presets.MAX_ACCOUNT_PRESETS):
                conn.execute(
                    "INSERT INTO route_presets (slug, name, kind, cidrs, "
                    "enabled, priority, created_at, account_id) VALUES "
                    "(?, ?, 'custom', '10.90.0.0/24', 1, 100, 'now', 1)",
                    (f"u1-fill-{index}", f"fill {index}"),
                )
        response = self.create_personal(headers, name="One too many")
        self.assertEqual(response.status_code, 409)

    def test_a_default_route_is_refused(self):
        self.seed_client()
        headers = self.api_login()
        response = self.create_personal(headers, cidrs="0.0.0.0/0")
        self.assertEqual(response.status_code, 400)

    def test_reserved_and_tunnel_ranges_are_refused(self):
        self.seed_client()
        headers = self.api_login()
        for cidr in ("10.80.0.0/24", "127.0.0.0/8",
                     "169.254.0.0/16", "224.0.0.0/4"):
            response = self.create_personal(headers, cidrs=cidr)
            self.assertEqual(response.status_code, 400, cidr)


class PresetIconTests(PanelTestCase):
    def test_the_icon_is_served_with_cache_headers(self):
        path = presets.ICONS["telegram"]
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        self.assertIn("image/svg+xml", response.headers["content-type"])
        self.assertIn("immutable", response.headers["cache-control"])
        self.assertIn("max-age=31536000", response.headers["cache-control"])
        self.assertIn("etag", response.headers)
        again = self.client.get(
            path, headers={"If-None-Match": response.headers["etag"]}
        )
        self.assertEqual(again.status_code, 304)

    def test_the_png_icon_is_served_with_cache_headers(self):
        path = presets.ICON_PNGS["claude"]
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        self.assertIn("image/png", response.headers["content-type"])
        self.assertIn("immutable", response.headers["cache-control"])
        again = self.client.get(
            path, headers={"If-None-Match": response.headers["etag"]}
        )
        self.assertEqual(again.status_code, 304)

    def test_icons_stay_public_with_the_anonymous_login_page(self):
        with app.db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) "
                "VALUES ('login_anonymous', '1')"
            )
        icon = self.client.get(presets.ICONS["telegram"])
        self.assertEqual(icon.status_code, 200)
        # Everything else under /static still disappears.
        self.assertEqual(self.client.get("/static/theme.css").status_code, 404)


class CabinetPresetsTests(PanelTestCase):
    def test_the_page_needs_login(self):
        response = self.client.get("/me/presets")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")

    def test_a_preset_is_created_and_deleted(self):
        aid, cid = self.seed_client()
        self.login("c1@example.com", USER_PASSWORD)
        self.assertEqual(self.client.get("/me/presets").status_code, 200)
        csrf = self.csrf("/me/presets")
        created = self.client.post("/me/presets/new", data={
            "name": "My services", "description": "d",
            "cidrs": "10.90.0.0/24", "csrf_token": csrf,
        })
        self.assertEqual(created.status_code, 303)
        with app.db() as conn:
            row = conn.execute(
                "SELECT * FROM route_presets WHERE slug LIKE 'u1-%'"
            ).fetchone()
        self.assertEqual(row["account_id"], aid)
        self.assertIn("My services", self.client.get("/me/presets").text)
        deleted = self.client.post(f"/me/presets/{row['id']}/delete", data={
            "csrf_token": csrf,
        })
        self.assertEqual(deleted.status_code, 303)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM route_presets WHERE id = ?", (row["id"],)
            ).fetchone()[0], 0)

    def test_a_foreign_preset_cannot_be_deleted(self):
        self.seed_client()
        with app.db() as conn:
            pid = conn.execute(
                "INSERT INTO route_presets (slug, name, kind, cidrs, enabled, "
                "priority, created_at, account_id) VALUES "
                "('u2-x', 'X', 'custom', '10.9.0.0/24', 1, 100, 'now', 2)"
            ).lastrowid
        self.login("c1@example.com", USER_PASSWORD)
        response = self.client.post(f"/me/presets/{pid}/delete", data={
            "csrf_token": self.csrf("/me/presets"),
        })
        self.assertEqual(response.status_code, 404)

    def test_a_personal_preset_is_edited_with_an_icon(self):
        aid, cid = self.seed_client()
        self.seed_client(name="c2", ip="10.80.0.9", email="c2@example.com")
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf("/me/presets")
        self.client.post("/me/presets/new", data={
            "name": "Mine", "cidrs": "10.90.0.0/24", "csrf_token": csrf,
        })
        with app.db() as conn:
            pid = conn.execute(
                "SELECT id FROM route_presets WHERE account_id = ?", (aid,)
            ).fetchone()[0]
        page = self.client.get(f"/me/presets/{pid}")
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn("Mine", page.text)
        response = self.client.post(
            f"/me/presets/{pid}/edit",
            data={
                "name": "Mine v2", "description": "updated",
                "cidrs": "10.90.0.0/24, 10.91.0.0/24",
                "csrf_token": self.csrf(f"/me/presets/{pid}"),
            },
            files={"icon": ("mine.png", PNG_ICON, "image/png")},
        )
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            row = conn.execute("SELECT * FROM route_presets WHERE id = ?",
                               (pid,)).fetchone()
        self.assertEqual(row["name"], "Mine v2")
        self.assertEqual(row["description"], "updated")
        self.assertTrue(row["icon"].startswith("/preset-icons/"))
        self.assertEqual(self.client.get(row["icon"]).status_code, 200)
        headers = {"Authorization": "Bearer " + self.client.post(
            "/api/login", data={"email": "c1@example.com",
                                "password": USER_PASSWORD},
        ).json()["token"]}
        entry = self.client.get(
            "/api/me/presets", headers=headers).json()["presets"][0]
        self.assertEqual(entry["icon"], row["icon"])
        self.assertEqual(entry["icon_png"], row["icon"])

    def test_a_foreign_preset_cannot_be_edited(self):
        self.seed_client()
        with app.db() as conn:
            pid = conn.execute(
                "INSERT INTO route_presets (slug, name, kind, cidrs, enabled, "
                "priority, created_at, account_id) VALUES "
                "('u2-x', 'X', 'custom', '10.9.0.0/24', 1, 100, 'now', 2)"
            ).lastrowid
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf("/me/presets")
        self.assertEqual(self.client.get(f"/me/presets/{pid}").status_code, 404)
        response = self.client.post(f"/me/presets/{pid}/edit", data={
            "name": "Hijacked", "cidrs": "10.9.0.0/24", "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 404)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT name FROM route_presets WHERE id = ?", (pid,)
            ).fetchone()[0], "X")

    def test_a_personal_preset_refuses_the_tunnel_network(self):
        aid, cid = self.seed_client()
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf("/me/presets")
        self.client.post("/me/presets/new", data={
            "name": "Mine", "cidrs": "10.90.0.0/24", "csrf_token": csrf,
        })
        with app.db() as conn:
            pid = conn.execute(
                "SELECT id FROM route_presets WHERE account_id = ?", (aid,)
            ).fetchone()[0]
        response = self.client.post(f"/me/presets/{pid}/edit", data={
            "name": "Mine", "cidrs": "10.80.0.0/24",
            "csrf_token": self.csrf(f"/me/presets/{pid}"),
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT cidrs FROM route_presets WHERE id = ?", (pid,)
            ).fetchone()[0], "10.90.0.0/24")


class PresetAdminTests(PanelTestCase):
    def api_token(self, email="c1@example.com"):
        response = self.client.post("/api/login", data={
            "email": email, "password": USER_PASSWORD,
        })
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": "Bearer " + response.json()["token"]}
    def test_the_page_needs_an_administrator(self):
        page = self.client.get("/presets")
        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login")

    def test_the_page_lists_the_catalogue(self):
        self.login_admin()
        page = self.client.get("/presets").text
        self.assertIn("Telegram", page)
        self.assertIn("refresh now", page)
        self.assertIn("/api/me/presets", page)

    def test_account_presets_are_not_in_the_global_catalogue(self):
        self.seed_client()
        with app.db() as conn:
            conn.execute(
                "INSERT INTO route_presets (slug, name, kind, cidrs, enabled, "
                "priority, created_at, account_id) VALUES "
                "('u1-personal', 'Personal route set', 'custom', "
                "'10.9.0.0/24', 1, 100, 'now', 1)"
            )
        self.login_admin()
        page = self.client.get("/presets").text
        self.assertNotIn("Personal route set", page)

    def test_a_custom_preset_is_created_and_served(self):
        self.login_admin()
        response = self.client.post("/presets/new", data={
            "name": "My services", "description": "test",
            "cidrs": "10.90.0.0/24, 10.91.0.0/24", "source_kind": "",
            "source_value": "", "csrf_token": self.csrf("/presets"),
        })
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            row = conn.execute(
                "SELECT * FROM route_presets WHERE slug = 'my-services'"
            ).fetchone()
        self.assertEqual(row["kind"], "custom")
        self.assertEqual(row["cidrs"], "10.90.0.0/24,10.91.0.0/24")

    def test_a_default_route_is_refused(self):
        self.login_admin()
        response = self.client.post("/presets/new", data={
            "name": "bad", "cidrs": "0.0.0.0/0",
            "csrf_token": self.csrf("/presets"),
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM route_presets WHERE slug = 'bad'"
            ).fetchone()[0], 0)

    def test_toggling_a_preset_changes_the_api(self):
        self.seed_client()
        self.login_admin()
        with app.db() as conn:
            pid = conn.execute(
                "SELECT id FROM route_presets WHERE slug = 'telegram'"
            ).fetchone()[0]
            conn.execute(
                "UPDATE route_presets SET cidrs = '91.108.4.0/22', fetched_at = ? "
                "WHERE id = ?", (int(time.time()), pid),
            )
        response = self.client.post(f"/presets/{pid}/toggle", data={
            "csrf_token": self.csrf("/presets"),
        })
        self.assertEqual(response.status_code, 303)
        headers = self.api_token()
        self.assertEqual(
            self.client.get("/api/me/presets", headers=headers).json()["presets"], []
        )

    def test_a_builtin_preset_cannot_be_deleted(self):
        self.login_admin()
        with app.db() as conn:
            pid = conn.execute(
                "SELECT id FROM route_presets WHERE slug = 'telegram'"
            ).fetchone()[0]
        response = self.client.post(f"/presets/{pid}/delete", data={
            "csrf_token": self.csrf("/presets"),
        })
        self.assertEqual(response.status_code, 303)

    def test_a_builtin_preset_can_be_edited(self):
        self.login_admin()
        with app.db() as conn:
            pid = conn.execute(
                "SELECT id FROM route_presets WHERE slug = 'telegram'"
            ).fetchone()[0]
        page = self.client.get(f"/presets/{pid}")
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn("edit telegram", page.text.lower())
        response = self.client.post(f"/presets/{pid}/edit", data={
            "name": "Telegram (edited)", "description": "mine",
            "cidrs": "91.108.4.0/22", "source_kind": "cidr-text",
            "source_value": presets.DEFAULT_PRESETS[0]["source_value"],
            "csrf_token": self.csrf(f"/presets/{pid}"),
        })
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            row = conn.execute("SELECT * FROM route_presets WHERE id = ?",
                               (pid,)).fetchone()
        self.assertEqual(row["name"], "Telegram (edited)")
        self.assertEqual(row["kind"], "builtin")
        self.assertEqual(row["cidrs"], "91.108.4.0/22")

    def test_an_uploaded_icon_is_served_and_catalogued(self):
        self.seed_client()
        self.login_admin()
        with app.db() as conn:
            pid = conn.execute(
                "SELECT id FROM route_presets WHERE slug = 'telegram'"
            ).fetchone()[0]
            conn.execute(
                "UPDATE route_presets SET cidrs = '91.108.4.0/22', "
                "fetched_at = ? WHERE id = ?", (int(time.time()), pid),
            )
        response = self.client.post(
            f"/presets/{pid}/edit",
            data={
                "name": "Telegram", "description": "d",
                "cidrs": "91.108.4.0/22", "source_kind": "cidr-text",
                "source_value": presets.DEFAULT_PRESETS[0]["source_value"],
                "csrf_token": self.csrf(f"/presets/{pid}"),
            },
            files={"icon": ("tg.png", PNG_ICON, "image/png")},
        )
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            row = conn.execute("SELECT * FROM route_presets WHERE id = ?",
                               (pid,)).fetchone()
        self.assertTrue(row["icon"].startswith("/preset-icons/"), row["icon"])
        self.assertEqual(row["icon_png"], row["icon"])
        icon = self.client.get(row["icon"])
        self.assertEqual(icon.status_code, 200)
        self.assertEqual(icon.headers["content-type"], "image/png")
        self.assertIn("immutable", icon.headers["cache-control"])
        again = self.client.get(
            row["icon"], headers={"If-None-Match": icon.headers["etag"]})
        self.assertEqual(again.status_code, 304)
        headers = self.api_token()
        entry = self.client.get(
            "/api/me/presets", headers=headers).json()["presets"][0]
        self.assertEqual(entry["icon"], row["icon"])
        self.assertEqual(entry["icon_png"], row["icon"])

    def test_an_icon_can_be_removed(self):
        self.login_admin()
        with app.db() as conn:
            pid = conn.execute(
                "SELECT id FROM route_presets WHERE slug = 'telegram'"
            ).fetchone()[0]
        self.client.post(
            f"/presets/{pid}/edit",
            data={
                "name": "Telegram", "description": "d",
                "cidrs": "91.108.4.0/22", "csrf_token": self.csrf("/presets"),
            },
            files={"icon": ("tg.png", PNG_ICON, "image/png")},
        )
        with app.db() as conn:
            url = conn.execute("SELECT icon FROM route_presets WHERE id = ?",
                               (pid,)).fetchone()[0]
        self.client.post(f"/presets/{pid}/edit", data={
            "name": "Telegram", "cidrs": "91.108.4.0/22",
            "remove_icon": "1", "csrf_token": self.csrf(f"/presets/{pid}"),
        })
        with app.db() as conn:
            row = conn.execute("SELECT * FROM route_presets WHERE id = ?",
                               (pid,)).fetchone()
            self.assertFalse(row["icon"])
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM preset_icons").fetchone()[0], 0)
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_a_large_icon_fits_the_upload_limit(self):
        self.login_admin()
        with app.db() as conn:
            pid = conn.execute(
                "SELECT id FROM route_presets WHERE slug = 'telegram'"
            ).fetchone()[0]
        icon = PNG_ICON + b"\x00" * (100 * 1024)
        response = self.client.post(
            f"/presets/{pid}/edit",
            data={
                "name": "Telegram", "cidrs": "91.108.4.0/22",
                "csrf_token": self.csrf(f"/presets/{pid}"),
            },
            files={"icon": ("big.png", icon, "image/png")},
        )
        self.assertEqual(response.status_code, 303)
        self.assertNotIn("err=", response.headers["location"])

    def test_an_oversized_icon_is_refused_by_the_form(self):
        self.login_admin()
        with app.db() as conn:
            pid = conn.execute(
                "SELECT id FROM route_presets WHERE slug = 'telegram'"
            ).fetchone()[0]
        icon = PNG_ICON + b"\x00" * (presets.ICON_MAX_BYTES + 1)
        response = self.client.post(
            f"/presets/{pid}/edit",
            data={
                "name": "Telegram", "cidrs": "91.108.4.0/22",
                "csrf_token": self.csrf(f"/presets/{pid}"),
            },
            files={"icon": ("huge.png", icon, "image/png")},
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])

    def test_a_file_that_is_not_an_image_is_refused(self):
        self.login_admin()
        with app.db() as conn:
            pid = conn.execute(
                "SELECT id FROM route_presets WHERE slug = 'telegram'"
            ).fetchone()[0]
        response = self.client.post(
            f"/presets/{pid}/edit",
            data={
                "name": "Telegram", "cidrs": "91.108.4.0/22",
                "csrf_token": self.csrf(f"/presets/{pid}"),
            },
            files={"icon": ("x.png", b"not an image", "image/png")},
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        self.assertIn("err=", response.headers["location"])
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM route_presets WHERE id = ?", (pid,)
            ).fetchone()[0], 1)

    def test_a_custom_preset_can_be_deleted(self):
        self.login_admin()
        with app.db() as conn:
            pid = conn.execute(
                "INSERT INTO route_presets (slug, name, kind, cidrs, priority, "
                "created_at) VALUES ('mine', 'Mine', 'custom', '10.90.0.0/24', 1, 'now')"
            ).lastrowid
        response = self.client.post(f"/presets/{pid}/delete", data={
            "csrf_token": self.csrf("/presets"),
        })
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM route_presets WHERE id = ?", (pid,)
            ).fetchone()[0], 0)

    def test_csrf_is_required(self):
        self.login_admin()
        response = self.client.post("/presets/new", data={
            "name": "x", "cidrs": "10.90.0.0/24", "csrf_token": "nope",
        })
        self.assertEqual(response.status_code, 400)

    def test_refresh_now_reports_the_result(self):
        self.login_admin()
        with mock.patch.object(presets, "refresh", return_value=(2, 1, ["telegram: down"])):
            response = self.client.post("/presets/refresh", data={
                "csrf_token": self.csrf("/presets"),
            })
        self.assertEqual(response.status_code, 303)
        self.assertIn("ok=", response.headers["location"])


class SocksToggleTests(PanelTestCase):
    def test_the_administrator_can_enable_it(self):
        aid, cid = self.seed_client()
        self.login_admin()
        response = self.client.post(f"/configs/{cid}/socks", data={
            "csrf_token": self.csrf(f"/configs/{cid}"),
        })
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT socks FROM clients WHERE id = ?", (cid,)).fetchone()[0], 1)
        page = self.client.get(f"/configs/{cid}").text
        self.assertIn("SOCKS5 proxy", page)
        self.assertIn("10.80.0.1:1080", page)

    def test_the_account_can_enable_it(self):
        aid, cid = self.seed_client()
        self.login("c1@example.com", USER_PASSWORD)
        response = self.client.post(f"/me/configs/{cid}/socks", data={
            "csrf_token": self.csrf(f"/me/configs/{cid}"),
        })
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT socks FROM clients WHERE id = ?", (cid,)).fetchone()[0], 1)
        self.assertIn("SOCKS5 proxy",
                      self.client.get(f"/me/configs/{cid}").text)

    def test_a_foreign_configuration_cannot_be_toggled(self):
        aid, cid = self.seed_client()
        aid2, cid2 = self.seed_client(name="c2", ip="10.80.0.9",
                                      email="c2@example.com")
        self.login("c1@example.com", USER_PASSWORD)
        response = self.client.post(f"/me/configs/{cid2}/socks", data={
            "csrf_token": self.csrf(f"/me/configs/{cid}"),
        })
        self.assertEqual(response.status_code, 404)
        with app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT socks FROM clients WHERE id = ?", (cid2,)).fetchone()[0], 0)

    def test_the_configuration_object_reports_the_proxy(self):
        aid, cid = self.seed_client()
        with app.db() as conn:
            conn.execute("UPDATE clients SET socks = 1 WHERE id = ?", (cid,))
        response = self.client.post("/api/login", data={
            "email": "c1@example.com", "password": USER_PASSWORD,
        })
        headers = {"Authorization": "Bearer " + response.json()["token"]}
        config = self.client.get("/api/me", headers=headers).json()["client"]
        self.assertTrue(config["socks"])


    def test_the_toggle_reapplies_routing_and_reports_errors(self):
        aid, cid = self.seed_client()
        self.login_admin()
        with mock.patch.object(app.routing, "apply",
                               return_value={"errors": []} ) as apply:
            response = self.client.post(f"/configs/{cid}/socks", data={
                "csrf_token": self.csrf(f"/configs/{cid}"),
            })
        self.assertEqual(response.status_code, 303)
        apply.assert_called_once()
        with mock.patch.object(app.routing, "apply",
                               return_value={"errors": ["boom"]}):
            response = self.client.post(f"/configs/{cid}/socks", data={
                "csrf_token": self.csrf(f"/configs/{cid}"),
            })
        self.assertIn("err=", response.headers["location"])


    def test_the_lists_mark_configurations_with_the_proxy(self):
        aid, cid = self.seed_client()
        with app.db() as conn:
            conn.execute("UPDATE clients SET socks = 1 WHERE id = ?", (cid,))
        self.login_admin()
        marker = 'title="SOCKS5 proxy enabled">socks'
        self.assertIn(marker, self.client.get("/configs").text)
        self.assertIn(marker, self.client.get(f"/accounts/{aid}").text)
        self.login("c1@example.com", USER_PASSWORD)
        self.assertIn(marker, self.client.get("/me").text)


class MobileApiTests(PanelTestCase):
    def api_login(self, email="c1@example.com", password=USER_PASSWORD):
        response = self.client.post("/api/login", data={
            "email": email, "password": password,
        })
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": "Bearer " + response.json()["token"]}, response.json()

    def test_login_lists_configs_and_keeps_the_client_field(self):
        aid, cid = self.seed_client()
        _, payload = self.api_login()
        self.assertEqual(payload["client"]["id"], cid)
        self.assertEqual([c["id"] for c in payload["configs"]], [cid])

    def test_the_configuration_carries_the_tunnel_gateway(self):
        self.seed_client()
        headers, payload = self.api_login()
        self.assertEqual(payload["client"]["gateway"], "10.80.0.1")
        created = self.client.post("/api/me/configs", data={
            "name": "new-one"}, headers=headers)
        self.assertEqual(created.status_code, 200, created.text)
        self.assertEqual(created.json()["config"]["gateway"], "10.80.0.1")

    def test_exits_api_says_unknown_when_the_daemon_is_silent(self):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("first", "awg1"))
        headers, _ = self.api_login()
        fresh = {"ts": int(time.time()), "active": "awg1",
                 "exits": {"awg1": {"alive": True, "rtt_ms": 12}}}
        with mock.patch.object(app, "read_status", return_value=fresh):
            live = self.client.get("/api/me/exits", headers=headers).json()[0]
        self.assertTrue(live["alive"])
        self.assertTrue(live["active"])
        self.assertTrue(live["status_fresh"])
        old = {"ts": int(time.time()) - 300,
               "exits": {"awg1": {"alive": True, "rtt_ms": 12}}}
        with mock.patch.object(app, "read_status", return_value=old):
            silent = self.client.get("/api/me/exits", headers=headers).json()[0]
        self.assertIsNone(silent["alive"])
        self.assertIsNone(silent["rtt_ms"])
        self.assertIsNone(silent["active"])
        self.assertFalse(silent["status_fresh"])

    def test_exits_api_marks_only_the_active_exit(self):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("first", "awg1"), 10)
        self.grant(aid, cid, self.seed_exit("second", "awg2", priority=20), 20)
        headers, _ = self.api_login()
        status = {"ts": int(time.time()), "active": "awg2",
                  "exits": {"awg1": {"alive": True, "rtt_ms": 10},
                            "awg2": {"alive": True, "rtt_ms": 90}}}
        with mock.patch.object(app, "read_status", return_value=status):
            exits = self.client.get("/api/me/exits", headers=headers).json()
        self.assertEqual([e["active"] for e in exits], [False, True])

    def test_exits_api_reports_the_country(self):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("nl-1", "awg1"))
        with app.db() as conn:
            conn.execute("UPDATE exits SET country = 'Netherlands', comment = 'Amsterdam'")
        headers, _ = self.api_login()
        with mock.patch.object(app, "read_status",
                               return_value={"ts": int(time.time())}):
            exit_row = self.client.get("/api/me/exits", headers=headers).json()[0]
        self.assertEqual(exit_row["country"], "Netherlands")
        self.assertEqual(exit_row["comment"], "Amsterdam")

    def test_exits_api_marks_the_configuration_own_exit(self):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("first", "awg1"), 10)
        self.grant(aid, cid, self.seed_exit("second", "awg2", priority=20), 20)
        headers, _ = self.api_login()
        status = {
            "ts": int(time.time()),
            "active": "awg1",                      # server default route
            "clients": {"10.80.0.2": "awg2"},      # this configuration's table
            "exits": {"awg1": {"alive": True}, "awg2": {"alive": True}},
        }
        with mock.patch.object(app, "read_status", return_value=status):
            exits = self.client.get("/api/me/exits", headers=headers).json()
        self.assertEqual([e["active"] for e in exits], [True, False])
        self.assertEqual([e["current"] for e in exits], [False, True])
        self.assertEqual({e["current_iface"] for e in exits}, {"awg2"})

    def test_exits_api_says_unknown_when_the_configuration_has_no_route(self):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("first", "awg1"))
        headers, _ = self.api_login()
        status = {"ts": int(time.time()) - 600, "active": "awg1", "clients": {}}
        with mock.patch.object(app, "read_status", return_value=status):
            exits = self.client.get("/api/me/exits", headers=headers).json()
        self.assertIsNone(exits[0]["current"])
        self.assertIsNone(exits[0]["current_iface"])

    def test_create_conf_order_and_delete(self):
        aid, cid = self.seed_client(max_configs=5)
        exit_id = self.seed_exit()
        headers, _ = self.api_login()
        response = self.client.get("/api/me", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["configs"]), 1)

        response = self.client.post("/api/me/configs", data={"name": "tablet"},
                                    headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        new_cid = response.json()["config"]["id"]
        self.assertEqual(response.json()["config"]["name"], "tablet")

        response = self.client.get(f"/api/me/configs/{new_cid}/conf",
                                   headers=headers)
        self.assertEqual(response.status_code, 400)  # no access granted yet

        with app.db() as conn:
            conn.execute(
                "INSERT INTO account_exits (account_id, exit_id, priority) "
                "VALUES (?, ?, 10)", (aid, exit_id))
            app.sync_account_configs(conn, aid)
        response = self.client.get("/api/me/exits?config_id=" + str(new_cid),
                                   headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual([e["id"] for e in response.json()], [exit_id])
        response = self.client.get(f"/api/me/configs/{new_cid}/conf",
                                   headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("[Interface]", response.text)

        response = self.client.post("/api/me/exits/order", data={
            "config_id": str(new_cid), "exit_id": [str(exit_id)],
        }, headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        response = self.client.post("/api/me/exits/order", data={
            "config_id": str(new_cid), "exit_id": ["999"],
        }, headers=headers)
        self.assertEqual(response.status_code, 400)

        response = self.client.post(f"/api/me/configs/{new_cid}/toggle",
                                    headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["enabled"])

        response = self.client.delete(f"/api/me/configs/{new_cid}",
                                      headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        response = self.client.get(f"/api/me/configs/{new_cid}/conf",
                                   headers=headers)
        self.assertEqual(response.status_code, 404)

    def test_configs_carry_the_remote_address(self):
        aid, cid = self.seed_client()
        with app.db() as conn:
            pub = conn.execute(
                "SELECT public_key FROM clients WHERE id = ?", (cid,)
            ).fetchone()[0]
        peers = {pub: {"endpoint": "77.88.99.3:51820", "handshake": 1,
                       "rx": 1, "tx": 1}}
        live = {"ok": True, "device": {}, "peers": peers}
        with mock.patch.object(app, "iface_dump", return_value=live):
            response = self.client.post("/api/login", data={
                "email": "c1@example.com", "password": USER_PASSWORD,
            })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["configs"][0]["remote_ip"], "77.88.99.3")

    def test_a_silent_peer_has_an_empty_remote_address(self):
        self.seed_client()
        headers, payload = self.api_login()
        self.assertEqual(payload["configs"][0]["remote_ip"], "")
        response = self.client.get("/api/me", headers=headers)
        self.assertEqual(response.json()["configs"][0]["remote_ip"], "")

    def seed_traffic(self, cid):
        now = int(time.time())
        with app.db() as conn:
            conn.executemany(
                "INSERT INTO traffic (client_id, ts, step, rx, tx) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (cid, now - 600, 300, 100, 200),
                    (cid, now - 300, 300, 300, 400),
                    (cid, now - 600, 3600, 100, 200),
                ],
            )
        return now

    def test_traffic_history_is_returned_in_order(self):
        aid, cid = self.seed_client()
        now = self.seed_traffic(cid)
        headers, _ = self.api_login()
        response = self.client.get(
            f"/api/me/configs/{cid}/traffic?hours=1", headers=headers
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["config_id"], cid)
        self.assertEqual(payload["step_seconds"], 300)
        self.assertEqual(
            payload["points"],
            [
                {"ts": now - 600, "rx": 100, "tx": 200},
                {"ts": now - 300, "rx": 300, "tx": 400},
            ],
        )

    def test_traffic_switches_to_hourly_beyond_a_week(self):
        aid, cid = self.seed_client()
        self.seed_traffic(cid)
        headers, _ = self.api_login()
        response = self.client.get(
            f"/api/me/configs/{cid}/traffic?hours=200", headers=headers
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["step_seconds"], 3600)
        self.assertEqual(len(response.json()["points"]), 1)

    def test_empty_history_is_an_empty_list(self):
        aid, cid = self.seed_client()
        headers, _ = self.api_login()
        response = self.client.get(
            f"/api/me/configs/{cid}/traffic", headers=headers
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["points"], [])

    def test_deleting_a_configuration_drops_its_history(self):
        aid, cid = self.seed_client()
        self.seed_traffic(cid)
        headers, _ = self.api_login()
        response = self.client.delete(f"/api/me/configs/{cid}", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        with app.db() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM traffic").fetchone()[0], 0
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM traffic_state").fetchone()[0], 0
            )

    def test_traffic_of_a_foreign_configuration_is_not_found(self):
        self.seed_client()
        aid2, cid2 = self.seed_client(name="c2", ip="10.80.0.9",
                                      email="c2@example.com")
        headers, _ = self.api_login()
        response = self.client.get(
            f"/api/me/configs/{cid2}/traffic", headers=headers
        )
        self.assertEqual(response.status_code, 404)

    def test_conf_is_plain_text_for_the_app(self):
        # The app reads the body as text; only browser downloads changed.
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit())
        headers, _ = self.api_login()
        response = self.client.get("/api/me/conf", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.headers["content-type"].startswith("text/plain"))

    def test_limit_is_enforced(self):
        self.seed_client(max_configs=1)
        headers, _ = self.api_login()
        response = self.client.post("/api/me/configs", data={"name": "extra"},
                                    headers=headers)
        self.assertEqual(response.status_code, 409)


if __name__ == "__main__":
    unittest.main()
