"""HTTP and database tests for the panel.

They need FastAPI and the panel venv:

    /opt/kaskad/venv/bin/python -m unittest discover -s tests

The system side (awg, systemctl, ip) is mocked: these tests only check the
request handling, the database state and the transaction boundaries.
"""
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))

try:
    from fastapi.testclient import TestClient

    import app
    import auth
except ImportError:  # pragma: no cover - local python without fastapi
    app = None
    TestClient = None
    auth = None

ADMIN_PASSWORD = "admin-password-123"
USER_PASSWORD = "client-password-123"
SECRET = "test-session-secret"


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
        csrf = self.csrf("/me")
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
        csrf = self.csrf("/me")
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

    def test_healthz_is_public(self):
        fresh = {"ts": int(time.time())}
        with mock.patch.object(app, "read_status", return_value=fresh):
            response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])

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

    def test_healthz_fails_without_a_database(self):
        with mock.patch.object(app, "db", side_effect=RuntimeError("boom")):
            response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 503)


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
    def test_overview_measures_the_device_round_trip(self):
        self.seed_exit("e1", "awg1", mode="internet")
        status = {"exits": {"awg1": {"alive": True, "rtt_ms": 40}},
                  "active": "awg1", "clients": {}, "ts": 0}
        self.login_admin()
        with mock.patch.object(app, "read_status", return_value=status):
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


class RoutedChoiceTests(PanelTestCase):
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


class ConfigPingTests(PanelTestCase):
    def card(self, status):
        aid, cid = self.seed_client()
        self.grant(aid, cid, self.seed_exit("e1", "awg1"))
        self.login_admin()
        with mock.patch.object(app, "read_status", return_value=status):
            response = self.client.get(f"/configs/{cid}")
        self.assertEqual(response.status_code, 200)
        return response.text

    def test_card_shows_the_total_latency(self):
        text = self.card({
            "exits": {"awg1": {"alive": True, "rtt_ms": 40}},
            "client_ping": {"10.80.0.2": 10},
        })
        self.assertIn("≈ 50 ms", text)
        self.assertIn("client 10 + exit 40 ms", text)

    def test_card_falls_back_to_the_exit_latency(self):
        text = self.card({
            "exits": {"awg1": {"alive": True, "rtt_ms": 40}},
            "client_ping": {},
        })
        self.assertIn("exit 40 ms", text)
        self.assertIn("S1 to exit only", text)


class NavigationTests(PanelTestCase):
    def test_current_page_is_marked_for_screen_readers(self):
        self.login_admin()
        text = self.client.get("/accounts").text
        self.assertIn('aria-current="page"', text)
        self.assertEqual(text.count('aria-current="page"'), 1)

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
        csrf = self.csrf("/me")
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
        csrf = self.csrf("/me")
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

    def test_limit_is_enforced(self):
        self.seed_client(max_configs=1)
        headers, _ = self.api_login()
        response = self.client.post("/api/me/configs", data={"name": "extra"},
                                    headers=headers)
        self.assertEqual(response.status_code, 409)


if __name__ == "__main__":
    unittest.main()
