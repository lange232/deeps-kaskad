"""HTTP and database tests for the panel.

They need FastAPI and the panel venv:

    /opt/kaskad/venv/bin/python -m unittest discover -s tests

The system side (awg, systemctl, ip) is mocked: these tests only check the
request handling, the database state and the transaction boundaries.
"""
import json
import os
import re
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

    def seed_client(self, name="c1", ip="10.80.0.2", email="c1@example.com",
                    password=USER_PASSWORD, internet=1, enabled=1):
        with app.db() as conn:
            table = app.routing.allocate_table(conn)
            cur = conn.execute(
                "INSERT INTO clients (name, ip, public_key, private_key, "
                "preshared_key, enabled, created_at, internet, table_num) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name, ip, "pubkey", "privkey", "psk", enabled, "now", internet, table),
            )
            cid = cur.lastrowid
            conn.execute(
                "INSERT INTO users (client_id, email, password_hash, enabled, "
                "token_version, created_at) VALUES (?, ?, ?, 1, 1, ?)",
                (cid, email, auth.hash_password(password), "now"),
            )
        return cid

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

    def grants(self, cid):
        with app.db() as conn:
            return [tuple(r) for r in conn.execute(
                "SELECT exit_id, priority FROM client_internet_exits "
                "WHERE client_id = ? ORDER BY priority", (cid,))]

    def client_count(self):
        with app.db() as conn:
            return conn.execute("SELECT count(*) FROM clients").fetchone()[0]


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
        response = self.client.post("/clients", data={
            "name": "c1", "email": "c1@example.com", "password": USER_PASSWORD,
            "csrf_token": "wrong",
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client_count(), 0)


class RateLimitTests(PanelTestCase):
    def test_login_is_blocked_after_five_failures(self):
        for _ in range(5):
            self.assertEqual(self.login("admin", "wrong-password").status_code, 401)
        self.assertEqual(self.login("admin", "wrong-password").status_code, 429)


class RoleTests(PanelTestCase):
    def test_user_cannot_open_admin_pages(self):
        self.seed_client(email="c1@example.com")
        self.login("c1@example.com", USER_PASSWORD)
        for path in ("/clients", "/exits", "/journal"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 303, path)
            self.assertEqual(response.headers["location"], "/me")

    def test_user_cannot_change_grants(self):
        cid = self.seed_client(email="c1@example.com")
        exit_id = self.seed_exit()
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf("/me")
        response = self.client.post(f"/clients/{cid}/internet",
                                    data={"exits": [exit_id], "csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/me")
        self.assertEqual(self.grants(cid), [])

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
                "SELECT token_version FROM users").fetchone()[0], 2)

    def test_account_reset_revokes_user_sessions(self):
        cid = self.seed_client(email="c1@example.com")
        self.login("c1@example.com", USER_PASSWORD)
        cookie = self.client.cookies.get(app.COOKIE)
        self.client.post("/logout")

        self.login_admin()
        csrf = self.csrf(f"/clients/{cid}")
        response = self.client.post(f"/clients/{cid}/account/password",
                                    data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.stale_client(cookie).get("/me").headers["location"],
                         "/login")

    def test_healthz_is_public(self):
        fresh = {"ts": int(time.time())}
        with mock.patch.object(app, "read_status", return_value=fresh):
            response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])

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

    def test_create_client(self):
        self.login_admin()
        csrf = self.csrf("/clients/new")
        app.apply_conf.side_effect = self.rollback_error()
        response = self.client.post("/clients", data={
            "name": "rb", "email": "rb@example.com",
            "password": USER_PASSWORD, "csrf_token": csrf,
        })
        self.assert_warns(response)

    def test_toggle_client(self):
        cid = self.seed_client()
        self.login_admin()
        csrf = self.csrf(f"/clients/{cid}")
        app.apply_conf.side_effect = self.rollback_error()
        self.assert_warns(self.client.post(f"/clients/{cid}/toggle",
                                           data={"csrf_token": csrf}))

    def test_delete_client(self):
        cid = self.seed_client()
        self.login_admin()
        csrf = self.csrf(f"/clients/{cid}")
        app.apply_conf.side_effect = self.rollback_error()
        self.assert_warns(self.client.post(f"/clients/{cid}/delete",
                                           data={"csrf_token": csrf}))

    def test_reissue(self):
        self.seed_client(email="rb@example.com")
        self.login("rb@example.com", USER_PASSWORD)
        csrf = self.csrf("/me")
        app.apply_conf.side_effect = self.rollback_error()
        self.assert_warns(self.client.post("/me/reissue",
                                           data={"csrf_token": csrf}))


class ClientTests(PanelTestCase):
    def test_create_client_with_account(self):
        self.login_admin()
        csrf = self.csrf("/clients/new")
        response = self.client.post("/clients", data={
            "name": "new-client", "email": "new@example.com",
            "password": USER_PASSWORD, "internet": "on",
            "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("/clients/", response.headers["location"])
        with app.db() as conn:
            client = conn.execute("SELECT * FROM clients").fetchone()
            user = conn.execute("SELECT * FROM users").fetchone()
        self.assertEqual(client["name"], "new-client")
        self.assertEqual(client["ip"], "10.80.0.2")
        self.assertGreaterEqual(client["table_num"], app.routing.TABLE_POOL_BASE)
        self.assertEqual(user["client_id"], client["id"])
        self.assertEqual(user["email"], "new@example.com")
        app.apply_conf.assert_called()
        # The tunnel must be configured from the uncommitted transaction.
        self.assertIsNotNone(app.apply_conf.call_args.args[1])
        with app.db() as conn:
            claims = [tuple(r) for r in conn.execute(
                "SELECT table_num, kind, owner_id FROM table_numbers")]
        self.assertEqual(claims, [(client["table_num"], "client", client["id"])])

    def test_duplicate_email_creates_nothing(self):
        self.seed_client(email="taken@example.com")
        self.login_admin()
        csrf = self.csrf("/clients/new")
        response = self.client.post("/clients", data={
            "name": "other", "email": "taken@example.com",
            "password": USER_PASSWORD, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        self.assertEqual(self.client_count(), 1)

    def test_failed_apply_leaves_no_rows(self):
        self.login_admin()
        csrf = self.csrf("/clients/new")
        app.apply_conf.side_effect = RuntimeError("syncconf: boom")
        response = self.client.post("/clients", data={
            "name": "broken", "email": "broken@example.com",
            "password": USER_PASSWORD, "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        with app.db() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM clients").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM users").fetchone()[0], 0)

    def test_delete_removes_account_and_grants(self):
        cid = self.seed_client()
        exit_id = self.seed_exit()
        with app.db() as conn:
            conn.execute(
                "INSERT INTO client_internet_exits (client_id, exit_id, priority) "
                "VALUES (?, ?, 10)", (cid, exit_id))
        self.login_admin()
        csrf = self.csrf(f"/clients/{cid}")
        response = self.client.post(f"/clients/{cid}/delete",
                                    data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM clients").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM users").fetchone()[0], 0)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM client_internet_exits").fetchone()[0], 0)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM table_numbers").fetchone()[0], 0)

    def test_failed_apply_keeps_the_client(self):
        cid = self.seed_client()
        self.login_admin()
        csrf = self.csrf(f"/clients/{cid}")
        app.apply_conf.side_effect = RuntimeError("syncconf: boom")
        response = self.client.post(f"/clients/{cid}/delete",
                                    data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertIn("err=", response.headers["location"])
        self.assertEqual(self.client_count(), 1)


class GrantTests(PanelTestCase):
    def test_grants_are_saved_in_order(self):
        cid = self.seed_client()
        first = self.seed_exit("e1", "awg1", priority=10)
        second = self.seed_exit("e2", "awg2", priority=20)
        self.login_admin()
        csrf = self.csrf(f"/clients/{cid}")
        response = self.client.post(f"/clients/{cid}/internet", data={
            "exits": [second, first], "csrf_token": csrf,
        })
        self.assertEqual(response.status_code, 303)
        saved = {exit_id: prio for exit_id, prio in self.grants(cid)}
        self.assertEqual(saved, {first: 10, second: 20})

    def test_disabled_exit_cannot_be_granted(self):
        cid = self.seed_client()
        dead = self.seed_exit("dead", "awg5", enabled=0)
        self.login_admin()
        csrf = self.csrf(f"/clients/{cid}")
        self.client.post(f"/clients/{cid}/internet",
                         data={"exits": [dead], "csrf_token": csrf})
        self.assertEqual(self.grants(cid), [])

    def test_routed_exit_is_not_an_internet_grant(self):
        cid = self.seed_client()
        routed = self.seed_exit("sub", "awg2", mode="routes", routes="10.9.0.0/24")
        self.login_admin()
        csrf = self.csrf(f"/clients/{cid}")
        self.client.post(f"/clients/{cid}/internet",
                         data={"exits": [routed], "csrf_token": csrf})
        self.assertEqual(self.grants(cid), [])


class UserPageTests(PanelTestCase):
    def test_me_shows_only_own_client(self):
        self.seed_client("mine", "10.80.0.2", "mine@example.com")
        self.seed_client("other", "10.80.0.3", "other@example.com")
        self.login("mine@example.com", USER_PASSWORD)
        response = self.client.get("/me")
        self.assertEqual(response.status_code, 200)
        self.assertIn("10.80.0.2", response.text)
        self.assertNotIn("10.80.0.3", response.text)

    def test_reissue_changes_the_keys(self):
        cid = self.seed_client(email="c1@example.com")
        with app.db() as conn:
            before = conn.execute(
                "SELECT public_key FROM clients WHERE id = ?", (cid,)).fetchone()[0]
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf("/me")
        response = self.client.post("/me/reissue", data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 303)
        with app.db() as conn:
            after = conn.execute(
                "SELECT public_key FROM clients WHERE id = ?", (cid,)).fetchone()[0]
        self.assertNotEqual(before, after)
        app.apply_conf.assert_called()

    def test_reissue_failure_keeps_the_old_key(self):
        cid = self.seed_client(email="c1@example.com")
        with app.db() as conn:
            before = conn.execute(
                "SELECT public_key FROM clients WHERE id = ?", (cid,)).fetchone()[0]
        self.login("c1@example.com", USER_PASSWORD)
        csrf = self.csrf("/me")
        app.apply_conf.side_effect = RuntimeError("syncconf: boom")
        response = self.client.post("/me/reissue", data={"csrf_token": csrf})
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
                "SELECT token_version FROM users").fetchone()[0], 2)

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
                "SELECT token_version FROM users").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
