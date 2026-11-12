"""Logic tests for the failover decision and routing table cleanup.

Run with: python3 -m unittest discover -s tests
"""
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))

import auth  # noqa: E402
import failover  # noqa: E402
import routing  # noqa: E402


class ChooseTests(unittest.TestCase):
    def test_manual_pins_lower_priority(self):
        desired, clear = failover.choose(
            "awg2", ["awg1", "awg2"], "awg2", {"awg1": 0, "awg2": 0}, now=1000, stable=60
        )
        self.assertEqual(desired, "awg2")
        self.assertFalse(clear)

    def test_manual_survives_failback_window(self):
        # The better exit is stable, but the manual choice still wins.
        desired, clear = failover.choose(
            "awg2", ["awg1", "awg2"], "awg2", {"awg1": 900, "awg2": 950}, now=1000, stable=60
        )
        self.assertEqual(desired, "awg2")
        self.assertFalse(clear)

    def test_manual_dead_clears_and_falls_back(self):
        desired, clear = failover.choose(
            "awg2", ["awg1"], "awg2", {"awg1": 0}, now=1000, stable=60
        )
        self.assertEqual(desired, "awg1")
        self.assertTrue(clear)

    def test_active_dead_switches_immediately(self):
        desired, clear = failover.choose(
            "awg9", ["awg1"], "", {"awg1": 990}, now=1000, stable=60
        )
        self.assertEqual(desired, "awg1")
        self.assertFalse(clear)

    def test_failback_waits_for_stability(self):
        desired, clear = failover.choose(
            "awg2", ["awg1", "awg2"], "", {"awg1": 990, "awg2": 10}, now=1000, stable=60
        )
        self.assertEqual(desired, "awg2")

    def test_failback_after_stable(self):
        desired, clear = failover.choose(
            "awg2", ["awg1", "awg2"], "", {"awg1": 900, "awg2": 10}, now=1000, stable=60
        )
        self.assertEqual(desired, "awg1")

    def test_no_alive_exits(self):
        desired, clear = failover.choose("awg1", [], "", {}, now=1000, stable=60)
        self.assertIsNone(desired)
        self.assertFalse(clear)


class ClientExitTests(unittest.TestCase):
    def test_first_alive_wins(self):
        self.assertEqual(failover.pick_client_exit(["awg1", "awg2"], ["awg1", "awg2"]), "awg1")

    def test_falls_to_second_when_first_down(self):
        self.assertEqual(failover.pick_client_exit(["awg1", "awg2"], {"awg2"}), "awg2")

    def test_order_beats_exit_priority(self):
        # The client put awg3 first, so it wins even if awg1 is also alive.
        self.assertEqual(failover.pick_client_exit(["awg3", "awg1"], {"awg1", "awg3"}), "awg3")

    def test_all_down_means_no_internet(self):
        self.assertIsNone(failover.pick_client_exit(["awg1", "awg2"], set()))

    def test_no_grants(self):
        self.assertIsNone(failover.pick_client_exit([], {"awg1"}))


class ClientTableTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute(
            "CREATE TABLE exits (id INTEGER PRIMARY KEY, "
            "table_num INTEGER NOT NULL DEFAULT 0, mode TEXT)"
        )
        self.conn.execute(
            "CREATE TABLE clients (id INTEGER PRIMARY KEY, "
            "table_num INTEGER NOT NULL DEFAULT 0)"
        )

    def test_pool_starts_above_the_system_tables(self):
        self.assertGreaterEqual(routing.allocate_table(self.conn),
                                routing.TABLE_POOL_BASE)

    def test_skips_numbers_used_by_exits_and_clients(self):
        self.conn.execute("INSERT INTO exits (table_num, mode) VALUES (1001, 'routes')")
        self.conn.execute("INSERT INTO clients (table_num) VALUES (1002)")
        self.assertEqual(routing.allocate_table(self.conn), 1003)

    def test_reuses_freed_numbers(self):
        self.assertEqual(routing.allocate_table(self.conn), 1001)
        self.assertEqual(routing.allocate_table(self.conn), 1001)

    def test_never_returns_a_reserved_table(self):
        number = routing.allocate_table(self.conn)
        self.assertNotIn(number, routing.RESERVED_TABLES)


class ParseTests(unittest.TestCase):
    def test_rules_keeps_only_ours(self):
        output = (
            "0:\tfrom all lookup local\n"
            "10000:\tfrom 10.80.0.3 to 10.90.0.2 iif awg0 lookup 1001\n"
            "19000:\tfrom 10.80.0.2 iif awg0 lookup 1002\n"
            "20000:\tfrom 10.80.0.2 iif awg0 lookup 100\n"
            "32766:\tfrom all lookup main\n"
            "5000:\tfrom 10.80.0.9 iif eth0 lookup 1001\n"
        )
        rules = routing.parse_rules(output, 100)
        self.assertEqual(rules, {
            (10000, ("from", "10.80.0.3", "to", "10.90.0.2", "iif", "awg0", "lookup", "1001")),
            (19000, ("from", "10.80.0.2", "iif", "awg0", "lookup", "1002")),
            (20000, ("from", "10.80.0.2", "iif", "awg0", "lookup", "100")),
        })

    def test_rules_never_match_reserved_tables(self):
        output = "30000:\tfrom 10.80.0.2 iif awg0 lookup 254\n"
        self.assertEqual(routing.parse_rules(output, 100), set())

    def test_routes_parses_prefix_and_dev(self):
        output = "default dev awg3 scope link\n10.90.0.2 dev awg2 scope link\n"
        self.assertEqual(
            routing.parse_routes(output),
            {("default", "awg3"), ("10.90.0.2", "awg2")},
        )

    def test_host_prefixes_match_the_kernel_form(self):
        # The database stores 10.90.0.2/32, the kernel prints 10.90.0.2.
        self.assertEqual(routing._norm_prefix("10.90.0.2/32"), "10.90.0.2")
        self.assertEqual(routing._norm_prefix("10.90.0.2"), "10.90.0.2")
        self.assertEqual(routing._norm_prefix("10.90.0.5/30"), "10.90.0.4/30")
        self.assertEqual(routing._norm_prefix("default"), "default")

    def test_rules_normalize_the_to_prefix(self):
        output = "10000:\tfrom 10.80.0.3 to 10.90.0.2 iif awg0 lookup 1001\n"
        rules = routing.parse_rules(output, 100)
        desired = {(10000, ("from", "10.80.0.3", "to", routing._norm_prefix("10.90.0.2/32"),
                            "iif", "awg0", "lookup", "1001"))}
        self.assertEqual(rules, desired)


class PlanChangesTests(unittest.TestCase):
    def rule(self, prio, *spec):
        return (prio, tuple(spec))

    def test_empty_to_full_is_all_adds(self):
        desired = {self.rule(19000, "from", "10.80.0.2", "iif", "awg0", "lookup", "1002")}
        plan = routing.plan_changes(set(), desired, {}, {1002: {("default", "awg3")}}, set())
        self.assertEqual(plan["rules_del"], [])
        self.assertEqual(plan["rules_add"], sorted(desired))
        self.assertEqual(plan["routes_add"], [(1002, "default", "awg3")])
        self.assertEqual(plan["tables_flush"], [])

    def test_identical_state_is_a_noop(self):
        rules = {self.rule(19000, "from", "10.80.0.2", "iif", "awg0", "lookup", "1002")}
        routes = {1002: {("default", "awg3")}}
        plan = routing.plan_changes(rules, rules, routes, routes, {1002})
        self.assertEqual(plan["rules_del"], [])
        self.assertEqual(plan["rules_add"], [])
        self.assertEqual(plan["routes_del"], [])
        self.assertEqual(plan["routes_add"], [])
        self.assertEqual(plan["tables_flush"], [])

    def test_priority_change_is_del_plus_add(self):
        old = {self.rule(19000, "from", "10.80.0.2", "iif", "awg0", "lookup", "1002")}
        new = {self.rule(20000, "from", "10.80.0.2", "iif", "awg0", "lookup", "100")}
        plan = routing.plan_changes(old, new, {}, {}, set())
        self.assertEqual(plan["rules_del"], sorted(old))
        self.assertEqual(plan["rules_add"], sorted(new))

    def test_used_table_is_not_flushed_but_pruned(self):
        existing = {1002: {("default", "awg3"), ("10.9.9.0/24", "awg3")}}
        desired = {1002: {("default", "awg3")}}
        plan = routing.plan_changes(set(), set(), existing, desired, {1002})
        self.assertEqual(plan["tables_flush"], [])
        self.assertEqual(plan["routes_del"], [(1002, "10.9.9.0/24", "awg3")])
        self.assertEqual(plan["routes_add"], [])

    def test_orphan_table_is_flushed(self):
        plan = routing.plan_changes(set(), set(), {}, {1002: {("default", "awg3")}}, {1001, 1002})
        self.assertEqual(plan["tables_flush"], [1001])

    def test_reserved_and_low_tables_are_never_flushed(self):
        plan = routing.plan_changes(set(), set(), {}, {}, {254, 255, 1000, 100})
        self.assertEqual(plan["tables_flush"], [])


class FailoverStatusTests(unittest.TestCase):
    def test_failed_replace_is_not_reported(self):
        failed = subprocess.CompletedProcess(args=[], returncode=2, stdout="", stderr="boom")
        with mock.patch.object(failover, "run", return_value=failed), \
             mock.patch.object(failover, "current_default", return_value=None):
            used = failover.apply_client_routes({(1001, "10.80.0.2"): ["awg1"]}, {"awg1"})
        self.assertEqual(used, {})

    def test_confirmed_route_is_reported(self):
        ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with mock.patch.object(failover, "run", return_value=ok), \
             mock.patch.object(failover, "current_default", return_value="awg1"):
            used = failover.apply_client_routes({(1001, "10.80.0.2"): ["awg1"]}, {"awg1"})
        self.assertEqual(used, {"10.80.0.2": "awg1"})

    def test_no_table_is_skipped(self):
        used = failover.apply_client_routes({(0, "10.80.0.2"): ["awg1"]}, {"awg1"})
        self.assertEqual(used, {})


class SyncRoutingTests(unittest.TestCase):
    def setUp(self):
        failover.known_ifaces = None
        failover.routing_pending = False
        failover.routing_retry_at = 0.0
        failover.routing_backoff = 10
        failover.routing_last_error = ""

    def tearDown(self):
        failover.known_ifaces = None
        failover.routing_pending = False
        failover.routing_retry_at = 0.0
        failover.routing_backoff = 10
        failover.routing_last_error = ""

    def sync(self, ifaces, apply=None):
        apply = apply or mock.Mock(return_value={"errors": [], "tables": []})
        with mock.patch.object(failover, "awg_ifaces", return_value=set(ifaces)), \
             mock.patch.object(failover.routing, "apply", apply), \
             mock.patch.object(failover.time, "sleep"):
            failover.sync_routing({"route_table": 100})
        return apply

    def test_first_sync_applies_routing(self):
        apply = self.sync({"awg0", "awg1"})
        apply.assert_called_once()
        self.assertFalse(failover.routing_pending)
        self.assertEqual(failover.known_ifaces, {"awg0", "awg1"})

    def test_unchanged_interfaces_do_not_apply(self):
        self.sync({"awg0"})
        apply = self.sync({"awg0"})
        apply.assert_not_called()

    def test_appeared_exit_triggers_apply(self):
        self.sync({"awg0"})
        apply = self.sync({"awg0", "awg2"})
        apply.assert_called_once()

    def test_vanished_exit_triggers_apply(self):
        self.sync({"awg0", "awg2"})
        apply = self.sync({"awg0"})
        apply.assert_called_once()

    def test_failed_apply_is_retried_until_clean(self):
        self.sync({"awg0"})
        failing = mock.Mock(return_value={"errors": ["boom"], "tables": []})
        self.sync({"awg0", "awg2"}, failing)
        self.assertTrue(failover.routing_pending)
        self.assertGreater(failover.routing_backoff, 10)
        # Within the backoff window the daemon does not hammer the kernel.
        skipped = self.sync({"awg0", "awg2"})
        skipped.assert_not_called()
        # After the window it retries and, on success, clears the state.
        failover.routing_retry_at = 0.0
        apply = self.sync({"awg0", "awg2"})
        apply.assert_called_once()
        self.assertFalse(failover.routing_pending)
        self.assertEqual(failover.routing_backoff, 10)


class ActiveMarkerTests(unittest.TestCase):
    def test_stale_active_is_cleared(self):
        self.assertTrue(failover.should_clear_active(None, "awg1"))
        self.assertFalse(failover.should_clear_active(None, None))
        self.assertFalse(failover.should_clear_active(None, "none"))
        self.assertFalse(failover.should_clear_active("awg1", "awg1"))

    def test_none_marker_reads_as_no_active_exit(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "active-exit"
            old = failover.ACTIVE_FILE
            failover.ACTIVE_FILE = path
            try:
                self.assertIsNone(failover.read_active())
                path.write_text("none\n")
                self.assertIsNone(failover.read_active())
                path.write_text("awg2\n")
                self.assertEqual(failover.read_active(), "awg2")
            finally:
                failover.ACTIVE_FILE = old


class PasswordTests(unittest.TestCase):
    def test_round_trip(self):
        stored = auth.hash_password("correct horse battery")
        self.assertTrue(auth.check_password("correct horse battery", stored))
        self.assertFalse(auth.check_password("wrong password", stored))

    def test_salt_is_unique(self):
        one = auth.hash_password("same password")
        two = auth.hash_password("same password")
        self.assertNotEqual(one, two)
        self.assertTrue(auth.check_password("same password", one))
        self.assertTrue(auth.check_password("same password", two))

    def test_malformed_hash_fails_closed(self):
        for value in ("", "plain", "pbkdf2$abc$xx$yy", "md5$1$a$b"):
            self.assertFalse(auth.check_password("secret", value))

    def test_admin_hash_format_is_accepted(self):
        # panel.env uses the same pbkdf2$iterations$salt$hash layout.
        import base64
        import hashlib
        salt = b"0123456789abcdef"
        digest = hashlib.pbkdf2_hmac("sha256", b"adminpass", salt, 1000)
        stored = "pbkdf2$1000$%s$%s" % (
            base64.b64encode(salt).decode(), base64.b64encode(digest).decode()
        )
        self.assertTrue(auth.check_password("adminpass", stored))


class EmailTests(unittest.TestCase):
    def test_normalizes_case_and_spaces(self):
        self.assertEqual(auth.normalize_email("  User@Example.COM "), "user@example.com")

    def test_accepts_valid(self):
        self.assertIsNone(auth.email_error("user@example.com"))
        self.assertIsNone(auth.email_error("a.b+tag@mail.example.co.uk"))

    def test_rejects_invalid(self):
        for value in ("", "user", "user@", "@example.com", "user@example", "a b@example.com"):
            self.assertIsNotNone(auth.email_error(value))

    def test_password_policy(self):
        self.assertIsNotNone(auth.password_error("short"))
        self.assertIsNone(auth.password_error("twelve chars"))


class SessionTests(unittest.TestCase):
    secret = "test-session-secret"

    def test_admin_round_trip(self):
        token = auth.make_session(self.secret, "admin")
        data = auth.session_data(self.secret, token)
        self.assertEqual(data["role"], "admin")
        self.assertEqual(data["uid"], 0)

    def test_user_round_trip_keeps_version(self):
        token = auth.make_session(self.secret, "user", uid=7, tv=3)
        data = auth.session_data(self.secret, token)
        self.assertEqual((data["role"], data["uid"], data["tv"]), ("user", 7, 3))

    def test_forged_role_is_rejected(self):
        token = auth.make_session(self.secret, "root")
        self.assertIsNone(auth.session_data(self.secret, token))

    def test_other_secret_is_rejected(self):
        token = auth.make_session(self.secret, "admin")
        self.assertIsNone(auth.session_data("another-secret", token))

    def test_jti_is_present_and_unique(self):
        one = auth.session_data(self.secret, auth.make_session(self.secret, "admin"))
        two = auth.session_data(self.secret, auth.make_session(self.secret, "admin"))
        self.assertTrue(one["jti"])
        self.assertNotEqual(one["jti"], two["jti"])

    def test_expired_is_rejected(self):
        token = auth.make_session(self.secret, "admin", ttl=-1)
        self.assertIsNone(auth.session_data(self.secret, token))

    def test_garbage_is_rejected(self):
        for token in ("", "abc", "abc.def", None):
            self.assertIsNone(auth.session_data(self.secret, token))


if __name__ == "__main__":
    unittest.main()
