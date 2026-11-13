"""Logic tests for the failover decision and routing table cleanup.

Run with: python3 -m unittest discover -s tests
"""
import json
import sqlite3
import subprocess
import sys
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


class ProbeTests(unittest.TestCase):
    def test_ping_rtt_is_parsed(self):
        line = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms"
        self.assertEqual(failover.ping_rtt(line), 12.3)
        self.assertIsNone(failover.ping_rtt("Request timeout for icmp_seq 0"))
        self.assertIsNone(failover.ping_rtt(""))

    def test_internet_probe_returns_the_latency(self):
        answered = subprocess.CompletedProcess([], 0, "time=7.9 ms", "")
        with mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "run", return_value=answered):
            self.assertEqual(failover.probe({"iface": "awg1", "mode": "internet"}),
                             (True, 7.9))

    def test_failed_probe_has_no_latency(self):
        failed = subprocess.CompletedProcess([], 1, "", "timeout")
        with mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "run", return_value=failed):
            self.assertEqual(failover.probe({"iface": "awg1", "mode": "internet"}),
                             (False, None))

    def test_routed_probe_has_no_icmp_latency(self):
        handshake = subprocess.CompletedProcess(
            [], 0, f"peerkey {int(time.time())}\n", "")
        with mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "run", return_value=handshake):
            self.assertEqual(failover.probe({"iface": "awg2", "mode": "routes"}),
                             (True, None))

    def test_missing_interface_has_no_latency(self):
        with mock.patch.object(failover, "iface_exists", return_value=False):
            self.assertEqual(failover.probe({"iface": "awg9", "mode": "internet"}),
                             (False, None))

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


class ClientPingTests(unittest.TestCase):
    def setUp(self):
        failover.client_rtt.clear()

    def tearDown(self):
        failover.client_rtt.clear()

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
             mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "probe_client",
                               side_effect=lambda ip: values[ip]):
            self.assertEqual(failover.client_pings(),
                             {"10.80.0.2": 8, "10.80.0.3": None})

    def test_no_clients_means_no_pings(self):
        with mock.patch.object(failover, "client_rows", return_value=[]):
            self.assertEqual(failover.client_pings(), {})

    def test_a_recent_value_survives_a_missed_probe(self):
        failover.client_rtt.clear()
        with mock.patch.object(failover, "client_rows",
                               return_value=[{"ip": "10.80.0.2"}]), \
             mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "probe_client", return_value=7.6):
            self.assertEqual(failover.client_pings(), {"10.80.0.2": 8})
        with mock.patch.object(failover, "client_rows",
                               return_value=[{"ip": "10.80.0.2"}]), \
             mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "probe_client", return_value=None):
            self.assertEqual(failover.client_pings(), {"10.80.0.2": 8})

    def test_an_old_value_expires(self):
        failover.client_rtt.clear()
        failover.client_rtt["10.80.0.2"] = (8, int(time.time()) - 31)
        with mock.patch.object(failover, "client_rows",
                               return_value=[{"ip": "10.80.0.2"}]), \
             mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "probe_client", return_value=None):
            self.assertEqual(failover.client_pings(), {"10.80.0.2": None})

    def test_removed_clients_are_dropped_from_the_cache(self):
        failover.client_rtt.clear()
        failover.client_rtt["10.80.0.9"] = (8, int(time.time()))
        with mock.patch.object(failover, "client_rows",
                               return_value=[{"ip": "10.80.0.2"}]), \
             mock.patch.object(failover, "iface_exists", return_value=True), \
             mock.patch.object(failover, "probe_client", return_value=5.0):
            self.assertEqual(failover.client_pings(), {"10.80.0.2": 5})
        self.assertNotIn("10.80.0.9", failover.client_rtt)


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


if __name__ == "__main__":
    unittest.main()
