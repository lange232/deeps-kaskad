"""Unit tests for the SOCKS5 proxy helpers (no sockets are opened)."""
import ipaddress
import sqlite3
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))

import socks  # noqa: E402
import routing  # noqa: E402


class DestinationTests(unittest.TestCase):
    def test_public_and_private_networks_are_allowed(self):
        for raw in ("1.1.1.1", "93.184.216.34", "192.168.1.10", "172.16.0.5"):
            self.assertTrue(socks.destination_allowed(
                ipaddress.IPv4Address(raw), "10.80.0.0/24"), raw)

    def test_the_tunnel_and_service_ranges_are_refused(self):
        for raw in ("10.80.0.2", "10.80.0.1", "127.0.0.1",
                    "169.254.1.1", "224.0.0.1", "0.1.2.3", "255.255.255.255"):
            self.assertFalse(socks.destination_allowed(
                ipaddress.IPv4Address(raw), "10.80.0.0/24"), raw)


class ExitTests(unittest.TestCase):
    def test_a_fresh_status_gives_the_interface(self):
        status = {"ts": 1000, "clients": {"10.80.0.2": "awg1"}}
        self.assertEqual(socks.current_exit(status, "10.80.0.2", now=1030), "awg1")

    def test_a_stale_status_is_ignored(self):
        status = {"ts": 1000, "clients": {"10.80.0.2": "awg1"}}
        self.assertEqual(socks.current_exit(status, "10.80.0.2", now=2000), "")

    def test_an_unknown_address_has_no_exit(self):
        status = {"ts": 1000, "clients": {}}
        self.assertEqual(socks.current_exit(status, "10.80.0.9", now=1010), "")


class DnsTests(unittest.TestCase):
    def test_the_query_carries_the_name(self):
        txid, query = socks.build_dns_query("example.com", txid=0x1234)
        self.assertEqual(txid, 0x1234)
        self.assertIn(b"\x07example\x03com\x00", query)
        self.assertEqual(struct.unpack(">H", query[:2])[0], 0x1234)

    def test_the_first_a_record_is_read(self):
        txid = 0x1234
        header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
        question = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes((93, 184, 216, 34))
        self.assertEqual(socks.parse_dns_response(header + question + answer, txid),
                         "93.184.216.34")

    def test_a_mismatched_id_or_empty_answer_is_ignored(self):
        header = struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0)
        question = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        self.assertEqual(socks.parse_dns_response(header + question, 2), "")


class MarkRuleTests(unittest.TestCase):
    def test_the_rule_is_recognised(self):
        output = "18000:\tfrom all fwmark 0x4b03f1 lookup 1009\n"
        self.assertTrue(socks.mark_rule(output, 0x4b03F1))
        self.assertFalse(socks.mark_rule(output, 0x4B03F2))

    def test_other_rules_do_not_match(self):
        output = "19000:\tfrom 10.80.0.2 iif awg0 lookup 1009\n"
        self.assertFalse(socks.mark_rule(output, 0x4B03F1))


class MarkRulePresentTests(unittest.TestCase):
    def setUp(self):
        socks._MARK_CACHE.clear()

    def test_the_answer_is_cached_for_a_few_seconds(self):
        result = mock.Mock(
            returncode=0,
            stdout="18000:\tfrom all fwmark 0x4b03f1 lookup 1009\n",
        )
        with mock.patch.object(socks.subprocess, "run",
                               return_value=result) as run:
            self.assertTrue(socks.mark_rule_present(0x4B03F1, now=100.0))
            self.assertTrue(socks.mark_rule_present(0x4B03F1, now=102.0))
        self.assertEqual(run.call_count, 1)

    def test_a_missing_rule_is_false(self):
        result = mock.Mock(returncode=0, stdout="")
        with mock.patch.object(socks.subprocess, "run", return_value=result):
            self.assertFalse(socks.mark_rule_present(0x4B03F1, now=100.0))


class ReplyTests(unittest.TestCase):
    def test_a_success_reply(self):
        self.assertEqual(socks.socks_reply(socks.REPLY_OK),
                         b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_an_error_reply(self):
        self.assertEqual(socks.socks_reply(socks.REPLY_NOT_ALLOWED)[:2],
                         b"\x05\x02")


class ListenTests(unittest.TestCase):
    def test_the_configured_address_is_used(self):
        c = {"address": "10.80.0.1", "socks": {"host": "10.80.0.5", "port": 9050}}
        self.assertEqual(socks.listen_address(c), ("10.80.0.5", 9050))

    def test_defaults_when_the_section_is_missing(self):
        self.assertEqual(socks.listen_address({"address": "10.80.0.1"}),
                         ("10.80.0.1", 1080))


class ClientTests(unittest.TestCase):
    def test_only_enabled_configurations_with_the_proxy_on_get_a_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "db.sqlite")
            conn.execute(
                "CREATE TABLE clients (ip TEXT, enabled INTEGER, socks INTEGER, "
                "table_num INTEGER)")
            conn.executemany(
                "INSERT INTO clients VALUES (?, ?, ?, ?)",
                [("10.80.0.2", 1, 1, 1001), ("10.80.0.3", 1, 0, 1002),
                 ("10.80.0.4", 0, 1, 1003), ("10.80.0.5", 1, 1, 0)],
            )
            self.assertEqual(socks.client_table(conn, "10.80.0.2"), 1001)
            self.assertEqual(socks.client_table(conn, "10.80.0.3"), 0)
            self.assertEqual(socks.client_table(conn, "10.80.0.4"), 0)
            self.assertEqual(socks.client_table(conn, "10.80.0.5"), 0)
            self.assertEqual(socks.client_table(conn, "10.80.0.9"), 0)
            conn.close()

    def test_the_mark_follows_the_table(self):
        self.assertEqual(socks.mark_for(1001),
                         routing.SOCKS_MARK_BASE + 1001)


if __name__ == "__main__":
    unittest.main()
