"""Logic tests for the failover decision and routing table cleanup.

Run with: python3 -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path

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
    def test_table_range_is_above_routed(self):
        self.assertEqual(routing.client_table(7), 3007)
        self.assertGreater(routing.CLIENT_TABLE_BASE, routing.ROUTED_TABLE_BASE)

    def test_client_tables_are_cleaned(self):
        self.assertIn(3004, routing.tables_to_flush({3004}, set()))
        self.assertEqual(routing.tables_to_flush({3004}, set()), [3004])

    def test_client_tables_never_reserved(self):
        self.assertEqual(routing.tables_to_flush({254, 255, 3001}, {3001}), [3001])


class TablesTests(unittest.TestCase):
    def test_unions_current_and_previous(self):
        self.assertEqual(routing.tables_to_flush({1005}, {1001, 1065}), [1001, 1005, 1065])

    def test_never_touches_reserved_or_low_tables(self):
        self.assertEqual(routing.tables_to_flush({254, 1001}, {255, 1000}), [1001])

    def test_high_ids_are_cleaned(self):
        self.assertEqual(routing.tables_to_flush({1200}, set()), [1200])


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

    def test_expired_is_rejected(self):
        token = auth.make_session(self.secret, "admin", ttl=-1)
        self.assertIsNone(auth.session_data(self.secret, token))

    def test_garbage_is_rejected(self):
        for token in ("", "abc", "abc.def", None):
            self.assertIsNone(auth.session_data(self.secret, token))


if __name__ == "__main__":
    unittest.main()
