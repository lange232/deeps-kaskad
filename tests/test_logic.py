"""Logic tests for the failover decision and routing table cleanup.

Run with: python3 -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))

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


class TablesTests(unittest.TestCase):
    def test_unions_current_and_previous(self):
        self.assertEqual(routing.tables_to_flush({1005}, {1001, 1065}), [1001, 1005, 1065])

    def test_never_touches_reserved_or_low_tables(self):
        self.assertEqual(routing.tables_to_flush({254, 1001}, {255, 1000}), [1001])

    def test_high_ids_are_cleaned(self):
        self.assertEqual(routing.tables_to_flush({1200}, set()), [1200])


if __name__ == "__main__":
    unittest.main()
