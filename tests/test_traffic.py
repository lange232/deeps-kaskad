"""Tests for the traffic history sampler.

    /tmp/opencode/venv/bin/python -m unittest discover -s tests
"""
import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))

try:
    import traffic
except ImportError:  # pragma: no cover - local python without fastapi
    traffic = None

SCHEMA = """
CREATE TABLE clients (id INTEGER PRIMARY KEY, public_key TEXT NOT NULL);
CREATE TABLE traffic (
    client_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    step INTEGER NOT NULL,
    rx INTEGER NOT NULL,
    tx INTEGER NOT NULL,
    PRIMARY KEY (client_id, ts, step)
);
CREATE TABLE traffic_state (
    client_id INTEGER PRIMARY KEY,
    public_key TEXT NOT NULL,
    rx INTEGER NOT NULL,
    tx INTEGER NOT NULL,
    ts INTEGER NOT NULL
);
"""


@unittest.skipUnless(traffic, "traffic module is unavailable")
class SampleTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.execute("INSERT INTO clients (id, public_key) VALUES (5, 'pub5')")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def peers(self, rx, tx, key="pub5"):
        return {key: {"rx": rx, "tx": tx}}

    def rows(self, step):
        return [tuple(r) for r in self.conn.execute(
            "SELECT ts, rx, tx FROM traffic WHERE step = ? ORDER BY ts", (step,))]

    def state(self):
        return self.conn.execute("SELECT * FROM traffic_state").fetchone()

    def test_the_first_sample_is_only_a_baseline(self):
        traffic.sample(self.conn, self.peers(1000, 2000), now=1794800100)
        self.assertEqual(self.rows(traffic.STEP), [])
        self.assertEqual(self.rows(traffic.HOUR), [])
        state = self.state()
        self.assertEqual((state["rx"], state["tx"]), (1000, 2000))

    def test_deltas_land_in_both_resolutions(self):
        now = 1794800100
        traffic.sample(self.conn, self.peers(1000, 2000), now=now)
        traffic.sample(self.conn, self.peers(1500, 2600), now=now + 300)
        bucket = (now + 300) - (now + 300) % traffic.STEP
        hour = (now + 300) - (now + 300) % traffic.HOUR
        self.assertEqual(self.rows(traffic.STEP), [(bucket, 500, 600)])
        self.assertEqual(self.rows(traffic.HOUR), [(hour, 500, 600)])

    def test_one_bucket_accumulates_its_samples(self):
        now = 1794800100
        traffic.sample(self.conn, self.peers(100, 100), now=now)
        traffic.sample(self.conn, self.peers(200, 350), now=now + 60)
        traffic.sample(self.conn, self.peers(300, 500), now=now + 120)
        bucket = now - now % traffic.STEP
        self.assertEqual(self.rows(traffic.STEP), [(bucket, 200, 400)])

    def test_counters_that_went_backwards_are_a_fresh_start(self):
        now = 1794800100
        traffic.sample(self.conn, self.peers(5000, 9000), now=now)
        # A reboot resets both counters; what the peer reports now happened
        # after the reset.
        traffic.sample(self.conn, self.peers(200, 300), now=now + 300)
        self.assertEqual(
            [(rx, tx) for _, rx, tx in self.rows(traffic.STEP)], [(200, 300)]
        )

    def test_a_reissued_peer_starts_a_new_baseline(self):
        now = 1794800100
        traffic.sample(self.conn, self.peers(1000, 2000), now=now)
        self.conn.execute("UPDATE clients SET public_key = 'pub-new' WHERE id = 5")
        traffic.sample(self.conn, self.peers(10, 20, key="pub-new"), now=now + 300)
        self.assertEqual(self.rows(traffic.STEP), [])
        state = self.state()
        self.assertEqual(state["public_key"], "pub-new")
        self.assertEqual((state["rx"], state["tx"]), (10, 20))

    def test_a_peer_that_is_not_in_the_dump_is_skipped(self):
        traffic.sample(self.conn, {}, now=1794800100)
        self.assertEqual(self.rows(traffic.STEP), [])
        self.assertIsNone(self.state())

    def test_an_idle_reading_is_distinct_from_an_absent_peer(self):
        now = 1794800100
        traffic.sample(self.conn, self.peers(1000, 2000), now=now)
        traffic.sample(self.conn, self.peers(1000, 2000), now=now + 300)
        traffic.sample(self.conn, {}, now=now + 600)
        bucket = now + 300 - (now + 300) % traffic.STEP
        self.assertEqual(self.rows(traffic.STEP), [(bucket, 0, 0)])

    def test_prune_drops_old_points_and_orphans(self):
        now = 1794800100
        old_raw = now - traffic.RAW_TTL - 300
        old_hour = now - traffic.HOUR_TTL - 3600
        with self.conn:
            self.conn.executemany(
                "INSERT INTO traffic (client_id, ts, step, rx, tx) VALUES (?, ?, ?, 1, 1)",
                [
                    (5, now, traffic.STEP),
                    (5, old_raw, traffic.STEP),
                    (5, now, traffic.HOUR),
                    (5, old_hour, traffic.HOUR),
                    (99, now, traffic.STEP),
                ],
            )
            self.conn.execute(
                "INSERT INTO traffic_state VALUES (99, 'gone', 1, 1, ?)", (now,)
            )
        traffic.prune(self.conn, now)
        self.assertEqual(
            [tuple(r) for r in self.conn.execute(
                "SELECT client_id, ts, step FROM traffic ORDER BY step")],
            [(5, now, traffic.STEP), (5, now, traffic.HOUR)],
        )
        self.assertIsNone(
            self.conn.execute(
                "SELECT * FROM traffic_state WHERE client_id = 99"
            ).fetchone()
        )


@unittest.skipUnless(traffic, "traffic module is unavailable")
class SchemaTests(unittest.TestCase):
    def test_the_sampler_creates_its_own_tables(self):
        # The timer may fire while the panel is restarting; it cannot depend
        # on the panel having created the tables first.
        conn = sqlite3.connect(":memory:")
        try:
            traffic.ensure_schema(conn)
            names = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'")}
        finally:
            conn.close()
        self.assertIn("traffic", names)
        self.assertIn("traffic_state", names)


@unittest.skipUnless(traffic, "traffic module is unavailable")
class DumpTests(unittest.TestCase):
    def test_peer_counters_are_read_from_the_dump(self):
        output = "\n".join([
            "priv\tpub\t51820\toff",
            "peer1key\tpsk\t1.2.3.4:5\t10.80.0.2/32\t0\t1024\t2048\toff",
            "peer2key\tpsk\t(none)\t10.80.0.3/32\t0\t0\t0\toff",
        ]) + "\n"

        class Result:
            returncode = 0
            stdout = output
            stderr = ""

        original = traffic.subprocess.run
        traffic.subprocess.run = lambda *a, **kw: Result()
        try:
            peers = traffic.dump_peers("awg0")
        finally:
            traffic.subprocess.run = original
        self.assertEqual(peers["peer1key"], {"rx": 1024, "tx": 2048})
        self.assertEqual(peers["peer2key"], {"rx": 0, "tx": 0})


if __name__ == "__main__":
    unittest.main()
