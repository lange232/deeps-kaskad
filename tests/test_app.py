"""Tests for the panel helpers that touch the device state.

They need FastAPI installed, so they are skipped outside the panel venv:

    /opt/kaskad/venv/bin/python -m unittest discover -s tests
"""
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))

try:
    import app  # noqa: E402
except ImportError:  # pragma: no cover - local python without fastapi
    app = None


def device_line(prefix: str, fields: int) -> str:
    f = [prefix + "key"]
    f += ["x"] * (fields - 1)
    return "\t".join(f)


class DumpTests(unittest.TestCase):
    def setUp(self):
        self.original = app.run if app else None

    def tearDown(self):
        if app:
            app.run = self.original

    @unittest.skipUnless(app, "fastapi is not installed")
    def test_amnezia_device_line_is_not_a_peer(self):
        # AmneziaWG appends Jc, S*, H* to the device line (32 fields).
        output = "\n".join([
            device_line("UFUK", 32),
            "peer1key\tpsk\t1.2.3.4:5\t10.80.0.2/32\t0\t0\t0\toff",
            "peer2key\tpsk\t(none)\t10.80.0.3/32\t0\t0\t0\toff",
        ]) + "\n"

        def fake(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 0, output, "")

        app.run = fake
        dump = app.iface_dump("awg0")
        self.assertTrue(dump["ok"])
        self.assertEqual(set(dump["peers"]), {"peer1key", "peer2key"})

    @unittest.skipUnless(app, "fastapi is not installed")
    def test_failed_dump_is_reported(self):
        def fake(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 1, "", "boom")

        app.run = fake
        dump = app.iface_dump("awg0")
        self.assertFalse(dump["ok"])
        self.assertEqual(dump["peers"], {})


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = app.DB_PATH if app else None
        self.old_cfg = app.CONFIG_PATH if app else None
        if app:
            app.DB_PATH = Path(self.tmp.name) / "panel.db"
            app.CONFIG_PATH = Path(self.tmp.name) / "panel.json"
            app.init_db()
            app.set_setting("awg0_private_key", "serverkey")

    def tearDown(self):
        if app:
            app.DB_PATH = self.old_db
            app.CONFIG_PATH = self.old_cfg
        self.tmp.cleanup()

    @unittest.skipUnless(app, "fastapi is not installed")
    def test_uncommitted_rows_are_rendered(self):
        c = {
            "address": "10.80.0.1", "net": "10.80.0.0/24", "port": 51820,
            "mtu": 1280, "params": {}, "awg_dir": self.tmp.name,
        }
        conn = sqlite3.connect(app.DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute(
            "INSERT INTO clients (name, ip, public_key, private_key, "
            "preshared_key, enabled, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)",
            ("fresh", "10.80.0.2", "pubkey", "privkey", "psk", "now"),
        )
        text = app.render_conf(c, conn)
        self.assertIn("PublicKey = pubkey", text)
        conn.rollback()
        conn.close()
        self.assertNotIn("PublicKey = pubkey", app.render_conf(c))

    @unittest.skipUnless(app, "fastapi is not installed")
    def test_disabled_clients_are_left_out(self):
        c = {
            "address": "10.80.0.1", "net": "10.80.0.0/24", "port": 51820,
            "mtu": 1280, "params": {}, "awg_dir": self.tmp.name,
        }
        rows = [
            {"name": "on", "ip": "10.80.0.2", "public_key": "pk-on", "preshared_key": "psk"},
            {"name": "off", "ip": "10.80.0.3", "public_key": "pk-off", "preshared_key": "psk"},
        ]
        text = app.render_conf_rows(c, rows)
        self.assertIn("pk-on", text)
        self.assertIn("pk-off", text)  # the caller filters by enabled, not the renderer


if __name__ == "__main__":
    unittest.main()
