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
from unittest import mock

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
    def test_failed_apply_restores_the_previous_file(self):
        c = self.config()
        path = Path(self.tmp.name) / "awg0.conf"
        path.write_text("previous\n")
        failed = subprocess.CompletedProcess(args=[], returncode=1,
                                             stdout="", stderr="boom")
        with mock.patch.object(app, "iface_up", return_value=True), \
             mock.patch.object(app, "run", return_value=failed):
            with self.assertRaises(RuntimeError):
                app.apply_conf(c)
        self.assertEqual(path.read_text(), "previous\n")

    @unittest.skipUnless(app, "fastapi is not installed")
    def test_verify_failure_rolls_the_device_back(self):
        c = self.config()
        previous = "[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = oldkey\n"
        path = Path(self.tmp.name) / "awg0.conf"
        path.write_text(previous)
        ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        # First read is the post-apply verification (new state), the second
        # one checks the rollback (back to the previous file).
        peers = mock.Mock(side_effect=[{"newkey"}, {"oldkey"}])
        with mock.patch.object(app, "iface_up", return_value=True), \
             mock.patch.object(app, "run", return_value=ok) as run, \
             mock.patch.object(app, "applied_peers", peers):
            with self.assertRaises(RuntimeError) as ctx:
                app.apply_conf(c)
        self.assertIn("peers after apply", str(ctx.exception))
        self.assertEqual(path.read_text(), previous)
        syncconf_calls = [call for call in run.call_args_list
                          if call.args and call.args[0][:2] == ["bash", "-c"]]
        self.assertEqual(len(syncconf_calls), 2)

    @unittest.skipUnless(app, "fastapi is not installed")
    def test_failed_rollback_is_reported(self):
        c = self.config()
        path = Path(self.tmp.name) / "awg0.conf"
        path.write_text("[Peer]\nPublicKey = oldkey\n")
        ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        peers = mock.Mock(side_effect=[{"newkey"}, {"otherkey"}])
        with mock.patch.object(app, "iface_up", return_value=True), \
             mock.patch.object(app, "run", return_value=ok), \
             mock.patch.object(app, "applied_peers", peers):
            with self.assertRaises(RuntimeError) as ctx:
                app.apply_conf(c)
        self.assertIn("rollback failed", str(ctx.exception))

    @unittest.skipUnless(app, "fastapi is not installed")
    def test_interface_that_came_up_is_stopped_again(self):
        c = self.config()
        path = Path(self.tmp.name) / "awg0.conf"
        path.write_text("[Peer]\nPublicKey = oldkey\n")
        state = {"up": False}

        def fake_run(cmd, **kw):
            if cmd[:2] == ["systemctl", "start"]:
                state["up"] = True
            elif cmd[:2] == ["systemctl", "stop"]:
                state["up"] = False
            return subprocess.CompletedProcess(args=cmd, returncode=0,
                                               stdout="", stderr="")

        peers = mock.Mock(side_effect=[{"newkey"}, {"oldkey"}])
        with mock.patch.object(app, "iface_up", side_effect=lambda c: state["up"]), \
             mock.patch.object(app, "run", side_effect=fake_run) as run, \
             mock.patch.object(app, "applied_peers", peers):
            with self.assertRaises(RuntimeError):
                app.apply_conf(c)
        stops = [call for call in run.call_args_list
                 if call.args and call.args[0][:2] == ["systemctl", "stop"]]
        self.assertEqual(len(stops), 1)
        self.assertFalse(state["up"])

    @unittest.skipUnless(app, "fastapi is not installed")
    def test_missing_file_snapshots_the_running_device(self):
        c = self.config()
        path = Path(self.tmp.name) / "awg0.conf"
        self.assertFalse(path.exists())
        snapshot = "[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = oldkey\n"
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd[:2] == ["awg", "showconf"]:
                return subprocess.CompletedProcess(cmd, 0, snapshot, "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        peers = mock.Mock(side_effect=[{"newkey"}, {"oldkey"}])
        with mock.patch.object(app, "iface_up", return_value=True), \
             mock.patch.object(app, "run", side_effect=fake_run), \
             mock.patch.object(app, "applied_peers", peers):
            with self.assertRaises(RuntimeError):
                app.apply_conf(c)
        # The dump has no Address/MTU/Table, so it must not become awg0.conf.
        self.assertFalse(path.exists())
        self.assertFalse((Path(self.tmp.name) / "awg0-rollback.conf").exists())
        self.assertTrue(any(cmd[:2] == ["awg", "showconf"] for cmd in calls))
        syncs = [cmd for cmd in calls if cmd[:2] == ["bash", "-c"]]
        self.assertEqual(len(syncs), 2)
        self.assertTrue(any("rollback.conf" in cmd[2] for cmd in syncs))

    @unittest.skipUnless(app, "fastapi is not installed")
    def test_snapshot_failure_changes_nothing(self):
        c = self.config()
        path = Path(self.tmp.name) / "awg0.conf"

        def fake_run(cmd, **kw):
            if cmd[:2] == ["awg", "showconf"]:
                return subprocess.CompletedProcess(cmd, 1, "", "boom")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.object(app, "iface_up", return_value=True), \
             mock.patch.object(app, "run", side_effect=fake_run) as run:
            with self.assertRaises(RuntimeError) as ctx:
                app.apply_conf(c)
        self.assertIn("showconf", str(ctx.exception))
        self.assertFalse(path.exists())
        syncs = [call for call in run.call_args_list
                 if call.args[0][:2] == ["bash", "-c"]]
        self.assertEqual(syncs, [])

    def config(self):
        return {
            "address": "10.80.0.1", "net": "10.80.0.0/24", "port": 51820,
            "mtu": 1280, "params": {}, "awg_dir": self.tmp.name, "iface": "awg0",
        }

    @unittest.skipUnless(app, "fastapi is not installed")
    def test_renderer_does_not_filter_enabled(self):
        """The caller selects enabled clients; the renderer packs what it gets."""
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
