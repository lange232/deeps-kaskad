"""Tests for the route preset catalogue: parsers, validation and storage."""
import json
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))

import presets  # noqa: E402


class CidrTextTests(unittest.TestCase):
    def test_parses_lines_and_skips_noise(self):
        text = (
            "# Telegram ranges\n"
            "\n"
            "91.108.4.0/22\n"
            "2001:db8::/32\n"
            "not-a-cidr\n"
            "104.16.0.0/13  # comment\n"
        )
        self.assertEqual(presets.parse_cidr_text(text),
                         ["91.108.4.0/22", "104.16.0.0/13"])

    def test_commas_are_accepted_too(self):
        self.assertEqual(presets.parse_cidr_text("91.108.4.0/22, 104.16.0.0/13"),
                         ["91.108.4.0/22", "104.16.0.0/13"])

    def test_two_halves_collapse_into_one_network(self):
        self.assertEqual(presets.parse_cidr_text("10.0.0.0/25\n10.0.0.128/25\n"),
                         ["10.0.0.0/24"])

    def test_the_default_route_is_ignored(self):
        self.assertEqual(presets.parse_cidr_text("0.0.0.0/0\n"), [])


class RipePrefixTests(unittest.TestCase):
    def test_ipv4_prefixes_are_extracted(self):
        payload = {"data": {"prefixes": [
            {"prefix": "160.79.104.0/23"},
            {"prefix": "2607:6bc0::/48"},
            {"prefix": "broken"},
        ]}}
        self.assertEqual(presets.parse_ripe_prefixes(payload),
                         ["160.79.104.0/23"])

    def test_a_missing_data_section_is_empty(self):
        self.assertEqual(presets.parse_ripe_prefixes({}), [])


class ValidateTests(unittest.TestCase):
    def test_a_clean_list_has_no_errors(self):
        self.assertEqual(presets.validate_cidrs(["91.108.4.0/22"]), [])

    def test_an_empty_list_is_an_error(self):
        self.assertTrue(presets.validate_cidrs([]))

    def test_the_default_route_is_refused(self):
        errors = presets.validate_cidrs(["0.0.0.0/0"])
        self.assertTrue(any("default route" in e for e in errors))

    def test_duplicates_are_refused(self):
        errors = presets.validate_cidrs(["91.108.4.0/22", "91.108.4.0/22"])
        self.assertTrue(any("duplicate" in e for e in errors))

    def test_invalid_entries_are_refused(self):
        self.assertTrue(any("invalid" in e
                            for e in presets.validate_cidrs(["oops"])))


class SourceTests(unittest.TestCase):
    def test_a_manual_source_needs_nothing(self):
        self.assertIsNone(presets.validate_source("", ""))

    def test_a_url_must_be_https(self):
        self.assertIsNotNone(presets.validate_source("cidr-text", "http://x"))
        self.assertIsNone(presets.validate_source("cidr-text", "https://x/y"))

    def test_an_asn_must_be_a_number(self):
        self.assertIsNotNone(presets.validate_source("ripe-asn", "AS399358"))
        self.assertIsNone(presets.validate_source("ripe-asn", "399358"))

    def test_unknown_kind_is_refused(self):
        self.assertIsNotNone(presets.validate_source("magic", "x"))


class SlugTests(unittest.TestCase):
    def test_slugification(self):
        self.assertEqual(presets.slugify("My Services!"), "my-services")
        self.assertEqual(presets.slugify("Привет"), "custom")

    def test_duplicates_get_a_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "db.sqlite")
            presets.ensure_schema(conn)
            presets.ensure_schema(conn)  # seeding twice changes nothing
            self.assertEqual(len(presets.rows(conn)), 3)
            slug = presets.unique_slug(conn, "telegram")
            self.assertEqual(slug, "telegram-2")
            conn.close()


class EtagTests(unittest.TestCase):
    def test_matching_forms(self):
        tag = "abc123"
        for header in (tag, f'"{tag}"', f'W/"{tag}"', f'"x", "{tag}"', "*"):
            self.assertTrue(presets.etag_matches(header, tag), header)

    def test_misses(self):
        for header in (None, "", '"other"', f'W/"other"'):
            self.assertFalse(presets.etag_matches(header, "abc123"), header)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(Path(self.tmp.name) / "db.sqlite")
        presets.ensure_schema(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def fetch(self, url):
        if "telegram" in url:
            return "91.108.4.0/22\n149.154.160.0/20\n"
        if "cloudflare" in url:
            return "104.16.0.0/13\n"
        if "stat.ripe.net" in url:
            return json.dumps({"data": {"prefixes": [
                {"prefix": "160.79.104.0/23"}]}})
        raise AssertionError(url)

    def test_builtins_are_seeded_once(self):
        slugs = [p["slug"] for p in presets.rows(self.conn)]
        self.assertEqual(slugs, ["telegram", "claude", "cloudflare"])
        presets.ensure_schema(self.conn)
        self.assertEqual(len(presets.rows(self.conn)), 3)

    def test_refresh_fills_sourced_presets(self):
        updated, failed, errors = presets.refresh(self.conn, self.fetch)
        self.assertEqual((updated, failed, errors), (3, 0, []))
        by_slug = {p["slug"]: p for p in presets.rows(self.conn)}
        self.assertEqual(presets.cidr_list(by_slug["claude"]["cidrs"]),
                         ["160.79.104.0/23"])
        self.assertGreater(by_slug["telegram"]["fetched_at"], 0)

    def test_a_failed_source_keeps_the_previous_prefixes(self):
        presets.refresh(self.conn, self.fetch)
        before = {p["slug"]: p["cidrs"] for p in presets.rows(self.conn)}

        def broken(url):
            if "telegram" in url:
                raise RuntimeError("source is down")
            return self.fetch(url)

        updated, failed, errors = presets.refresh(self.conn, broken)
        self.assertEqual((updated, failed), (2, 1))
        self.assertTrue(errors)
        after = {p["slug"]: p for p in presets.rows(self.conn)}
        self.assertEqual(after["telegram"]["cidrs"], before["telegram"])
        self.assertIn("down", after["telegram"]["last_error"])

    def test_manual_presets_are_not_refreshed(self):
        self.conn.execute(
            "INSERT INTO route_presets (slug, name, kind, cidrs, enabled, "
            "priority, created_at) VALUES ('mine', 'Mine', 'custom', "
            "'10.90.0.0/24', 1, 5, 'now')")
        presets.refresh(self.conn, self.fetch)
        mine = {p["slug"]: p for p in presets.rows(self.conn)}["mine"]
        self.assertEqual(mine["cidrs"], "10.90.0.0/24")
        self.assertEqual(mine["fetched_at"], 0)

    def test_catalog_serves_only_enabled_entries_with_prefixes(self):
        presets.refresh(self.conn, self.fetch)
        self.conn.execute("UPDATE route_presets SET enabled = 0 WHERE slug = 'claude'")
        self.conn.execute(
            "INSERT INTO route_presets (slug, name, kind, cidrs, enabled, "
            "priority, created_at) VALUES ('empty', 'Empty', 'custom', '', 1, 1, 'now')")
        body = presets.catalog(self.conn)
        self.assertEqual([p["id"] for p in body["presets"]],
                         ["telegram", "cloudflare"])
        self.assertFalse(body["stale"])

    def test_builtin_presets_carry_an_icon(self):
        presets.refresh(self.conn, self.fetch)
        self.conn.execute(
            "INSERT INTO route_presets (slug, name, kind, cidrs, enabled, "
            "priority, created_at) VALUES ('mine', 'Mine', 'custom', "
            "'10.90.0.0/24', 1, 1, 'now')")
        by_id = {item["id"]: item for item in presets.catalog(self.conn)["presets"]}
        for slug in ("telegram", "claude", "cloudflare"):
            self.assertTrue(by_id[slug]["icon"].startswith("/static/presets/"))
            self.assertTrue(by_id[slug]["icon"].endswith(".svg"))
            self.assertTrue(by_id[slug]["icon_png"].startswith("/static/presets/"))
            self.assertTrue(by_id[slug]["icon_png"].endswith(".png"))
        self.assertNotIn("icon", by_id["mine"])
        self.assertNotIn("icon_png", by_id["mine"])

    def test_icon_files_exist_and_are_small(self):
        static = Path(__file__).resolve().parents[1] / "panel" / "static"
        for icon in presets.ICONS.values():
            path = static / icon.removeprefix("/static/")
            self.assertTrue(path.is_file(), path)
            self.assertLessEqual(path.stat().st_size, 64 * 1024, path)
        for icon in presets.ICON_PNGS.values():
            path = static / icon.removeprefix("/static/")
            self.assertTrue(path.is_file(), path)
            self.assertLessEqual(path.stat().st_size, 256 * 1024, path)
            # PNG IHDR: width and height are big-endian at bytes 16 and 20.
            header = path.read_bytes()[:24]
            width = int.from_bytes(header[16:20], "big")
            height = int.from_bytes(header[20:24], "big")
            self.assertEqual((width, height), (128, 128), path)

    def test_an_old_catalogue_is_stale(self):
        presets.refresh(self.conn, self.fetch)
        old = int(time.time()) - presets.STALE_AFTER - 60
        self.conn.execute("UPDATE route_presets SET fetched_at = ?", (old,))
        self.assertTrue(presets.catalog(self.conn)["stale"])

    def test_an_empty_catalogue_is_not_an_error(self):
        self.conn.execute("UPDATE route_presets SET enabled = 0")
        body = presets.catalog(self.conn)
        self.assertEqual(body["presets"], [])
        self.assertFalse(body["stale"])


if __name__ == "__main__":
    unittest.main()
