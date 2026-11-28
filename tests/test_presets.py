"""Tests for the route preset catalogue: parsers, validation and cache."""
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

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

    def test_two_halves_collapse_into_one_network(self):
        text = "10.0.0.0/25\n10.0.0.128/25\n"
        self.assertEqual(presets.parse_cidr_text(text), ["10.0.0.0/24"])

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


class EtagTests(unittest.TestCase):
    def test_matching_forms(self):
        tag = "abc123"
        for header in (tag, f'"{tag}"', f'W/"{tag}"', f'"x", "{tag}"', "*"):
            self.assertTrue(presets.etag_matches(header, tag), header)

    def test_misses(self):
        for header in (None, "", '"other"', f'W/"other"'):
            self.assertFalse(presets.etag_matches(header, "abc123"), header)


class CacheTests(unittest.TestCase):
    def catalog(self, generated=None):
        return {
            "version": "2026-11-28T00:00:00+00:00",
            "generated": int(time.time()) if generated is None else generated,
            "presets": [{
                "id": "telegram", "name": "Telegram", "description": "d",
                "cidrs": ["91.108.4.0/22"], "source": "test", "fetched": 1,
            }],
        }

    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "presets.json"
            presets.save_cache(self.catalog(), path)
            loaded = presets.load_cache(path)
        self.assertEqual(loaded["presets"][0]["id"], "telegram")

    def test_a_broken_cache_reads_as_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "presets.json"
            path.write_text("{not json")
            self.assertIsNone(presets.load_cache(path))

    def test_staleness(self):
        now = 1_800_000_000
        self.assertFalse(presets.is_stale(self.catalog(now), now + 60))
        self.assertTrue(
            presets.is_stale(self.catalog(now), now + presets.STALE_AFTER + 1)
        )

    def test_payload_exposes_only_client_fields(self):
        body = presets.catalog_payload(self.catalog())
        self.assertEqual(body["version"], "2026-11-28T00:00:00+00:00")
        self.assertFalse(body["stale"])
        self.assertEqual(set(body["presets"][0]),
                         {"id", "name", "description", "cidrs", "source", "fetched"})


class RefreshTests(unittest.TestCase):
    def test_a_failed_source_keeps_the_previous_entry(self):
        old = {"id": "telegram", "name": "Telegram", "description": "d",
               "cidrs": ["91.108.4.0/22"], "source": "test", "fetched": 1}
        fresh = dict(old, cidrs=["149.154.160.0/20"], fetched=2)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "presets.json"
            presets.save_cache({"version": "old", "generated": 1,
                                "presets": [old]}, path)
            def entry(preset, now):
                if preset["id"] == "telegram":
                    raise RuntimeError("source is down")
                return dict(fresh, id=preset["id"], name=preset["name"])
            with mock.patch.object(presets, "CACHE_PATH", path), \
                 mock.patch.object(presets, "_entry", side_effect=entry):
                code = presets.refresh()
            loaded = presets.load_cache(path)
        self.assertEqual(code, 0)
        telegram = next(p for p in loaded["presets"] if p["id"] == "telegram")
        self.assertEqual(telegram["cidrs"], ["91.108.4.0/22"])

    def test_nothing_refreshed_is_an_error_and_keeps_the_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "presets.json"
            presets.save_cache({"version": "old", "generated": 1, "presets": []}, path)
            with mock.patch.object(presets, "CACHE_PATH", path), \
                 mock.patch.object(presets, "_entry",
                                   side_effect=RuntimeError("down")):
                code = presets.refresh()
            loaded = presets.load_cache(path)
        self.assertEqual(code, 1)
        self.assertEqual(loaded["version"], "old")


if __name__ == "__main__":
    unittest.main()
