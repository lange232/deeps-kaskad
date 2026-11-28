"""Route presets the mobile app applies on its own.

The catalogue lives in the panel database: built-in entries point at public
sources and are refreshed by a timer, custom entries are maintained by the
administrator. The API serves the enabled entries; the panel never routes
these prefixes itself.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.environ.get("KASKAD_DB", "/var/lib/kaskad/panel.db"))
MAX_PREFIXES = 4096
STALE_AFTER = 24 * 3600
FETCH_TIMEOUT = 10
MAX_BYTES = 1 << 20
RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
IPRANGES = "https://raw.githubusercontent.com/lord-alfred/ipranges/main"

SCHEMA = """
CREATE TABLE IF NOT EXISTS route_presets (
    id INTEGER PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'custom',
    source_kind TEXT NOT NULL DEFAULT '',
    source_value TEXT NOT NULL DEFAULT '',
    cidrs TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 0,
    fetched_at INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
"""

# Cloudflare covers Discord, OpenCode and many other sites that share its
# edge, so they do not get separate entries. Anthropic has its own network.
DEFAULT_PRESETS = (
    {
        "slug": "telegram",
        "name": "Telegram",
        "description": "Official Telegram IPv4 ranges.",
        "source_kind": "cidr-text",
        "source_value": f"{IPRANGES}/telegram/ipv4_merged.txt",
        "priority": 10,
    },
    {
        "slug": "claude",
        "name": "Claude (Anthropic)",
        "description": "IPv4 prefixes announced by Anthropic's own network.",
        "source_kind": "ripe-asn",
        "source_value": "399358",
        "priority": 20,
    },
    {
        "slug": "cloudflare",
        "name": "Cloudflare (Discord, OpenCode, other sites)",
        "description": (
            "Cloudflare edge ranges. Discord and OpenCode run through it, and "
            "so do many other sites: this preset is not limited to them."
        ),
        "source_kind": "cidr-text",
        "source_value": f"{IPRANGES}/cloudflare/ipv4_merged.txt",
        "priority": 30,
    },
)

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,31}$")
SOURCE_KINDS = ("", "cidr-text", "ripe-asn")


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Creates the table and fills the built-in entries exactly once."""
    conn.executescript(SCHEMA)
    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for preset in DEFAULT_PRESETS:
        conn.execute(
            "INSERT OR IGNORE INTO route_presets "
            "(slug, name, description, kind, source_kind, source_value, "
            " enabled, priority, created_at) "
            "VALUES (?, ?, ?, 'builtin', ?, ?, 1, ?, ?)",
            (preset["slug"], preset["name"], preset["description"],
             preset["source_kind"], preset["source_value"],
             preset["priority"], created),
        )


def _dicts(cursor) -> list[dict]:
    """Rows as dicts without depending on the connection's row factory."""
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, values)) for values in cursor.fetchall()]


def _one(conn: sqlite3.Connection, sql: str, params=()) -> dict | None:
    fetched = _dicts(conn.execute(sql, params))
    return fetched[0] if fetched else None


def rows(conn: sqlite3.Connection) -> list[dict]:
    return _dicts(conn.execute(
        "SELECT * FROM route_presets ORDER BY priority, id"
    ))


def row(conn: sqlite3.Connection, preset_id: int) -> dict | None:
    return _one(conn, "SELECT * FROM route_presets WHERE id = ?", (preset_id,))


def cidr_list(value: str) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def collapse(networks) -> list[str]:
    """The shortest IPv4 list covering these networks."""
    ordered = sorted({n for n in networks},
                     key=lambda n: (int(n.network_address), n.prefixlen))
    return [str(n) for n in ipaddress.collapse_addresses(ordered)][:MAX_PREFIXES]


def _network(value) -> ipaddress.IPv4Network | None:
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None
    if net.version != 4 or net.prefixlen == 0:
        return None
    return net


def parse_cidr_text(text: str) -> list[str]:
    """A plain list of CIDRs, one per line or comma-separated."""
    networks = []
    for raw in text.replace(",", "\n").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        net = _network(line)
        if net is not None:
            networks.append(net)
    return collapse(networks)


def parse_ripe_prefixes(payload: dict) -> list[str]:
    """IPv4 prefixes from RIPEstat's announced-prefixes response."""
    prefixes = (payload.get("data") or {}).get("prefixes") or []
    networks = []
    for item in prefixes:
        value = item.get("prefix") if isinstance(item, dict) else item
        net = _network(value)
        if net is not None:
            networks.append(net)
    return collapse(networks)


def validate_cidrs(cidrs: list[str]) -> list[str]:
    """Errors for a preset's CIDR list; empty means it is usable."""
    errors: list[str] = []
    if not cidrs:
        return ["the list has no IPv4 prefixes"]
    if len(cidrs) > MAX_PREFIXES:
        errors.append(f"more than {MAX_PREFIXES} prefixes")
    seen = set()
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=True)
        except ValueError:
            errors.append(f"invalid CIDR: {cidr}")
            continue
        if net.version != 4:
            errors.append(f"not IPv4: {cidr}")
        if net.prefixlen == 0:
            errors.append("the default route is not allowed")
        if cidr in seen:
            errors.append(f"duplicate: {cidr}")
        seen.add(cidr)
    return errors


def validate_source(kind: str, value: str) -> str | None:
    if kind not in SOURCE_KINDS:
        return "unknown source kind"
    if not kind:
        return None
    value = value.strip()
    if not value:
        return "the source needs a URL or an ASN"
    if kind == "cidr-text" and not value.startswith("https://"):
        return "the source URL must start with https://"
    if kind == "ripe-asn" and not value.isdigit():
        return "the ASN must be a number, without AS"
    return None


def slugify(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return base[:32] or "custom"


def unique_slug(conn: sqlite3.Connection, base: str) -> str:
    base = base[:32] or "custom"
    candidate, index = base, 2
    while conn.execute("SELECT 1 FROM route_presets WHERE slug = ?",
                       (candidate,)).fetchone():
        suffix = f"-{index}"
        candidate = base[:32 - len(suffix)] + suffix
        index += 1
    return candidate


def etag(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def etag_matches(header: str | None, tag: str) -> bool:
    if not header:
        return False
    for part in header.split(","):
        value = part.strip()
        if value == "*":
            return True
        if value.startswith("W/"):
            value = value[2:]
        if value.strip('"') == tag:
            return True
    return False


def fetch(url: str, timeout: int = FETCH_TIMEOUT) -> str:
    request = urllib.request.Request(
        url, headers={"User-Agent": "kaskad-presets/1"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise RuntimeError("the source is larger than the limit")
    return data.decode("utf-8", "replace")


def fetch_source(kind: str, value: str, fetcher=fetch) -> list[str]:
    if kind == "cidr-text":
        cidrs = parse_cidr_text(fetcher(value))
    elif kind == "ripe-asn":
        payload = json.loads(fetcher(RIPE_URL.format(asn=value.strip())))
        cidrs = parse_ripe_prefixes(payload)
    else:
        raise RuntimeError(f"unknown source kind: {kind}")
    errors = validate_cidrs(cidrs)
    if errors:
        raise RuntimeError("; ".join(errors))
    return cidrs


def catalog(conn: sqlite3.Connection, now: int | None = None) -> dict:
    """The API payload: enabled entries with fetched prefixes."""
    now = int(time.time()) if now is None else now
    items = _dicts(conn.execute(
        "SELECT * FROM route_presets WHERE enabled = 1 AND cidrs <> '' "
        "ORDER BY priority, id"
    ))
    presets = [
        {
            "id": item["slug"],
            "name": item["name"],
            "description": item["description"],
            "cidrs": cidr_list(item["cidrs"]),
            "source": item["source_value"] or "manual",
            "fetched": int(item["fetched_at"] or 0),
        }
        for item in items
    ]
    source_rows = [item for item in items if item["source_kind"]]
    stale = any(
        not item["fetched_at"] or now - int(item["fetched_at"]) > STALE_AFTER
        for item in source_rows
    )
    newest = max((int(item["fetched_at"] or 0) for item in items), default=0)
    version = (
        datetime.fromtimestamp(newest, timezone.utc).isoformat(timespec="seconds")
        if newest else ""
    )
    return {"version": version, "stale": stale, "presets": presets}


def refresh(conn: sqlite3.Connection, fetcher=fetch) -> tuple[int, int, list[str]]:
    """Refreshes every sourced entry; failures keep the previous prefixes."""
    now = int(time.time())
    updated = failed = 0
    errors: list[str] = []
    for item in rows(conn):
        if not item["source_kind"]:
            continue
        try:
            cidrs = fetch_source(item["source_kind"], item["source_value"], fetcher)
        except Exception as exc:
            failed += 1
            errors.append(f"{item['slug']}: {exc}")
            conn.execute(
                "UPDATE route_presets SET last_error = ? WHERE id = ?",
                (str(exc)[:300], item["id"]),
            )
            continue
        conn.execute(
            "UPDATE route_presets SET cidrs = ?, fetched_at = ?, last_error = '' "
            "WHERE id = ?",
            (",".join(cidrs), now, item["id"]),
        )
        updated += 1
    return updated, failed, errors


def main() -> int:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        ensure_schema(conn)
        updated, failed, errors = refresh(conn)
        conn.commit()
    finally:
        conn.close()
    for error in errors:
        print(f"presets: {error}", file=sys.stderr, flush=True)
    print(f"presets: {updated} refreshed, {failed} failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
