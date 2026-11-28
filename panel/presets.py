"""Route presets the mobile app applies on its own.

The CIDR lists are not stored in the repository: this module only describes
the public sources. Running it as a script refreshes the cache file from those
sources; the API serves the cache and the panel never routes these prefixes
itself.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CACHE_PATH = Path(os.environ.get("KASKAD_PRESETS", "/var/lib/kaskad/presets.json"))
MAX_PREFIXES = 4096
STALE_AFTER = 24 * 3600
FETCH_TIMEOUT = 10
MAX_BYTES = 1 << 20
RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
IPRANGES = "https://raw.githubusercontent.com/lord-alfred/ipranges/main"

# Sources only; the data itself is fetched to the cache. Cloudflare covers
# Discord, OpenCode and many other sites that share its edge, so they do not
# get separate entries. Anthropic has its own network, hence its own preset.
PRESETS = (
    {
        "id": "telegram",
        "name": "Telegram",
        "description": "Official Telegram IPv4 ranges.",
        "source": {
            "kind": "cidr-text",
            "url": f"{IPRANGES}/telegram/ipv4_merged.txt",
            "label": "lord-alfred/ipranges",
        },
    },
    {
        "id": "claude",
        "name": "Claude (Anthropic)",
        "description": "IPv4 prefixes announced by Anthropic's own network.",
        "source": {
            "kind": "ripe-asn",
            "asn": 399358,
            "label": "RIPEstat, AS399358",
        },
    },
    {
        "id": "cloudflare",
        "name": "Cloudflare (Discord, OpenCode, other sites)",
        "description": (
            "Cloudflare edge ranges. Discord and OpenCode run through it, and "
            "so do many other sites: this preset is not limited to them."
        ),
        "source": {
            "kind": "cidr-text",
            "url": f"{IPRANGES}/cloudflare/ipv4_merged.txt",
            "label": "lord-alfred/ipranges",
        },
    },
)


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
    """A plain list of CIDRs, one per line; comments and IPv6 are ignored."""
    networks = []
    for raw in text.splitlines():
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
        return ["the source returned no IPv4 prefixes"]
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


def load_cache(path: Path | None = None) -> dict | None:
    """The last fetched catalogue, or None when it is missing or broken."""
    path = CACHE_PATH if path is None else path
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("presets"), list):
        return None
    return data


def save_cache(catalog: dict, path: Path | None = None) -> None:
    """Atomic write: a reader never sees half a catalogue."""
    path = CACHE_PATH if path is None else path
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w") as handle:
            json.dump(catalog, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def catalog_payload(catalog: dict) -> dict:
    """The response body: only the fields the client needs."""
    return {
        "version": catalog.get("version", ""),
        "stale": is_stale(catalog),
        "presets": [
            {
                "id": item.get("id", ""),
                "name": item.get("name", ""),
                "description": item.get("description", ""),
                "cidrs": item.get("cidrs", []),
                "source": item.get("source", ""),
                "fetched": item.get("fetched", 0),
            }
            for item in catalog.get("presets", [])
        ],
    }


def is_stale(catalog: dict, now: int | None = None) -> bool:
    try:
        generated = int(catalog.get("generated") or 0)
    except (TypeError, ValueError):
        return True
    now = int(time.time()) if now is None else now
    return generated <= 0 or now - generated > STALE_AFTER


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


def _entry(preset: dict, now: int) -> dict:
    source = preset["source"]
    if source["kind"] == "cidr-text":
        cidrs = parse_cidr_text(fetch(source["url"]))
    elif source["kind"] == "ripe-asn":
        payload = json.loads(fetch(RIPE_URL.format(asn=source["asn"])))
        cidrs = parse_ripe_prefixes(payload)
    else:
        raise RuntimeError(f"unknown source kind: {source['kind']}")
    errors = validate_cidrs(cidrs)
    if errors:
        raise RuntimeError("; ".join(errors))
    return {
        "id": preset["id"],
        "name": preset["name"],
        "description": preset["description"],
        "cidrs": cidrs,
        "source": source.get("label") or source.get("url", ""),
        "fetched": now,
    }


def refresh() -> int:
    """Fetches every preset, keeps the previous entry when one source fails."""
    now = int(time.time())
    previous = {item.get("id"): item
                for item in (load_cache() or {}).get("presets", [])}
    entries = []
    failures = 0
    for preset in PRESETS:
        try:
            entries.append(_entry(preset, now))
        except Exception as exc:  # a source is foreign input and can fail
            failures += 1
            print(f"presets: {preset['id']}: {exc}", file=sys.stderr, flush=True)
            if preset["id"] in previous:
                entries.append(previous[preset["id"]])
    if not entries:
        print("presets: no source could be refreshed", file=sys.stderr, flush=True)
        return 1
    version = datetime.now(timezone.utc).isoformat(timespec="seconds")
    save_cache({"version": version, "generated": now, "presets": entries})
    print(f"presets: {len(entries)} entries, {failures} source(s) failed")
    return 0


if __name__ == "__main__":
    sys.exit(refresh())
