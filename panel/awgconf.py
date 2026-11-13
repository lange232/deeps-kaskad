"""Parser for upstream AmneziaWG/WireGuard configs.

Providers hand out configs with things we do not want: DNS (would rewrite
the resolv.conf of S1), PostUp/PreDown (kill-switch) and IPv6. This module
turns them into something suitable for awg-quick with Table = off.
"""
from __future__ import annotations

import ipaddress

DROP_INTERFACE = {
    "dns", "postup", "predown", "postdown", "saveconfig",
    "table", "mtu", "listenport", "fwmark",
}
KEEP_PEER = {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}
REQUIRED_IFACE = {"address", "privatekey"}
REQUIRED_PEER = {"publickey", "endpoint"}

# AmneziaWG obfuscation keys. When they are absent the config comes from
# plain WireGuard and the interface needs neutral parameters, otherwise the
# handshake never matches (awg defaults H1..H4 to 0, while a standard packet
# has type 1..4).
OBFUSCATION_KEYS = {
    "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
    "h1", "h2", "h3", "h4", "headerprotectionkey", "i1", "i2", "i3", "i4", "i5",
}
PLAIN_PARAMS = [
    ("Jc", "0"), ("Jmin", "0"), ("Jmax", "0"),
    ("S1", "0"), ("S2", "0"), ("S3", "0"), ("S4", "0"),
    ("H1", "1"), ("H2", "2"), ("H3", "3"), ("H4", "4"),
    ("ContentPaddingAddition", "0"), ("RandomTrailers", "off"), ("DisableCookies", "off"),
]


def _split(line: str) -> tuple[str, str]:
    key, _, value = line.partition("=")
    return key.strip(), value.strip()


def parse_text(text: str) -> dict:
    section = None
    iface: dict[str, str] = {}
    extra: list[tuple[str, str]] = []
    peers: list[dict[str, str]] = []

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low == "[interface]":
            section = "iface"
            continue
        if low == "[peer]":
            section = "peer"
            peers.append({})
            continue
        if "=" not in line:
            continue
        key, value = _split(line)
        k = key.lower()

        if section == "iface":
            if k in DROP_INTERFACE:
                continue
            if k in {"address", "privatekey"}:
                if k == "address":
                    value = ", ".join(v for v in value.split(",") if ":" not in v)
                iface[key] = value
            else:
                extra.append((key, value))
        elif section == "peer":
            if k not in KEEP_PEER:
                continue
            if k == "allowedips":
                value = ", ".join(v for v in value.split(",") if ":" not in v)
            peers[-1][key] = value

    return {"iface": iface, "extra": extra, "peers": peers}


def validate(text: str) -> list[str]:
    data = parse_text(text)
    errors = []
    present = {k.lower() for k in data["iface"]}
    missing = REQUIRED_IFACE - present
    if missing:
        errors.append("missing in [Interface]: " + ", ".join(sorted(missing)))
    if not data["peers"]:
        errors.append("no [Peer] section")
    for i, peer in enumerate(data["peers"], 1):
        present = {k.lower() for k in peer}
        missing = REQUIRED_PEER - present
        if missing:
            errors.append(f"missing in [Peer] #{i}: " + ", ".join(sorted(missing)))
    return errors


def endpoint(text: str) -> str:
    data = parse_text(text)
    for peer in data["peers"]:
        for key, value in peer.items():
            if key.lower() == "endpoint":
                return value
    return ""


def allowed_networks(text: str) -> list[str]:
    """IPv4 networks from the peers' AllowedIPs, without the default route."""
    nets: list[str] = []
    for raw in text.splitlines():
        key, _, value = raw.strip().partition("=")
        if key.strip().lower() != "allowedips":
            continue
        for item in value.split(","):
            item = item.strip()
            if not item or ":" in item:
                continue
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                continue
            if net.prefixlen == 0:
                continue
            shown = str(net)
            if shown not in nets:
                nets.append(shown)
    return nets


def guess_routes(text: str) -> list[str]:
    """Subnets for a routed exit: AllowedIPs, or the Address network."""
    nets = allowed_networks(text)
    if nets:
        return nets
    data = parse_text(text)
    for item in str(data["iface"].get("Address", "")).split(","):
        item = item.strip()
        if not item or ":" in item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if net.prefixlen > 0:
            return [str(net)]
    return []


def is_plain(text: str) -> bool:
    data = parse_text(text)
    # parse_text stores obfuscation keys in extra, not in iface.
    present = {k.lower() for k in data["iface"]}
    present |= {k.lower() for k, _ in data["extra"]}
    return not (present & OBFUSCATION_KEYS)


def render(text: str, mtu: int, routes: list[str] | None = None) -> str:
    data = parse_text(text)
    iface = data["iface"]
    out = [
        "# Generated by kaskad-panel from the provider config.",
        "[Interface]",
        f"Address = {iface.get('Address', '').strip()}",
        f"PrivateKey = {iface.get('PrivateKey', '').strip()}",
        f"MTU = {mtu}",
        "Table = off",
    ]
    for key, value in data["extra"]:
        out.append(f"{key} = {value}")

    if is_plain(text):
        for key, value in PLAIN_PARAMS:
            out.append(f"{key} = {value}")

    for peer in data["peers"]:
        out += ["", "[Peer]"]
        for key in ("PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"):
            if key not in peer:
                continue
            value = peer[key]
            if key == "AllowedIPs" and routes:
                # For exits with specific subnets the interface must not
                # claim the whole internet.
                value = ", ".join(routes)
            out.append(f"{key} = {value}")

    return "\n".join(out) + "\n"
