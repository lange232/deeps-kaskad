#!/usr/bin/env python3
"""Builds seed.json for the panel from the old Ansible files.

Clients come from state/clients.yml, the exit from state/upstream.conf.
Only needed during migration: afterwards the panel SQLite is the source
of truth.
"""
import json
import sys
from pathlib import Path

import yaml

root = Path(__file__).resolve().parents[1]
out = {"clients": [], "exits": []}

clients_file = root / "state" / "clients.yml"
if clients_file.exists():
    clients = (yaml.safe_load(clients_file.read_text()) or {}).get("kaskad_clients", [])
    for c in clients:
        key_file = root / "state" / "clients" / c["name"] / f"{c['name']}.key"
        if not key_file.exists():
            print(f"skipping {c['name']}: {key_file} is missing", file=sys.stderr)
            continue
        out["clients"].append(
            {
                "name": c["name"],
                "ip": c["ip"],
                "public_key": c["public_key"],
                "private_key": key_file.read_text().strip(),
            }
        )

upstream = root / "state" / "upstream.conf"
if upstream.exists():
    out["exits"].append(
        {
            "name": "main",
            "iface": "awg1",
            "priority": 10,
            "conf": upstream.read_text(),
        }
    )

dest = root / "state" / "seed.json"
dest.write_text(json.dumps(out, indent=2))
dest.chmod(0o600)
print(f"{dest}: {len(out['clients'])} clients, {len(out['exits'])} exits")
