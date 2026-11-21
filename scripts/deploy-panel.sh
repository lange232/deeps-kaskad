#!/usr/bin/env bash
# Deploys the panel code to one host and restarts its services.
#
# A full playbook run on a slow link spends seconds on every task; this does
# the same job with one archive transfer and takes seconds to a minute. Use it
# for code-only deploys; anything else (units, TLS, firewall) still goes
# through playbooks/site.yml.
#
#   scripts/deploy-panel.sh inventory.libra.yml
set -euo pipefail

inventory=${1:?usage: deploy-panel.sh <inventory>}
repo=$(cd "$(dirname "$0")/.." && pwd)
host=$(ansible all -i "$repo/$inventory" --list-hosts | awk 'NR==2 {print $1}')
[ -n "$host" ] || { echo "no host in $inventory" >&2; exit 1; }

vars=$(ansible-inventory -i "$repo/$inventory" --host "$host")
user=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["ansible_user"])' <<<"$vars")
key=$(python3 -c 'import json,sys,os;print(os.path.expanduser(json.load(sys.stdin)["ansible_ssh_private_key_file"]))' <<<"$vars")
addr=$(python3 -c 'import json,sys;print(json.load(sys.stdin).get("ansible_host",""))' <<<"$vars")
addr=${addr:-$host}
ssh_opts=(-i "$key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

archive=$(mktemp /tmp/kaskad-panel.XXXXXX.tgz)
trap 'rm -f "$archive"' EXIT
tar -czf "$archive" --exclude=__pycache__ -C "$repo/panel" .

echo "deploying panel to $addr"
scp -q "${ssh_opts[@]}" "$archive" "$user@$addr:/tmp/kaskad-panel.tgz"
ssh "${ssh_opts[@]}" "$user@$addr" '
  sudo -n tar -xzf /tmp/kaskad-panel.tgz -C /opt/kaskad/app --overwrite --no-same-owner
  sudo -n chown -R root:root /opt/kaskad/app
  sudo -n systemctl restart kaskad-panel kaskad-failover
  rm -f /tmp/kaskad-panel.tgz
'
echo "done: $addr"
