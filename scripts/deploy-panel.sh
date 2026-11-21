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
mapfile -t hosts < <(ansible all -i "$repo/$inventory" --list-hosts | awk 'NR>1 {print $1}')
if [ "${#hosts[@]}" -ne 1 ]; then
  echo "expected exactly one host in $inventory, found ${#hosts[@]}" >&2
  exit 1
fi
host=${hosts[0]}

vars=$(ansible-inventory -i "$repo/$inventory" --host "$host")
user=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["ansible_user"])' <<<"$vars")
key=$(python3 -c 'import json,sys,os;print(os.path.expanduser(json.load(sys.stdin)["ansible_ssh_private_key_file"]))' <<<"$vars")
addr=$(python3 -c 'import json,sys;print(json.load(sys.stdin).get("ansible_host",""))' <<<"$vars")
addr=${addr:-$host}
ssh_opts=(-i "$key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

archive=$(mktemp /tmp/kaskad-panel.XXXXXX.tgz)
trap 'rm -f "$archive"' EXIT
tar -czf "$archive" --exclude=__pycache__ -C "$repo/panel" .
version=$(tr -d '[:space:]' < "$repo/VERSION")

echo "deploying panel to $addr"
scp -q "${ssh_opts[@]}" "$archive" "$user@$addr:/tmp/kaskad-panel.tgz"
ssh "${ssh_opts[@]}" "$user@$addr" "
  sudo -n tar -xzf /tmp/kaskad-panel.tgz -C /opt/kaskad/app --overwrite --no-same-owner
  sudo -n chown -R root:root /opt/kaskad/app
  # The playbook writes the version into panel.json; a code-only deploy must
  # not leave a stale number in the panel footer.
  sudo -n sed -i 's/\"version\": \"[^\"]*\"/\"version\": \"$version\"/' /etc/kaskad/panel.json
  sudo -n systemctl restart kaskad-panel kaskad-failover
  rm -f /tmp/kaskad-panel.tgz
  for unit in kaskad-panel kaskad-failover; do
    if ! systemctl is-active --quiet \"\$unit\"; then
      echo \"\$unit did not start after the deploy\" >&2
      exit 1
    fi
  done
  echo \"panel and failover are active\"
"
echo "done: $addr"
