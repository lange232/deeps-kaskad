#!/bin/bash
# Full check: servers via Ansible plus the container client.
set -euo pipefail
cd "$(dirname "$0")/.."

name="${1:-test1}"

echo "== servers"
ansible-playbook playbooks/check.yml

echo
echo "== client $name"
cont="kaskad-client-$name"
if ! docker inspect "$cont" >/dev/null 2>&1; then
    echo "container $cont is not running, starting it"
    scripts/test-client.sh up "$name" >/dev/null
fi

docker exec "$cont" sh -c '
set -e
printf "exit ip:   %s\n" "$(curl -4 -s --max-time 10 https://ifconfig.me)"
printf "dns:       %s\n" "$(dig +short +time=3 @1.1.1.1 example.com A | head -1)"
printf "mtu 1280:  %s\n" "$(ping -c1 -W3 -M do -s 1252 1.1.1.1 >/dev/null 2>&1 && echo ok || echo fail)"
'
