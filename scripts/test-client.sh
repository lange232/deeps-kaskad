#!/bin/bash
# Test WireGuard client in a container: lives in its own netns and does not
# touch the host routes or DNS. The config is pulled from S1 via the panel.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=kaskad-client
NAME="${2:-test1}"
CONT="kaskad-client-$NAME"
RUN_DIR="state/clients/$NAME"

inv() {
    python3 - "$1" <<'PY'
import sys, yaml
from pathlib import Path
d = yaml.safe_load(Path(__import__("os").environ.get("KASKAD_INVENTORY", "inventory.yml")).read_text())
h = d["all"]["hosts"]["s1"]
key = str(Path(d["all"]["vars"]["ansible_ssh_private_key_file"]).expanduser())
print({"host": h["ansible_host"], "user": d["all"]["vars"]["ansible_user"], "key": key}[sys.argv[1]])
PY
}

fetch_conf() {
    local host user key
    host="$(inv host)"; user="$(inv user)"; key="$(inv key)"
    mkdir -p "$RUN_DIR"
    ssh -i "$key" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o BatchMode=yes \
        "$user@$host" "sudo /opt/kaskad/venv/bin/python /opt/kaskad/app/app.py conf $NAME" > "$RUN_DIR/$NAME.conf"
    chmod 0600 "$RUN_DIR/$NAME.conf"
}

case "${1:-up}" in
  build)
    docker build -t "$IMAGE" images/client
    ;;
  up)
    # Always fetch: the cached file may point at another host or an old key.
    fetch_conf
    conf="$RUN_DIR/$NAME.conf"
    [ -s "$conf" ] || { echo "failed to fetch the config for $NAME"; exit 1; }

    dns="$(sed -n 's/^DNS *= *//p' "$conf" | head -1)"
    addr="$(sed -n 's/^Address *= *//p' "$conf" | head -1)"
    mtu="$(sed -n 's/^MTU *= *//p' "$conf" | head -1)"
    endpoint="$(sed -n 's/^Endpoint *= *//p' "$conf" | head -1)"
    allowed="$(sed -n 's/^AllowedIPs *= *//p' "$conf" | head -1)"
    # wg resolves the name on setconf, but the route to the server needs an IP.
    ep_host="${endpoint%:*}"
    ep_port="${endpoint##*:}"
    ep_ip="$(getent ahostsv4 "$ep_host" | awk 'NR==1{print $1}')"
    [ -n "$ep_ip" ] || ep_ip="$ep_host"
    endpoint="$ep_ip:$ep_port"

    # Config without wg-quick specific fields: the entrypoint brings it up.
    grep -vE "^(Address|DNS|MTU|Table|PreUp|PostUp|PreDown|PostDown|SaveConfig)[[:space:]]*=" "$conf" > "$RUN_DIR/wg0.setconf"

    docker build -q -t "$IMAGE" images/client >/dev/null
    docker rm -f "$CONT" >/dev/null 2>&1 || true
    docker run -d --name "$CONT" \
      --cap-add NET_ADMIN \
      --device /dev/net/tun \
      -e "WG_ADDR=$addr" \
      -e "WG_DNS=$dns" \
      -e "WG_MTU=${mtu:-1280}" \
      -e "WG_ENDPOINT=$endpoint" \
      -e "WG_ALLOWED=$allowed" \
      -v "$PWD/$RUN_DIR:/etc/wireguard:ro" \
      "$IMAGE"
    sleep 2
    docker exec "$CONT" wg show
    ;;
  shell)
    docker exec -it "$CONT" sh
    ;;
  logs)
    docker logs --tail 50 "$CONT"
    ;;
  down)
    docker rm -f "$CONT" >/dev/null 2>&1 || true
    echo "$CONT removed"
    ;;
  *)
    echo "usage: $0 {build|up|shell|logs|down} [name]" >&2
    exit 2
    ;;
esac
