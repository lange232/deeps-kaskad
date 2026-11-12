#!/bin/sh
set -e

: "${WG_ADDR:?WG_ADDR is not set}"
WG_DNS="${WG_DNS:-}"
: "${WG_ENDPOINT:?WG_ENDPOINT is not set}"
WG_MTU="${WG_MTU:-1280}"

ip link add wg0 type wireguard
wg setconf wg0 /etc/wireguard/wg0.setconf
ip addr add "$WG_ADDR" dev wg0
ip link set mtu "$WG_MTU" up dev wg0

# Keep the server address on the external interface, everything else in the tunnel.
GW="$(ip route show default | awk '{print $3; exit}')"
EP_HOST="${WG_ENDPOINT%:*}"
EP_PORT="${WG_ENDPOINT##*:}"
EP_IP="$(getent ahostsv4 "$EP_HOST" 2>/dev/null | awk 'NR==1{print $1}')"
[ -n "$EP_IP" ] || EP_IP="$EP_HOST"
ip route add "$EP_IP" via "$GW" 2>/dev/null || true

# Honour AllowedIPs: a full tunnel gets a default route, a routed client only
# gets its subnets.
if [ -z "${WG_ALLOWED:-}" ] || printf '%s' "$WG_ALLOWED" | grep -q '0.0.0.0/0'; then
    ip route replace default dev wg0
else
    printf '%s\n' "$WG_ALLOWED" | tr ',' '\n' | while read -r cidr; do
        cidr="$(printf '%s' "$cidr" | tr -d ' ')"
        [ -n "$cidr" ] && ip route add "$cidr" dev wg0 2>/dev/null || true
    done
fi

if [ -n "$WG_DNS" ]; then
    {
        printf '%s\n' "$WG_DNS" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$' | sed 's/^/nameserver /'
    } > /etc/resolv.conf
fi

# The tunnel is IPv4 only: without this the resolver returns IPv6 first and
# curl tries it instead of IPv4.
printf 'precedence ::ffff:0:0/96 100\n' > /etc/gai.conf

cleanup() {
    ip link del wg0 2>/dev/null || true
}
trap cleanup TERM INT

while :; do
    sleep 3600 &
    wait $! || true
done
