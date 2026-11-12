# deeps kaskad

A single entry server for a two-hop VPN. Clients connect with a stock
WireGuard client; traffic leaves through one of several external
AmneziaWG/WireGuard servers (exits), or reaches only the subnets published by
those exits.

```
client ──plain WG──> S1 ──AmneziaWG/WG──> exit N ──> internet or subnets
        awg0           awg1..awgN          NAT
                          ↑
                 failover picks the internet exit by priority
```

## Two client classes

| Class | What it gets | AllowedIPs | DNS |
|---|---|---|---|
| internet | full tunnel via the active internet exit | `0.0.0.0/0` | `1.1.1.1, 1.0.0.1` |
| subnets | only the CIDRs assigned to the client | union of subnets | DNS of its exit |
| both | internet plus subnets | `0.0.0.0/0` | global |

Access is granted per client in the panel: an internet toggle plus checkboxes
for the routed exits. A client with neither has no access at all.

## Two exit modes

| Mode | Behaviour | Failover |
|---|---|---|
| `internet` | default route, NAT to the internet, participates in selection | yes, strict priority |
| `routes` | only the listed subnets, own routing table | no |

Exits are added in the panel: name, mode, priority, subnets, DNS and the
provider config (AmneziaWG or plain WireGuard).

## Addressing and ports

| Segment | Subnet | S1 |
|---|---|---|
| Clients (`awg0`) | `10.80.0.0/24` | `10.80.0.1` |
| Internet exits (`awg1..awgN`) | assigned by the provider | own `/32` each |
| Client port | `51820/udp` | |
| MTU | `awg0` 1280, exits 1340 | |
| Routing tables | `100` internet, `1000+` routed exits | |

## AmneziaWG limitation

Obfuscation parameters are configured **per device**, not per peer: the
`AdvancedSecurity` flag exists in the API but is not used in the data path
(kernel module `v3.1.20260906`, `amneziawg-go v3.1.20260828`). A stock
WireGuard client therefore only works against an interface with neutral
parameters:

```
Jc=0, S1=S2=S3=S4=0, H1=1, H2=2, H3=3, H4=4,
ContentPaddingAddition=0, RandomTrailers=off, no HeaderProtectionKey
```

These are the parameters of `awg0`, so the entry hop is ordinary WireGuard on
the wire and is visible to DPI. Obfuscation applies to the exits
`awg1..awgN`.

## Plain WireGuard as an exit

If a provider config has no `Jc/S*/H*/HeaderProtectionKey`, it is treated as
plain WireGuard and neutral parameters are added automatically — otherwise the
handshake never matches (`H1..H4` default to 0, while a standard packet has
type 1..4). For a routed exit, the peer `AllowedIPs` is rewritten to the
exit's CIDRs.

On the provider side, the subnets must be allowed in the peer and routed back
to us. That part is outside this project.

## Client routing

`panel/routing.py` applies the state from the database:

```
10000  from 10.80.0.7 to 192.168.50.0/24 iif awg0 lookup 1001
20000  from 10.80.0.7 iif awg0 lookup 100
```

- specific subnets always win over the default route (lower number wins);
- the internet rule is installed **only for clients with the internet toggle**,
  otherwise a subnets-only client would still leave through the internet exit;
- table `100` holds the active internet exit and is managed by the failover
  daemon;
- exit tables start at `1000`;
- the script removes its own rules before every apply, so deleting a client or
  an exit leaves no stale state.

**Never use tables 253/254/255** — these are `default`, `main` and `local`.
A range of `201..264` once wiped the main table and cut a host off the network.
Exit tables start at 1000 and the system tables are excluded explicitly.

## Failover

Every 10 seconds each enabled internet exit is probed (`ping -I awgN`), the
first alive one by ascending `priority` becomes active, and the route
`default dev awgN table 100` is replaced. Returning to a higher-priority exit
happens only after 60 seconds of stable operation. An exit is considered dead
after 3 failed probes and alive after 2 successful ones. Client conntrack
entries are flushed on switch, otherwise the old NAT would send packets to the
wrong address.

Manual switching is a button in the panel: the chosen interface is stored in
the `manual_exit` setting and stays pinned while that exit is alive; "return
to auto" clears it. State lives in `/run/kaskad/status.json` and
`/run/kaskad/active-exit`.

Routed exits are not part of the selection: a subnet has a single owner.

The daemon also watches the set of `awg*` interfaces. Tunnels can come up
after `kaskad-routing.service` has already run (or be restarted by hand), so
when one appears or disappears the daemon re-applies the routing — with a
retry on the next tick if the apply reported errors.

## Firewall

`kaskad-firewall.service` installs iptables rules rather than a separate nft
table: on hosts with Docker the `FORWARD` policy is `DROP`, and another inet
table cannot override it. Only `-i awg0 -o awg+` is accepted; the rest of the
traffic from `awg0` is dropped so a client without an internet exit cannot
leak through `eth0`. NAT is `-s 10.80.0.0/24 -o awg+`; client-to-client
traffic is untouched.

## Requirements

- Ubuntu 24.04, root access over SSH, `ansible-core`.
- The `amneziawg` kernel module from `ppa:amnezia/ppa` (or local packages, see
  `files/awg/README.md`). If DKMS fails on your kernel, `amneziawg-go` works
  as a userspace replacement with the same configs.

## Deployment

```bash
cp inventory.example.yml inventory.yml   # edit hosts and the SSH key
ansible-playbook playbooks/site.yml --check
ansible-playbook playbooks/site.yml
scripts/check.sh demo
```

Tags: `base`, `amneziawg`, `panel`, `entry`.

Tests:

```bash
python3 -m unittest discover -s tests          # logic only, no extra deps
/opt/kaskad/venv/bin/pip install -r panel/requirements-dev.txt
/opt/kaskad/venv/bin/python -m unittest discover -s tests   # + panel HTTP tests
```

`kaskad_awg_packages_mode` is `ppa` by default; switch it to `local` for hosts
without access to Launchpad.

`state/` is gitignored: provider configs, client keys and migration seeds.

## Panel

`https://<host>:8080`, FastAPI + SQLite. The certificate is self-signed by
default; see [TLS](#tls) to use Let's Encrypt.

The panel has two kinds of sign-in:

- **administrator** — login `admin` and the password generated during the
  first deploy and printed once; only its hash is stored in
  `/etc/kaskad/panel.env`. Reset: delete the file, run `--tags panel`, restart
  `kaskad-panel`.
- **client** — an account created from the client page; the email is the
  login and the password is generated or set by the administrator and shown
  once. A client signs in at `/me` and sees only their own config: download,
  QR, WireGuard instructions, self-service key reissue and password change.

The administrator manages clients (create, change class and access, account,
download the config, QR, enable/disable, delete), exits (add, enable/disable,
delete, manual switch), service status and the action journal.

Sign-in limits: five failed attempts for the same email from the same address
block that pair for five minutes, twenty failures from one address block the
address, and repeated guesses against one email only add a growing delay — so
nobody can lock the administrator out by guessing his address from elsewhere.
Sessions are stored server-side: signing out revokes the cookie, changing the
password or resetting it kills every session of that account, and a client can
press "sign out everywhere" on `/me`.

`/healthz` answers without authentication and returns
`{"ok": true, "version": ..., "active": ...}`; it is meant for monitoring and
returns 503 when the database cannot be read.

Internet exits are granted per client: the administrator ticks the exits a
client may use, and the client puts them in their own order on `/me`.
Traffic uses the first granted exit that is alive; if none of them is up the
client has no internet. Clients without granted exits stay on the automatic
active exit selected by the failover daemon.

Access mode is controlled by `kaskad_panel_expose`: `lan` keeps the port open,
`clients` exposes it only through the tunnel at `https://10.80.0.1:8080`.

## Fail2ban

`fail2ban` is installed by the panel role. A rejected sign-in writes
`KASKAD_AUTH_FAIL ip=<address>` to the journal; five failures within ten
minutes ban the address for an hour on the panel port. The VPN subnet and
localhost are whitelisted, and the sshd jail allows ten attempts. Bans use
iptables, not nftables, and do not touch Docker chains.

```bash
fail2ban-client status kaskad-panel
fail2ban-client set kaskad-panel unbanip 203.0.113.9
```

## TLS

By default the panel generates a self-signed certificate valid for the host
name, its public IP and the tunnel address. Browsers will warn about it.

For a publicly trusted certificate, point a DNS A record at the host, leave
port 80 reachable from the internet and set:

```yaml
kaskad_tls_mode: letsencrypt
kaskad_le_domain: vpn.example.com
kaskad_le_email: admin@example.com
kaskad_le_staging: false   # true while testing: avoids Let's Encrypt limits
```

Then run `ansible-playbook -i inventory.yml playbooks/site.yml --tags panel`.
Certbot validates over HTTP-01 on port 80, which is free while the panel
listens on its own port; issuance does not interrupt the panel. Renewal is
handled by `certbot.timer`, and a deploy hook in
`/etc/letsencrypt/renewal-hooks/deploy/` restarts `kaskad-panel` after a new
certificate is issued.

The certificate is issued for the domain only, so clients opening the panel by
IP will still see the self-signed warning; use the domain name.

## Layout

- `awg0`: clients, `Table=off`, neutral parameters, MTU 1280.
- `awg1..awgN`: exits, `Table=off`, MTU 1340.
- `kaskad-routing.service`: runs `routing.py apply` at boot.
- `kaskad-failover.service`: selects the active internet exit.
- `kaskad-firewall.service`: iptables, MSS clamp, NAT.
- `kaskad-panel.service`: the panel. Runs as root (netlink is required) with
  `ProtectSystem=strict` and `ReadWritePaths` limited to two directories.
- `/run/kaskad` is created by `tmpfiles.d`; the units do not remove it.

## Backups

`kaskad-backup.timer` runs `/usr/local/sbin/kaskad-backup` daily at 03:30
(configurable with `kaskad_backup_oncalendar`) and keeps
`kaskad_backup_keep_days` days. Each run writes one root-only archive to
`/var/backups/kaskad`:

- `panel.db` — a consistent copy made with the SQLite backup API and verified
  with `PRAGMA integrity_check` (the panel keeps running);
- `/etc/kaskad` — panel config, admin password hash, session secret, TLS keys;
- `/etc/amnezia/amneziawg` — tunnel configs and server keys;
- `/etc/letsencrypt` — public certificates and their private keys.

```bash
/usr/local/sbin/kaskad-backup          # run now
systemctl list-timers kaskad-backup.timer
tar -tzf /var/backups/kaskad/kaskad-*.tar.gz | head
```

Restore:

```bash
systemctl stop kaskad-panel kaskad-failover
mkdir -p /root/kaskad-restore
tar -xzf /var/backups/kaskad/kaskad-<stamp>.tar.gz -C /root/kaskad-restore panel.db
install -o root -m 0600 /root/kaskad-restore/panel.db /var/lib/kaskad/panel.db
tar -xzf /var/backups/kaskad/kaskad-<stamp>.tar.gz -C / --exclude panel.db
systemctl start kaskad-panel kaskad-failover
```

The archive lives on the same host, so it survives a bad deploy or a deleted
row, but not the loss of the machine. Copy it off-site if that matters.

## Diagnostics

```bash
awg show                                   # handshakes and traffic
ip rule show                               # our rules
ip route show table 100                    # active internet exit
ip route show table 1001                   # subnets of a routed exit
iptables -S FORWARD | head                 # rules for awg0
cat /run/kaskad/status.json                # exit health
journalctl -u kaskad-failover -u kaskad-panel -u kaskad-routing -n 50
/opt/kaskad/venv/bin/python /opt/kaskad/app/routing.py apply   # rebuild rules
```

If the handshake succeeds but no traffic flows, the problem is on the provider
side (`AllowedIPs`/NAT); locally you can only check `curl -4 ifconfig.me` from
a client.

## Limitations

- Internet exits are health-checked with ICMP through the tunnel. A provider
  that filters ICMP will be considered dead even though it may work.
- Two exits must not share the same provider config: the provider sees one
  public key from two endpoints and roams the session between them. The panel
  rejects such configs.
- Client tunnels are IPv4 only; on dual-stack devices IPv6 bypasses the tunnel.
- The panel is exposed over a self-signed certificate (or a Let's Encrypt one,
  which covers the domain, not the IP) and a password.
- Client sessions are invalidated when the account is disabled or its client
  is disabled; the account and the client are a one-to-one pair.

## License

MIT, see `LICENSE`. The UI kit in `panel/static` is vendored under its own MIT
license, see `panel/static/opencode-ui-NOTICE`.
