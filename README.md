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

## Accounts and configurations

The account is the email. It signs in at the panel and in the Android app,
owns its WireGuard configurations and holds the access to exits:

```
account alice@example.com
├── account_exits   finland, amsterdam, lab-subnet   (what may be used)
└── configurations
    ├── alice-laptop   10.80.0.2   order: finland, amsterdam
    └── alice-phone    10.80.0.3   order: amsterdam, finland
```

- an account can have several configurations; the default limit is 5 and is
  set on the settings page, while the administrator can override it per
  account;
- access is granted to the **account**: it decides which internet exits and
  which subnets may be used at all;
- the configuration picks what it actually uses. The internet **order** is a
  per-configuration copy of the account order: a new configuration copies it,
  the user can reorder it, and "apply to all" resets every configuration to
  the account order. The **subnets** are a checklist: the account grants a
  set, each configuration switches on the ones that device needs (all of them
  by default), and the generated `.conf` carries only those;
- the server generates the keys and the address for every configuration, both
  when the administrator creates it and when the user does it in the cabinet;
- accounts are created only by the administrator;
- a configuration can be **disabled** (the peer stays, the tunnel stops) or
  **deleted** (the peer and its keys are erased).

One configuration is meant for one device: a WireGuard peer keeps one session,
so two devices imported from the same `.conf` keep taking it over from each
other. The cabinet says so next to "new configuration".

Rows in the `clients` table are configurations, not devices; the physical
table name is kept for compatibility.

## Two access classes

| Class | What it gets | AllowedIPs | DNS |
|---|---|---|---|
| internet | full tunnel via the first alive granted exit | `0.0.0.0/0` | `1.1.1.1, 1.0.0.1` |
| subnets | only the CIDRs the configuration switched on | union of subnets | DNS of its exit |
| both | internet plus subnets | `0.0.0.0/0` | global |

Access is granted per account in the panel: internet exits and routed exits
are checkboxes on the account page. Which of the granted subnets a device
actually uses is a per-configuration checklist on the configuration page (and
in the cabinet), because a phone rarely needs the office LAN. An account with neither has no access at
all. A configuration created before accounts existed keeps its old per-client
grants until it is deleted and recreated under an account.

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

## Own exit nodes

An exit does not have to come from a provider. `roles/exit` turns a plain
Ubuntu host into one: it installs AmneziaWG, enables forwarding, generates the
interface key on the host itself, writes `awg0` with the obfuscation
parameters from the inventory and NATs the transit range to the uplink.

```bash
cp inventory.exit.example.yml inventory.exit.yml   # gitignored
ansible-playbook -i inventory.exit.yml playbooks/exit.yml --check
ansible-playbook -i inventory.exit.yml playbooks/exit.yml
```

The run prints the node's public key. The S1 side is built from it: transit
`10.9.0.2/32`, `Endpoint = <name>:51820`, the same `Jc/S*/H*`, `AllowedIPs =
0.0.0.0/0`; then it is pasted into `/exits/new` with mode `internet`. The
private key of S1 stays in `state/` on the control machine and never reaches
the node.

Several S1 hosts can share one exit: `kaskad_exit_peers` takes a list, and
every host gets its own key and its own transit address (`10.9.0.3/32` for the
second, and so on). One key on two hosts makes the server move the session
between them, which is the same rule the provider exits follow.

Both ends must carry the same obfuscation values - they are per tunnel, not
per server - and changing them means changing both and restarting both
interfaces. The magic headers `H1..H4` must be distinct and below 2^31; an
out-of-range value makes `awg setconf` fail with a bare `configuration parsing
error`. The panel does not edit an exit config, so point the endpoint at a
DNS name: moving the node to another address later means recreating the exit.

## Client configs

Every generated `.conf` carries `PersistentKeepalive`, 25 seconds by default
(the WireGuard recommendation behind NAT). It is tunable per installation:

```yaml
kaskad_client_keepalive: 10        # wake up every 10 s instead of 25
```

A smaller value helps when a NAT drops the mapping between keepalives, but it
does not help against a network that blocks the protocol itself: a Wi-Fi or
ISP that kills plain WireGuard after a few seconds of idle UDP — the tunnel
comes up, traffic flows, then "we stopped hearing back after 15 seconds" while
the server keeps answering — is DPI, not a timeout. Keepalive does not fix
that; obfuscation on `awg0` does, see [Obfuscated `awg0`](#obfuscated-awg0).

The value is read when the config is generated, so an existing tunnel must be
re-imported to pick up a change.

## Obfuscated `awg0`

`awg0` is plain WireGuard by default: any stock WireGuard client can connect,
and DPI can recognise the protocol. When that matters, give `awg0` the same
obfuscation the exits use:

```yaml
kaskad_awg0_params:
  Jc: 4
  Jmin: 40
  Jmax: 70
  S1: 50
  S2: 100
  S3: 0
  S4: 0
  H1: 1048573
  H2: 1234567
  H3: 1500001
  H4: 1999999
  ContentPaddingAddition: 0
  RandomTrailers: "off"
  DisableCookies: "off"
```

`H1..H4` must be the same on both sides and may be any distinct numbers; pick
random ones so installations differ. When the parameters differ from the
neutral set, the panel writes them into every client `.conf` as well, so the
app configures its side identically. A plain WireGuard client can no longer
connect to such a host — the client must understand AmneziaWG parameters.

The port is not part of the obfuscation: `kaskad_awg0_port` (51820 by default)
can be moved to 443/udp if that helps on the networks you care about; remember
the firewall role opens the configured port.

## Client routing

`panel/routing.py` applies the state from the database:

```
10000  from 10.80.0.7 to 192.168.50.0/24 iif awg0 lookup 1001
20000  from 10.80.0.7 iif awg0 lookup 1002
```

- specific subnets always win over the default route (lower number wins);
- a configuration whose account has internet exits gets its own table
  (`1000 + n`) holding those exits in the configuration's order, so each
  configuration switches independently;
- the internet rule is installed **only when the account actually has an
  internet exit granted** — otherwise a subnets-only account would still leave
  through the internet exit, and an account with no grants has no internet at
  all, by design;
- table `100` holds the active internet exit for configurations from before
  accounts existed and is managed by the failover daemon;
- exit tables start at `1000`;
- the script removes its own rules before every apply, so deleting a
  configuration or an exit leaves no stale state.

**Never use tables 253/254/255** — these are `default`, `main` and `local`.
A range of `201..264` once wiped the main table and cut a host off the network.
Exit tables start at 1000 and the system tables are excluded explicitly.

## Failover

Every 10 seconds each enabled internet exit is probed through its own
interface: a TCP handshake to a public address (ICMP is a fallback for networks
that drop TCP probes), then three HTTP targets in three networks. Each target's
hostname is resolved **through the exit**, with the same resolver clients use,
and the fetch is pinned to the address that answer returned (`curl
--resolve`). A probe therefore sees the internet the way a client of that exit
does; the server's own DNS has no say. The first alive one by ascending
`priority` becomes active, and the route `default dev awgN table 100` is
replaced. An exit that answers the transport probe but fails two of the three
HTTP targets is marked `degraded` after 3 bad rounds; clients and the active
exit prefer a healthy one, and the degraded exit returns only after 3 good
rounds and 60 seconds of stability. An exit is dead after 3 failed transport
probes and alive after 2 successful ones. Probes are bounded in time: a probe
that outlives the budget keeps its previous verdict, and account checks run on
their own pool so they never hold up the route or the status file. The last
result of every target is visible on the exit page, so a `degraded` badge says
which destination failed instead of only that something did. Client conntrack
entries are flushed on switch, otherwise the old NAT would send packets to the
wrong address.

A configuration can also be pinned to one exit: the cabinet offers "use" next
to every granted exit, and the pinned one is used even when the failover marks
it degraded, as long as its tunnel is alive. If it dies, the configuration's
order takes over again until it returns. This is how a client keeps a slower
exit that reaches what it needs instead of a healthy one that does not.

An account can keep up to three of its own destinations — an HTTP URL or a
host for ICMP — in the cabinet (`/me/checks`). They are probed through every
exit the account may use; an exit that fails them for that account is skipped
for that account's configurations only, and only while another allowed exit
works. Other accounts and the global active exit are not affected. Checks are
probed for at most four accounts per cycle, rotating, so many accounts cannot
stretch the ten-second interval; a host with more accounts sees each of them
every few cycles.

An exit can carry a `country` next to its comment. The cabinet names the exit
a configuration rides by that country, falling back to the comment and then
the name, so a client reads a place instead of an internal interface.

Manual switching is a button in the panel: the chosen interface is stored in
the `manual_exit` setting and stays pinned while that exit is alive; "return
to auto" clears it. State lives in `/run/kaskad/status.json` and
`/run/kaskad/active-exit`.

Wrong or slow exit: the latency column is the ping the failover probe makes
from the server to each exit; `/me` adds the client's own round-trip to the
panel, measured in the browser, so the number there is what the client feels.

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
leak through `eth0`.

NAT lives in its own `KASKAD-NAT` chain, one masquerade rule per exit. Every
internet exit always masquerades; a routed exit can keep the client address
when the far side routes `10.80.0.0/24` back to this server (checkbox `NAT` on
the exit, off by exception). The panel rebuilds the chain on every routing
apply; the firewall unit only guarantees the chain and the `POSTROUTING` jump,
so a restart of that unit does not wipe NAT. Client-to-client traffic is
untouched.

## Requirements

- Ubuntu 24.04, root access over SSH, `ansible-core`.
- The `amneziawg` kernel module from `ppa:amnezia/ppa` (or local packages, see
  `files/awg/README.md`). If DKMS fails on your kernel, `amneziawg-go` works
  as a userspace replacement with the same configs.

## Deployment

```bash
cp inventory.example.yml inventory.yml   # hosts, SSH key, panel port
ansible-playbook playbooks/site.yml --check
ansible-playbook playbooks/site.yml
scripts/check.sh demo
```

Tags: `base`, `amneziawg`, `panel`, `entry`.

Addresses, the panel port and TLS belong in the inventory, which is
gitignored; `group_vars/all.yml` holds only shared defaults and is the same
for every host. `inventory.example.yml` is the template.

A production inventory sets `kaskad_production: true`, and then `site.yml`
refuses to run unless the repository is a clean `main` on a release tag: a
working tree with half-merged branches must not reach a live host. Stands
leave the flag out and deploy from any branch.

Tests:

```bash
python3 -m unittest discover -s tests          # logic only, no extra deps
/opt/kaskad/venv/bin/pip install -r panel/requirements-dev.txt
/opt/kaskad/venv/bin/python -m unittest discover -s tests   # + panel HTTP tests
```

`kaskad_awg_packages_mode` is `ppa` by default; switch it to `local` for hosts
without access to Launchpad.

`state/` is gitignored: provider configs, client keys and migration seeds.

### Upgrading to the account model

The panel used to keep one account per client (`users.client_id UNIQUE`); an
account now owns several configurations. There is no automatic data migration:

1. back up the database (see [Backups](#backups));
2. deploy as usual — the schema is extended in place, the old `users` table and
   the old rows in `clients` are left untouched. Existing sessions are dropped
   on the first start: account ids can collide with old user ids, so a cookie
   from before the upgrade must not sign in as a new account;
3. open `/accounts`, recreate the accounts by hand, grant the exits and create
   the configurations (this generates new keys, so devices need the new
   `.conf`);
4. deal with the old rows: they appear as "unassigned" on `/configs` and keep
   working with their old grants. Each one can be either

   - attached to an account from its page ("assign to account"): the keys and
     the address stay, the account's exits and their order replace the old
     grants, so the device keeps its tunnel. If the access class changes (for
     example the account has only subnets), download the `.conf` again — the
     keys are the same but `AllowedIPs` and `DNS` are not; or
   - deleted, which erases its keys and releases its routing table.

Account-page and configuration-page paths are `/accounts` and `/configs`; the
old `/clients*` routes are gone, so bookmarks must be updated.

## Versioning

`VERSION` in `develop` announces the upcoming release; its notes live under
`Unreleased`. The heading gets the number and the date, and the tag is
created, when the branch is merged into `main`. A patch release is for an
urgent fix, not for every commit.

The panel shows the version and the commit it runs; the commit comes from
`git rev-parse --short` with a `-dirty` suffix when the tree has uncommitted
changes, so a deploy from an unclean tree is visible.

## Panel

`https://<host>:<port>`, FastAPI + SQLite. The port is `kaskad_panel_port`
from the inventory (`8080` when it is not set). The certificate is
self-signed by default; see [TLS](#tls) to use Let's Encrypt.

The panel has two kinds of sign-in:

- **administrator** — login `admin` and the password generated during the
  first deploy and printed once; only its hash is stored in
  `/etc/kaskad/panel.env`. Reset: delete the file, run `--tags panel`, restart
  `kaskad-panel`.
- **account** — an email created by the administrator; the password is
  generated or set there and shown once. The account signs in at `/me`, sees
  all its configurations, downloads a `.conf` or scans a QR for any of them,
  creates up to its limit, disables or deletes them, reissues keys, orders its
  exits per configuration and changes its password.

The administrator manages accounts (`/accounts`), configurations
(`/configs`), exits, service status and the action journal. A configuration
created before accounts existed shows up as "unassigned" until it is attached
to an account from its page. On the account
page: grants, exit order with "apply to all", the configuration limit, login
state, password reset, delete. On the configuration page: download, QR, key
reissue, link to the account, internet order, disable, delete.

Pages: `/`, `/exits`, `/accounts`, `/configs`, `/journal`, `/settings`, plus
`/accounts/new`, `/accounts/{id}`, `/configs/new`, `/configs/{id}` and the
cabinet under `/me`, `/me/configs/new`, `/me/configs/{id}`, `/me/checks` and
`/me/account`
(password and sessions). Both the admin and cabinet configuration pages draw the traffic history for 1h, 24h, 7d, 30d or 90d
(`?range=`), with the downloaded and uploaded totals and the peak rate; the
chart uses paired SVG bars, leaving missing time buckets blank.

`/settings` has a `Sign-in page` switch: it serves a standalone minimal page
with its own inline styles instead of the panel template, so the source names
neither the product nor what it does, and loads none of the panel's scripts,
styles or navigation. While it is on, `/static` is answered with an empty 404
unless the request carries a valid session. It applies to the whole panel, not
to one account, and does not change the authenticated pages. The domain and
the TLS certificate stay visible.

Sign-in limits: five failed attempts for the same email from the same address
block that pair for five minutes, twenty failures from one address block the
address, and repeated guesses against one email only add a growing delay — so
nobody can lock the administrator out by guessing his address from elsewhere.
Sessions are stored server-side: signing out revokes the cookie, changing the
password or resetting it kills every session of that account, and an account can
press "sign out everywhere" on `/me`.

Pages update handshakes, traffic and exit state in place every 20 seconds
(`/status.json`, the account's own numbers only): the page itself is not
reloaded, so scroll, focus and an open QR or config stay.

The failover daemon writes `/run/kaskad/status.json` every ten seconds. The
panel trusts it for sixty seconds; after that every page, `/status.json` and
`/healthz` treat the exits as unknown and show `Stale` instead of repeating
the last known state.

`/healthz` answers without authentication and returns
`{"ok": true, "failover_age": 10}`; it is meant for monitoring and returns 503
when the database cannot be read or the failover status is stale. It says
nothing about the product or the release, so a host with an anonymous sign-in
page does not describe itself through this endpoint either.

Internet exits are granted per account: the administrator ticks the exits an
account may use, and every configuration puts them in its own order on `/me`
(or the user does it in the app). Traffic uses the first granted exit that is
alive; if none of them is up the configuration has no internet. Configurations
created before accounts existed stay on the automatic active exit selected by
the failover daemon.

Access mode is controlled by `kaskad_panel_expose`: `lan` keeps the port open,
`clients` exposes it only through the tunnel at `https://10.80.0.1:<port>`.

### Mobile API

A small bearer-token API for the mobile app (a WireGuard Android fork). It
uses the same accounts as `/me`; the administrator login is not accepted.
Form-encoded requests, JSON responses, the same sign-in limits and fail2ban
logging as the web login (`via=api` in the journal line).

The full reference, with request and response bodies, the error catalogue and
examples, is in [`docs/API.md`](docs/API.md). The list below is a quick index.

```
POST /api/login                   email, password -> {token, expires_at, email, client, configs}
GET  /api/me                      -> account and its configurations
POST /api/me/configs              name, device_id (optional) -> creates a configuration;
                                    the same device_id on the same account returns the
                                    existing configuration instead of a second one
GET  /api/me/conf?config_id=N     the awg0 config of that configuration (first by default)
GET  /api/me/configs/{id}/conf    the same, addressed by configuration
POST /api/me/configs/{id}/toggle  enable or disable one configuration
DELETE /api/me/configs/{id}       delete one configuration and its keys
GET  /api/me/exits?config_id=N    granted internet exits in this configuration's
                                    order (id, name, comment, alive, rtt_ms,
                                    status_fresh); an empty list means the
                                    account has no grants; alive and rtt_ms are
                                    null while the failover status is stale
POST /api/me/exits/order          exit_id (repeated) + config_id -> sets the order;
                                    the list must contain every granted exit exactly once
GET  /api/me/subnets?config_id=N  subnets the account grants, with the choice of this
                                    configuration (id, name, comment, routes, enabled)
POST /api/me/subnets              subnet_id (repeated) + config_id -> switches subnets on;
                                    any subset of the grants, an empty list turns all off
GET  /api/me/configs/{id}/traffic?hours=24
                                    traffic history: {config_id, step_seconds, points};
                                    points are {ts, rx, tx} deltas in ascending order,
                                    five-minute buckets up to a week, hourly up to 90 days
POST /api/logout                  revokes the token
```

Changing the subnets changes `AllowedIPs` and `DNS` of the generated `.conf`,
so the device has to import the file again; the keys stay the same.

`client` is a compatibility field: the account's first configuration (`null`
while the account has none), for app versions that predate the account model.
New code should use `configs`.

Each configuration in `configs` carries `remote_ip`: the peer's address as the
host sees it, without the port. It is an empty string while the peer has never
connected, and the current address after a roam.

`kaskad-traffic.timer` runs every five minutes: it reads the peer counters
from `awg show awg0 dump`, stores the delta per configuration and keeps
five-minute points for a week and hourly points for 90 days. A counter that
went backwards (reboot, reissued peer) starts a new baseline instead of a
negative delta; a gap in the history means the sampler was down. The endpoint
uses 300-second points for `hours` up to 168 and 3600 beyond, and `step_seconds`
in the response tells the client which one it got.

Each configuration carries `device_id`, the identifier the app sends on its
first connect (`[A-Za-z0-9-]`, 8 to 64 characters). The name stays human: the
app sends the device model there, and the panel can rename a configuration
(`/configs/{id}` and `/me/configs/{id}`), so the two never have to be glued
into one ugly string. `device_id` is unique per account. If the name the app
sends is already taken, creation through the API appends `-2`, `-3`; the
response carries the name that was actually used.

API tokens live 30 days, are stored server-side like web sessions, and die
with a password change or "sign out everywhere".

### Android client

The panel distributes the companion Android app, the
[deeps-kaskad-client](https://github.com/lange232/deeps-kaskad-client) fork of
WG Tunnel. Releases are published there as arm64 APKs; fetch the latest one
into the repo and deploy it:

```bash
scripts/fetch-apk.sh              # latest release -> files/app/app.apk
scripts/fetch-apk.sh --tag v5.8.2 # or a pinned release
ansible-playbook -i inventory.yml playbooks/site.yml --tags panel
```

The APK copy carries the `apk` tag. A code-only deploy on a slow link skips
it: `--tags panel --skip-tags apk`. The file stays as it was on the host.

The script reads the GitHub releases API (one request per run, set
`GITHUB_TOKEN` if the anonymous 60/hour limit is a problem), downloads
`*-arm64.apk` together with `SHA256SUMS.txt` from the same release and
replaces `files/app/app.apk` only when the checksum matches. The panel role
then copies it to `/var/lib/kaskad/app.apk`, checks the copy on the host and
serves it at `/download/android` without authentication; the client's `/me`
page shows an "android app" button once the file is uploaded. `files/app/` is
gitignored.

Dropping a locally built APK into `files/app/app.apk` still works, but then it
must be the same build that was published: users update in place, so a
different signing key or a lower `versionCode` than the installed client means
a reinstall or a refused update. Releases are `v<versionName>` with
`versionCode` in `gradle/libs.versions.toml`; never reuse a version number for
a different build.

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
- Own exit nodes run `playbooks/exit.yml` and nothing else from this
  repository; the panel on S1 owns their client config.
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
rm -f /var/lib/kaskad/panel.db-wal /var/lib/kaskad/panel.db-shm
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

- Internet exits are probed with ICMP and two HTTP targets. A provider that
  filters ICMP is considered dead; a destination it blackholes can still be
  missed unless the account adds it as one of its own checks.
- Two exits must not share the same provider config: the provider sees one
  public key from two endpoints and roams the session between them. The panel
  rejects such configs.
- Client tunnels are IPv4 only; on dual-stack devices IPv6 bypasses the tunnel.
- The panel is exposed over a self-signed certificate (or a Let's Encrypt one,
  which covers the domain, not the IP) and a password.
- Account sessions are invalidated when the account is disabled or its
  password is reset. A configuration belongs to an account; disabling one
  configuration only stops that peer, not the account.

## License

MIT, see `LICENSE`. The UI kit in `panel/static` is vendored under its own MIT
license, see `panel/static/opencode-ui-NOTICE`.
