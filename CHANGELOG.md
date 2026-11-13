# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.7] - 2026-11-13

### Added

- The new-exit form fills `subnets` from the provider config: the peers'
  IPv4 `AllowedIPs` (the default route is ignored), and when those are only
  `0.0.0.0/0`, the network of the `[Interface] Address`. The field is only
  filled while it is empty or still holds the previous suggestion, so manual
  input is never overwritten. The server applies the same fallback when the
  field arrives empty.
- NAT is configured per exit. Internet exits always masquerade; a routed
  exit can opt out when the far side has a route back to the client network.
  The rules live in the `KASKAD-NAT` chain, rebuilt by the panel on every
  apply, one rule per exit; the legacy catch-all `-o awg+` rule is removed.
  `check.yml` compares the chain with the database.
- Exit latency: the failover probe records the ping round-trip to every
  internet exit (`rtt_ms`, refreshed every 10 s). It is shown in the overview,
  the exit list, the exit card and on the administrator's client card. `/me`
  shows the number a client actually feels: the browser measures its own
  round-trip to the panel through `/ping` (median of four samples) and adds
  the panel-to-exit part; both pages refresh every 30 s.
- The administrator's client card shows the total latency for that client:
  the failover daemon pings every enabled client through `awg0` every 10 s
  (`client_ping` in `/run/kaskad/status.json`) and the card adds the exit
  part, e.g. `≈ 50 ms` with `client 10 + exit 40 ms` underneath. When the
  client does not answer ICMP the card shows `exit N ms` and says so in the
  tooltip.

### Fixed

- On `/me` the exit ping no longer looks like a finished total before the
  browser measures its own round-trip: the server value is labelled as
  `panel to exit`, the parts are shown under the number, and a failed
  measurement says `unavailable` instead of silently leaving half of the sum.

## [0.3.6] - 2026-11-12

### Added

- `/healthz`: an unauthenticated liveness endpoint that reports the database
  state, version and active exit (503 when the database is unreadable).
- "sign out everywhere" on `/me`: revokes every session of the account.
- `check.yml` verifies the panel certificate has at least two weeks left,
  that both fail2ban jails are active, and that table numbers are unique and
  client links point at existing rows.
- HTTP and database tests (`tests/test_http.py`): login and throttling, role
  separation, client creation with an account, duplicate emails, grants and
  their order, delete with grants, user pages, key reissue and password change
  with session invalidation, plus the rollback when the tunnel cannot be
  configured. They run with `fastapi.testclient`; `panel/requirements-dev.txt`
  adds the one extra dependency (`httpx`).
- Daily backups: `kaskad-backup.timer` writes one root-only archive with a
  consistent copy of `panel.db`, `/etc/kaskad`, the tunnel configs and the TLS
  certificates to `/var/backups/kaskad`, keeping 14 days by default. The
  database copy is verified with `PRAGMA integrity_check` before packing, and
  the README documents the restore steps.
- `check.yml` warns when the newest backup is older than two days.

### Changed

- Sign-in limits are split: a wrong password blocks only that email from that
  address (5 attempts) and an address after 20 failures, while repeated
  guesses against one email add a growing delay instead of a hard block. The
  administrator can no longer be locked out from the whole internet by
  guessing his address.
- Sessions are stored server-side, so signing out really invalidates the
  cookie; a password change, reset or disabling an account revokes every
  session of that user. Sessions from before this release need one new
  sign-in.

### Fixed

- The snapshot used to restore a running device that had no config file is
  kept (`0600`, path in the error message) when the restore or the peer check
  fails, so a manual recovery is possible; it is removed only after the
  device has been restored and verified.
- When `awg0.conf` is missing but the interface is running, the live device
  configuration is snapshotted with `awg showconf` before anything changes. A
  failed apply restores the device from that snapshot through a temporary
  config file and leaves no file behind (the dump has no Address/MTU/Table,
  so it must not replace `awg0.conf`); a failed snapshot aborts the change
  before the device is touched.
- A failed device rollback is reported as such in the panel: the affected
  pages say the live tunnel could not be rolled back and that `awg0` needs
  inspection, instead of claiming that nothing changed.
- A failed post-apply verification now rolls the **device** back as well:
  the previous `awg0.conf` is restored, `syncconf` is applied again and the
  peer set is compared with the old file; an interface that was started for
  the change is stopped. If the live state cannot be restored the error says
  `rollback failed` instead of looking like a normal apply failure.
- Routing table numbers are reserved in a `table_numbers` registry inside the
  same transaction as the client or exit, so a client and a routed exit can
  no longer receive the same number concurrently. The registry is rebuilt
  from live rows on startup and repairs cross-type duplicates left by older
  databases (the moved object is logged).
- Expired entries are pruned from the login limiter and from the one-time
  password stash instead of growing forever.
- The panel reports the commit from `git describe --always --dirty`, so a
  deploy from an unclean tree no longer claims to run the previous commit.
- When no internet exit is alive, `/run/kaskad/active-exit` is set to `none`
  instead of keeping the last dead interface; `check.yml` accepts that value,
  so the panel and the checks no longer show a dead exit as active.
- `check.yml` also verifies the certificate has at least two weeks left, that
  both fail2ban jails are active, and that table numbers are unique with no
  orphan client links.
- Routing is re-applied when an `awg*` interface appears or disappears, so
  subnet routes of exits that came up after `kaskad-routing.service` are
  created without a restart. A failed apply is retried on the next tick.
- `check.yml` verifies that the subnets of routed exits are present in their
  routing tables.
- Database changes and the WireGuard config are applied in one transaction:
  the config is rendered from the uncommitted rows and `syncconf` runs before
  the commit. A failed apply rolls the client, its account, its keys and its
  grants back and shows an error instead of a 500.
- The result of an apply is verified against `awg show <iface> dump`, so a
  `syncconf` that reports success without changing the device is treated as a
  failure.
- The device line of `awg show dump` is no longer parsed as a peer:
  AmneziaWG prints extra device fields, and the phantom peer inflated peer
  counts and made the verification fail.
- Changing a client's subnet access no longer rewrites and re-applies
  `awg0.conf`, because it does not change the tunnel.

## [0.3.5] - 2026-11-12

### Fixed

- Applying the routing no longer tears down and recreates every rule and
  table: the desired state is diffed against the kernel and only the
  difference runs. A panel change used to briefly drop every client's
  traffic; now untouched clients see no interruption.
- Prefixes from the database are normalized to the kernel form
  (`10.90.0.2/32` vs `10.90.0.2`), so the diff does not churn.
- A client table keeps the exit the failover daemon chose instead of being
  reset to the first choice on every apply.

## [0.3.4] - 2026-11-12

### Fixed

- `routing.py` now checks every `ip rule` and `ip route` command, reports
  failures in the journal and exits non-zero, instead of silently continuing.
- The failover daemon reports the exit it read back from the routing table,
  never the one it merely tried to install; failed changes are logged.
- Pages with forms no longer auto-refresh while a field is focused or has
  unsaved input.
- The README describes manual exit selection as the `manual_exit` setting,
  not the removed `/run/kaskad/requested-exit` file.

### Changed

- Routing table numbers are allocated in the database and stored on the
  exit/client row. The old `1000 + id` and `3000 + id` ranges could collide
  after enough create/delete cycles.

## [0.3.3] - 2026-11-12

### Fixed

- Deleting a client or an exit now removes its `client_internet_exits`
  rows. SQLite reuses freed ids, so a new client or exit could otherwise
  inherit the granted internet exits of the deleted one.
- On startup the panel also drops links that point at a missing client or
  exit, repairing databases created before this fix.

## [0.3.2] - 2026-11-12

### Added

- Fail2ban with a panel jail: rejected sign-ins are logged as
  `KASKAD_AUTH_FAIL ip=...` in the journal, and an address is banned for an
  hour after five failures. The VPN subnet and localhost are never banned.
- The sshd jail is enabled with a ten-attempt threshold.
- Bans use iptables and only the panel port, so Docker chains and SSH from
  other networks are not affected.

## [0.3.1] - 2026-11-12

### Added

- Exits have a public comment, set when the exit is created and editable in
  its card. Clients see the comment instead of the interface name (`awg3`)
  in the exit list and in the "in use" line.

## [0.3.0] - 2026-11-12

### Added

- Internet exits are granted per client by the administrator and ordered by
  the client in the panel; traffic uses the first granted exit that is alive.
- Each client with granted exits gets its own routing table, so the choice is
  independent of the shared automatic exit.
- `/me` shows the granted exits with their state, the exit in use and
  up/down controls for the order.
- The client page has an internet exits section for the administrator.

### Fixed

- The failover daemon repairs a missing default route even when the
  active-exit file already names the right interface, which could happen
  after a service restart.

## [0.2.3] - 2026-11-12

### Added

- Optional Let's Encrypt certificate for the panel: set
  `kaskad_tls_mode: letsencrypt` with `kaskad_le_domain` and
  `kaskad_le_email`. Certbot issues over HTTP-01 on port 80, the panel keeps
  serving during issuance, and a renewal hook restarts it after a new
  certificate.
- The setup fails early with a clear message when the DNS record does not
  point at the host or port 80 is unreachable.

## [0.2.2] - 2026-11-12

### Added

- A copy button next to the generated account password, with a fallback for
  browsers that block the clipboard API.

## [0.2.1] - 2026-11-12

### Changed

- The new client form creates the account together with the client: email is
  required, the password can be set or generated and is shown once on the
  client page.
- An email that already belongs to an account is rejected before the client
  is created.

## [0.2.0] - 2026-11-12

### Added

- Per-client accounts: the administrator creates an account for a client in
  the panel, the email is the login, and the password is generated and shown
  once.
- Self-service page `/me`: config download, QR code, WireGuard installation
  instructions, key reissue and password change.
- Role-based access: administrators keep the environment password, clients
  can only reach their own config; users cannot open admin pages.
- Sessions carry the role and a token version, so a password reset, account
  disable or client disable signs existing sessions out immediately.
- Login rate limiting counts attempts per IP and per email.
- Account column on the clients page and account management in the client
  detail page.

### Fixed

- Passwords use a shared pbkdf2 implementation for the administrator and
  client accounts.

## [0.1.0] - 2026-11-12

### Added

- Two-hop VPN: a stock WireGuard entry (`awg0`) with one or more external
  AmneziaWG/WireGuard exits (`awg1..awgN`).
- Two exit modes: `internet` with strict-priority failover and `routes` for
  specific subnets with per-client rules.
- Panel (FastAPI + SQLite) for clients and exits, client configs and QR codes,
  service status and an action journal.
- Plain WireGuard exits by injecting neutral AmneziaWG parameters.
- Ansible deployment with roles for base packages, AmneziaWG, the panel and
  the network layer, plus a diagnostic playbook.

### Fixed

- Diagnostics now verify per-client routing rules against the panel database
  and the current iptables rules instead of the old subnet-wide ones.
- Manual exit selection is stored in the database and stays pinned while the
  exit is alive, instead of reverting on the next failover tick.
- The panel no longer needs write access to `/run`, which is read-only under
  `ProtectSystem=strict`.
- Routing tables are tracked in the database, so exits with ids above 64 are
  cleaned up too.
