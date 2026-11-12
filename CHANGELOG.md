# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- HTTP and database tests (`tests/test_http.py`): login and rate limiting,
  role separation, client creation with an account, duplicate emails, grants
  and their order, delete with grants, user pages, key reissue and password
  change with session invalidation, plus the rollback when the tunnel cannot
  be configured. They run with `fastapi.testclient`; `panel/requirements-dev.txt`
  adds the one extra dependency (`httpx`).
- Daily backups: `kaskad-backup.timer` writes one root-only archive with a
  consistent copy of `panel.db`, `/etc/kaskad`, the tunnel configs and the TLS
  certificates to `/var/backups/kaskad`, keeping 14 days by default. The
  database copy is verified with `PRAGMA integrity_check` before packing, and
  the README documents the restore steps.
- `check.yml` warns when the newest backup is older than two days.

### Fixed

- Routing is re-applied when an `awg*` interface appears or disappears, so
  subnet routes of exits that came up after `kaskad-routing.service` are
  created without a restart. A failed apply is retried on the next tick.
- `check.yml` verifies that the subnets of routed exits are present in their
  routing tables.

## [0.3.6] - 2026-11-12

### Fixed

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
