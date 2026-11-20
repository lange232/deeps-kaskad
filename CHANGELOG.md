# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.9] - 2026-11-20

### Added

- Accounts can keep up to three destinations that matter to them (HTTP or
  ICMP) in the cabinet (`/me/checks`). The failover probes them through every
  exit the account may use; an exit failing them is skipped for that account's
  configurations while another allowed exit works. Other accounts and the
  global active exit are not affected. Only public targets are accepted, and
  the address is re-checked at probe time so a name that starts resolving into
  private space is not followed.
- The cabinet shows which exit each configuration rides and its state: up,
  degraded, down or no data. The exit is named by its country, then its
  comment, then its name.
- An account page in the cabinet lists its own exit order - the order a new
  configuration starts with - with the same state badges.
- Exits carry a `country` field, editable next to the comment in the exit
  page; the administrator's exit list shows it too.
- `GET /api/me/exits` reports `active`: whether the default route points at
  that exit right now. It is `null` while the failover status is stale, like
  `alive`, `degraded` and `rtt_ms`.

### Changed

- Account checks are probed for a rotating slice of accounts per failover
  cycle, at most four accounts at a time, so a host with many accounts does
  not stretch the ten-second interval. Each account is still covered within a
  few cycles.

### Fixed

- A check whose account has no exit yet is shown as unknown instead of
  passing: nothing was probed, so nothing may look green.
- Checks left behind by a removed account are cleaned up on start, the same
  way as stale exit grants.
- The three-check limit is enforced by the insert itself, so two parallel
  requests cannot add a fourth check.

## [0.4.8] - 2026-11-20

### Changed

- Failover probes every internet exit with ICMP and HTTP targets instead of a
  single ping. An exit that answers ping but cannot reach some destinations is
  marked `degraded`; clients move to a healthy exit, and the degraded one is
  used again only after it is healthy for three rounds and stable for a
  minute. The reason is recorded in `Activity`, and the panel shows a
  `degraded` badge.

## [0.4.7] - 2026-11-20

### Added

- `Sign-in page` on `/settings`: one switch serves a standalone minimal page
  instead of the panel template. Its source has no brand, footer, version,
  favicon, panel styles, scripts or navigation, and names neither the product
  nor its features. It applies to the whole panel.
- `docs/API.md`: a complete reference for the mobile API, with authentication,
  every endpoint, object shapes, the error catalogue, status codes and
  examples. The README links to it.

### Changed

- `/healthz` no longer reports the version, commit or active exit: it answers
  `{"ok": ..., "failover_age": ...}` so an anonymous host does not describe
  itself through the monitoring endpoint.
- Browser-facing errors, redirects and 404s carry no body, and trailing-slash
  redirects are disabled: no framework JSON or extra paths are handed out.
  The mobile API keeps its JSON `detail`.
- While the anonymous sign-in page is on, `/static` is answered with an empty
  404 unless the request carries a valid session.
- Stylesheet comments no longer name the design system or its origin.

## [0.4.6] - 2026-11-20

### Interface

- Configuration details distinguish disabled configurations, missing access,
  missing or old handshakes, and recent handshakes without a working internet
  exit. Exit details separate current routing assignments from alternatives.
- `Activity` records changes to the active internet exit and their reason.
  Destructive actions confirm the impact on configurations, keys or sessions.
- Overview links to affected exits and services. Administration uses a compact
  menu on phones, with account and VPN address visible in configuration search.
- Overview refreshes the active exit, latency, health warnings and counters
  every 20 seconds. A failed refresh keeps the last values and marks them
  `Stale`.
- Configuration search combines with `Recent handshake`, `Disabled` and
  `Unassigned` filters. The access column shows a subnet count rather than
  listing every subnet.
- Configuration and account links in tables and the active exit tile use
  themed styling with visible keyboard focus.
- The cabinet puts downloads and QR codes first; `/me/account` holds password
  and session controls. Admin and cabinet configuration cards share the same
  traffic chart with separate bars for download and upload.
- Configuration cards show how many subnets allowed by the account are
  selected. Administrators can also see ungranted subnets and jump directly
  to the account's access settings.
- Hover, tap or use the keyboard to inspect a traffic interval and see when
  it occurred and how much was downloaded and uploaded. `No sample` is
  distinct from a measured `0 B`; older gaps are not backfilled.

### Added

- Configurations have a `device_id` apart from the name. The mobile app sends
  the device identifier when it creates the configuration and gets the
  existing one back when the same account connects with the same device, so a
  reinstall no longer leaves a duplicate. Two devices of one model get
  `pixel-8` and `pixel-8-2` instead of a name collision. The panel shows the
  identifier in the configuration card.
- A configuration can be renamed: `POST /configs/{id}/name` in the panel and
  `POST /me/configs/{id}/name` in the cabinet, with the same name rules. This
  fixes the old glued names like `sm-s921b-ba9bcded` by hand.
- The cabinet configuration page shows traffic history as a chart for 1h,
  24h, 7d, 30d or 90d, with downloaded and uploaded totals and the peak rate.
  The chart is a server-rendered inline SVG with an interactive interval
  inspector and no external charting library.
- Traffic history: `kaskad-traffic.timer` samples the peer counters every
  five minutes and stores per-configuration deltas (five-minute points for a
  week, hourly for 90 days). `GET /api/me/configs/{id}/traffic?hours=24`
  returns them as ascending `{ts, rx, tx}` points with `step_seconds`.
- The mobile API returns `remote_ip` for every configuration: the peer's
  address as the host sees it, without the port (empty while it never
  connected, the current address after a roam). The app shows it next to the
  tunnel address.

### Changed

- The latency in the exit list of a configuration is two lines again: the
  total in normal text, the split ("client 212 + exit 50 ms") faint under it,
  instead of one grey line with a separator. Both lines keep their height and
  the single-value cells keep their width while the ticker fills them, so rows
  no longer change size when the numbers arrive; the configuration page also
  measures the device round-trip, so the split appears there too.
- Pages no longer reload themselves. A small ticker asks `/status.json` every
  20 seconds and updates live status in place, so
  scroll position, focus and an open `<details>` (QR, config) stay as they
  were. `/status.json` returns the account's own configurations only.

### Fixed

- Removing a configuration from the panel or cabinet clears its traffic
  history and sampler baseline, so a reused ID cannot inherit another
  device's history.
- An expired failover status no longer presents cached exits as healthy: the
  exit list, exit cards, configuration cards, `/status.json`, `/healthz` and
  `/api/me/exits` report the state as unknown, and the live pages show
  `Stale` until fresh routing status is available.
- Traffic chart timestamps follow the reader's timezone rather than the
  server's, and the volume labels are formatted in the browser.
- After a missed traffic sample, the next reading resets the baseline rather
  than assigning traffic from the gap to the current chart interval.
- Downloading a `.conf` from the panel no longer ends up as `name.conf.txt` on
  Android: the browser download is sent as `application/octet-stream`, so
  Chrome keeps the extension from `Content-Disposition`. The mobile API still
  returns `text/plain`, unchanged for the app.

## [0.4.4] - 2026-11-18

### Fixed

- `panel/routing.py` did not add the routed rule for the subnets a
  configuration chose: `client_exits` was read but never joined into
  `routed_links`, so the subnet was configured and its table routed, but
  traffic was never steered into it. Legacy per-client rows were unaffected,
  which hid the bug on the only host that had them.

## [0.4.3] - 2026-11-18

### Added

- Mobile API: `GET /api/me/subnets?config_id=N` lists the subnets the account
  grants with this configuration's choice, and `POST /api/me/subnets` switches
  them on (`subnet_id` repeated, any subset of the grants, empty means none).
- `playbooks/site.yml` refuses to deploy a production inventory
  (`kaskad_production: true`) from a dirty tree, a branch other than `main`
  or a commit without a release tag. Stands are not affected.

## [0.4.2] - 2026-11-18

### Fixed

- `panel/routing.py` queried `client_exits` after closing its own database
  connection, so `kaskad-failover` failed every cycle with "Cannot operate on
  a closed database" and stopped updating the active exit. The query runs
  inside the open connection again; a test now calls `desired_state()` on a
  real database.


### Changed

- Lists open an object by clicking its row: the "open" button and its
  column are gone from accounts, configurations, exits and the cabinet.
  Links and controls inside a row keep their own target, and Enter on a
  focused row opens it too.

### Added

- The configuration page and the cabinet list the subnets the account grants
  as checkboxes: each device switches on the ones it needs, and the generated
  `.conf` carries only those. A new configuration starts with all of them, a
  revoked grant disappears from every configuration, and the choice survives
  later grant changes.
- `panel/routing.py` builds a routed rule only for a subnet the configuration
  actually switched on, so a device no longer reaches a LAN it does not need.

## [0.4.1] - 2026-11-17

### Added

- `/configs/{id}` offers "assign to account" for a configuration created
  before accounts existed: the keys and the address stay, the account's
  exits and their order replace the legacy per-client grants, so the device
  keeps working without a new `.conf`.

### Changed

- The sidebar groups by task (overview, accounts, configs, exits, then the
  journal and settings), marks the current page with `aria-current`, wraps
  into two rows on a phone instead of scrolling out of sight, and the
  cabinet has no one-item sidebar. The topbar drops the redundant "panel"
  badge and links the current object (email, address, interface).
- The panel keeps labels, states and warnings but drops most of the
  explanatory paragraphs and hints: page subtitles, section prose and field
  notes that repeated what the UI already shows.

## [0.4.0] - 2026-11-16

### Added

- Accounts: the email is now the primary entity. An account owns several
  WireGuard configurations, holds the access to exits and signs in at `/me`
  and in the mobile app. Accounts are created only by the administrator.
- `/accounts`, `/accounts/new`, `/accounts/{id}`: grants (internet and routed
  exits), the account exit order with "apply to all configurations", the
  per-account configuration limit, login state, password reset and delete.
- `/configs`, `/configs/new`, `/configs/{id}` replace the old client pages.
  A configuration is one WireGuard peer with server-generated keys; it can be
  disabled (the peer stays) or deleted (the keys are erased).
- The cabinet (`/me`, `/me/configs/new`, `/me/configs/{id}`) lists all the
  configurations of the account, lets the user create new ones up to the
  limit, download `.conf`/QR, reorder exits per configuration, reissue keys,
  disable and delete them, and warns that one configuration is for one device.
- `settings.default_max_configs` (5 by default) with a form on `/settings`;
  the administrator can override it per account, and lowering it below the
  current count is rejected.
- Mobile API: `GET /api/me/configs` (as `configs` in `/api/login` and
  `/api/me`), `POST /api/me/configs`, `GET /api/me/configs/{id}/conf`,
  `POST /api/me/configs/{id}/toggle`, `DELETE /api/me/configs/{id}`, and a
  `config_id` parameter on `/api/me/conf` and `/api/me/exits[?/order]`.

### Changed

- `kaskad_client_keepalive` (25 seconds by default) sets
  `PersistentKeepalive` in every generated client config instead of the
  hard-coded 25.
- When `kaskad_awg0_params` differ from the neutral set, the parameters are
  written into every client config too, so an obfuscated `awg0` works with the
  app; a stock WireGuard client cannot connect to such a host.
- Access is granted to the account, not to a single client: every
  configuration of the account uses the same exits. The internet order stays
  per configuration: a new configuration copies the account order, the user
  can reorder it, and "apply to all" resets it.
- `panel/routing.py`: a configuration whose account has internet exits gets
  its own table; a configuration whose account has no grants gets no internet
  rule at all. Rows without an account keep the old per-client grants and the
  shared table, so an existing database keeps working until they are deleted.
- The physical `clients` table is kept as the configuration store (a new
  nullable `account_id` column) instead of being renamed; `client_exits` and
  `client_internet_exits` are reused as per-configuration rows. New tables:
  `accounts`, `account_exits`.
- The old `users` table is no longer read or created on fresh databases. With
  no automatic migration, the administrator recreates the existing accounts by
  hand and deletes the unassigned rows (see "Upgrading to the account model" in
  the README).
- Compatibility shims for the released app: `/api/login` and `/api/me` still
  return `client` (the first configuration, `null` while the account has none),
  `/api/me/conf`, `/me/conf`, `/me/qr.png` and `/me/exits/move` operate on the
  first configuration.
- `/settings` shows accounts and configurations instead of clients and owns
  the default configuration limit.

### Fixed

- The generated account password (shown once after creating an account or
  resetting it) has the reveal and copy buttons back; they were lost when the
  client page was replaced by the account page. The field is masked until the
  eye is pressed, and the copy button falls back to `execCommand` when the
  clipboard API is unavailable.
- `roles/panel/tasks/tls.yml`: a staging certificate is deleted before the
  real one is issued. `certbot --keep-until-expiring` treated the test
  certificate as valid for 90 days and never replaced it, so a stand deployed
  with `kaskad_le_staging: true` stayed on a staging certificate after the
  flag was turned off.

### Removed

- `/clients*` pages and their templates; `/configs*` replaces them.

## [0.3.9] - 2026-11-14

### Changed

- The Android client APK is taken from the client's GitHub release instead
  of a local build: `scripts/fetch-apk.sh` resolves the release, downloads the
  arm64 asset together with its `SHA256SUMS.txt`, and replaces
  `files/app/app.apk` only when the checksum matches, so a broken download
  never reaches the panel.
- The panel role compares the APK copied to `/var/lib/kaskad/app.apk` with
  the local file and fails the run when they differ.

## [0.3.8] - 2026-11-13

### Added

- Mobile API for the WireGuard Android fork: `POST /api/login` (the same
  client email/password as `/me`; the administrator login is rejected),
  `GET /api/me`, `GET /api/me/conf` (the awg0 client config) and
  `POST /api/logout`. Bearer tokens live 30 days, are stored server-side
  like web sessions, die with a password change or "sign out everywhere",
  and share the web login's rate limits and fail2ban logging.
- Exit switching for the mobile app: `GET /api/me/exits` lists the granted
  internet exits in the user's order with `alive`/`rtt_ms`, and
  `POST /api/me/exits/order` replaces the order in one call (it must list
  every granted exit exactly once).
- The panel distributes the Android client: `GET /download/android` serves
  the APK the deployer drops into `files/app/app.apk` (copied to
  `/var/lib/kaskad/app.apk` by the panel role; the directory is gitignored),
  and `/me` shows an "android app" button next to the config download once
  the file is uploaded.

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

- Admin pages (`overview`, `exits`, the exit card) show the latency this
  device feels: a self-contained script, same as on `/me`, measures the
  browser's round-trip to the panel and adds the server-to-exit part,
  labelled `your device N + exit M ms`. `kaskadAutoRefresh` is defined in
  the document head, because page scripts run before the body-end script —
  previously the call threw `ReferenceError` and pages never refreshed.

### Changed

- The footer no longer repeats the project name; it still shows the version
  and commit.

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
