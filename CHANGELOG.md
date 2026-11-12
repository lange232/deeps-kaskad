# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
