# Panel HTTP API

Reference for the HTTP interface of a deployed kaskad panel. It covers the
bearer-token API used by the Android client, the public monitoring endpoints
and the internal endpoint the panel's own pages poll. The HTML administration
and cabinet pages are not part of this API: they use a session cookie, HTML
forms and a CSRF token.

- Base URL: `https://<host>:<port>` (TLS with a Let's Encrypt or self-signed
  certificate). The port comes from the host inventory (`kaskad_panel_port`);
  `8080` is the default and `443` is common. Examples below use `:8080`.
- API prefix: `/api/`.
- Panel version at the time of writing: `0.4.x`.

## Conventions

- Requests with a body are `application/x-www-form-urlencoded`. The API does
  not accept JSON request bodies.
- Responses are JSON (`application/json; charset=utf-8`) unless an endpoint
  says otherwise. The `.conf` endpoints return `text/plain; charset=utf-8`.
- Authentication is `Authorization: Bearer <token>`.
- There is no CSRF token on API calls: the bearer token is the only proof.
- API errors are `{"detail": "<message>"}`. Validation errors are
  `{"detail": [{"type": ..., "loc": [...], "msg": ...}]}` with status `422`.
- Browser (non-API) errors carry an empty body. Do not rely on a JSON `detail`
  outside `/api/`.
- Field names and status codes are stable. New fields may be added; clients
  must ignore unknown keys and must not assume an exact key set.

## Authentication

`POST /api/login` exchanges an account email and password for a bearer token.
Only regular accounts can sign in: the administrator login (`admin`) is
rejected, and a disabled account is rejected like a wrong password.

- Token lifetime: **30 days**.
- `expires_at` is a Unix timestamp in seconds.
- The token is opaque and signed; it is stored server-side and can be revoked.
- `POST /api/logout` revokes the presented token.
- Changing the password, resetting it, or "sign out everywhere" revokes every
  token of the account.
- Disabling the account invalidates its tokens.
- A revoked, expired or malformed token gets `401` with `sign in again`.

### Sign-in limits

Failed sign-ins are counted per address and per address + email for 5 minutes:

- 5 failures for the same address and email block that pair with `429`;
- 20 failures from one address block that address with `429`;
- after 3 failures for one email each further attempt is delayed by up to 3
  seconds;
- a successful sign-in clears the counters for that account.

Failures are logged as `KASKAD_AUTH_FAIL ... via=api` and written to the
journal. The response is always `401 wrong email or password`, so it does not
reveal whether the account exists or is disabled.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/login` | Exchange email and password for a token |
| GET | `/api/me` | Account and its configurations |
| POST | `/api/logout` | Revoke the presented token |
| POST | `/api/me/configs` | Create a configuration, or return this device's |
| POST | `/api/me/configs/{id}/toggle` | Enable or disable a configuration |
| DELETE | `/api/me/configs/{id}` | Delete a configuration, its keys and history |
| GET | `/api/me/conf` | Download a `.conf` (first configuration by default) |
| GET | `/api/me/configs/{id}/conf` | Download the `.conf` of one configuration |
| GET | `/api/me/configs/{id}/traffic` | Traffic history of one configuration |
| GET | `/api/me/exits` | Internet exits available to a configuration |
| POST | `/api/me/exits/order` | Set the configuration's exit order |
| POST | `/api/me/exits/pin` | Pin a configuration to one exit, or back to automatic |
| GET | `/api/me/subnets` | Subnets granted to the account and their choice |
| POST | `/api/me/subnets` | Switch subnets on or off for a configuration |
| GET | `/api/me/presets` | Route presets for the client's own split tunneling |
| POST | `/api/me/presets` | Add a personal route preset |
| DELETE | `/api/me/presets/{id}` | Delete one of your own presets |
| GET | `/api/android` | Public: Android client version, digest and download URL |
| GET | `/download/windows` | Public: Windows client MSI |

Object shapes are collected in [Data objects](#data-objects).

---

### POST /api/login

Form fields:

| Field | Required | Notes |
|---|---|---|
| `email` | yes | Account email, case-insensitive |
| `password` | yes | 12 characters or more |

Response `200`:

```json
{
  "token": "eyJyb2xlIjogInVzZXIi...",
  "expires_at": 1797393600,
  "email": "user@example.com",
  "client": { "id": 4, "name": "pixel-8", "...": "..." },
  "configs": [ { "id": 4, "name": "pixel-8", "...": "..." } ]
}
```

- `client` is a compatibility field: the account's first configuration by id,
  or `null` when the account has none. New code should use `configs`.
- `configs` contains full [configuration objects](#configuration).

Errors: `401 wrong email or password`, `401` for a disabled account,
`429 too many attempts, wait 5 minutes`, `422` for a missing password.

---

### GET /api/me

Requires a bearer token. Returns the same account view without a token:

```json
{
  "email": "user@example.com",
  "client": null,
  "configs": []
}
```

---

### POST /api/logout

Revokes the token from the `Authorization` header. Calling it without a token
is not an error.

```json
{"ok": true}
```

---

### POST /api/me/configs

Creates a configuration with server-generated keys. Also acts as an idempotent
"get or create" for a device.

Form fields:

| Field | Required | Notes |
|---|---|---|
| `name` | no | Latin letters, digits, `.`, `-`, up to 32 characters, starts with a letter or digit. If omitted, the server derives a name from the email |
| `device_id` | no | Latin letters, digits, `-`, 8 to 64 characters. The app sends its stable device identifier |

Behaviour:

- With a `device_id` that the account already has, the existing configuration
  is returned and no second one is created.
- If `name` is already taken and the call creates a new configuration, the
  server appends `-2`, `-3`, and so on. The response carries the name actually
  used.
- The account configuration limit applies. The default is 5; the
  administrator can override it per account and in the settings.

Response `200` (not `201`):

```json
{
  "config": {
    "id": 7,
    "name": "pixel-8",
    "device_id": "a1b2c3d4e5f60718",
    "ip": "10.80.0.7",
    "internet": true,
    "enabled": true
  },
  "configs": [ { "id": 7, "name": "pixel-8", "...": "..." } ]
}
```

`config` is the created or reused configuration (a shorter shape);
`configs` is the full current list.

Errors:

| Status | Detail |
|---|---|
| 400 | `device_id: latin letters, digits, dash; 8 to 64 characters` |
| 400 | `name: latin letters, digits, dot, dash; up to 32 characters` |
| 409 | `this account already has N of M allowed configurations` |
| 409 | `configuration already exists` (a raced request without a known device) |
| 500 | `the WireGuard config could not be applied; not saved` |

If applying the new configuration to the live interface fails, the row is
rolled back and the error is returned.

---

### POST /api/me/configs/{id}/toggle

Enables a disabled configuration or disables an enabled one. No body.

```json
{"ok": true, "enabled": false}
```

Errors: `404 configuration not found`, `500` when the generated `awg0`
configuration cannot be applied.

---

### DELETE /api/me/configs/{id}

Deletes the configuration, its keys, its routing table allocation and its
traffic history. This cannot be undone; the device loses access immediately.

```json
{"ok": true}
```

Errors: `404 configuration not found`, `500` when the live interface cannot be
updated.

---

### GET /api/me/conf?config_id=N

Returns the WireGuard/AmneziaWG configuration as plain text, ready to import.
`config_id` is optional; `0` or an omitted value means the account's first
configuration.

- Content type: `text/plain; charset=utf-8`.
- No `Content-Disposition`: the app reads the body directly.
- The browser download (`/me/configs/{id}/conf`) is different: it is sent as
  `application/octet-stream` with a `.conf` filename, so Android Chrome does
  not rename it to `.txt`.

Errors: `409 no configuration yet; create one first`, `404 configuration not
found`, `400 configuration has neither internet nor subnets assigned`.

---

### GET /api/me/configs/{id}/conf

The same body as above, addressed by configuration id.

---

### GET /api/me/configs/{id}/traffic?hours=24

Traffic deltas recorded by the five-minute sampler.

| Query | Default | Notes |
|---|---|---|
| `hours` | 24 | Clamped to 1..2160 (90 days) |

Resolution: 300-second points for `hours <= 168`, hourly points above that.
The response says which one it used.

```json
{
  "config_id": 7,
  "step_seconds": 300,
  "points": [
    {"ts": 1797393000, "rx": 1024, "tx": 20480},
    {"ts": 1797393300, "rx": 0, "tx": 0}
  ]
}
```

- `rx`: bytes the peer sent, i.e. the client's upload.
- `tx`: bytes the server sent, i.e. the client's download.
- Points are deltas for their bucket, in ascending order.
- A missing bucket means the sampler was not running; it is not a zero.
- `points: []` means there is no history yet (for example, a new
  configuration).
- History older than a week is only kept hourly; older than 90 days is
  dropped.

---

### GET /api/me/exits?config_id=N

Internet exits granted to the account, in this configuration's order.
Optional `config_id`; omitted or `0` means the first configuration.

```json
[
  {
    "id": 2,
    "name": "nl-1",
    "comment": "Amsterdam",
    "country": "Netherlands",
    "alive": true,
    "degraded": false,
    "rtt_ms": 42,
    "active": true,
    "pinned": false,
    "current": true,
    "current_iface": "awg1",
    "status_fresh": true
  }
]
```

- An empty list means the administrator granted no internet exit. The
  configuration then has no internet access.
- `alive` is `true` or `false`. It is `null` when the failover daemon has not
  reported for more than 60 seconds; `rtt_ms`, `degraded` and `active` are also
  `null` then and `status_fresh` is `false`. Do not treat `null` as "down".
- `current` is `true` for the exit this configuration's own routing table
  points at, and `current_iface` names it. This is not `active`: `active` is
  the server's default route, while a configuration with its own order or a
  pin usually rides another exit. Both are `null` while the failover status is
  stale; `current` is also `null` when the table points at no live exit.
- `pinned` is `true` for the exit this configuration is pinned to. A pinned
  exit is used even when it is marked `degraded`, while its tunnel is alive;
  when it dies the configuration's order takes over.
- `country` is where the exit is hosted, set by the administrator; an empty
  string means it was left blank. Show it in preference to `comment`, which is
  an internal note such as the provider or the bandwidth.
- `degraded` means the exit answers ICMP but cannot reach every HTTP probe
  target. Clients and the active exit prefer a healthy one.
- `active` is `true` for the exit the default route (`table 100`) points at
  right now. It is not necessarily the configuration's first choice: the
  account's own checks or the failover may have picked another one.
- `rtt_ms` is the panel-to-exit round trip, not the device's latency.
- The order is the configuration's own order, which the user can change with
  `/api/me/exits/order`.

Errors: `409 no configuration yet; create one first`, `404 configuration not
found`.

---

### POST /api/me/exits/order

Replaces the configuration's exit order.

| Field | Required | Notes |
|---|---|---|
| `exit_id` | yes | Repeated field. Must list **every** granted exit exactly once |
| `config_id` | no | Default `0`: the account's first configuration |

```json
{"ok": true}
```

Errors: `400 the order must list every granted exit once`, `404 configuration
not found`, `409 no configuration yet; create one first`.

---

### POST /api/me/exits/pin

Pins the configuration to one granted exit, or returns it to automatic.

| Field | Required | Notes |
|---|---|---|
| `action` | no | `pin` (default) or `auto` |
| `exit_id` | for `pin` | One of the exits from `/api/me/exits` |
| `config_id` | no | Default `0`: the account's first configuration |

```json
{"ok": true, "pinned": "awg2"}
```

`pinned` is the interface name of the pinned exit, or an empty string after
`auto`. It is not the exit `name` and not the `active` exit.

A pinned exit is used even when the failover marks it `degraded`, as long as
it is alive; a dead tunnel is never forced.

Errors: `404 exit not granted`, `404 configuration not found`,
`409 no configuration yet; create one first`.

---

### GET /api/me/subnets?config_id=N

Subnet exits granted to the account, with the choice of the given
configuration. Optional `config_id`; omitted or `0` means the first.

```json
[
  {
    "id": 5,
    "name": "office",
    "comment": "Office LAN",
    "routes": "10.20.0.0/16, 10.21.0.0/16",
    "enabled": true
  }
]
```

- `routes` is a comma-separated list of CIDRs.
- `enabled` says whether this configuration currently uses the subnet.
- Only enabled, granted routed exits are listed. Internet exits are separate
  and come from `/api/me/exits`.

---

### POST /api/me/subnets

Switches subnets on or off for one configuration.

| Field | Required | Notes |
|---|---|---|
| `subnet_id` | no | Repeated field. Any subset of the account's grants; an empty list turns all off |
| `config_id` | no | Default `0`: the account's first configuration |

```json
{
  "ok": true,
  "subnets": [
    {"id": 5, "name": "office", "enabled": true},
    {"id": 6, "name": "lab", "enabled": false}
  ]
}
```

Errors: `400 the account does not grant all of these subnets`, `404
configuration not found`, `409 no configuration yet; create one first`.

On a subnet-only configuration, changing subnets changes `AllowedIPs` and
`DNS` in the generated `.conf`; the keys stay the same, but the device must
import the new file. A configuration with an internet exit keeps
`AllowedIPs = 0.0.0.0/0` and the global DNS, so its file does not change and
no re-import is needed: the server routes the chosen subnets.

---

### GET /api/me/presets

Curated route presets for the client's own split tunneling: Telegram, Claude
(Anthropic) and Cloudflare, which covers Discord, OpenCode and many other
sites. The panel does not put these prefixes into any configuration or routing
table — the app decides what to do with them.

Only presets the administrator enabled are listed; an empty `presets` array
means everything is switched off. Sourced presets are refreshed from public
sources every six hours. `stale` is `true` when the newest enabled sourced
preset is older than a day.

| Header | Notes |
|---|---|
| `ETag` | On `200`. Send it back in `If-None-Match` to get `304 Not Modified` with an empty body |
| `Cache-Control` | `no-cache`: the client must revalidate |

```json
{
  "version": "2026-11-28T06:17:00+00:00",
  "stale": false,
  "presets": [
    {
      "id": "telegram",
      "name": "Telegram",
      "description": "Official Telegram IPv4 ranges.",
      "cidrs": ["91.105.192.0/23", "91.108.4.0/22"],
      "source": "lord-alfred/ipranges",
      "fetched": 1795800000,
      "icon": "/static/presets/telegram-6a604913.svg",
      "icon_png": "/static/presets/telegram-d88c6300.png"
    }
  ]
}
```

Errors: `401` without a token. An empty `presets` array is a normal answer:
the administrator switched every preset off.

A signed-in account also receives its own presets, after the global ones. They
carry no `icon`/`icon_png`; the client shows a generic icon.

### POST /api/me/presets

Adds a personal preset, visible only to this account.

| Field | Required | Notes |
|---|---|---|
| `name` | yes | Up to 64 characters |
| `description` | no | Up to 240 characters |
| `cidrs` | yes | IPv4 prefixes, one per line or comma-separated; `0.0.0.0/0` is refused |

```json
{
  "id": "u4-my-services",
  "name": "My services",
  "description": "",
  "cidrs": ["10.90.0.0/24"],
  "source": "manual",
  "fetched": 0
}
```

Errors: `400` for invalid input (including `0.0.0.0/0`, reserved ranges and
prefixes that overlap the tunnel or panel network), `409` when the account
already has 20 personal presets. The response is `201 Created`.

### DELETE /api/me/presets/{id}

Deletes one of the account's own presets. Global presets and presets of other
accounts answer `404`.

```json
{"ok": true, "deleted": "u4-my-services"}
```

---

## Data objects

### Configuration

Returned by `/api/login`, `/api/me` and `/api/me/configs`.

| Field | Type | Meaning |
|---|---|---|
| `id` | int | Configuration id |
| `account_id` | int | Owning account |
| `name` | string | Human name, unique across the panel |
| `device_id` | string | Device identifier from the app; empty for old rows |
| `ip` | string | Tunnel address without the prefix length |
| `enabled` | bool | Peer enabled on the server |
| `internet` | bool | The account grants at least one internet exit |
| `exits` | string[] | Names of the routed subnets this configuration uses |
| `remote_ip` | string | Peer address as the host sees it; empty until first connect |
| `handshake` | int | Unix time of the last handshake; `0` for never |
| `online` | bool | Handshake younger than three minutes; always false while disabled |
| `rx` | int | Bytes received from the peer since the interface came up |
| `tx` | int | Bytes sent to the peer since the interface came up |

`rx`/`tx` are live counters, not deltas. Use `/api/me/configs/{id}/traffic`
for history.

### Created configuration

Returned as `config` by `POST /api/me/configs`:

| Field | Type |
|---|---|
| `id` | int |
| `name` | string |
| `device_id` | string |
| `ip` | string |
| `internet` | bool |
| `enabled` | bool |

### Exit

| Field | Type |
|---|---|
| `id` | int |
| `name` | string |
| `comment` | string, may be empty |
| `alive` | `true`, `false` or `null` |
| `rtt_ms` | int or `null` |
| `status_fresh` | bool |

### Subnet

| Field | Type |
|---|---|
| `id` | int |
| `name` | string |
| `comment` | string, may be empty |
| `routes` | string, comma-separated CIDRs |
| `enabled` | bool |

The `subnets` array returned by `POST /api/me/subnets` has only `id`, `name`
and `enabled`.

### Route preset

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable identifier: `telegram`, `claude`, `cloudflare` |
| `name` | string | Human name |
| `description` | string | What the preset covers and how exact it is |
| `cidrs` | string[] | IPv4 prefixes; `0.0.0.0/0` never appears |
| `source` | string | Where the ranges come from |
| `fetched` | int | Unix time of the fetch that produced this entry |
| `icon` | string, optional | Built-in presets only: an absolute path under `/static/presets/`, versioned by content. Custom presets have no icon and the client shows a generic one |
| `icon_png` | string, optional | The same artwork as a 128×128 PNG for clients that cannot render SVG (the Windows UI uses GDI+). Present wherever `icon` is |

Personal presets answer without `icon`/`icon_png`; their `source` is `manual`
and `fetched` is `0`.

Preset icons are public: they are served with `Cache-Control: public,
max-age=31536000, immutable` and an `ETag`. The path never changes without the
file changing.

### Traffic point

| Field | Type |
|---|---|
| `ts` | int, Unix time of the bucket start |
| `rx` | int, bytes uploaded in the bucket |
| `tx` | int, bytes downloaded in the bucket |

---

## Status codes

| Code | When |
|---|---|
| 200 | Success, including create and toggle |
| 400 | Invalid field value, invalid order or a foreign subnet |
| 401 | Missing, expired or revoked token; wrong password |
| 404 | Unknown configuration id |
| 409 | No configuration yet, or the account is at its configuration limit |
| 422 | Malformed form (missing required field, wrong type) |
| 429 | Too many failed sign-ins |
| 500 | The live interface could not be applied to; the database was rolled back |
| 503 | `/api/android` has no metadata that matches the published APK |

`500` bodies describe the failure generically. If the live device could not be
rolled back after a failed apply, the message says so and asks to inspect
`awg0` before continuing.

---

## Examples

Sign in and keep the token:

```sh
TOKEN=$(curl -s https://panel.example.com:8080/api/login \
  --data-urlencode email=user@example.com \
  --data-urlencode 'password=correct horse battery staple' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
```

List configurations:

```sh
curl -s https://panel.example.com:8080/api/me \
  -H "Authorization: Bearer $TOKEN"
```

Create or reuse this device's configuration:

```sh
curl -s https://panel.example.com:8080/api/me/configs \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode name=pixel-8 \
  --data-urlencode device_id=a1b2c3d4e5f60718
```

Download the configuration:

```sh
curl -s https://panel.example.com:8080/api/me/configs/7/conf \
  -H "Authorization: Bearer $TOKEN" -o phone.conf
```

Set the exit order (the ids must match `/api/me/exits`):

```sh
curl -s https://panel.example.com:8080/api/me/exits/order \
  -H "Authorization: Bearer $TOKEN" \
  -d config_id=7 -d exit_id=2 -d exit_id=1
```

Switch one subnet on and another off:

```sh
curl -s https://panel.example.com:8080/api/me/subnets \
  -H "Authorization: Bearer $TOKEN" \
  -d config_id=7 -d subnet_id=5
```

Sign out:

```sh
curl -s -X POST https://panel.example.com:8080/api/logout \
  -H "Authorization: Bearer $TOKEN"
```

---

## Public and internal endpoints

These are not part of the mobile API and need no token.

### GET /healthz

Liveness probe for monitoring. It deliberately says nothing about the product
or the release.

```json
{"ok": true, "failover_age": 7}
```

- `200` when the database responds and the failover status is younger than 60
  seconds.
- `503` when the database cannot be read or the status is stale; the body then
  also carries `"error": "database"` in the database case.
- `failover_age` is seconds since the failover daemon last wrote its status,
  or `null` when it never did.

### GET /api/android

Update check for the Android client. It needs no token: the client asks before
it signs in. The answer describes the APK that `/download/android` serves.

```json
{
  "package": "ru.deffhost.kaskad",
  "versionCode": 50804,
  "versionName": "5.8.2.3",
  "minSdk": 26,
  "url": "https://panel.example.com/download/android",
  "sha256": "7b276974643eee840d165555ef99c31120e6ab1ffa50516e769b16f03d76706a",
  "size": 18667850,
  "published": "2026-11-21T10:00:00Z"
}
```

- `Cache-Control: public, max-age=300`.
- `versionCode` grows with every release; update only into a greater value of
  the same `package`. The client still compares against what it has installed.
- `versionName` is informational; it is not the panel version.
- `minSdk` is present when the APK manifest declares it.
- `sha256` and `size` describe the file at `/download/android` and are checked
  by the client before it installs anything.
- `published` is the UTC time the APK was placed on the server.
- `404` when no APK is published. `503` when the file on the host cannot be
  read as an Android package: treat it as "no update now" and retry later,
  never as "current version".
- Everything is read from the file on the host, with the result cached until
  the file changes: replacing the APK takes effect on the next request,
  without a deploy or a restart.

### GET /download/windows

The Windows client MSI, served from `/var/lib/kaskad/app.msi` on the host. It
needs no token. `404` until the file exists. There is no metadata endpoint:
the file is advertised only by its presence, and the cabinet's Client apps
section and the configuration's Connect block show a "for windows" button
once it is there.

### GET /ping

Tiny target the panel's pages use to measure their round trip to the server.
Returns `pong` as `text/plain` with `Cache-Control: no-store`.

### GET /status.json

Internal endpoint for the panel's own live page updates. It uses the session
cookie, not a bearer token: an administrator sees all configurations, an
account sees only its own. `?overview=true` adds the `overview` block for the
administrator.

The shape is an implementation detail of the web UI and may change without
notice; the mobile client must not call it.

---

## Change policy

The API has no version prefix. Changes are additive: new fields appear, and
clients must ignore unknown keys. Removing a field or changing its type is a
breaking change and gets a new panel release with a note in `CHANGELOG.md`.
