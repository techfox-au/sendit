# Configuration reference

Settings come from **environment variables** at process start. There is no required
`appsettings` secret store for production secrets.

| Consumer | Source of truth |
|----------|-----------------|
| **API** (`Sendit.Api`) | `SenditOptions.FromEnvironment()` + `TicketKeyStore` (`SENDIT_TICKET_KEY`) + `SENDIT_STATIC_ROOT` (read in `Program.cs`) |
| **Dev LAN HTTPS** | `scripts/run-lan-https.sh` only |

Unset optional variables keep the defaults below. Invalid values are usually ignored
unless noted (startup throws).

Compose sample: `deploy/docker-compose.yml`. Host nginx: `deploy/nginx/sendit.conf`.
Layout: [`deploy/README.md`](../deploy/README.md).

---

## Which variables apply where

| Variable group | Dev (dotnet / LAN script) | **Docker (API)** |
|----------------|---------------------------|------------------|
| Core, uploads, PoW, keys, email, collect IPs, branding, logs | yes | yes |
| `SENDIT_STATIC_ROOT` | yes (often set) | usually **omit** (host nginx serves `public/`) |
| `SENDIT_EDGE_SECURITY_HEADERS` | usually **omit** (Kestrel sets headers) | **`1`** (host nginx owns headers) |
| `SENDIT_CERT_DIR` / LAN HTTPS helpers | LAN script only | **no** (TLS on host) |
| `ASPNETCORE_URLS` | optional | default `http://0.0.0.0:8080` |

---

## Core (API)

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDIT_DB_PATH` | `sendit.db` | SQLite database file path. The Docker image defaults to `/data/sendit.db`. Share this volume across multi-instance APIs. |
| `SENDIT_PUBLIC_BASE_URL` | `http://localhost:8080` | Absolute site origin used in password-reset / email links (no trailing slash). **Production: `https://your.domain`.** Also passed to the client-IP Worker canary as `baseUrl` (must be the public origin clients hit through nginx; localhost skips the probe). |
| `SENDIT_IP_PROBE_SECRET` | `70fded0f66a1c64e08f16f253ce41d6adfb13701ca1dcedf62995ef6cea252a3` | Shared secret for `GET /api/v1/diagnostics/client-ip`. Callers send `X-Sendit-Ip-Probe: <secret>` (or `Authorization: Bearer <secret>`). Wrong/missing secret → **404**. Authorized: **200** if client IP is **public**, **503** if private/loopback. Default is public and matches the Cloudflare Worker’s `PROBE_SECRET` default. Override (≥16 chars) for a private probe secret. |
| `SENDIT_IP_CHECK_WORKER_URL` | `https://sendit-check-ip.domains-8c1.workers.dev` | Cloudflare Worker canary origin. **Once at API startup** (not a loop), Sendit! POSTs `{ "baseUrl": "<SENDIT_PUBLIC_BASE_URL>" }` and waits for the reply. Public default Worker is shared. Override with your own URL, or set empty / `off` / `false` / `0` / `no` / `disabled` to skip (skip **disables** IP restrictions). Outcomes: public IP → Info; non-public IP → Warning + restrictions off; unreachable Worker → Warning inconclusive, restrictions stay on. |
| `SENDIT_IP_CHECK_WORKER_CALLER_SECRET` | `18c471779a90d164c6e47df4e67770114cdd32c6b425f718dbcdb31f9a5c97dd` | Bearer token Sendit! sends to the Worker (`Authorization: Bearer …`) so the Worker’s `CALLER_SECRET` gate allows the startup request. Default matches the public Worker. Override for a private Worker, or set empty / `off` / `false` / `0` / `no` / `disabled` to send **no** auth header. **Not** used by the Sendit! diagnostics endpoint (that uses `SENDIT_IP_PROBE_SECRET` only). |
| `SENDIT_STATIC_ROOT` | *(auto)* | Directory of built frontend (`public/`) when the **API** serves static files (dev). Search order: env → content-root relatives → `cwd/public`. **Production:** leave unset; host nginx serves static assets. |
| `SENDIT_EDGE_SECURITY_HEADERS` | `0` / unset | When `1` / `true` / `yes` / `on`, **Kestrel does not emit browser security headers** (CSP, `X-Frame-Options`, Permissions-Policy, COOP/CORP, etc.). Use when **host nginx** already sets them—avoids duplicate headers on `/api/` and proxied responses. The Docker image defaults this **on**. Leave unset for direct `dotnet run` / LAN helper so Kestrel still protects browsers. |

### Client-IP check (Cloudflare Worker canary)

External one-shot check that nginx + `UseForwardedHeaders` give the API a **public** client IP. Not a self-HTTP loop to `SENDIT_PUBLIC_BASE_URL` (that often yields private IPs under Docker/split-horizon).

| Piece | Default |
|-------|---------|
| Worker URL (`SENDIT_IP_CHECK_WORKER_URL`) | `https://sendit-check-ip.domains-8c1.workers.dev` |
| Caller Bearer (`SENDIT_IP_CHECK_WORKER_CALLER_SECRET`) | `18c471779a90d164c6e47df4e67770114cdd32c6b425f718dbcdb31f9a5c97dd` |
| Probe secret (`SENDIT_IP_PROBE_SECRET`) | `70fded0f66a1c64e08f16f253ce41d6adfb13701ca1dcedf62995ef6cea252a3` |

**Startup flow (once per process):**

1. After listen (~2s settle), if Worker URL is enabled and `SENDIT_PUBLIC_BASE_URL` is a **public** origin…
2. Sendit! → Worker: `POST` + JSON `{ "baseUrl": "…" }` + optional `Authorization: Bearer <CALLER_SECRET>`
3. Worker → Sendit!: `GET {baseUrl}/api/v1/diagnostics/client-ip` with `X-Sendit-Ip-Probe: <PROBE_SECRET>`
4. Worker returns JSON with `ok: true` → **Info** (public client IP confirmed; restrictions remain **enabled**)
5. Worker returns a definitive **non-public** client IP (`check.isPrivateOrLocal: true`) or probe is **skipped** (disabled Worker URL / localhost / **LAN or private IP** base URL such as `192.168.x.x` — Cloudflare cannot reach those) → **Warning**, IP restrictions **disabled**. If `SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS` is a real allow-list (not blank/`*`), **Error** + process **exits**
6. **Cannot reach** the Worker (timeout, DNS, TLS, etc.) or Worker responds without a confirmed public/non-public IP (e.g. wrong secret) → **Warning** “inconclusive” only — **not** a private client IP and **does not disable** IP restrictions (they remain enabled)

nginx should use `$proxy_add_x_forwarded_for`; Kestrel processes XFF right-to-left (`ForwardLimit=1`).

Frontend: `GET /api/v1/branding/config` includes:

| Field | Meaning |
|-------|---------|
| `ipRestrictionsEnabled` | Default true; false only after non-public canary or probe skip |
| `clientIpProbeFinished` | One-shot probe has completed (any outcome) |
| `clientIpPublicVerified` | Worker confirmed a public client IP this process |

Create send hides Allowed IPs when `ipRestrictionsEnabled` is false.

Manual retry (same defaults):

```bash
curl -sS -X POST "https://sendit-check-ip.domains-8c1.workers.dev/" \
  -H "Authorization: Bearer 18c471779a90d164c6e47df4e67770114cdd32c6b425f718dbcdb31f9a5c97dd" \
  -H "Content-Type: application/json" \
  -d '{"baseUrl":"https://your.domain"}'
```

Worker source and deploy notes: [`deploy/cloudflare-worker-check-ip/README.md`](../deploy/cloudflare-worker-check-ip/README.md).

---

## Uploads and storage (API)

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDIT_MAX_UPLOAD_BYTES` | `210000000` (200 000 000 × **1.05**) | Max body / ciphertext for large payload routes: **authenticated** `POST /api/v1/send` and `POST /api/v1/collect`, and **public** `POST /api/v1/collect/{id}/upload`. 5% headroom over the intended ~200 MB cap so host nginx (`client_max_body_size 200m` = 209 715 200) still rejects first. Create-collect is large-path for consistency; payload bulk is on upload. |
| `SENDIT_MAX_REQUEST_BODY_BYTES` | `275251` (256 KiB × **1.05**) | Default max request body for all other endpoints (auth, meta, etc.). 5% above nginx `client_max_body_size 256k` so the edge rejects first. |
| `SENDIT_USER_STORAGE_QUOTA` | `1024` | Per-user storage quota in **megabytes** (integer ≥ 1). Counts owned send + collect payload blobs (ciphertext + IV + wrapped key + ephemeral public key). Enforced on `POST /api/v1/send` and `POST /api/v1/collect/{id}/upload` with **HTTP 413** when exceeded. |
| `SENDIT_MAX_EXPIRY_HOURS` | `1080` (45 days) | Maximum send/collect lifetime. |
| `SENDIT_OPTIMIZE_HOUR_UTC` | `3` | UTC hour (0–23) for nightly SQLite checkpoint + `VACUUM` + `PRAGMA optimize`. |

Minimum expiry is **1 minute** (code constant; not env-configurable).

### Fixed field limits (not env-configurable)

Client `maxlength` / validation and server wire checks use `FieldLimits` /
`FIELD_LIMITS` (`src/Sendit.Api/Util/FieldLimits.cs`, `src/frontend/js/app.js`):

| Field | Max |
|-------|-----|
| Send / collect **name** (plaintext) | **256** characters |
| Name wire (UDK / hybrid ciphertext) | **4 096** characters (`NameCiphertext`) |
| Account / link / unlock **passwords** | **256** characters (min account password **8**) |
| Private note (plaintext) | **5 000 000** characters |
| Private note wire (UDK ciphertext) | **30 000 000** characters (`PrivateNoteCiphertext`) |
| Allowed IPs / CIDRs string (send) | **5 000 000** characters; at most **250 000** entries (`IpRestriction.MaxEntries`) |
| Secret text (plaintext) | **90 000 000** characters (still subject to upload/body size + quota) |

---

## Abuse control and proof-of-work (API)

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDIT_POW_DIFFICULTY_BITS` | `12` | Leading zero **bits** for HMAC-SHA256 PoW. **Range 1–28** (values &lt; 1 are raised to **1** — there is no off switch). Values **&lt; 12** log a startup **Warning**: `SENDIT_POW_DIFFICULTY_BITS is set low at {n}, recommended a value of at least 12!`. Applies to send/collect access and auth (login, email-OTP, TOTP, forgot-password). Each challenge is **one-time** (deleted on successful consume). |
| `SENDIT_POW_CHALLENGE_TTL_SECONDS` | `120` | PoW challenge lifetime (30–600). Challenges are issued at **action time** (not while waiting for email OTP). The browser abandons work **5 s before** `expiresAt` and **seamlessly requests a new challenge** until a solution is found (attempt count shown from the 2nd challenge onward). |
| `SENDIT_SCAN_BUDGET_WINDOW_SECONDS` | `60` | Sliding-window length (seconds) for the share/collect scan budget (not a fixed ban duration). Values **&lt; 30** are treated as **60**. **10** failures (404 + bad PoW) in the window → **429** until the oldest event ages out. PoW challenge issue also capped at **30** per window. |

**Fixed rate limits** (not env-configurable; multi-instance via SQLite when DB is shared):

| Scope | Limit |
|-------|--------|
| Auth actions (login, OTP, TOTP, reset, password change, TOTP enroll, UDK key endpoints) | **60 / minute / IP** |
| Forgot-password | **30 / minute / IP** |
| All `/api/*` | **600 / minute / IP** |

ASP.NET process-local policies mirror the same numbers as a backstop.
These app limits are intentionally generous; tighten further with nginx `limit_req` if needed.

Other fixed (not env): password PBKDF2 **893241** iterations, min password length **8**, max password length **256**, progressive password-attempt spacing (base **2 s**, doubles with fails up to 16×, cap **60 s**). PoW algorithm is **HMAC-SHA256** (not bare hash of nonce alone).

---

## Registration, branding, logging (API)

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDIT_ALLOWED_EMAIL_DOMAINS` | *(empty = any)* | Comma-separated domains allowed to **auto-register** (e.g. `example.com,corp.example`). `*` = any domain. Existing accounts can still log in regardless. |
| `SENDIT_BANNED_EMAILS` | *(empty = none)* | Comma-separated **exact email addresses** banned from **registration** (e.g. `bad@example.com,spam@evil.org`). Case-insensitive. Applied before the domain allow-list. Also blocks **email OTP**, **password-reset** tokens/mail, and **all outbound mail** to those addresses. Existing confirmed accounts may still **log in** (password/TOTP). |
| `SENDIT_HIGHLIGHT` | `#c8ab37` | UI accent; fills for in-process wordmark (`/api/v1/branding/logo.svg`) and rocket favicon (`/favicon.ico`, `/api/v1/branding/favicon.svg`). `#RGB` or `#RRGGBB`. Set to `#random` (or `random`) to pick a random accent **once at API startup** (stable for that process; logged as `UI highlight: #……`). Random picks are vivid mid-bright tones only — never black, white, grey, or low-contrast colours on the dark UI (WCAG ≥ 4.5:1 vs page background and vs dark button labels). Invalid values fall back to default. **In Docker Compose / YAML always quote the value** (e.g. `SENDIT_HIGHLIGHT: "#a586e0"` or `SENDIT_HIGHLIGHT: "#random"`) — an unquoted `#` starts a YAML comment, so the variable is empty and the default gold is used. |
| `SENDIT_LOG_FILE` | *(none)* | Extra path for logs (in addition to console). Docker: e.g. `/data/security.log` on the data volume. Console and file lines are prefixed with UTC **`[yyyy-MM-dd - HH:mm:ss]`**. |
| `SENDIT_LOG_LEVEL` | `INFO` | Minimum level for console and file: `INFO` / `INFORMATION`, `WARN` / `WARNING`, `ERROR`. Invalid values fall back to INFO. |

---

## Cryptographic keys — server (API)

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDIT_TICKET_KEY` | *(file next to DB)* | High-entropy secret **≥ 32 characters** for HMAC of auth tickets, email OTP hashes, and reset tokens. Short passphrases are **rejected at startup**. If unset, a 256-bit hex key is written to **`.sendit-ticket-key`** beside the DB (mode `0600` when possible). **Set explicitly for multi-host clusters.** |
| `SENDIT_DATA_KEY` | *(falls back to ticket key)* | Optional dedicated material for at-rest AES-GCM on TOTP secrets and collect owner-key envelopes. **Recommended in production** so ticket and data keys differ. |

Browser **user data key (UDK)** is not an env var: it is generated per account in the client, password-wrapped, and stored only as an opaque package on the server.

---

## Email — SMTP and/or Mailgun (API)

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDIT_SMTP_HOST` | *(unset)* | SMTP host; when set, SMTP is the primary transport. |
| `SENDIT_SMTP_PORT` | `587` | SMTP port. Prefer **587** (submission + STARTTLS). |
| `SENDIT_SMTP_USER` | *(unset)* | SMTP username. |
| `SENDIT_SMTP_PASSWORD` | *(unset)* | SMTP password. |
| `SENDIT_SMTP_FROM` | `noreply@localhost` | From address for SMTP (and Mailgun fallback From). |
| `SENDIT_SMTP_ENABLE_SSL` | `true` | Enable STARTTLS-style TLS for SMTP (`true` / `false`). See note below. |
| `SENDIT_MAILGUN_DOMAIN` | *(unset)* | Mailgun **sending domain** only (e.g. `mg.example.com` or sandbox `sandbox….mailgun.org`). Not a From mailbox. Must exist in the same Mailgun account/region as the API key. |
| `SENDIT_MAILGUN_API_KEY` | *(unset)* | Mailgun **private API key** (`key-…` from the account settings). Not a domain sending key alone if the account expects the private key. |
| `SENDIT_MAILGUN_FROM` | *(see SMTP From)* | Optional Mailgun From header (e.g. `Sendit! <noreply@mg.example.com>`). Address domain should be authorized on that Mailgun domain. |
| `SENDIT_MAILGUN_BASE_URL` | `https://api.mailgun.net` | API host only (**no** `/v3` path). US default; **EU domains need** `https://api.eu.mailgun.net`. Wrong region often yields HTTP **404** `page not found`. |

**Transport selection:** SMTP only · Mailgun only · SMTP primary with Mailgun **failover** if both are set · neither → Development may log message bodies; non-Development logs an error without body.

**Mailgun URL Sendit! calls:** `POST {BASE_URL}/v3/{DOMAIN}/messages` (e.g. `https://api.mailgun.net/v3/mg.example.com/messages`). HTTP **404** almost always means: (1) **EU domain** with US base URL (or the reverse), (2) **DOMAIN typo** / domain not in that Mailgun account, or (3) **BASE_URL** incorrectly includes `/v3` (would become `/v3/v3/…` — Sendit! strips a trailing `/v3` if present).

**SMTP TLS (STARTTLS only):** Sendit! uses .NET `System.Net.Mail.SmtpClient`. With `SENDIT_SMTP_ENABLE_SSL=true` it expects **STARTTLS** (plain TCP connect, then upgrade)—the usual setup on port **587**. It does **not** reliably support **implicit SSL/TLS** (encrypt immediately on connect), which is what many servers expose on port **465** (`smtps` / `submissions`). Use **587 + STARTTLS**, or put a STARTTLS-capable listener in front of your mail stack. Port 465 often fails with “lost connection after CONNECT” / `SSL_accept` errors against this client.

**Send timeouts:** Each transport (SMTP, then Mailgun if configured as failover) is limited to **7 seconds**. SMTP failure or timeout triggers Mailgun when set; if all configured transports fail, login returns **`code: email_send_failed`** and the browser resets the sign-in form with an error (no infinite “Signing in…” hang).

---

## Collect payload IP allow-list (API)

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS` | *(empty = any)* | Comma-separated IPv4/IPv6 or CIDRs allowed to call `GET /api/v1/collect/{id}/payload`. Empty or `*` = any IP. **Invalid values prevent startup.** If set to a real allow-list and the client-IP canary reports a **non-public** client IP (or the probe is skipped), the API logs **Error** and **exits**. Unreachable Worker is inconclusive and does **not** trigger this exit. |

Upload to a collect link and public collect GET are **not** restricted by this list (only payload retrieve).

Wrong-IP denials on send meta/payload and collect payload append activity-audit kinds
`send_ip_denied` / `collect_ip_denied` and return **403** without burning one-time payloads.

---

## Docker container (API only)

- **Compose:** `deploy/docker-compose.yml`
- **Image:** API only; listens on **8080** (`ASPNETCORE_URLS=http://0.0.0.0:8080`)
- **Publish:** `127.0.0.1:8080:8080` (loopback only — do not expose publicly)
- **Volume:** `/data` → SQLite (`SENDIT_DB_PATH`), optional `.sendit-ticket-key`, optional log file
- **TLS + static UI:** **host nginx** (`deploy/nginx/sendit.conf`); build frontend with `python3 scripts/build-frontend.py` and deploy `public/`
- **Certificates:** host-managed (certbot, etc.). No ACME or TLS inside the container.

Minimal production env:

```yaml
SENDIT_DB_PATH: /data/sendit.db
SENDIT_PUBLIC_BASE_URL: https://sendit.example.com
SENDIT_TICKET_KEY: "…"   # ≥32 char high-entropy
SENDIT_DATA_KEY: "…"     # recommended
SENDIT_ALLOWED_EMAIL_DOMAINS: example.com
# SENDIT_BANNED_EMAILS: bad@example.com,spam@evil.org
# plus SMTP and/or Mailgun
```

---

## ASP.NET listen URL (containers / process)

| Variable | Docker default | Description |
|----------|----------------|-------------|
| `ASPNETCORE_URLS` | `http://0.0.0.0:8080` | Kestrel bind address. Not a `SENDIT_*` name; standard ASP.NET Core. Compose publishes only `127.0.0.1:8080`. |
| `SENDIT_EDGE_SECURITY_HEADERS` | `1` (image default) | Host nginx owns security headers; Kestrel skips its browser suite. |

---

## Dev helpers (`scripts/run-lan-https.sh` only)

Not used by the Docker image.

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDIT_PORT` | `8443` | HTTPS listen port for the LAN helper. |
| `SENDIT_LAN_IP` | *(auto-detect)* | LAN IP for cert CN / `PUBLIC_BASE_URL`. |
| `SENDIT_CERT_DIR` | `$ROOT/.certs` | Directory for the helper’s TLS certs. |
| `SENDIT_STATIC_ROOT` | `$ROOT/public` | Frontend root for the helper process. |
| `SENDIT_DB_PATH` | `$ROOT/sendit.dev.db` | Dev DB if unset. |
| `SENDIT_PUBLIC_BASE_URL` | set by script | Overridden to `https://$LAN_IP:$PORT`. |

---

## Multi-instance checklist

When running more than one API process:

1. Shared **`SENDIT_DB_PATH`** (or volume) — PoW, scan budget, auth throttle, rate limits, tickets.
2. Same **`SENDIT_TICKET_KEY`** (or shared `.sendit-ticket-key` on the volume).
3. Same **`SENDIT_DATA_KEY`** if set.
4. Reverse proxy with trusted **X-Forwarded-For** only from known peers (see `Program.cs` / `deploy/nginx/sendit.conf`).

---

## Related docs

- Auth behavior: [`AUTH.md`](AUTH.md)
- Crypto protocol: [`CRYPTO.md`](CRYPTO.md)
- Deploy layout: [`ARCHITECTURE.md`](ARCHITECTURE.md), [`../deploy/README.md`](../deploy/README.md)
- Technical overview: [`README-TECHNICAL.md`](README-TECHNICAL.md)
- Security model: [`SECURITY.md`](SECURITY.md)
