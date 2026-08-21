# Sendit!

Self-hosted secure credential and file send/collect. Secrets are encrypted in the browser; the API stores only ciphertext and account data. Product brand: **Sendit!**

## Features

- **Send** encrypted text or files (large-body routes ~**200 MB + 5%** via `SENDIT_MAX_UPLOAD_BYTES` so nginx `200m` is the first gate; secret text UI cap 90M characters)
- **Collect** secrets via upload links (same large-body cap for guest upload)
- **Accounts** with dashboard, email OTP registration, password reset, optional TOTP
- **One-time** or multi-view until expiry; optional max access count
- Optional **link password**, **Allowed IPs** (send), **private notes** (owner UDK)
- Per-user **storage quota** (default 1 GB)
- Proof-of-work (**HMAC-SHA256**) + rate limits on public share access and auth
- **Immutable site-wide activity audit** (`/audit`) with infinite scroll
- **Docker** + **host nginx** deployment on Linux
- Documented crypto and auth for audit (`docs/`, `src/frontend/js/crypto.js`)

## Quick start (development)

Requirements: .NET 10 SDK, Python 3 (frontend build).

```bash
# Build static assets into public/
python3 scripts/build-frontend.py

# Run API + static files together (dev helper)
export SENDIT_DB_PATH=./data/sendit.db
export SENDIT_PUBLIC_BASE_URL=http://127.0.0.1:8080
export SENDIT_STATIC_ROOT=./public
dotnet run --project src/Sendit.Api --launch-profile http
```

Open `http://127.0.0.1:8080` (redirects to sign-in). New accounts on domains listed in
`SENDIT_ALLOWED_EMAIL_DOMAINS` are created from the sign-in form and verified with an email OTP
(printed to the server console when SMTP is not configured).

In production, **host nginx** serves `public/` and only proxies `/api/` to the API container (JSON under `/api/v1/…`; see `deploy/nginx/sendit.conf`). The Docker image is **API-only** — no frontend, no in-container nginx or ACME.

## Docker

One image (details: [`../deploy/README.md`](../deploy/README.md)):

| | **sendit** |
|--|------------|
| Image | API only |
| Dockerfile | `deploy/Dockerfile` |
| Compose | `deploy/docker-compose.yml` |
| TLS / static | **Host nginx** (`deploy/nginx/sendit.conf`) |

Self-contained Alpine musl binary. Build on the target machine (native arch) with Compose:

```bash
docker compose -f deploy/docker-compose.yml up -d --build
```

### API + host nginx

```bash
python3 scripts/build-frontend.py
# rsync public/ → e.g. /var/www/sendit/public on the server
docker compose -f deploy/docker-compose.yml up -d --build
# Install deploy/nginx/sendit.conf (TLS certs via certbot on the host)
```

## Configuration

**Full reference (API + Docker + multi-instance):** [`CONFIGURATION.md`](CONFIGURATION.md).

Common API variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDIT_DB_PATH` | `sendit.db` (Docker: `/data/sendit.db`) | SQLite file path (share volume for multi-instance) |
| `SENDIT_PUBLIC_BASE_URL` | `http://localhost:8080` | Origin used in password-reset / notify emails |
| `SENDIT_STATIC_ROOT` | *(auto-detect `public/`)* | When the API serves static files (dev); omit in production behind nginx |
| `SENDIT_MAX_UPLOAD_BYTES` | `210000000` (200M × 1.05) | Large body/ciphertext: create send/collect + collect upload (above nginx `200m`) |
| `SENDIT_MAX_REQUEST_BODY_BYTES` | `275251` (256 KiB × 1.05) | Default max body for other API routes (above nginx `256k`) |
| `SENDIT_USER_STORAGE_QUOTA` | `1024` | Per-user storage quota in **MB** (sends + collect payloads); **413** when exceeded |
| `SENDIT_MAX_EXPIRY_HOURS` | `1080` (45 days) | Max send/collect lifetime |
| `SENDIT_OPTIMIZE_HOUR_UTC` | `3` | UTC hour for nightly SQLite `VACUUM` / optimize |
| `SENDIT_POW_DIFFICULTY_BITS` | `12` | HMAC-SHA256 PoW leading zero bits (min `1`, never off; max `28`; &lt;12 logs a warning) |
| `SENDIT_POW_CHALLENGE_TTL_SECONDS` | `120` | PoW challenge lifetime (30–600) |
| `SENDIT_SCAN_BUDGET_WINDOW_SECONDS` | `60` | Sliding window for share/collect scan budget (seconds); values &lt; 30 treated as 60 |
| `SENDIT_ALLOWED_EMAIL_DOMAINS` | empty = any | Domains allowed to **register** (`example.com` or `*`) |
| `SENDIT_BANNED_EMAILS` | empty = none | Exact emails banned from **registration** only |
| `SENDIT_TICKET_KEY` | auto file next to DB | ≥32 chars high-entropy HMAC key for tickets/OTP/reset |
| `SENDIT_DATA_KEY` | falls back to ticket key | Recommended dedicated at-rest key (TOTP + collect-key envelopes) |
| `SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS` | empty = any | IPs/CIDRs allowed to **retrieve** collect payloads |
| `SENDIT_HIGHLIGHT` | `#c8ab37` | UI accent (`#RRGGBB`, or `#random` once at startup; quote in Compose YAML) |
| `SENDIT_EDGE_SECURITY_HEADERS` | unset (Docker: `1`) | When set, Kestrel skips browser security headers (nginx owns them) |
| `SENDIT_LOG_FILE` | unset | Optional log file path (in addition to console) |
| `SENDIT_LOG_LEVEL` | `INFO` | `INFO` \| `WARNING` \| `ERROR` — minimum level for console and file |
| `SENDIT_SMTP_HOST` / `PORT` / `USER` / `PASSWORD` / `FROM` / `ENABLE_SSL` | see docs | SMTP (primary when host set) |
| `SENDIT_MAILGUN_DOMAIN` / `API_KEY` / `FROM` / `BASE_URL` | see docs | Mailgun alone or SMTP failover |

## Layout

```
src/frontend/      # audited HTML/JS/CSS source
src/Sendit.Api/    # .NET 10 API
public/            # minified production static root (*.min.js/css/html); SRI-pinned
docs/              # CONFIGURATION, CRYPTO, AUTH, AUDIT, ARCHITECTURE, SECURITY
deploy/            # Dockerfile, compose, host nginx sample
scripts/           # build-frontend.py (minify → *.min.* + SRI integrity pins)
```

## Security model

### Client-side encryption

Secrets are encrypted in the browser before anything is uploaded:

1. A random **AES-256** key encrypts the secret (or file) with **AES-GCM**.
2. That AES key is **wrapped** for an **X25519** public key: ECDH produces a shared secret, **HKDF-SHA-256** derives a wrap key, and **AES-GCM** encrypts the AES key.
3. The server stores only ciphertext, IVs, wrapped keys, and public keys—not plaintext and not unwrapped AES keys.

Decryption private keys travel only in the URL fragment (`#sk=…`). Browsers do not send fragments to the server on HTTP requests. Optional **link password** seals that key with PBKDF2-SHA512 + AES-256-GCM in the fragment (server only stores a boolean flag).

Protocol detail: [`CRYPTO.md`](CRYPTO.md) and [`../src/frontend/js/crypto.js`](../src/frontend/js/crypto.js).

### What the server stores

- Ciphertext, IVs, wrapped keys, and (for collects) X25519 public keys  
- For **collects only**, the owner’s X25519 private key **wrapped client-side with the user data key (UDK)** so the dashboard can re-open collect links (optional second server layer via `SENDIT_DATA_KEY`)  
- Account email and password hashes (**PBKDF2-HMAC-SHA512**, 893,241 iterations, 64-byte salt; max password length 256)  
- Optional TOTP secrets when 2FA is enabled (encrypted at rest)  
- Dashboard metadata (labels, expiry, status, access counts, IP restriction flag)  
- Append-only **activity audit** rows (creates, deletes, views, IP denials, auth failures, …)  
- **Send** decrypt keys remain only in the URL `#sk=` fragment (not stored on the server); optional `passwordProtected` flag only  

### Accounts and access

- Login is required to **create** sends and collects (ownership + dashboard).  
- Recipients and uploaders do **not** need accounts.  
- Registration is domain-gated (`SENDIT_ALLOWED_EMAIL_DOMAINS`), may ban exact addresses (`SENDIT_BANNED_EMAILS`), and is verified with **email OTP**.  
- Optional **TOTP** second factor; password reset via email when SMTP/Mailgun is configured.  
- Per-user **storage quota** limits total owned encrypted payload size.  
- Dashboard and audit use **cursor pagination** (infinite scroll; dashboard page **100**, audit page **500**).  

### Frontend build integrity

`python3 scripts/build-frontend.py` writes minified assets to `public/` as **`*.min.js`**, **`*.min.css`**, and **`*.min.html`**, rewrites page references to those paths, and pins every `/js/*` and `/vendor/*` script tag plus **`/css/style.min.css`** with a **SHA-384 Subresource Integrity** hash. Clean URLs (`/login`) map to `login.min.html` via nginx / the API. Dynamic branding CSS (`/api/v1/branding/theme.css`) is not pinned. Rebuild after frontend changes so HTML and assets stay in sync. Details: [`SECURITY.md`](SECURITY.md).

### Threat notes

- Anyone with the **full link** (path + `#sk=…` fragment) can decrypt an unprotected item; password-protected sends also need the link password.  
- A compromised browser or malicious script can steal secrets at encrypt/decrypt time.  
- Protect the SQLite volume (ciphertext, password hashes, TOTP material, audit log).  
- Terminate TLS at nginx (or equivalent) in production.  
- Set `SENDIT_PUBLIC_BASE_URL` and email transport for OTP/reset; set `SENDIT_TICKET_KEY` (and ideally `SENDIT_DATA_KEY`) for multi-instance production.  
- Keep nginx at `200m` / `256k`; API body defaults are ~5% higher so the edge rejects first.  

Audit path: [`AUDIT.md`](AUDIT.md). Configuration: [`CONFIGURATION.md`](CONFIGURATION.md). Vulnerability reporting: [`SECURITY.md`](SECURITY.md).

## License

See [LICENSE](../LICENSE).
