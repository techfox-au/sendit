# Architecture

```
Browser (public/)          nginx                 Sendit.Api (.NET 10)
─────────────────          ─────                 ────────────────────
HTML/JS/CSS  ────────────► static files
crypto.js encrypts
fetch /api/v1/* ────────────► proxy /api/ ────────► Minimal APIs
                                                 SQLite volume
                                                 (data + shared abuse state)
```

- **src/frontend/** — documented UI source (audit this, not minified `public/`)
- **public/** — minified build output (`*.min.js` / `*.min.css` / `*.min.html`); nginx `root`. Production HTML pins `/js/*`, `/vendor/*`, and `/css/style.min.css` with **SHA-384 Subresource Integrity** hashes from `scripts/build-frontend.py` (see [`SECURITY.md`](SECURITY.md)); branding `theme.css` is not pinned. Clean URLs map to `*.min.html`.
- **src/Sendit.Api** — JSON API only (no SPA required in production)

## API versioning

All JSON endpoints live under **`/api/v1/…`**. **POST** creates; **GET/DELETE** on
`/{id}` obtain or manage existing items:

| Action | Page | API |
|--------|------|-----|
| Create send | `/send/new` | `POST /api/v1/send` (auth; optional `passwordProtected`, `allowedCidr`) |
| Open send | `/send?id=…#sk=…` | `GET /api/v1/send/{id}` (+ `/meta`, `/pow`) |
| Delete send | dashboard | `DELETE /api/v1/send/{id}` (auth, owner) |
| Create collect | `/collect/new` | `POST /api/v1/collect` (auth; optional `passwordProtected`) |
| Open collect | `/collect?id=…#sk=…` | `GET /api/v1/collect/{id}/…` (+ `/payload`, `/meta`, `/pow`) |
| Delete collect | dashboard | `DELETE /api/v1/collect/{id}` (auth, owner) |
| Upload to collect | `/upload?id=…` | `POST /api/v1/collect/{id}/upload` (public + PoW) |
| Dashboard list | `/dashboard` | `GET /api/v1/me/items` (auth; **paginated**, default 100) |
| Activity audit | `/audit` | `GET /api/v1/me/audit` (auth; **paginated**, default 500, site-wide) |
| Auth | `/login` | `/api/v1/auth/…` |

Optional **link password** on send **and** collect links: client seals `#sk` with PBKDF2 + AES-256-GCM;
API stores only a boolean for meta/UI (see [`CRYPTO.md`](CRYPTO.md)).

nginx still proxies the whole `/api/` prefix. A future major protocol change (for example
post-quantum hybrid encryption) can ship as **`/api/v2/…`** while `v1` stays available for
older clients. The browser client uses the constant path prefix **`/api/v1`**.

## Request body size (Kestrel + nginx)

| Routes | Default cap |
|--------|-------------|
| Authenticated `POST /api/v1/send`, `POST /api/v1/collect` (session required to raise limit) | **`SENDIT_MAX_UPLOAD_BYTES`** (`210000000` = 200 000 000 × 1.05) |
| Public `POST /api/v1/collect/{id}/upload` | **`SENDIT_MAX_UPLOAD_BYTES`** (same) |
| All other endpoints (auth, meta, audit, …) | **`SENDIT_MAX_REQUEST_BODY_BYTES`** (`275251` = 256 KiB × 1.05) |

API defaults include **5% headroom** over the intended decimal caps so host nginx
(`client_max_body_size 200m` / `256k` in `deploy/nginx/sendit.conf`) rejects first.
(`200m` is binary 209 715 200; the upload default still sits slightly above it.) Create-collect
is on the large-body path for consistency even though the create body is metadata-only.
Middleware raises Kestrel’s limit only for the large routes above. See [`CONFIGURATION.md`](CONFIGURATION.md).

## Dashboard and audit pagination

| Endpoint | Default page | Caps | Infinite scroll |
|----------|--------------|------|-----------------|
| `GET /api/v1/me/items` | 100 (cursor: `beforeCreatedAt` + `beforeId`) | Cursor pages max **100**; no-cursor top-N max **2000** (poll refresh) | Dashboard loads older rows near bottom |
| `GET /api/v1/me/audit` | 500 (cursor: `beforeAtUtc` + `beforeId`) | Max **500** per request | Audit page loads older events near bottom |

`GET /api/v1/me/items` also purges expired/consumed rows eagerly so the UI does not lag the background job.

## Activity audit log

Append-only SQLite table `audit_log` (UPDATE/DELETE blocked by triggers). Any authenticated user
can list the **site-wide** log. Kinds include creates/deletes, views/decrypts/collects, IP denials,
account events, and credential failures. See [`AUTH.md`](AUTH.md) § Activity audit and
`ActivityAuditStore`.

## Background maintenance

`ExpiryCleanupService` (hosted):

| Cadence | Work |
|---------|------|
| Every **1 minute** | Purge expired/consumed secrets and collects; expired sessions, reset tokens, auth tickets; expired PoW challenges; old rate-limit and scan-event rows |
| Once per day at `SENDIT_OPTIMIZE_HOUR_UTC` | WAL checkpoint, `VACUUM`, `PRAGMA optimize` |

## Shared multi-instance state (same DB file)

| Concern | Storage |
|---------|---------|
| Secrets / collects / users / sessions | SQLite tables |
| Activity audit | `audit_log` |
| PoW challenges (one-time; difficulty always ≥ 1) | `pow_challenges` |
| Scan / bad-PoW budget | `scan_events` |
| Auth lockout, email budget | `auth_throttle_state` |
| IP rate limits (auth / forgot / api) | `rate_limit_events` |
| One-time auth step tickets | `auth_tickets` |

ASP.NET rate limiters remain process-local backstops. See [`CONFIGURATION.md`](CONFIGURATION.md) and [`AUTH.md`](AUTH.md).

## Deploy

One API image; **host nginx** for TLS and static UI (see [`deploy/README.md`](../deploy/README.md)):

| Piece | Path |
|-------|------|
| API image | `deploy/Dockerfile` |
| Compose | `deploy/docker-compose.yml` |
| Host nginx | `deploy/nginx/sendit.conf` |

```text
Internet → host nginx (TLS + public/) → 127.0.0.1:8080 → sendit container (API)
```

Environment variables: [`CONFIGURATION.md`](CONFIGURATION.md).
