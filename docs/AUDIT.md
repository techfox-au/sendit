# Audit guide

This document is a **security / code-review checklist** for Sendit! (not the in-app
activity log UI — see [Activity audit UI](#activity-audit-ui) below).

## Source of truth

| Area | Path |
|------|------|
| Client crypto | `src/frontend/js/crypto.js` |
| Crypto protocol | `docs/CRYPTO.md` |
| Auth / passwords / TOTP / PoW / rate limits | `src/Sendit.Api/Services/AuthService.cs`, `AuthThrottleService.cs`, `PasswordHasher.cs`, `docs/AUTH.md` |
| Configuration surface | `src/Sendit.Api/Configuration/SenditOptions.cs`, `docs/CONFIGURATION.md` |
| Field length limits | `src/Sendit.Api/Util/FieldLimits.cs` (server); `FIELD_LIMITS` in `src/frontend/js/app.js` (client) |
| Storage quota | `src/Sendit.Api/Services/UserStorageQuota.cs`, send/collect create-upload endpoints |
| SQL access | `src/Sendit.Api/Services/*Store.cs`, `Data/Schema.cs` |
| API surface | `src/Sendit.Api/Endpoints/` |
| Activity audit | `Services/ActivityAuditStore.cs`, `GET /api/v1/me/audit` |
| DB maintenance | `SqliteMaintenance.cs`, `ExpiryCleanupService.cs` |
| Production static assets | generated `public/` (minified) — **do not audit alone** |
| Frontend build / SRI | `scripts/build-frontend.py` emits `*.min.*` under `public/` and pins `/js/*`, `/vendor/*`, and `/css/style.min.css` in production HTML |

## Checklist

1. Confirm no server path decrypts payload `Ciphertext` / `WrappedKey` (only client crypto).
2. Confirm URL fragments (`#sk=`) are not read server-side.
3. Confirm all SQL uses parameters (search for string interpolation into SQL).
4. Confirm PBKDF2 parameters match `AUTH.md` (SHA-512, 893241, 64-byte salt; password max **256** chars).
5. Confirm one-time retrieve burns ciphertext only **after** valid PoW (and IP allow-list where set).
6. Compare `src/frontend/js/crypto.js` steps to `CRYPTO.md`.
7. Review vendored `src/frontend/vendor/nacl-fast.js` version (TweetNaCl 1.0.3) and `qrcode.js` (qrcode-generator; see `src/frontend/vendor/VENDOR.md`).
8. Confirm auth tickets are jti-backed and consumed on successful OTP/TOTP.
9. Confirm PoW is **HMAC-SHA256** (Web Crypto + server `HMACSHA256`), bound to email/ticket for auth and issue-at-action-time for shares; difficulty always ≥ 1 (no disable path); challenges are one-time (no replay).
10. Confirm shared SQLite rate limits use exclusive transactions (`BEGIN IMMEDIATE`).
11. Confirm per-user storage quota is enforced on send create and collect upload.
12. Confirm `GET /api/v1/auth/me` does not return `wrappedUserDataKey` (unlock uses `GET /auth/user-data-key`).
13. Confirm `SENDIT_TICKET_KEY` rejects short secrets; multi-instance shares DB + ticket key.
14. Confirm collect payload retrieve respects `SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS`.
15. Confirm production `public/**/*.min.html` pins `/js/*.min.js`, `/vendor/*.min.js` scripts and `/css/style.min.css` with matching `integrity="sha384-…"` and `crossorigin="anonymous"` (rebuild via `scripts/build-frontend.py`). Do **not** require SRI on `/api/v1/branding/theme.css`.
16. Confirm optional **link password** on send **and** collect: client wraps 32-byte `sk` with PBKDF2-SHA512 + **AES-256-GCM** (`wrapSecretKeyWithPassword`); server stores only `passwordProtected` flag; package is never uploaded; meta exposes the flag; wrong password fails GCM.
17. Confirm large request bodies are limited to create-send / create-collect (auth) and collect upload; default body cap is **275251** (`SENDIT_MAX_REQUEST_BODY_BYTES` = 256 KiB × 1.05, so nginx `256k` rejects first).
18. Confirm send Allowed IPs and collect retrieve allow-list denials append `send_ip_denied` / `collect_ip_denied` audit rows **without** burning one-time payloads.
19. Confirm `audit_log` is append-only (SQLite triggers block UPDATE/DELETE).
20. Confirm identity for create/delete audit comes from the **session cookie** (`CurrentUser`), not client-supplied email/id.

## Activity audit UI

| Item | Detail |
|------|--------|
| Table | `audit_log` (immutable) |
| List API | `GET /api/v1/me/audit?limit=500&beforeAtUtc=…&beforeId=…` (max limit **500**) |
| Visibility | Any authenticated user; **site-wide** (all accounts) |
| UI | `/audit` — infinite scroll, page size 500 |
| Identity | Actor from session when known; client IP always recorded when available |

### Kind reference (non-exhaustive)

| Kind | When |
|------|------|
| `account_registered` | Auto-register path completed enough to create the user row |
| `password_changed` | Successful password change |
| `totp_enabled` / `totp_disabled` | 2FA enroll confirm / disable |
| `send_created` / `collect_created` | Owner creates item (message includes resource id) |
| `send_deleted` / `collect_deleted` | Owner deletes item |
| `send_viewed` | Public send meta success |
| `send_decrypted` | Public send payload download (after PoW) |
| `collect_uploaded` | Guest upload success |
| `collect_retrieved` | Collect payload retrieve |
| `send_ip_denied` / `collect_ip_denied` | Client IP outside allow-list |
| `auth_password_failed` / `auth_otp_failed` / `auth_totp_failed` | Credential failures |

Messages are human-readable; codes and passwords are never stored. Failed audit writes are logged and must not fail the user action.

## Configuration audit

Walk every variable in [`CONFIGURATION.md`](CONFIGURATION.md) against production env / compose.
Flag defaults that are unsafe for public internet (open registration, empty `DATA_KEY`, weak ticket key).
Note: PoW cannot be disabled (minimum difficulty **1**).
