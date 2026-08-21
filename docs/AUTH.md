# Sendit! authentication

Related: full env reference in [`CONFIGURATION.md`](CONFIGURATION.md).

## Registration allow / ban lists

| Variable | Behavior |
|----------|----------|
| `SENDIT_ALLOWED_EMAIL_DOMAINS` | Comma-separated domains that may **auto-register** on sign-in. Empty or `*` = any domain. Existing accounts may always log in. |
| `SENDIT_BANNED_EMAILS` | Comma-separated exact emails banned from **registration** (case-insensitive). Empty = none. Checked before the domain allow-list. Existing **confirmed** accounts may still log in with password/TOTP. |

Blocked registration attempts (banned email or domain not allowed) return the same client message as a bad password (`Invalid email or password.`) and are audited as `register_email_banned` or `register_domain_blocked`.

For banned addresses the API also **never**:

- Issues or reuses **email OTP** (or completes a pending OTP)
- Creates **password-reset tokens** or sends reset mail
- Delivers **any outbound mail** via `EmailSender` (OTP, reset, and notification mail are suppressed)

## Password hashing

| Parameter | Value |
|-----------|--------|
| Algorithm | PBKDF2 with HMAC-SHA512 |
| Iterations | 893,241 |
| Salt | 64 random bytes, unique per password |
| Derived key | 64 bytes |
| Min password length | **8** |
| Max password length | **256** (`FieldLimits.Password`; account + link passwords) |
| Attempt interval | Progressive **per IP + email**: base **2 s** (not env-configurable), doubles each failure up to 16×, hard cap **60 s** |
| Lockout | 10 failed password/OTP/TOTP attempts for that **IP + email** → 15 minutes (other IPs unaffected) |

Stored columns: `PasswordSalt`, `PasswordHash`, `PasswordHashIterations`.

No artificial login timing pad: the response already discloses the path (e.g. email OTP for
new/unconfirmed accounts vs session or TOTP for confirmed accounts).

Verification uses constant-time comparison (`CryptographicOperations.FixedTimeEquals`).
Passwords longer than 256 characters are rejected (hash/verify).

Lockout, progressive delay, email budgets, and IP rate limits are stored in SQLite so
**multiple API instances that share the same database file share the same quotas**.

## Sessions

HTTP-only cookie `sendit_session` (SameSite=Strict, Secure when HTTPS). Lifetime is **8 hours**
(server session row + cookie `Max-Age`). Session rows bind to `SecurityStamp`; password changes
rotate the stamp and delete all sessions. Session id is high-entropy (256-bit class).

`GET /api/v1/auth/me` returns identity only (**no** `wrappedUserDataKey`). The password-wrapped
user data key is available only from `GET /api/v1/auth/user-data-key` (authenticated unlock flow)
and from login step responses.

Create/delete of sends and collects resolve the actor via **`CurrentUser` → session cookie** only
(never from client-supplied email/id in the body).

## Email OTP (new / unconfirmed accounts)

| Parameter | Value |
|-----------|--------|
| Code | **Exactly 6** digits (CSPRNG); other lengths rejected |
| Lifetime | 15 minutes |
| Storage | HMAC-SHA256(code) with server ticket key (not bare SHA-256) |
| Failures | 5 invalid codes → OTP cleared and fail counter reset; sign in again for a new code (same 5-fail wipe repeats until success) |
| Ticket | HMAC auth ticket with **one-time jti** in SQLite; consumed only after a **correct** code |
| PoW | Action-time, bound to ticket (`GET /login/email-otp/pow?ticket=…`) |
| Restart | Sign in again before OTP completes re-issues/reuses a code when the password matches. If the password differs and a `wrappedUserDataKey` is sent, credentials are replaced (incomplete registration only), the prior OTP is wiped, and a new code is required. Wrap-based restarts keep the progressive password interval (no lockout-counter reset) so PBKDF2 cannot be hammered without delay |

## TOTP

RFC 6238 via Otp.NET. Enrollment:

1. `POST /api/v1/auth/totp/begin` → `otpauth://` URI (secret stored as pending)
2. User scans QR and submits a valid code
3. `POST /api/v1/auth/totp/confirm` → `TotpEnabled = true`, **all sessions deleted**, session cookie cleared  
   Client must sign in again (password + TOTP). Response includes `requiresReLogin: true`.

Login with TOTP: password step returns `totpTicket`; `POST /api/v1/auth/login/totp` completes login
(requires action-time PoW bound to the ticket; ticket is one-time on success).

| Parameter | Value |
|-----------|--------|
| Digits | **8** (`digits=8` in otpauth URI; verify requires exactly 8 digits) |
| Algorithm | SHA1 |
| Period | 30 seconds |
| Clock skew | ±1 step (~±30 s) |
| Failures | Counted toward **per-IP + email** lockout (same as passwords) |
| Password reset | **Required** when TOTP is enabled (`totpCode` on reset) |
| Change password | **Required** when TOTP is enabled (`totpCode` on `POST /auth/change-password`) |
| After enable | All sessions deleted; client must re-login with password + TOTP |
| PoW | Action-time on login TOTP complete |

**Migration:** Authenticators enrolled under the old 6-digit policy will not verify. Disable and re-enroll 2FA.

## Proof-of-work (auth)

Login password, email-OTP complete, TOTP complete, and **forgot-password** each **always** require a
one-time **HMAC-SHA256** PoW challenge (there is no “PoW off” mode). Challenges are issued when the user
submits (so they do not expire while waiting for email).

Client (`pow.js`) and server (`ProofOfWorkService`) use Web Crypto / .NET **HMAC-SHA256** with a
server-issued key; the client searches nonces until the MAC has the required leading zero **bits**.

Challenges are **bound** to the action identity:

| Action | Challenge | Resource bind |
|--------|-----------|----------------|
| Login / register | `GET /api/v1/auth/login/pow?email=` | hash of normalized email |
| Email OTP | `GET /api/v1/auth/login/email-otp/pow?ticket=` | hash of ticket |
| TOTP | `GET /api/v1/auth/login/totp/pow?ticket=` | hash of ticket |
| Forgot password | `GET /api/v1/auth/forgot-password/pow?email=` | hash of email |

| Parameter | Value |
|-----------|--------|
| Default difficulty | **12** leading zero bits (`SENDIT_POW_DIFFICULTY_BITS`) |
| Allowed range | **1–28** (values &lt; 1 raised to 1; never disabled) |
| Low-bits warning | Startup **Warning** if configured bits **&lt; 12** |
| Challenge TTL | 120 seconds default (`SENDIT_POW_CHALLENGE_TTL_SECONDS`) |
| Storage | SQLite `pow_challenges` (multi-instance) |
| Consume | Successful use **deletes** the challenge row (no replay) |
| Bad/missing PoW | 403; counts toward scan failure budget → **429** |

**Rate budget:** shared IP auth limits apply to the **action POST** (not the GET `/pow` challenge),
so a normal login does not double-spend the 60/min quota. Challenge minting still has a scan
issue budget + process-local ASP.NET policy. Tighten further at nginx if needed.

## Auth emails (OTP + password reset)

Shared budget per address for OTP and password-reset emails (SQLite, multi-instance):

| Sends already allowed | Min interval before next |
|----------------------|--------------------------|
| 0–5 (first 6 emails) | **10 seconds** |
| 6+ | **1 minute** |

### Notification emails (collect ready / send opened)

Optional per-account toggles (`NotifyCollectReady`, `NotifySendOpened`). When a pref is on,
Sendit! builds multipart emails (plain + HTML) with a Dashboard link and sends them through
the same `IEmailSender` path as OTP (SMTP / Mailgun / Development console log). There is
**no** separate gate on `IsEmailTransportConfigured` — without transport, Development logs
the body and other environments log an error without the body.

Separate budget (`notify_email` kind), **4× more permissive** than OTP/reset so normal
activity is not blocked by a recent verification mail:

| Parameter | OTP / reset | Notifications (4×) |
|-----------|-------------|---------------------|
| Fast-lane length | first **6** sends | first **24** sends |
| Fast interval | **10 s** | **2.5 s** |
| Slow interval | **1 min** | **15 s** |

Throttled notification sends are skipped (logged); the HTTP request still succeeds.
`NoteNotifyEmailSent` runs only after a successful send so failed transports do not burn budget.

## Password reset

1. `POST /api/v1/auth/forgot-password` with email + PoW (always generic success)
2. Email is sent only for **confirmed** accounts (`EmailConfirmed`). Unconfirmed /
   abandoned registration rows are treated like “no account” (no reset link; resume via
   sign-in + email OTP). Client response is always the same success message.
3. Prior reset tokens for the user are **deleted**; only the latest is valid
4. Email contains one-time link; server stores **HMAC-SHA256(token)** only
5. Token lifetime: **30 minutes**
6. `POST /api/v1/auth/reset-password` with `token`, `password` (≤256 chars), `wrappedUserDataKey`, and `totpCode` if 2FA is on
7. Token consume is **atomic** (`UsedAt` set only if still unused). Tokens for still-unconfirmed
   users are rejected as invalid.
8. Reset rotates security stamp, deletes sessions, deletes owned sends and collects (frees storage quota)

## Rate limits

Layered per client IP (XFF only from trusted proxies — see deploy):

| Layer | Scope | Limit |
|-------|--------|--------|
| SQLite shared (`rate_limit_events` bucket `auth`) | login, email-OTP, TOTP, reset, change-password, totp enroll/disable, get/set user-data-key | **60 / minute** |
| SQLite shared (`forgot`) | forgot-password | **30 / minute** |
| SQLite shared (`api`) | all `/api/*` | **600 / minute** |
| ASP.NET policy `auth` / `forgot` | process-local backstop | same 60 / 30 |
| ASP.NET global | all `/api/*` process-local backstop | **600 / minute** |
| Scan budget (SQLite) | bad PoW / share 404s | **10 failures / ~60s** → 429 |

Shared SQLite windows are the multi-instance source of truth; ASP.NET policies add a per-process backstop.
Fixed-window inserts use `BEGIN IMMEDIATE` to avoid concurrent overshoot.

### Email transport

| Config | Role |
|--------|------|
| `SENDIT_SMTP_*` | SMTP primary when `SENDIT_SMTP_HOST` is set |
| `SENDIT_MAILGUN_DOMAIN` + `SENDIT_MAILGUN_API_KEY` | Mailgun primary when SMTP is unset; **failover** if SMTP is set and send throws |
| `SENDIT_MAILGUN_FROM` | Optional From for Mailgun (else `SENDIT_SMTP_FROM`, else `noreply@{domain}`) |
| `SENDIT_MAILGUN_BASE_URL` | Optional API host (default `https://api.mailgun.net`; EU: `https://api.eu.mailgun.net`) |

If **both** SMTP and Mailgun are configured: try SMTP first, then Mailgun on failure.  
If **neither**: full message body is logged **only in Development**; other environments log an error without the body (no reset links / OTP codes in logs).

Each transport attempt is capped (~7 s). Total failure returns `code: email_send_failed` so the UI can reset instead of hanging.

### Ticket key

`SENDIT_TICKET_KEY` must be **≥ 32 characters** of high-entropy random material
(e.g. `openssl rand -base64 32`). Short passphrases are rejected at startup.

If unset, the server creates a 256-bit hex key in `.sendit-ticket-key` next to the DB (owner-only mode when possible).

Share the same `SENDIT_DB_PATH` (or volume) so PoW, scan budget, auth throttle, tickets, and rate limits stay consistent across instances.

## Server keys (summary)

| Variable | Role |
|----------|------|
| `SENDIT_TICKET_KEY` | ≥32-char high-entropy secret for tickets / OTP / reset HMAC (or auto file next to DB) |
| `SENDIT_DATA_KEY` | Optional dedicated at-rest key for TOTP + collect-key envelopes (else ticket-key material) |

## Security logging and activity audit

Auth failures, lockouts, email throttles, and HTTP 429s are logged at **Warning** under category `Sendit.Security` (console by default).

**Site-wide Audit UI** (`audit_log`, page `/audit`) records credential failures and product events:

| Kind | When |
|------|------|
| `auth_password_failed` | Wrong password at sign-in, change-password, or TOTP disable |
| `auth_otp_failed` | Wrong or malformed email verification code |
| `auth_totp_failed` | Wrong authenticator code at sign-in, password reset, change-password, or TOTP disable |
| `send_created` / `collect_created` | Owner creates a send/collect (includes resource id) |
| `send_deleted` / `collect_deleted` | Owner deletes item |
| `send_viewed` / `send_decrypted` | Public view / payload download |
| `collect_uploaded` / `collect_retrieved` | Guest upload / owner retrieve |
| `send_ip_denied` / `collect_ip_denied` | IP allow-list rejection (no burn) |
| `account_registered`, `password_changed`, `totp_enabled`, `totp_disabled` | Account lifecycle |

Each row includes actor email when known, client IP, and a short human message. Codes and passwords are never stored. List API: `GET /api/v1/me/audit` (paginated; default and max **500**). See also [`AUDIT.md`](AUDIT.md).

Optional file mirror and level:

```bash
export SENDIT_LOG_FILE=/var/log/sendit/security.log
export SENDIT_LOG_LEVEL=WARNING   # INFO (default) | WARNING | ERROR
```
