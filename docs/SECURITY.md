# Security

## Reporting

Report vulnerabilities privately to the repository maintainers. Please do not open public issues for exploitable flaws until maintainers have had a chance to respond.

## Scope of this document

This file explains **how Sendit! protects secrets**, **why the crypto is shaped the way it is**, and **what an attacker can and cannot do**. It is the narrative security model.

| Deeper reference | Content |
|------------------|---------|
| [`CRYPTO.md`](CRYPTO.md) | Protocol steps, parameters, fragment edge cases |
| [`../src/frontend/js/crypto.js`](../src/frontend/js/crypto.js) | Only place secret payloads are encrypted/decrypted |
| [`../src/frontend/js/user-data-key.js`](../src/frontend/js/user-data-key.js) | User data key (UDK) wrap/unwrap |
| [`AUTH.md`](AUTH.md) | Passwords, sessions, OTP, TOTP, auth PoW |
| [`CONFIGURATION.md`](CONFIGURATION.md) | Env vars, keys, rate limits, quotas |
| [`AUDIT.md`](AUDIT.md) | Checklist for code review |

**Audit source of truth:** `src/frontend/` and `src/Sendit.Api/` — not minified `public/` alone.

---

## Design goals

1. **Server never sees plaintext secrets** or unwrapped AES payload keys.
2. **Decrypt capability travels only in URL fragments** (`#sk=…`), which browsers do not send to the server on normal HTTP requests.
3. **One hybrid protocol** for both **send** and **collect** (AES for bulk data + X25519 wrap for the AES key).
4. **Owner-private dashboard fields** (collect private keys, private notes, names) use a separate **user data key (UDK)** bound to the account password.
5. **Abuse resistance** (HMAC-SHA256 PoW always ≥ 1 bit, dual request-body caps, rate limits, quotas, scan budget) is layered on top; it does not replace crypto.

---

## Mental model: why wrap the AES-256 key?

| Piece | Where it lives |
|--------|----------------|
| AES-256 payload key `K` | **Never** stored in the clear on the server |
| Ciphertext under `K` | Server database |
| `K` wrapped for a recipient **X25519 public key** | Server (`wrappedKey` + `ephemeralPublicKey`) |
| Matching **X25519 private key** | Only in the URL fragment `#sk=…` |

### Core diagram (all payload crypto)

```text
  plaintext
      │
      ▼
  AES-256-GCM (random key K)  ──────────► ciphertext  ──► server
      │
      ▼
  wrap K to recipient X25519 public key
  (ECDH → HKDF-SHA-256 → AES-GCM wrap)
      │
      ▼
  wrappedKey + ephemeralPublicKey  ──────► server

  only holder of recipient X25519 private key (#sk=)
  can recover K and decrypt
```

### Why not share raw AES only?

1. **Collect requires asymmetric encryption.**  
   The owner publishes a **public** key. Guests upload without knowing a shared secret. They generate `K`, encrypt the secret, and **wrap `K` to the owner’s public key**. The owner later uses `#sk=` (private key) to unwrap `K`.  
   A “raw AES in the link” design cannot let strangers contribute ciphertext that only the owner can open.

2. **One protocol for send and collect.**  
   Send generates an ephemeral X25519 keypair, encrypts to its public half, and puts the private half in `#sk=`. Same hybrid stack as collect.

3. **Capability in the fragment.**  
   Unprotected: `#sk=` is the **32-byte X25519 secret** (canonical base64url).  
   Optional **link password**: `#sk=` is a compact package where that secret is sealed with
   **PBKDF2-SHA512 → AES-256-GCM** (password never leaves the browser; server only stores a
   `passwordProtected` flag). Bulk payload data still uses AES-GCM under the hybrid-wrapped key.

4. **DB theft vs link theft (same high-level outcome, clearer roles).**  
   - **Database alone:** ciphertext + wraps; no `#sk=` → cannot decrypt.  
   - **Full link (path + fragment)** without link password: capability to decrypt that item.  
   - **Full link + password** when password-protected: both are required.  
   The hybrid wrap makes the server’s stored package “ciphertext + seal that only the private key opens,” not “ciphertext under a key that only exists off-server.”

**Short form:** AES encrypts the data; X25519 wrapping **transports** that AES key so guests can encrypt to a public key and so send/collect share one design.

---

## Primitives (protocol v1)

| Role | Algorithm | Notes |
|------|-----------|--------|
| Payload | AES-256-GCM | 12-byte IV, 128-bit tag; `K` = 32 random bytes |
| Key agreement | X25519 ECDH | TweetNaCl `nacl.scalarMult` / `box.keyPair` |
| KDF | HKDF-SHA-256 | salt = 32 zero bytes; info = `sendit-v1-wrap`; 32-byte output |
| Key wrap | AES-256-GCM | wrap IV (12) \|\| ciphertext+tag of `K` |
| Encoding | base64url | no padding; raw `#sk` must be **canonical** |
| Link password (optional) | PBKDF2-SHA512 + AES-256-GCM | Seals fragment `sk`; same iteration budget as UDK |

Implementation: `src/frontend/js/crypto.js`. Wire steps: `docs/CRYPTO.md`.

---

## Flow: Send a secret

**Who:** Account holder creates a link; recipient needs no account.

```text
  Sender browser
  ──────────────
  1. Generate X25519 keypair (recipientSk, recipientPk)
  2. Encrypt payload to recipientPk (AES K + hybrid wrap)
  3. POST ciphertext, iv, wrappedKey, ephemeralPublicKey
     (+ passwordProtected flag if link password set)  ──► server
  4. Build link:
       Unprotected:  #sk={base64url(recipientSk)}
       Password:     #sk={base64url(JSON {i,s,iv,ct})}  // AES-GCM seal of recipientSk

  Server
  ──────
  • Stores ciphertext + wrap material only (+ passwordProtected bit)
  • Never sees recipientSk, K, or the link password

  Recipient browser
  ────────────────
  1. PoW + meta (sees passwordProtected)
  2. If protected: enter link password → unwrap sk from #sk package
  3. GET payload (after PoW) → unwrap K with sk → decrypt plaintext
```

**Optional controls:** IP/CIDR allow-list, one-time or multi-view, expiry, hide-text UI, private note (UDK-encrypted for owner only), **link password** on send **and** collect (client-side PBKDF2 + AES-256-GCM on `#sk`).

**Threat note:** Unprotected full URL (including `#sk=`) decrypts the item. With a link password, the URL alone is not enough — treat the password like a second secret and share it out of band.

---

## Flow: Collect a secret

**Who:** Account holder creates collect + upload links; uploader needs no account.

```text
  Owner browser
  ─────────────
  1. Generate X25519 keypair (ownerSk, ownerPk)
  2. POST publicKey = ownerPk  ──► server
  3. Encrypt ownerSk under UDK; store protected blob for dashboard re-open
  4. Keep private collect link:

       https://host/collect?id={id}#sk={base64url(ownerSk)}

  5. Share public upload link (no #sk):

       https://host/upload?id={id}

  Uploader browser
  ────────────────
  1. GET collect public key (PoW)
  2. Encrypt payload to ownerPk (same hybrid as send)
  3. POST ciphertext … ──► server (PoW; counts against owner storage quota)

  Owner later
  ───────────
  1. Open collect link with #sk=
  2. Fetch payload (PoW; optional COLLECTION_RETRIEVE IP allow-list)
  3. Unwrap K with ownerSk, decrypt
```

```text
  Upload link (no secret)          Collect link (#sk= private)
         │                                    │
         ▼                                    ▼
  Anyone can encrypt & fill            Only owner can decrypt
  (until expiry / one-time rules)      (and reopen from dashboard via UDK)
```

**Why two links:** The upload URL is safe to share widely; the collect URL is the capability.

---

## Flow: User data key (UDK)

Account-bound key for **owner-only** fields (not for send/collect payload links).

```text
  On register / password set
  ──────────────────────────
  UDK ← random(32)
  wrap = PBKDF2-SHA-512(password) → AES-GCM(UDK)
  Server stores wrap only (opaque)

  After login (browser)
  ─────────────────────
  unwrap UDK with password → sessionStorage for this tab

  Used to encrypt
  ───────────────
  • Collect owner private key (for dashboard re-open)
  • Private notes / owner labels (dashboard)

  Password change / reset
  ───────────────────────
  New UDK; old sends/collects deleted (cannot re-wrap under unknown old UDK)
```

Optional **server second layer** (`SENDIT_DATA_KEY`, else ticket-key material): AES-GCM envelope on already UDK-wrapped collect-key blobs and TOTP secrets at rest. The server still cannot derive UDK from the password wrap without the password.

Implementation: `user-data-key.js`. Unlock package is **not** returned on every `GET /auth/me`; use `GET /auth/user-data-key` when unlocking a tab.

---

## What the server stores vs never sees

| Server may store | Server never has |
|------------------|------------------|
| Payload ciphertext, IVs, wrapped keys, eph public keys | Plaintext secrets |
| Collect X25519 **public** keys | Unwrapped AES payload keys `K` |
| UDK-wrapped owner packages | Raw UDK (only password holder unwraps in browser) |
| Password **hashes** (PBKDF2-SHA-512) | Account password (except in transit over TLS to verify) |
| Encrypted TOTP secrets at rest | Ability to decrypt payloads without `#sk=` / UDK |
| Metadata (expiry, one-time, access counts, CIDR) | URL fragments `#sk=` |

---

## Accounts and auth (security-relevant summary)

Not payload crypto; still part of the security posture.

| Control | Role |
|---------|------|
| Password hash | PBKDF2-HMAC-SHA512, 893,241 iters, 64-byte salt |
| Registration | Domain allow-list + email OTP + password reconfirm (client) |
| Sessions | HttpOnly, `SameSite=Strict` cookie, 8h, stamp-bound |
| TOTP | Optional second factor; required on reset when enabled |
| Auth tickets | HMAC + one-time jti in SQLite (email-OTP / TOTP steps) |
| Auth PoW | HMAC-SHA256; bound to email or ticket; action-time challenges |
| Passwords | PBKDF2-SHA512; min 8 / max **256** characters |
| Rate limits | Shared SQLite + ASP.NET backstops (see CONFIGURATION) |
| Body size | Default **275251** (256 KiB × 1.05); **210000000** (200M × 1.05) only for create send/collect (auth) and collect upload — Kestrel looser than nginx so the edge rejects first |
| Storage quota | Per-user cap on owned ciphertext blobs |
| Activity audit | Append-only site-wide log (creates, deletes, views, IP denials, auth failures) |

Details: [`AUTH.md`](AUTH.md).

---

## Abuse controls around secrets (not encryption)

These limit scanning and resource abuse; they do **not** replace `#sk=` secrecy.

| Control | Effect |
|---------|--------|
| HMAC-SHA256 PoW on send/collect ID access, collect upload, and auth | Cost before meta/payload/upload/auth (difficulty always ≥ 1; never off) |
| One-time PoW challenges | Successful consume deletes challenge (no replay) |
| Scan budget | Bad PoW / 404 → 429 |
| Valid PoW before burn | Invalid work never consumes one-time secrets |
| Per-user storage quota | Caps total encrypted payload size |
| Request body caps | Stops oversized auth/meta posts; large ciphertext only on designated routes |
| Optional send CIDR allow-list | Restrict who can open a send (403 + `send_ip_denied` audit; no burn) |
| Optional collect retrieve IP allow-list | Restrict who can pull submitted collect payloads (403 + `collect_ip_denied`) |

---

## Threat model

### Protected against (with correct deploy)

| Threat | Outcome |
|--------|---------|
| Server operator / DB dump only | Cannot read payload plaintext without client keys |
| Passive of ciphertext in transit (TLS) | Confidentiality depends on TLS termination |
| Casual ID guessing | Opaque IDs + PoW + rate limits |
| Online password / OTP brute force (single IP) | KDF cost, OTP wipe@5, lockouts, PoW, rate limits |
| Multi-instance quota bypass (shared DB) | Shared SQLite throttle / rate tables |
| Abandoned registration restart | Unconfirmed accounts may replace password+UDK wrap with a full client payload; prior OTP is wiped; progressive password interval is **not** cleared on wrap-based restart; session still requires email OTP |

### Not protected against

| Threat | Outcome |
|--------|---------|
| **Full link disclosure** (`id` + `#sk=`) | Decrypts unprotected sends; password-protected needs password too |
| **Malicious or compromised browser / XSS** | Can steal secrets at encrypt/decrypt time or session/UDK |
| **Stolen session + password** | Account access; wrap package offline attack |
| **Large botnet / many IPs** | Per-IP limits scale with attacker IPs |
| **Open registration** (`ALLOWED_EMAIL_DOMAINS` empty/`*`) | Account/mail/storage abuse still possible under PoW tax |
| **Missing TLS or mis-trusted XFF** | Cookie/IP controls weaken |
| **Full control of host static root** | Attacker who rewrites **both** HTML and assets can re-pin SRI hashes |

### Production frontend integrity (SRI)

Production HTML is generated by [`../scripts/build-frontend.py`](../scripts/build-frontend.py). Built pages pin:

| Asset | How |
|-------|-----|
| **`/js/*.min.js`**, **`/vendor/*.min.js`** | Each `<script src>` gets `integrity="sha384-…"` + `crossorigin="anonymous"` |
| **`/css/style.min.css`** | Each matching `<link href>` gets the same SRI attributes |
| **`/api/v1/branding/theme.css`** | **Not pinned** (generated at runtime from `SENDIT_HIGHLIGHT`) |

Browsers refuse to apply/execute those resources if the bytes diverge from the build.

This is **defense in depth for static delivery** (tampered or swapped files after build, partial overwrites). It does **not** replace TLS, CSP, or reviewing source under `src/frontend/`. Rebuild `public/` after any frontend change so HTML and asset hashes stay in sync. An attacker who can rewrite both HTML and assets on the origin can re-pin hashes; SRI does not stop full origin compromise.

### Fragment edge cases (not vulnerabilities)

- Base64url last-character padding: non-canonical `#sk=` values are **rejected** (canonical check).
- X25519 clamping: flipping only certain high bits of the raw private key can yield the same scalar; standard Curve25519 behavior. Real corruption fails AES-GCM.

---

## Production hardening checklist

1. TLS at reverse proxy; API not public without proxy.  
2. `SENDIT_TICKET_KEY` ≥ 32 chars high-entropy; prefer separate `SENDIT_DATA_KEY`.  
3. Tight `SENDIT_ALLOWED_EMAIL_DOMAINS`.  
4. Email transport (SMTP and/or Mailgun).  
5. `SENDIT_POW_DIFFICULTY_BITS` ≥ 12 recommended (minimum 1; never off).  
6. Trust only known proxies for `X-Forwarded-For`.  
7. Back up SQLite volume **and** ticket-key material together.  
8. Deploy a fresh `public/` from `python3 scripts/build-frontend.py` so HTML SRI pins match JS/vendor/CSS bytes.  
9. Optional: nginx rate limits, collect retrieve IP allow-list, monitoring of 429/auth failures.  
10. Keep nginx `client_max_body_size` at **256k** / **200m** (API defaults are 5% above the decimal caps / slightly above binary `200m` so nginx is the first gate).  
11. Prefer dedicated `SENDIT_DATA_KEY`; backup DB + ticket key together.

Full env reference: [`CONFIGURATION.md`](CONFIGURATION.md).

---

## Where to read the code

| Concern | Path |
|---------|------|
| Hybrid encrypt/decrypt | `src/frontend/js/crypto.js` |
| Send UI | `src/frontend/js/send.js`, `view.js` |
| Collect UI | `src/frontend/js/request.js` |
| Dashboard / audit UI | `dashboard.js`, `audit.js` |
| UDK | `src/frontend/js/user-data-key.js` |
| Frontend build + SRI pins | `scripts/build-frontend.py` → `public/` |
| Auth | `src/Sendit.Api/Services/AuthService.cs` |
| PoW | `ProofOfWorkService.cs`, `pow.js` |
| Quotas | `UserStorageQuota.cs` |
| Field limits | `Util/FieldLimits.cs` |
| Activity audit | `ActivityAuditStore.cs` |
| Stores (ciphertext only) | `SecretStore.cs`, `RequestStore.cs` |

Protocol steps and constants: [`CRYPTO.md`](CRYPTO.md).  
Audit checklist + activity log kinds: [`AUDIT.md`](AUDIT.md).
