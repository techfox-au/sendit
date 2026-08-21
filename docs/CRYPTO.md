# Sendit! cryptography (protocol v1)

This document describes the client-side encryption protocol. Implementation:
`src/frontend/js/crypto.js`. The API never decrypts secret payloads.

Server env for ticket/data keys and PoW difficulty: [`CONFIGURATION.md`](CONFIGURATION.md).
Auth and password hashing: [`AUTH.md`](AUTH.md).

## Goals

- Server stores only ciphertext and key-wrap material.
- Private keys for decryption travel in URL fragments (`#sk=…`) and are not sent on HTTP requests.
- Hybrid encryption: AES-256-GCM for data; X25519 ECDH + HKDF-SHA-256 + AES-GCM for key wrap.
- Optional **link password** (send **and** collect) seals the fragment `sk` with PBKDF2 + AES-256-GCM (server never sees the password or unwrapped `sk`).

## Primitives

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Payload | AES-256-GCM | 12-byte IV, 128-bit tag |
| Payload key / IVs / salts / keys | **CSPRNG** | See [Randomness (CSPRNG)](#randomness-csprng) |
| Key agreement | X25519 ECDH | TweetNaCl `nacl.scalarMult` / `nacl.box.keyPair` (seeded by CSPRNG) |
| KDF (payload key wrap) | HKDF-SHA-256 | salt = 32 zero bytes; info = UTF-8 `sendit-v1-wrap`; L = 32 |
| Key wrap (AES `K`) | AES-256-GCM | 12-byte wrap IV prepended to wrap ciphertext |
| Encoding | base64url | No padding, RFC 4648 §5; raw fragment `#sk` must be **canonical** |
| Optional link password | PBKDF2-HMAC-SHA512 → AES-256-GCM | Same iteration count as UDK / password hash; salt 16 B, IV 12 B, `ct` = GCM(ciphertext‖tag) of 32-byte `sk` |

## Randomness (CSPRNG)

A **CSPRNG** (cryptographically secure pseudorandom number generator) produces bits that are
unpredictable to an attacker who does not control the OS/browser entropy source. Sendit! uses
CSPRNGs for all security-relevant random material—not general-purpose PRNGs such as
`Math.random` or `System.Random`.

### Browser (payload protocol)

Implementation: `src/frontend/js/crypto.js` (`randomBytes`), `user-data-key.js`, TweetNaCl
(`nacl-fast.js` sets its PRNG from the same source).

| API | Role |
|-----|------|
| **`crypto.getRandomValues`** (Web Crypto) | Sole client CSPRNG for keys, IVs, salts, and X25519 key material |

Used for:

- Payload AES key `K` (32 bytes) and GCM IV (12 bytes)
- Ephemeral X25519 keypairs and recipient `#sk` key material (via NaCl + Web Crypto)
- Key-wrap AES-GCM IV (12 bytes)
- Optional link-password wrap: salt (16 bytes), IV (12 bytes)
- Account **user data key (UDK)** (32 bytes) and UDK-wrap salt/IV

Notation in the steps below (`random(n)`) means **n bytes from this CSPRNG**.

### Server (API; not payload decryption)

The API never generates payload content keys, but still uses a CSPRNG for auth and storage
material. Implementation: `System.Security.Cryptography.RandomNumberGenerator` (OS CSPRNG).

| Use | Location (examples) |
|-----|---------------------|
| Opaque IDs, auth tickets / stamps | `Util/IdGenerator` |
| Password hash salt | `PasswordHasher` |
| Data-at-rest nonces | `DataAtRestProtector` |
| PoW challenge id + key | `ProofOfWorkService` |
| Durable ticket HMAC key (first run) | `TicketKeyStore` |
| Email OTP digits | `AuthService` |
| TOTP enrollment secret | `TotpService` → Otp.NET `KeyGeneration.GenerateRandomKey` |

## Encrypt for a recipient public key

1. `K ← random(32)`; `iv ← random(12)` (CSPRNG)
2. `ciphertext ← AES-GCM-Encrypt(K, iv, plaintext)`
3. Ephemeral X25519 keypair `(ephSk, ephPk)` (CSPRNG seed)
4. `shared ← X25519(ephSk, recipientPk)`
5. `wrapKey ← HKDF-SHA-256(ikm=shared, salt=0x00×32, info="sendit-v1-wrap", len=32)`
6. `wrapIv ← random(12)` (CSPRNG)
7. `wrapped ← AES-GCM-Encrypt(wrapKey, wrapIv, K)`
8. `wrappedKey field ← wrapIv || wrapped`
9. Upload JSON: `ciphertext`, `iv`, `wrappedKey`, `ephemeralPublicKey` (all base64url)

## Decrypt with recipient secret key

1. Decode fields from base64url
2. `shared ← X25519(recipientSk, ephemeralPublicKey)`
3. Derive `wrapKey` as above
4. Split `wrappedKey` into `wrapIv` (12) + ciphertext
5. `K ← AES-GCM-Decrypt(wrapKey, wrapIv, …)`
6. `plaintext ← AES-GCM-Decrypt(K, iv, ciphertext)`

## Send flow

Sender generates a keypair, encrypts to the public key, stores ciphertext on the server,
and puts the secret key in the link fragment:

```
https://host/send?id={id}#sk={base64url(secretKey)}
```

### Optional link password (password-protected `#sk`)

When the sender sets a **link password** (optional on create):

1. `salt ← random(16)`; `iv ← random(12)` (CSPRNG)
2. `wrapKey ← PBKDF2-HMAC-SHA512(password, salt, i, dkLen=32)`  
   (`i` from `GET /api/v1/crypto/params` → `skWrapIterations` / `udkWrapIterations`, default 893241)
3. `ct ← AES-256-GCM-Encrypt(wrapKey, iv, sk)`  
   Web Crypto output is **ciphertext ‖ 128-bit tag** (typically 48 bytes for a 32-byte `sk`)
4. Compact package (algorithm fixed by protocol — not on the wire):
   `{ "i": <iterations>, "s": <salt b64url>, "iv": <iv b64url>, "ct": <ct b64url> }`
5. Fragment: `#sk={base64url(UTF-8 JSON package)}` (longer than the raw 43-char key)
6. Server stores only **`passwordProtected: true`** on the send row / public meta; never sees the
   password, package, or unwrapped `sk`

Recipient open flow:

1. PoW + `GET /api/v1/send/{id}/meta` → `passwordProtected`
2. If true: show **Link password** field; on Reveal, unwrap package → raw `sk`, then hybrid decrypt
3. Wrong password: AES-GCM auth fails closed (no plaintext)
4. Recipient-facing send name (`encryptedLabel`) is also sealed to `sk` — UI shows **Hidden** until unwrap

Optional **allowed IPs / CIDRs** (`allowedCidr` on `POST /api/v1/send`): a **comma-separated**
list of single IPv4, single IPv6, IPv4 CIDR, and/or IPv6 CIDR entries (e.g.
`203.0.113.10, 192.168.1.0/24, 2001:db8::/32`). Client and server both validate; the server
stores a canonical form and enforces it on meta/payload access (403 if the client IP matches
**none** of the entries; also writes activity audit `send_ip_denied`). Prefix length must be
valid (IPv4 0–32, IPv6 0–128). Empty or `*` = any IP. Max input length and entry count:
`IpRestriction.MaxInputLength` (**5 000 000** chars) / `MaxEntries` (**250 000**). Enforcement is
skipped when the client-IP canary has disabled IP restrictions (`ipRestrictionsEnabled: false`).

### Fragment `#sk` parsing

**Unprotected** (raw key):

- 32-byte keys encode as **exactly 43** base64url characters (no `=`).
- The final character only carries **4 data bits**; the remaining 2 bits of that
  sextet are padding. Without a canonical check, up to **four** different last
  characters decode to the **same** 32-byte key — so changing “the last character
  of sk” can still decrypt. That is base64 encoding, not weak AES/X25519.
- `secretKeyFromLocationHash` requires the fragment value to be the
  **canonical** unpadded base64url of a 32-byte key (`encode(decode(s)) === s`).
  Non-canonical last-character variants are rejected as a missing/invalid key.
- A **middle** character change always alters the decoded key; AES-GCM unwrap
  then fails closed (authentication tag mismatch).

**Password-protected** (wrap package):

- Fragment value is longer than 43 characters (base64url of UTF-8 JSON).
- `secretKeyPackageFromLocationHash` parses `{i,s,iv,ct}`; unwrap validates
  salt length 16, IV length 12, and `ct` length ≥ 48 before AES-GCM decrypt.

### Curve25519 clamping note

TweetNaCl clamps private scalars before ECDH (`sk[0] &= 248`, `sk[31] &= 127`,
`sk[31] |= 64`). Flipping only bit 6 or bit 7 of the **last raw key byte** yields
the same clamped scalar and the same shared secret. That is standard X25519,
not an application bug. Real key corruption of other bits fails decrypt.

## Collect flow

Collector generates a keypair, stores **only the public key** on the server with the collect item,
keeps `collect` link with `#sk=…`, and sends the upload URL (no private key). Uploader encrypts
to the collect public key.

### Optional link password (collect `#sk`)

Same client package as send (`{ i, s, iv, ct }` via PBKDF2-SHA512 + AES-256-GCM). Server stores
`passwordProtected` on the collect row for public meta.

Owner re-open material (`privateKeyCiphertext` / dashboard collect key):

- **No link password:** UDK-encrypt the raw 32-byte sk (dashboard builds `#sk=` raw).
- **With link password:** UDK-encrypt the **password-wrap package** (UTF-8 JSON); dashboard rebuilds
  the password-protected `#sk=` fragment. Opening the collect still requires the link password
  (UDK unlock alone is not enough).

## Account password hashing (server)

Not used for secret payloads. See `docs/AUTH.md`.

- PBKDF2-HMAC-SHA512, 893241 iterations, 64-byte salt (CSPRNG per password), 64-byte DK
- Account and link passwords: min **8** (account), max **256** characters

## Proof-of-work (client + server)

Public ID access, collect upload, and auth steps use **HMAC-SHA256** PoW:

1. Server issues `challengeId`, `hmacKey` (secret), `difficultyBits`, `expiresAt`
2. Client finds ASCII nonce such that `HMAC-SHA256(hmacKey, nonce)` has `difficultyBits` leading zero **bits**
3. Server verifies and **deletes** the challenge (one-time)

Implementation: `src/frontend/js/pow.js`, `ProofOfWorkService`. Difficulty always ≥ 1.
