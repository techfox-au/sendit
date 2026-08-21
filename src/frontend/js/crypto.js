/**
 * Sendit! client-side cryptography
 * =================================
 *
 * This module is the ONLY place secret material is encrypted or decrypted.
 * The Sendit! server stores ciphertext and wrapped keys; it never sees plaintext
 * secrets or unwrapped AES keys.
 *
 * Protocol version: 1
 *
 * Layers
 * ------
 * 1. Payload encryption
 *    - Algorithm: AES-256-GCM
 *    - Key K: 32 random bytes (crypto.getRandomValues)
 *    - IV: 12 random bytes (unique per encryption)
 *    - Tag: 128-bit authentication tag (appended by Web Crypto)
 *
 * 2. Key agreement (to transport K)
 *    - Algorithm: X25519 ECDH (via TweetNaCl nacl.scalarMult / box keyPair)
 *    - Ephemeral sender keypair (ephSk, ephPk) generated per wrap
 *    - shared = X25519(ephSk, recipientPk)
 *
 * 3. Key derivation
 *    - HKDF-SHA-256 (Web Crypto)
 *    - salt: 32 zero bytes (protocol-fixed; shared secret already high entropy)
 *    - info: UTF-8 "sendit-v1-wrap"
 *    - output: 32-byte wrap key
 *
 * 4. Key wrap (AES payload key K)
 *    - AES-256-GCM encrypt K under the HKDF wrap key
 *    - Separate 12-byte IV for the wrap (stored with wrapped key blob)
 *
 * Wire layout for wrappedKey field (binary, then base64url in JSON):
 *    wrapIv (12) || gcm(ciphertext||tag of K)
 *
 * 5. Optional link password (send and collect) — seals the fragment sk
 *    - PBKDF2-HMAC-SHA512(password, salt=16B, i from /api/v1/crypto/params) → 32B
 *    - AES-256-GCM(wrapKey, iv=12B, sk) → ct (ciphertext‖128-bit tag)
 *    - Compact package in fragment (alg fixed by protocol, not on wire):
 *         { i, s, iv, ct }  all b64url except i (integer)
 *    - Server stores only passwordProtected boolean; never sees password or sk
 *
 * URL fragment convention
 * -----------------------
 * Private keys travel only in the URL fragment (#...), which browsers do not
 * send to the server on HTTP requests:
 *    Unprotected:  /send?id=…#sk=<base64url 32-byte X25519 private key>
 *    Password:     /send?id=…#sk=<base64url(UTF-8 JSON {i,s,iv,ct})>
 * Collect link may use the password form. Dashboard stores UDK(raw sk) or, when password-
 * protected, UDK(password-wrap package) so re-opened links still require the link password.
 *
 * Dependencies
 * ------------
 * - window.nacl  (TweetNaCl nacl-fast.js) for X25519
 * - window.crypto.subtle for AES-GCM, HKDF, and PBKDF2
 *
 * Auditors: prefer this file + docs/CRYPTO.md over minified public/js/crypto.min.js.
 */

(function (global) {
  "use strict";

  const PROTOCOL_VERSION = 1;
  const HKDF_INFO = new TextEncoder().encode("sendit-v1-wrap");
  const HKDF_SALT = new Uint8Array(32); // fixed zeros; documented in CRYPTO.md
  const AES_KEY_BITS = 256;
  const IV_LENGTH = 12;
  const X25519_LEN = 32;
  const GCM_TAG_LEN = 16;

  // Optional link-password wrap of fragment sk (params from /api/v1/crypto/params).
  const PW_WRAP_SALT_LEN = 16;
  const PW_WRAP_IV_LEN = 12; // AES-GCM standard nonce size
  let PW_WRAP_ITERATIONS = 893241; // same default as server password / UDK policy
  let PW_WRAP_HASH = "SHA-512";
  let pwWrapParamsLoaded = false;

  // ---------------------------------------------------------------------------
  // Encoding helpers (base64url, no padding)
  // ---------------------------------------------------------------------------

  /**
   * Encode bytes as base64url without '=' padding.
   */
  function b64urlEncode(bytes) {
    let bin = "";
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  /**
   * Decode base64url (with or without padding) to Uint8Array.
   */
  function b64urlDecode(str) {
    let s = str.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /**
   * Decode base64url only if it is the canonical (unpadded) encoding of
   * exactly `expectedLen` bytes. Rejects non-canonical last-character
   * variants that base64 would otherwise accept as identical payloads
   * (32 bytes → 43 chars; the final char carries only 4 data bits).
   */
  function b64urlDecodeCanonical(str, expectedLen) {
    if (typeof str !== "string" || !str) return null;
    if (!/^[A-Za-z0-9_-]+$/.test(str)) return null;
    let decoded;
    try {
      decoded = b64urlDecode(str);
    } catch (_) {
      return null;
    }
    if (decoded.length !== expectedLen) return null;
    // Reject padding noise / alternate encodings of the same bytes.
    if (b64urlEncode(decoded) !== str) return null;
    return decoded;
  }

  function requireNacl() {
    if (!global.nacl || !global.nacl.box || !global.nacl.scalarMult) {
      throw new Error("TweetNaCl (nacl) is required for X25519.");
    }
  }

  /** AES-GCM / HKDF need crypto.subtle (HTTPS or localhost only). */
  function requireSubtle() {
    const subtle = global.crypto && global.crypto.subtle;
    if (subtle) return subtle;
    throw new Error(
      "Web Crypto is unavailable. Use HTTPS or http://localhost " +
        "(plain HTTP on a phone LAN IP blocks encryption)."
    );
  }

  // ---------------------------------------------------------------------------
  // Randomness and key generation
  // ---------------------------------------------------------------------------

  /** Cryptographically secure random bytes. */
  function randomBytes(n) {
    const b = new Uint8Array(n);
    global.crypto.getRandomValues(b);
    return b;
  }

  /**
   * Generate an X25519 keypair for hybrid encryption.
   * Returns { publicKey: Uint8Array(32), secretKey: Uint8Array(32) }.
   *
   * Uses nacl.box.keyPair which is X25519 (Curve25519 ECDH keys).
   */
  function generateKeyPair() {
    requireNacl();
    const kp = global.nacl.box.keyPair();
    return {
      publicKey: new Uint8Array(kp.publicKey),
      secretKey: new Uint8Array(kp.secretKey),
    };
  }

  /**
   * Derive a keypair from an existing 32-byte secret key.
   */
  function keyPairFromSecretKey(secretKey) {
    requireNacl();
    const sk = secretKey instanceof Uint8Array ? secretKey : new Uint8Array(secretKey);
    if (sk.length !== X25519_LEN) throw new Error("X25519 secret key must be 32 bytes.");
    const kp = global.nacl.box.keyPair.fromSecretKey(sk);
    return {
      publicKey: new Uint8Array(kp.publicKey),
      secretKey: new Uint8Array(kp.secretKey),
    };
  }

  // ---------------------------------------------------------------------------
  // AES-256-GCM payload encrypt / decrypt
  // ---------------------------------------------------------------------------

  /**
   * Import a raw 32-byte AES key for encrypt or decrypt.
   */
  async function importAesKey(rawKey, usages) {
    return requireSubtle().importKey("raw", rawKey, { name: "AES-GCM" }, false, usages);
  }

  /**
   * Encrypt plaintext bytes with a fresh AES-256 key.
   *
   * Steps:
   * 1. Generate 32-byte key K
   * 2. Generate 12-byte IV
   * 3. AES-GCM encrypt plaintext under K
   * 4. Return { key, iv, ciphertext } where ciphertext includes the GCM tag
   */
  async function encryptPayload(plaintextBytes) {
    const keyBytes = randomBytes(32);
    const iv = randomBytes(IV_LENGTH);
    const key = await importAesKey(keyBytes, ["encrypt"]);
    const ciphertext = new Uint8Array(
      await requireSubtle().encrypt({ name: "AES-GCM", iv }, key, plaintextBytes)
    );
    return { key: keyBytes, iv, ciphertext };
  }

  /**
   * Decrypt AES-256-GCM ciphertext with key and IV.
   */
  async function decryptPayload(keyBytes, iv, ciphertext) {
    const key = await importAesKey(keyBytes, ["decrypt"]);
    const plain = await requireSubtle().decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
    return new Uint8Array(plain);
  }

  // ---------------------------------------------------------------------------
  // ECDH + HKDF + AES-GCM key wrap
  // ---------------------------------------------------------------------------

  /**
   * X25519 ECDH shared secret: scalarMult(ourSecret, theirPublic).
   */
  function ecdhShared(secretKey, publicKey) {
    requireNacl();
    const shared = global.nacl.scalarMult(secretKey, publicKey);
    return new Uint8Array(shared);
  }

  /**
   * HKDF-SHA-256 → 32-byte AES key from ECDH shared secret.
   *
   * Steps:
   * 1. Import shared secret as HKDF IKM
   * 2. Derive bits with salt=zeros, info="sendit-v1-wrap", length=256
   */
  async function deriveWrapKey(sharedSecret) {
    const subtle = requireSubtle();
    const baseKey = await subtle.importKey(
      "raw",
      sharedSecret,
      "HKDF",
      false,
      ["deriveBits"]
    );
    const bits = await subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: HKDF_SALT,
        info: HKDF_INFO,
      },
      baseKey,
      AES_KEY_BITS
    );
    return new Uint8Array(bits);
  }

  /**
   * Wrap AES payload key K for a recipient X25519 public key.
   *
   * Steps:
   * 1. Generate ephemeral X25519 keypair (ephSk, ephPk)
   * 2. shared = X25519(ephSk, recipientPublicKey)
   * 3. wrapKey = HKDF-SHA-256(shared, info="sendit-v1-wrap")
   * 4. Encrypt K with AES-GCM(wrapKey, wrapIv)
   * 5. Return { wrappedKey: wrapIv||ct, ephemeralPublicKey: ephPk }
   *
   * Recipient needs ephPk + their secret key to reverse this.
   */
  async function wrapKey(aesKeyBytes, recipientPublicKey) {
    if (aesKeyBytes.length !== 32) throw new Error("AES key must be 32 bytes.");
    if (recipientPublicKey.length !== X25519_LEN) {
      throw new Error("Recipient public key must be 32 bytes.");
    }

    const eph = generateKeyPair();
    const shared = ecdhShared(eph.secretKey, recipientPublicKey);
    // Best-effort wipe of ephemeral secret from our view (GC still applies).
    eph.secretKey.fill(0);

    const wrapKeyBytes = await deriveWrapKey(shared);
    shared.fill(0);

    const wrapIv = randomBytes(IV_LENGTH);
    const wk = await importAesKey(wrapKeyBytes, ["encrypt"]);
    wrapKeyBytes.fill(0);

    const wrapped = new Uint8Array(
      await requireSubtle().encrypt({ name: "AES-GCM", iv: wrapIv }, wk, aesKeyBytes)
    );

    // Layout: 12-byte IV || ciphertext+tag
    const packed = new Uint8Array(IV_LENGTH + wrapped.length);
    packed.set(wrapIv, 0);
    packed.set(wrapped, IV_LENGTH);

    return {
      wrappedKey: packed,
      ephemeralPublicKey: eph.publicKey,
    };
  }

  /**
   * Unwrap AES payload key using recipient secret key and sender ephemeral public key.
   *
   * Steps:
   * 1. shared = X25519(recipientSk, ephemeralPublicKey)
   * 2. wrapKey = HKDF-SHA-256(shared, ...)
   * 3. Split wrappedKey into wrapIv || ct
   * 4. AES-GCM decrypt → K
   */
  async function unwrapKey(wrappedKeyPacked, ephemeralPublicKey, recipientSecretKey) {
    if (wrappedKeyPacked.length < IV_LENGTH + 16) {
      throw new Error("wrappedKey too short.");
    }
    if (ephemeralPublicKey.length !== X25519_LEN) {
      throw new Error("ephemeralPublicKey must be 32 bytes.");
    }
    if (recipientSecretKey.length !== X25519_LEN) {
      throw new Error("recipient secret key must be 32 bytes.");
    }

    const wrapIv = wrappedKeyPacked.slice(0, IV_LENGTH);
    const ct = wrappedKeyPacked.slice(IV_LENGTH);

    const shared = ecdhShared(recipientSecretKey, ephemeralPublicKey);
    const wrapKeyBytes = await deriveWrapKey(shared);
    shared.fill(0);

    const wk = await importAesKey(wrapKeyBytes, ["decrypt"]);
    wrapKeyBytes.fill(0);

    const aesKey = new Uint8Array(
      await requireSubtle().decrypt({ name: "AES-GCM", iv: wrapIv }, wk, ct)
    );
    if (aesKey.length !== 32) throw new Error("Unwrapped key has unexpected length.");
    return aesKey;
  }

  // ---------------------------------------------------------------------------
  // High-level encrypt-for-recipient / decrypt-with-secret
  // ---------------------------------------------------------------------------

  /**
   * Encrypt a secret for a known recipient public key (send or collect-upload).
   *
   * @param {Uint8Array} plaintextBytes
   * @param {Uint8Array} recipientPublicKey - 32-byte X25519 public key
   * @returns wire object ready for JSON (base64url fields)
   */
  async function encryptForRecipient(plaintextBytes, recipientPublicKey) {
    const { key, iv, ciphertext } = await encryptPayload(plaintextBytes);
    const { wrappedKey, ephemeralPublicKey } = await wrapKey(key, recipientPublicKey);
    key.fill(0);

    return {
      v: PROTOCOL_VERSION,
      ciphertext: b64urlEncode(ciphertext),
      iv: b64urlEncode(iv),
      wrappedKey: b64urlEncode(wrappedKey),
      ephemeralPublicKey: b64urlEncode(ephemeralPublicKey),
    };
  }

  /**
   * Decrypt a wire payload using the recipient's X25519 secret key.
   */
  async function decryptWithSecretKey(payload, secretKey) {
    const ciphertext = b64urlDecode(payload.ciphertext);
    const iv = b64urlDecode(payload.iv);
    const wrappedKey = b64urlDecode(payload.wrappedKey);
    const ephPk = b64urlDecode(payload.ephemeralPublicKey);

    const aesKey = await unwrapKey(wrappedKey, ephPk, secretKey);
    const plain = await decryptPayload(aesKey, iv, ciphertext);
    aesKey.fill(0);
    return plain;
  }

  /**
   * Collect name dual-access encryption: AES-256-GCM key = SHA-256(publicKey).
   * Server stores ciphertext only. Upload decrypts with publicKey from meta (after PoW);
   * collect page derives publicKey from #sk=. Uses digest (not HKDF) for wide browser support.
   */
  async function deriveCollectNameKey(publicKey) {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== X25519_LEN) {
      throw new Error("Collect public key must be 32 bytes.");
    }
    // Domain-separate from other SHA-256 uses of the public key bytes.
    const input = new Uint8Array(16 + publicKey.length);
    input.set(new TextEncoder().encode("sendit-v1-cname"), 0);
    input.set(publicKey, 16);
    return new Uint8Array(await requireSubtle().digest("SHA-256", input));
  }

  /**
   * Encrypt collect name bound to the collect X25519 public key (not plaintext on server).
   * @returns wire { v, bound, ciphertext, iv } base64url fields
   */
  async function encryptCollectName(plaintextBytes, publicKey) {
    const keyBytes = await deriveCollectNameKey(publicKey);
    try {
      const iv = randomBytes(IV_LENGTH);
      const key = await importAesKey(keyBytes, ["encrypt"]);
      const ciphertext = new Uint8Array(
        await requireSubtle().encrypt({ name: "AES-GCM", iv: iv }, key, plaintextBytes)
      );
      return {
        v: PROTOCOL_VERSION,
        bound: "collect-pk-v2",
        ciphertext: b64urlEncode(ciphertext),
        iv: b64urlEncode(iv),
      };
    } finally {
      keyBytes.fill(0);
    }
  }

  /**
   * Decrypt collect name with the collect public key (from meta after PoW, or derived from #sk=).
   */
  async function decryptCollectName(wire, publicKey) {
    if (!wire) throw new Error("Invalid collect name ciphertext.");
    const ctB64 = wire.ciphertext || wire.Ciphertext;
    const ivB64 = wire.iv || wire.Iv;
    if (!ctB64 || !ivB64) throw new Error("Invalid collect name ciphertext.");
    const keyBytes = await deriveCollectNameKey(publicKey);
    try {
      const ivBytes = b64urlDecode(ivB64);
      const ciphertext = b64urlDecode(ctB64);
      if (ivBytes.length !== IV_LENGTH) throw new Error("Invalid collect name IV.");
      const key = await importAesKey(keyBytes, ["decrypt"]);
      return new Uint8Array(
        await requireSubtle().decrypt({ name: "AES-GCM", iv: ivBytes }, key, ciphertext)
      );
    } finally {
      keyBytes.fill(0);
    }
  }

  /**
   * Load PBKDF2 parameters for password-wrapping the fragment sk.
   * Same iteration count / hash as UDK wrap (bound to server password policy).
   */
  async function ensurePasswordWrapParams() {
    if (pwWrapParamsLoaded) return;
    try {
      const res = await fetch("/api/v1/crypto/params", { credentials: "same-origin" });
      if (res.ok) {
        const p = await res.json();
        // Prefer skWrap* when present; fall back to udkWrap* (same policy).
        const iters = p.skWrapIterations || p.udkWrapIterations;
        if (iters > 0) PW_WRAP_ITERATIONS = iters | 0;
        const hash = p.skWrapHash || p.udkWrapHash;
        if (hash) PW_WRAP_HASH = String(hash);
      }
    } catch {
      /* keep defaults */
    }
    pwWrapParamsLoaded = true;
  }

  /**
   * PBKDF2 → AES-256-GCM key (256 bits). Used only for password-wrapping fragment sk.
   */
  async function derivePasswordWrapKey(password, salt, iterations, hashName) {
    const subtle = requireSubtle();
    const enc = new TextEncoder();
    const hash = hashName || PW_WRAP_HASH || "SHA-512";
    const baseKey = await subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await subtle.deriveBits(
      { name: "PBKDF2", hash: hash, salt, iterations },
      baseKey,
      256
    );
    return subtle.importKey("raw", bits, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
  }

  /**
   * Wrap a 32-byte X25519 secret key with a password:
   *   wrapKey = PBKDF2-HMAC-SHA512(password, salt, i) → 32 bytes
   *   ct = AES-256-GCM(wrapKey, iv, sk)  // Web Crypto appends 128-bit tag to ct
   * Compact JSON for the fragment: { i, s, iv, ct } (no alg/v/purpose on wire).
   */
  async function wrapSecretKeyWithPassword(secretKey, password) {
    if (!(secretKey instanceof Uint8Array) || secretKey.length !== X25519_LEN) {
      throw new Error("Secret key must be 32 bytes.");
    }
    if (typeof password !== "string" || !password) {
      throw new Error("Password is required to wrap the decryption key.");
    }
    await ensurePasswordWrapParams();
    const salt = crypto.getRandomValues(new Uint8Array(PW_WRAP_SALT_LEN));
    const iv = crypto.getRandomValues(new Uint8Array(PW_WRAP_IV_LEN));
    const key = await derivePasswordWrapKey(
      password,
      salt,
      PW_WRAP_ITERATIONS,
      PW_WRAP_HASH
    );
    // AES-GCM: ciphertext || 16-byte auth tag (32+16 = 48 bytes for sk).
    const ct = new Uint8Array(
      await requireSubtle().encrypt({ name: "AES-GCM", iv }, key, secretKey)
    );
    if (ct.length < X25519_LEN + GCM_TAG_LEN) {
      throw new Error("AES-GCM wrap produced unexpected length.");
    }
    return JSON.stringify({
      i: PW_WRAP_ITERATIONS,
      s: b64urlEncode(salt),
      iv: b64urlEncode(iv),
      ct: b64urlEncode(ct),
    });
  }

  /**
   * Unwrap password-protected secret-key package → 32-byte X25519 sk.
   * Package: { i, s, iv, ct }. Algorithm fixed: PBKDF2-SHA512 + AES-256-GCM.
   */
  async function unwrapSecretKeyWithPassword(packageJson, password) {
    if (typeof password !== "string" || !password) {
      throw new Error("Password is required.");
    }
    const pkg =
      typeof packageJson === "string" ? JSON.parse(packageJson) : packageJson;
    if (!pkg || !pkg.s || !pkg.iv || !pkg.ct) {
      throw new Error("Invalid password-protected key package.");
    }
    const iterations =
      typeof pkg.i === "number" && pkg.i > 0 ? pkg.i : PW_WRAP_ITERATIONS;
    const salt = b64urlDecode(pkg.s);
    const iv = b64urlDecode(pkg.iv);
    const ct = b64urlDecode(pkg.ct);
    if (salt.length !== PW_WRAP_SALT_LEN) throw new Error("Invalid wrap salt length.");
    if (iv.length !== PW_WRAP_IV_LEN) throw new Error("Invalid wrap IV length.");
    // ct must include AES-GCM tag + plaintext (32-byte sk).
    if (ct.length < X25519_LEN + GCM_TAG_LEN) {
      throw new Error("Invalid wrap ciphertext length.");
    }
    const key = await derivePasswordWrapKey(
      password,
      salt,
      iterations,
      PW_WRAP_HASH || "SHA-512"
    );
    let plain;
    try {
      plain = new Uint8Array(
        await requireSubtle().decrypt({ name: "AES-GCM", iv }, key, ct)
      );
    } catch {
      throw new Error("Incorrect password or corrupted key package.");
    }
    if (plain.length !== X25519_LEN) {
      throw new Error("Unwrapped key has unexpected length.");
    }
    return plain;
  }

  /** Raw #sk= value from the fragment (string), or null. */
  function rawSkParamFromHash(hash) {
    const h = (hash || "").replace(/^#/, "");
    if (!h) return null;
    const params = new URLSearchParams(h);
    const sk = params.get("sk");
    if (sk) return sk;
    // Bare base64url fragment (legacy short form for raw 32-byte keys only).
    if (/^[A-Za-z0-9_-]+$/.test(h)) return h;
    return null;
  }

  /**
   * Parse #sk=... as a raw 32-byte X25519 key (unprotected sends).
   * Requires canonical base64url so last-character padding variants fail closed.
   */
  function secretKeyFromLocationHash(hash) {
    const sk = rawSkParamFromHash(hash);
    if (!sk) return null;
    return b64urlDecodeCanonical(sk, X25519_LEN);
  }

  /**
   * Parse #sk= as a password-wrap package JSON string (password-protected sends).
   * Package is UTF-8 JSON, base64url-encoded in the fragment.
   */
  function secretKeyPackageFromLocationHash(hash) {
    const sk = rawSkParamFromHash(hash);
    if (!sk || sk.length < 44) return null; // raw keys are exactly 43 chars
    try {
      const bytes = b64urlDecode(sk);
      const text = new TextDecoder().decode(bytes);
      const pkg = JSON.parse(text);
      if (!pkg || !pkg.s || !pkg.iv || !pkg.ct) return null;
      return text;
    } catch {
      return null;
    }
  }

  function buildFragment(secretKey) {
    return "#sk=" + b64urlEncode(secretKey);
  }

  /** Fragment for password-wrapped sk (package JSON → base64url). */
  function buildPasswordProtectedFragment(packageJson) {
    const bytes = new TextEncoder().encode(packageJson);
    return "#sk=" + b64urlEncode(bytes);
  }

  // Public API (page scripts + dashboard). Internal helpers stay private.
  global.SenditCrypto = {
    b64urlEncode,
    b64urlDecode,
    generateKeyPair,
    keyPairFromSecretKey,
    encryptForRecipient,
    decryptWithSecretKey,
    encryptCollectName,
    decryptCollectName,
    secretKeyFromLocationHash,
    secretKeyPackageFromLocationHash,
    buildFragment,
    buildPasswordProtectedFragment,
    wrapSecretKeyWithPassword,
    unwrapSecretKeyWithPassword,
  };
})(typeof window !== "undefined" ? window : globalThis);
