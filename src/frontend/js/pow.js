/**
 * Browser proof-of-work for send/collect ID access and auth (login / email-OTP / TOTP / forgot).
 * HMAC-SHA256(serverKey, ascii(nonce)) must have `difficultyBits` leading zero bits.
 * Server always issues difficulty ≥ 1 (never disabled); default is 14 bits (~16k average tries).
 * Each challenge is one-time on the server — do not reuse challengeId after a successful request.
 *
 * Challenges include expiresAt (ISO). Solving abandons work 5s before expiry and, when used via
 * solveRefreshing / solvePow(fetcher), seamlessly fetches a new challenge until a solution is found.
 */
(function (global) {
  "use strict";

  /** Abandon the current challenge this many ms before server expiresAt. */
  var ABANDON_BEFORE_MS = 5000;

  function b64urlDecode(str) {
    var s = str.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function b64urlEncode(bytes) {
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  /** Pure check; bits ≤ 0 is vacuous (true). Production challenges always use ≥ 1. */
  function hasLeadingZeroBits(hash, bits) {
    if (bits <= 0) return true;
    var full = (bits / 8) | 0;
    var rem = bits % 8;
    for (var i = 0; i < full; i++) {
      if (hash[i] !== 0) return false;
    }
    if (rem === 0) return true;
    var mask = 0xff << (8 - rem);
    return (hash[full] & mask) === 0;
  }

  function powExpiredError() {
    var err = new Error("PoW challenge nearing expiry.");
    err.powExpired = true;
    return err;
  }

  /**
   * Deadline (epoch ms) to stop working on this challenge: expiresAt − 5s.
   * Null if expiresAt missing/invalid (no auto-abandon).
   * @param {{ expiresAt?: string }} challenge
   * @returns {number|null}
   */
  function abandonDeadlineMs(challenge) {
    if (!challenge || !challenge.expiresAt) return null;
    var exp = Date.parse(challenge.expiresAt);
    if (isNaN(exp)) return null;
    return exp - ABANDON_BEFORE_MS;
  }

  /**
   * Solve a single challenge. Abandons with err.powExpired when within 5s of expiresAt.
   * @param {{ hmacKey: string, difficultyBits: number, challengeId: string, expiresAt?: string }} challenge
   * @param {{ onProgress?: function(number, number=): void, attempt?: number }} [opts]
   *   onProgress(tries, attempt?) — attempt is optional (set by solveRefreshing)
   * @returns {Promise<{ challengeId: string, nonce: string, hash: string, tries: number }>}
   */
  async function solve(challenge, opts) {
    opts = opts || {};
    var attempt = opts.attempt | 0;
    // Defensive floor if a misconfigured peer sends 0; server clamps the same way.
    var bits = challenge.difficultyBits | 0;
    if (bits < 1) bits = 1;
    var keyBytes = b64urlDecode(challenge.hmacKey);
    var subtle = global.crypto && global.crypto.subtle;
    if (!subtle) throw new Error("Web Crypto unavailable for proof of work.");

    var deadline = abandonDeadlineMs(challenge);
    if (deadline != null && Date.now() >= deadline) {
      throw powExpiredError();
    }

    var key = await subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    var nonce = 0;
    var tries = 0;
    var enc = new TextEncoder();
    // Yield to UI every N iterations so the page stays responsive.
    var yieldEvery = 250;

    if (opts.onProgress) {
      try {
        opts.onProgress(0, attempt || undefined);
      } catch (_) {
        /* ignore UI errors */
      }
    }

    while (true) {
      if (deadline != null && Date.now() >= deadline) {
        throw powExpiredError();
      }

      var nonceStr = String(nonce);
      var mac = new Uint8Array(
        await subtle.sign("HMAC", key, enc.encode(nonceStr))
      );
      tries++;
      if (hasLeadingZeroBits(mac, bits)) {
        return {
          challengeId: challenge.challengeId,
          nonce: nonceStr,
          hash: b64urlEncode(mac),
          tries: tries,
        };
      }
      nonce++;
      if (tries % yieldEvery === 0) {
        if (deadline != null && Date.now() >= deadline) {
          throw powExpiredError();
        }
        if (opts.onProgress) {
          try {
            opts.onProgress(tries, attempt || undefined);
          } catch (_) {
            /* ignore */
          }
        }
        await new Promise(function (r) {
          setTimeout(r, 0);
        });
      }
    }
  }

  /**
   * Fetch challenges and solve until success. When a challenge is within 5s of
   * expiresAt, drop it and request a fresh one (no user-facing error).
   * Attempt counter: first challenge is attempt 1 (no UI counter expected);
   * attempt ≥ 2 is passed to onProgress for display.
   *
   * @param {function(): Promise<object>} fetchChallenge async () => challenge
   * @param {{ onProgress?: function(number, number): void, maxAttempts?: number }} [opts]
   *   onProgress(tries, attempt) — attempt is 1-based
   * @returns {Promise<{ challengeId: string, nonce: string, hash: string, tries: number, attempts: number }>}
   */
  async function solveRefreshing(fetchChallenge, opts) {
    opts = opts || {};
    if (typeof fetchChallenge !== "function") {
      throw new Error("solveRefreshing requires a fetchChallenge function.");
    }
    var maxAttempts =
      typeof opts.maxAttempts === "number" && opts.maxAttempts > 0
        ? opts.maxAttempts
        : 10000;
    var attempt = 0;

    while (attempt < maxAttempts) {
      attempt++;
      var challenge = await fetchChallenge();
      if (!challenge || !challenge.challengeId || !challenge.hmacKey) {
        throw new Error("Invalid proof-of-work challenge from server.");
      }
      try {
        var solution = await solve(challenge, {
          attempt: attempt,
          onProgress: opts.onProgress,
        });
        solution.attempts = attempt;
        return solution;
      } catch (err) {
        if (err && err.powExpired) {
          // Seamlessly continue with a new challenge.
          continue;
        }
        throw err;
      }
    }
    throw new Error(
      "Proof-of-work could not complete after " + maxAttempts + " challenges."
    );
  }

  /**
   * Status label helper: base text, plus " (N)" when attempt ≥ 2.
   * @param {string} base
   * @param {number} attempt
   */
  function statusLabel(base, attempt) {
    var b = base || "Performing proof-of-work…";
    if (attempt > 1) return b + " (" + attempt + ")";
    return b;
  }

  global.SenditPow = {
    solve: solve,
    solveRefreshing: solveRefreshing,
    statusLabel: statusLabel,
    ABANDON_BEFORE_MS: ABANDON_BEFORE_MS,
  };
})(typeof window !== "undefined" ? window : globalThis);
