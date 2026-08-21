/**
 * Per-user data key (UDK) — client-only unwrap
 * ============================================
 *
 * On account creation the browser generates a random 32-byte SENDIT_USER_DATA_KEY
 * (we call it the user data key / UDK). It is:
 *   1. Wrapped with the account password (PBKDF2-SHA-512 + AES-256-GCM;
 *      iteration count matches server password hash via /api/v1/crypto/params)
 *   2. Stored on the server as an opaque package (server never unwraps it)
 *   3. Unwrapped in the browser after login and kept in sessionStorage for the tab
 *
 * UDK encrypts owner-private fields (e.g. collect private keys) before
 * they are sent to the API, so one user cannot decrypt another user's stored keys
 * even with DB access (and with SENDIT_DATA_KEY the server adds a second layer).
 *
 * Password change / reset: generate a NEW UDK, wrap with the new password, and the
 * server deletes all sends/collects that depended on the old UDK.
 */
(function (global) {
  "use strict";

  const STORAGE_KEY = "sendit_udk";
  // Default matches PasswordHasher.DefaultIterations; overridden by GET /api/v1/crypto/params.
  let WRAP_ITERATIONS = 893241;
  let WRAP_HASH = "SHA-512";
  const UDK_BYTES = 32;
  let paramsLoaded = false;

  /** Load server-bound UDK wrap parameters (same iteration count as password hash). */
  async function ensureWrapParams() {
    if (paramsLoaded) return;
    try {
      const res = await fetch("/api/v1/crypto/params", { credentials: "same-origin" });
      if (res.ok) {
        const p = await res.json();
        if (p && p.udkWrapIterations > 0) WRAP_ITERATIONS = p.udkWrapIterations | 0;
        if (p && p.udkWrapHash) WRAP_HASH = String(p.udkWrapHash);
      }
    } catch {
      // keep defaults
    }
    paramsLoaded = true;
  }

  /**
   * Web Crypto (crypto.subtle) only works in a secure context: HTTPS or
   * http://localhost / http://127.0.0.1. Plain http://192.168.x.x on a phone
   * has subtle === undefined → "Cannot read properties of undefined (reading 'importKey')".
   */
  function requireSubtle() {
    const subtle = global.crypto && global.crypto.subtle;
    if (subtle) return subtle;
    const host = (global.location && global.location.hostname) || "";
    const isLan =
      /^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) || host.endsWith(".local");
    throw new Error(
      isLan
        ? "This browser blocks encryption on plain HTTP LAN addresses. " +
            "Open Sendit! via HTTPS (or use http://localhost on this machine). " +
            "From the project: ./scripts/run-lan-https.sh"
        : "Web Crypto is unavailable (need HTTPS or localhost). " +
            "Cannot wrap/unwrap encryption keys in this browser context."
    );
  }

  function b64urlEncode(bytes) {
    let bin = "";
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function b64urlDecode(str) {
    let s = str.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function deriveWrapKey(password, salt, iterations, hashName) {
    const subtle = requireSubtle();
    const enc = new TextEncoder();
    const hash = hashName || WRAP_HASH || "SHA-512";
    const baseKey = await subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: hash,
        salt,
        iterations,
      },
      baseKey,
      256
    );
    return subtle.importKey("raw", bits, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
  }

  /** Generate a new random 32-byte user data key. */
  function generateUserDataKey() {
    return crypto.getRandomValues(new Uint8Array(UDK_BYTES));
  }

  /**
   * Wrap UDK with password → JSON package string for the server.
   */
  async function wrapUserDataKey(udkBytes, password) {
    if (!(udkBytes instanceof Uint8Array) || udkBytes.length !== UDK_BYTES) {
      throw new Error("User data key must be 32 bytes.");
    }
    await ensureWrapParams();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveWrapKey(password, salt, WRAP_ITERATIONS, WRAP_HASH);
    const ct = new Uint8Array(
      await requireSubtle().encrypt({ name: "AES-GCM", iv }, key, udkBytes)
    );
    const alg =
      WRAP_HASH === "SHA-512"
        ? "PBKDF2-SHA512-AES-256-GCM"
        : "PBKDF2-SHA256-AES-256-GCM";
    return JSON.stringify({
      v: 1,
      alg: alg,
      iterations: WRAP_ITERATIONS,
      salt: b64urlEncode(salt),
      iv: b64urlEncode(iv),
      ct: b64urlEncode(ct),
    });
  }

  /**
   * Unwrap server package with password → Uint8Array UDK.
   * Requires current package format: PBKDF2-SHA512 + AES-256-GCM (no legacy packages).
   */
  async function unwrapUserDataKey(packageJson, password) {
    const pkg = typeof packageJson === "string" ? JSON.parse(packageJson) : packageJson;
    if (!pkg || pkg.v !== 1 || !pkg.salt || !pkg.iv || !pkg.ct) {
      throw new Error("Invalid wrapped user data key package.");
    }
    if (pkg.alg && String(pkg.alg).indexOf("SHA512") < 0) {
      throw new Error(
        "Unsupported encryption package (legacy format). Re-register or reset password with a fresh database."
      );
    }
    const iterations = pkg.iterations || WRAP_ITERATIONS;
    const salt = b64urlDecode(pkg.salt);
    const iv = b64urlDecode(pkg.iv);
    const ct = b64urlDecode(pkg.ct);
    const key = await deriveWrapKey(password, salt, iterations, "SHA-512");
    const plain = new Uint8Array(
      await requireSubtle().decrypt({ name: "AES-GCM", iv }, key, ct)
    );
    if (plain.length !== UDK_BYTES) throw new Error("Unwrapped UDK has unexpected length.");
    return plain;
  }

  function storeUserDataKey(udkBytes) {
    sessionStorage.setItem(STORAGE_KEY, b64urlEncode(udkBytes));
  }

  function clearUserDataKey() {
    sessionStorage.removeItem(STORAGE_KEY);
  }

  function loadUserDataKey() {
    const s = sessionStorage.getItem(STORAGE_KEY);
    if (!s) return null;
    try {
      const b = b64urlDecode(s);
      if (b.length !== UDK_BYTES) return null;
      return b;
    } catch {
      return null;
    }
  }

  /**
   * Modal password prompt (type=password). window.prompt cannot mask input.
   * @param {string} message
   * @returns {Promise<string|null>} password or null if cancelled
   */
  function promptPassword(message) {
    return new Promise(function (resolve) {
      const prev = document.getElementById("sendit-pw-modal");
      if (prev) prev.remove();

      const overlay = document.createElement("div");
      overlay.id = "sendit-pw-modal";
      overlay.className = "pw-modal-overlay";
      overlay.setAttribute("role", "dialog");
      overlay.setAttribute("aria-modal", "true");
      overlay.setAttribute("aria-label", "Enter password");

      const card = document.createElement("div");
      card.className = "pw-modal-card";

      const title = document.createElement("h2");
      title.className = "pw-modal-title";
      title.textContent = "Unlock encryption";

      const msg = document.createElement("p");
      msg.className = "pw-modal-msg";
      msg.textContent = message;

      const form = document.createElement("form");
      form.className = "pw-modal-form";
      form.method = "post";
      form.action = "#";
      form.autocomplete = "on";

      // Optional username context for password managers when email is known.
      const userAssist = document.createElement("input");
      userAssist.type = "email";
      userAssist.name = "username";
      userAssist.autocomplete = "username";
      userAssist.className = "pm-assist-field";
      userAssist.tabIndex = -1;
      userAssist.setAttribute("aria-hidden", "true");
      userAssist.readOnly = true;
      try {
        const em = document.querySelector("[data-nav-email]");
        if (em && em.textContent) userAssist.value = em.textContent.trim();
      } catch {
        /* ignore */
      }

      const label = document.createElement("label");
      label.setAttribute("for", "sendit-pw-input");
      label.textContent = "Password";

      const input = document.createElement("input");
      input.id = "sendit-pw-input";
      input.type = "password";
      input.name = "password";
      input.autocomplete = "current-password";
      input.required = true;
      input.minLength = 1;
      input.maxLength = 256;
      input.spellcheck = false;

      const actions = document.createElement("div");
      actions.className = "pw-modal-actions";

      // Same pattern as logout confirm / New send + New collect.
      const cancelBtn = document.createElement("button");
      cancelBtn.type = "button";
      cancelBtn.className = "btn secondary";
      cancelBtn.textContent = "Cancel";

      const okBtn = document.createElement("button");
      okBtn.type = "submit";
      okBtn.className = "btn";
      okBtn.textContent = "Unlock";

      function setBusy(busy) {
        if (
          global.SenditApp &&
          typeof global.SenditApp.setButtonBusy === "function"
        ) {
          global.SenditApp.setButtonBusy(okBtn, !!busy);
        } else {
          okBtn.disabled = !!busy;
        }
        cancelBtn.disabled = !!busy;
        if (busy) cancelBtn.setAttribute("aria-disabled", "true");
        else cancelBtn.removeAttribute("aria-disabled");
      }

      function cleanup(value) {
        input.value = "";
        overlay.remove();
        document.removeEventListener("keydown", onKey);
        resolve(value);
      }

      function onKey(ev) {
        if (ev.key === "Escape") {
          ev.preventDefault();
          if (cancelBtn.disabled) return;
          cleanup(null);
        }
      }

      cancelBtn.addEventListener("click", function () {
        if (cancelBtn.disabled) return;
        cleanup(null);
      });
      overlay.addEventListener("click", function (ev) {
        if (ev.target === overlay && !cancelBtn.disabled) cleanup(null);
      });
      form.addEventListener("submit", function (ev) {
        ev.preventDefault();
        if (
          okBtn.disabled ||
          okBtn.getAttribute("aria-disabled") === "true" ||
          okBtn.classList.contains("ui-busy")
        ) {
          return;
        }
        const v = input.value;
        setBusy(true);
        cleanup(v || null);
      });
      document.addEventListener("keydown", onKey);

      actions.appendChild(cancelBtn);
      actions.appendChild(okBtn);
      form.appendChild(userAssist);
      form.appendChild(label);
      form.appendChild(input);
      form.appendChild(actions);
      card.appendChild(title);
      card.appendChild(msg);
      card.appendChild(form);
      overlay.appendChild(card);
      document.body.appendChild(overlay);
      setTimeout(function () {
        input.focus();
      }, 0);
    });
  }

  /**
   * Ensure UDK is in sessionStorage for this tab.
   * @param {{ force?: boolean }} [opts] force:true clears any stored UDK and always prompts.
   */
  async function requireUserDataKey(opts) {
    opts = opts || {};
    if (opts.force) {
      clearUserDataKey();
    } else {
      let k = loadUserDataKey();
      if (k) return k;
    }

    // Session cookie may exist without sessionStorage UDK (new tab).
    // Fetch the password-wrapped package only via dedicated unlock endpoint (not /me).
    if (typeof SenditApi === "undefined" || !SenditApi.getUserDataKey) {
      throw new Error(
        "User data key is not available in this browser session. Please log in again."
      );
    }

    let me;
    try {
      me = await SenditApi.me();
    } catch {
      throw new Error("Not signed in. Please log in again.");
    }
    if (!me || me.authenticated === false || !me.email) {
      throw new Error("Not signed in. Please log in again.");
    }

    let keyPack;
    try {
      keyPack = await SenditApi.getUserDataKey();
    } catch (err) {
      const detail =
        err && err.message ? String(err.message) : "Not signed in. Please log in again.";
      throw new Error(detail);
    }
    let wrapped = keyPack && keyPack.wrappedUserDataKey;
    if (!wrapped) {
      // Account without wrap package: create one (requires password) and store it once.
      const password = await promptPassword(
        "Enter your account password to set up encryption for this browser session."
      );
      if (!password) throw new Error("Password required to unlock encryption.");
      const udk = generateUserDataKey();
      wrapped = await wrapUserDataKey(udk, password);
      await SenditApi.setupUserDataKey(wrapped);
      storeUserDataKey(udk);
      return udk;
    }

    const password = await promptPassword(
      "Enter your account password to unlock encryption in this browser tab."
    );
    if (!password) throw new Error("Password required to unlock encryption.");
    try {
      const k = await unlockFromLoginResponse(wrapped, password);
      return k;
    } catch {
      throw new Error("Could not unlock encryption. Check your password and try again.");
    }
  }

  /**
   * Encrypt arbitrary bytes with UDK (AES-256-GCM).
   * Wire: base64url( iv(12) || ciphertext+tag )
   */
  async function encryptWithUserDataKey(plaintextBytes, udkBytes) {
    const udk = udkBytes || (await requireUserDataKey());
    const subtle = requireSubtle();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await subtle.importKey("raw", udk, { name: "AES-GCM" }, false, [
      "encrypt",
    ]);
    const ct = new Uint8Array(
      await subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBytes)
    );
    const packed = new Uint8Array(12 + ct.length);
    packed.set(iv, 0);
    packed.set(ct, 12);
    return b64urlEncode(packed);
  }

  async function decryptWithUserDataKey(ciphertextB64, udkBytes) {
    const udk = udkBytes || (await requireUserDataKey());
    const packed = b64urlDecode(ciphertextB64);
    if (packed.length < 12 + 16) throw new Error("Ciphertext too short.");
    const iv = packed.slice(0, 12);
    const ct = packed.slice(12);
    const subtle = requireSubtle();
    const key = await subtle.importKey("raw", udk, { name: "AES-GCM" }, false, [
      "decrypt",
    ]);
    return new Uint8Array(
      await subtle.decrypt({ name: "AES-GCM", iv }, key, ct)
    );
  }

  /**
   * After login (or register+login): unwrap package and store UDK.
   */
  async function unlockFromLoginResponse(wrappedUserDataKey, password) {
    if (!wrappedUserDataKey) {
      throw new Error(
        "Account has no user data key. Re-register or contact the administrator."
      );
    }
    const udk = await unwrapUserDataKey(wrappedUserDataKey, password);
    storeUserDataKey(udk);
    return udk;
  }

  global.SenditUserDataKey = {
    generateUserDataKey,
    wrapUserDataKey,
    storeUserDataKey,
    clearUserDataKey,
    loadUserDataKey,
    requireUserDataKey,
    encryptWithUserDataKey,
    decryptWithUserDataKey,
    unlockFromLoginResponse,
  };
})(typeof window !== "undefined" ? window : globalThis);
