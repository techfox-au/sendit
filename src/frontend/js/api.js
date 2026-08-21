/**
 * Sendit! API client
 * -----------------
 * Thin fetch wrappers. Credentials (session cookie) are included by default
 * for same-origin requests. Never logs response bodies that may contain ciphertext.
 *
 * All JSON endpoints are under /api/v1 so future protocol/crypto major versions
 * (e.g. post-quantum) can ship as /api/v2 without breaking old clients.
 */
(function (global) {
  "use strict";

  /** Current API major version prefix. */
  const API = "/api/v1";

  function parseJsonResponse(text) {
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      return { error: text };
    }
  }

  function httpError(status, statusText, data) {
    const err = new Error(
      (data && data.error) ||
        (statusText && String(statusText).trim()) ||
        "Request failed (HTTP " + status + ")"
    );
    err.status = status;
    err.data = data;
    // Gateway-only. Do NOT treat 503 as automatic downtime: nginx limit_req
    // defaults to 503 when you tap too fast, which is not "API down".
    if (status === 502 || status === 504) {
      err.apiUnreachable = true;
    }
    // 503: possible real outage OR rate-limit / brief overload — probe before modal.
    if (status === 503) {
      err.maybeUnreachable = true;
    }
    return err;
  }

  /** Set if a failure happens before app.js registers the modal handler. */
  var pendingApiUnreachable = false;
  /** In-flight debounce so rapid taps only open the modal after a health check fails. */
  var unreachableProbeTimer = null;
  var unreachableProbeInFlight = false;

  function isHealthPath(path) {
    return path && String(path).indexOf("/health") !== -1;
  }

  function isAbortLikeError(err) {
    if (!err) return false;
    if (err.name === "AbortError") return true;
    var msg = String(err.message || err || "");
    return /abort(ed)?|AbortError|cancelled|canceled/i.test(msg);
  }

  /**
   * Show the downtime modal (or queue it if app.js has not loaded yet).
   */
  function showApiUnreachableModal() {
    try {
      const app = global.SenditApp;
      if (app && typeof app.notifyApiUnreachable === "function") {
        pendingApiUnreachable = false;
        app.notifyApiUnreachable();
        return;
      }
    } catch {
      /* fall through */
    }
    pendingApiUnreachable = true;
  }

  /**
   * Confirm the API is actually down before alarming the user.
   * Rapid iOS taps can produce flaky TypeError / transient 503 without real downtime;
   * a short delayed /health probe filters those out.
   */
  function scheduleUnreachableProbe(path) {
    if (isHealthPath(path)) return;
    if (unreachableProbeInFlight) return;
    if (unreachableProbeTimer != null) return;

    unreachableProbeTimer = setTimeout(function () {
      unreachableProbeTimer = null;
      unreachableProbeInFlight = true;
      var healthUrl = API + "/health";
      // Prefer a bare fetch so we do not re-enter request() error paths.
      fetch(healthUrl, {
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "application/json" },
      })
        .then(function (res) {
          unreachableProbeInFlight = false;
          // Healthy or any non-gateway response ⇒ API is up; suppress modal.
          if (res.ok) return;
          if (res.status === 502 || res.status === 503 || res.status === 504) {
            showApiUnreachableModal();
          }
        })
        .catch(function () {
          unreachableProbeInFlight = false;
          showApiUnreachableModal();
        });
    }, 450);
  }

  async function request(path, options) {
    const opts = Object.assign({ credentials: "same-origin" }, options || {});
    opts.headers = Object.assign({ Accept: "application/json" }, opts.headers || {});
    if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    let res;
    try {
      res = await fetch(path, opts);
    } catch (err) {
      var e = err instanceof Error ? err : new Error(String(err));
      // Aborts / navigation cancels are not downtime.
      if (isAbortLikeError(e)) {
        throw e;
      }
      // iOS Safari often throws TypeError ("Load failed" / "Failed to fetch") under
      // concurrent taps; probe health before showing the full-screen modal.
      e.apiUnreachable = true;
      scheduleUnreachableProbe(path);
      throw e;
    }
    const text = await res.text();
    const data = parseJsonResponse(text);
    if (!res.ok) {
      const err = httpError(res.status, res.statusText, data);
      if (err.apiUnreachable || err.maybeUnreachable) {
        scheduleUnreachableProbe(path);
      }
      throw err;
    }
    return data;
  }

  /**
   * POST JSON with upload progress (XHR). fetch() cannot report request body progress.
   * @param {string} path
   * @param {object} body JSON-serializable object
   * @param {{ onUploadProgress?: function(number, number, number): void }} [opts]
   *   onUploadProgress(fraction 0..1, loaded, total)
   */
  function requestPostWithProgress(path, body, opts) {
    opts = opts || {};
    const json = JSON.stringify(body == null ? {} : body);
    return new Promise(function (resolve, reject) {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", path);
      xhr.withCredentials = true;
      xhr.setRequestHeader("Accept", "application/json");
      xhr.setRequestHeader("Content-Type", "application/json");
      if (typeof opts.onUploadProgress === "function") {
        xhr.upload.onprogress = function (ev) {
          if (!ev.lengthComputable || ev.total <= 0) return;
          opts.onUploadProgress(ev.loaded / ev.total, ev.loaded, ev.total);
        };
      }
      xhr.onload = function () {
        const data = parseJsonResponse(xhr.responseText);
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(data);
          return;
        }
        const err = httpError(xhr.status, xhr.statusText, data);
        if (err.apiUnreachable || err.maybeUnreachable) {
          scheduleUnreachableProbe(path);
        }
        reject(err);
      };
      xhr.onerror = function () {
        const err = new Error("Network error while uploading.");
        err.apiUnreachable = true;
        scheduleUnreachableProbe(path);
        reject(err);
      };
      xhr.onabort = function () {
        // Do not open the downtime modal for a cancelled upload.
        reject(new Error("Upload cancelled."));
      };
      xhr.send(json);
    });
  }

  global.SenditApi = {
    /** True if a failure was recorded before SenditApp could show the modal. */
    consumePendingApiUnreachable: function () {
      const v = pendingApiUnreachable;
      pendingApiUnreachable = false;
      return v;
    },
    health: () => request(API + "/health"),
    /** PoW challenge bound to email for password login / auto-register. */
    loginPowChallenge: (email) =>
      request(API + "/auth/login/pow?email=" + encodeURIComponent(email || "")),
    /** PoW challenge bound to email-otp ticket. */
    loginEmailOtpPowChallenge: (ticket) =>
      request(
        API + "/auth/login/email-otp/pow?ticket=" + encodeURIComponent(ticket || "")
      ),
    /** PoW challenge bound to totp ticket. */
    loginTotpPowChallenge: (ticket) =>
      request(API + "/auth/login/totp/pow?ticket=" + encodeURIComponent(ticket || "")),
    /** PoW challenge bound to email for forgot-password. */
    forgotPasswordPowChallenge: (email) =>
      request(
        API + "/auth/forgot-password/pow?email=" + encodeURIComponent(email || "")
      ),
    login: (email, password, wrappedUserDataKey, pow) =>
      request(API + "/auth/login", {
        method: "POST",
        body: Object.assign(
          { email, password, wrappedUserDataKey: wrappedUserDataKey || null },
          powBody(pow)
        ),
      }),
    loginEmailOtp: (emailOtpTicket, code, pow) =>
      request(API + "/auth/login/email-otp", {
        method: "POST",
        body: Object.assign({ emailOtpTicket, code }, powBody(pow)),
      }),
    loginTotp: (totpTicket, code, pow) =>
      request(API + "/auth/login/totp", {
        method: "POST",
        body: Object.assign({ totpTicket, code }, powBody(pow)),
      }),
    logout: () => request(API + "/auth/logout", { method: "POST", body: {} }),
    me: () => request(API + "/auth/me"),
    /** Fetch password-wrapped UDK for tab unlock (not included on /me). */
    getUserDataKey: () => request(API + "/auth/user-data-key"),
    setupUserDataKey: (wrappedUserDataKey) =>
      request(API + "/auth/user-data-key", {
        method: "POST",
        body: { wrappedUserDataKey },
      }),
    forgotPassword: (email, pow) =>
      request(API + "/auth/forgot-password", {
        method: "POST",
        body: Object.assign({ email }, powBody(pow)),
      }),
    resetPassword: (token, password, wrappedUserDataKey, totpCode) =>
      request(API + "/auth/reset-password", {
        method: "POST",
        body: {
          token,
          password,
          wrappedUserDataKey,
          totpCode: totpCode || null,
        },
      }),
    changePassword: (currentPassword, newPassword, wrappedUserDataKey, totpCode) =>
      request(API + "/auth/change-password", {
        method: "POST",
        body: {
          currentPassword,
          newPassword,
          wrappedUserDataKey,
          totpCode: totpCode || null,
        },
      }),
    totpBegin: () => request(API + "/auth/totp/begin", { method: "POST", body: {} }),
    totpConfirm: (code) =>
      request(API + "/auth/totp/confirm", { method: "POST", body: { code } }),
    totpDisable: (password, code) =>
      request(API + "/auth/totp/disable", { method: "POST", body: { password, code } }),
    /** Update optional email notification prefs (both booleans required). */
    updateNotifications: (notifyCollectReady, notifySendOpened) =>
      request(API + "/auth/notifications", {
        method: "PATCH",
        body: {
          notifyCollectReady: !!notifyCollectReady,
          notifySendOpened: !!notifySendOpened,
        },
      }),
    // Send: POST /send creates; GET /send/{id}/meta requires PoW; GET /send/{id} obtains payload
    createSecret: (payload, progressOpts) =>
      progressOpts && typeof progressOpts.onUploadProgress === "function"
        ? requestPostWithProgress(API + "/send", payload, progressOpts)
        : request(API + "/send", { method: "POST", body: payload }),
    secretPowChallenge: (id) =>
      request(API + "/send/" + encodeURIComponent(id) + "/pow"),
    secretMeta: (id, pow) =>
      request(API + "/send/" + encodeURIComponent(id) + "/meta" + powQuery(pow)),
    secretGet: (id, pow) =>
      request(API + "/send/" + encodeURIComponent(id) + powQuery(pow)),
    secretDelete: (id) =>
      request(API + "/send/" + encodeURIComponent(id), { method: "DELETE" }),
    // Collect: meta/GET/upload/payload all require PoW (upload/payload challenge starts at action time)
    createRequest: (payload) => request(API + "/collect", { method: "POST", body: payload }),
    requestPowChallenge: (id) =>
      request(API + "/collect/" + encodeURIComponent(id) + "/pow"),
    requestGet: (id, pow) =>
      request(API + "/collect/" + encodeURIComponent(id) + powQuery(pow)),
    requestMeta: (id, pow) =>
      request(API + "/collect/" + encodeURIComponent(id) + "/meta" + powQuery(pow)),
    requestUpload: (id, payload, progressOpts) =>
      progressOpts && typeof progressOpts.onUploadProgress === "function"
        ? requestPostWithProgress(
            API + "/collect/" + encodeURIComponent(id) + "/upload",
            payload,
            progressOpts
          )
        : request(API + "/collect/" + encodeURIComponent(id) + "/upload", {
            method: "POST",
            body: payload,
          }),
    requestPayload: (id, pow) =>
      request(API + "/collect/" + encodeURIComponent(id) + "/payload" + powQuery(pow)),
    requestDelete: (id) =>
      request(API + "/collect/" + encodeURIComponent(id), { method: "DELETE" }),
    /**
     * Owner dashboard items (newest first).
     * @param {{ limit?: number, beforeCreatedAt?: string, beforeId?: string }|null} opts
     */
    myItems: (opts) => {
      var q = [];
      if (opts && opts.limit) q.push("limit=" + encodeURIComponent(String(opts.limit)));
      if (opts && opts.beforeCreatedAt)
        q.push("beforeCreatedAt=" + encodeURIComponent(opts.beforeCreatedAt));
      if (opts && opts.beforeId) q.push("beforeId=" + encodeURIComponent(opts.beforeId));
      var qs = q.length ? "?" + q.join("&") : "";
      return request(API + "/me/items" + qs);
    },
    /**
     * Site-wide audit log page (newest first).
     * @param {{ limit?: number, beforeAtUtc?: string, beforeId?: string }|null} opts
     *   Pass beforeAtUtc + beforeId from the last row to load the next older page.
     */
    myAudit: (opts) => {
      var q = [];
      if (opts && opts.limit) q.push("limit=" + encodeURIComponent(String(opts.limit)));
      if (opts && opts.beforeAtUtc)
        q.push("beforeAtUtc=" + encodeURIComponent(opts.beforeAtUtc));
      if (opts && opts.beforeId) q.push("beforeId=" + encodeURIComponent(opts.beforeId));
      var qs = q.length ? "?" + q.join("&") : "";
      return request(API + "/me/audit" + qs);
    },
  };

  /** Build ?powChallengeId=&powNonce=&powHash= for ID-access endpoints. */
  function powQuery(pow) {
    if (!pow || !pow.challengeId) return "";
    return (
      "?powChallengeId=" +
      encodeURIComponent(pow.challengeId) +
      "&powNonce=" +
      encodeURIComponent(pow.nonce) +
      (pow.hash ? "&powHash=" + encodeURIComponent(pow.hash) : "")
    );
  }

  /** JSON body fields for auth (and similar) POST endpoints that require PoW. */
  function powBody(pow) {
    if (!pow || !pow.challengeId) return {};
    return {
      powChallengeId: pow.challengeId,
      powNonce: pow.nonce,
      powHash: pow.hash || null,
    };
  }
})(typeof window !== "undefined" ? window : globalThis);
