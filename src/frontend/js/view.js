/**
 * Open / decrypt a send (/send?id=…#sk=…).
 *
 * Flow: PoW → meta → (optional link password unwrap of #sk) → Reveal → payload PoW → decrypt.
 * Page h1 is "Reveal secret" then "Secret" (send name lives only in the meta card).
 * Password-protected: #sk is a compact AES-GCM package; password field required before Reveal.
 * Guests allowed; wrong password / key fails closed with no redirect.
 * Not-found / already-consumed: redirect to dashboard only if signed in.
 */
(async function () {
  const {
    $,
    setAlert,
    paintNav,
    loadUser,
    pathId,
    secretTextBlockHtml,
    wireSecretTextBlock,
    setButtonBusy,
    isShareGoneMessage,
    failMaybeDashboard,
  } = SenditApp;

  function setRevealBusy(busy) {
    if (!revealBtn) return;
    if (typeof setButtonBusy === "function") setButtonBusy(revealBtn, busy);
    else revealBtn.disabled = !!busy;
  }
  const alertEl = $("#alert");
  const metaBox = $("#meta");
  const confirmBox = $("#confirm-box");
  const revealBtn = $("#reveal");
  const passwordWrap = $("#link-password-wrap");
  const passwordEl = $("#link-password");

  const user = await loadUser();
  paintNav(user);

  function hideSendPanels() {
    if (metaBox) {
      metaBox.classList.add("hidden");
      metaBox.innerHTML = "";
    }
    if (confirmBox) confirmBox.classList.add("hidden");
  }

  /** Stay on page (guests and non-gone errors). */
  function fail(message) {
    hideSendPanels();
    setAlert(alertEl, "error", message);
  }

  /** Not-found / consumed: dashboard redirect only for signed-in users. */
  function failGone(message) {
    return failMaybeDashboard(alertEl, message, {
      hide: hideSendPanels,
      user: user,
    });
  }

  const id = new URLSearchParams(location.search).get("id") || pathId();
  // Presence check only — unwrap after meta tells us if password-protected.
  const hasFragmentSk =
    !!SenditCrypto.secretKeyFromLocationHash(location.hash) ||
    !!SenditCrypto.secretKeyPackageFromLocationHash(location.hash);

  if (!id) {
    fail("Missing secret id.");
    return;
  }
  if (!hasFragmentSk) {
    fail("Missing decryption key. Open the full link including the #sk=… fragment.");
    return;
  }

  // PoW on ID access: bots probing send IDs must solve before meta is returned.
  setAlert(alertEl, "info", "Performing proof-of-work…");
  let meta;
  try {
    const solve =
      typeof SenditApp.solvePow === "function"
        ? SenditApp.solvePow
        : SenditPow.solveRefreshing.bind(SenditPow);
    const solution = await solve(
      function () {
        return SenditApi.secretPowChallenge(id);
      },
      {
        onProgress: function (_tries, attempt) {
          var base = "Performing proof-of-work…";
          var label =
            typeof SenditPow !== "undefined" &&
            typeof SenditPow.statusLabel === "function"
              ? SenditPow.statusLabel(base, attempt)
              : attempt > 1
                ? base + " (" + attempt + ")"
                : base;
          setAlert(alertEl, "info", label);
        },
      }
    );
    meta = await SenditApi.secretMeta(id, solution);
  } catch (err) {
    const msg = (err && err.message) || "Secret not found.";
    // Not-found / already consumed / 404 → dashboard only for signed-in users.
    if (
      (err && err.status === 404) ||
      (typeof isShareGoneMessage === "function" && isShareGoneMessage(msg)) ||
      /not found|already consumed|no longer available/i.test(msg)
    ) {
      await failGone(msg);
    } else {
      fail(msg);
    }
    return;
  }
  setAlert(alertEl, null, null);

  /** @type {Uint8Array|null} raw sk when not password-protected; resolved on reveal when protected */
  let sk = null;
  /** @type {string|null} password-wrap package JSON when password-protected */
  let skPackage = null;
  /** @type {string|null} decrypted send name (after sk available) */
  let sendName = null;
  /**
   * Recipient-facing send name is hybrid-encrypted to sk (encryptedLabel).
   * Until sk is unwrapped we cannot show it — display "Hidden" instead.
   */
  const nameLockedBehindPassword = !!(meta.passwordProtected && meta.encryptedLabel);

  /** Page h1 / tab: never the send name (that stays in the meta card only). */
  function setPageHeading(text) {
    const pageTitle = $("#page-title");
    if (pageTitle) pageTitle.textContent = text;
    document.title = text + " · Sendit!";
  }

  if (meta.passwordProtected) {
    skPackage = SenditCrypto.secretKeyPackageFromLocationHash(location.hash);
    if (!skPackage) {
      fail(
        "This send is password-protected, but the link does not contain a wrapped key. Open the full link."
      );
      return;
    }
    if (passwordWrap) passwordWrap.classList.remove("hidden");
    setRevealBusy(true);
    if (passwordEl) {
      function syncRevealEnabled() {
        setRevealBusy(!passwordEl.value);
      }
      passwordEl.addEventListener("input", syncRevealEnabled);
      passwordEl.addEventListener("change", syncRevealEnabled);
      syncRevealEnabled();
      try {
        passwordEl.focus();
      } catch {
        /* ignore */
      }
    }
  } else {
    sk = SenditCrypto.secretKeyFromLocationHash(location.hash);
    if (!sk) {
      fail(
        "Missing or invalid decryption key. Open the full link including the #sk=… fragment."
      );
      return;
    }

    // Decrypt send name early when key is already available.
    if (meta.encryptedLabel) {
      try {
        const nameBytes = await SenditCrypto.decryptWithSecretKey(meta.encryptedLabel, sk);
        sendName = new TextDecoder().decode(nameBytes);
      } catch {
        sk.fill(0);
        fail("Incorrect decryption key.");
        return;
      }
    }
  }

  setPageHeading("Reveal secret");

  /**
   * @param {string|null} extraHtml
   * @param {{ hideExpires?: boolean }} [opts]
   */
  function renderMetaPanel(extraHtml, opts) {
    opts = opts || {};
    let html = "";
    if (sendName) {
      html += "<p class='secret-label'><strong>" + escapeHtml(sendName) + "</strong></p>";
    } else if (nameLockedBehindPassword) {
      html +=
        "<p class='secret-label muted'><strong>Hidden</strong>" +
        ' <span class="secret-label-hint">(enter link password to reveal)</span></p>';
    }
    // One-time after reveal is destroyed — expiry is meaningless.
    if (!opts.hideExpires) {
      html +=
        "<p><strong>Expires:</strong> " +
        SenditApp.formatWhen(meta.expiresAt) +
        "</p>";
    }
    html +=
      "<p><strong>Mode:</strong> " +
      (meta.oneTime
        ? "One-time (destroyed after reveal)"
        : meta.maxAccessCount
          ? "Multi-view (max " + meta.maxAccessCount + " opens)"
          : "Multi-view until expiry") +
      "</p>";
    if (meta.filename) {
      html += "<p><strong>File:</strong> " + escapeHtml(meta.filename) + "</p>";
    }
    if (extraHtml) html += extraHtml;
    metaBox.innerHTML = html;
    metaBox.classList.remove("hidden");
  }

  renderMetaPanel(null);

  /**
   * Resolve sk (unwrap with password if needed) and optional encrypted send name.
   * @returns {Promise<Uint8Array>}
   */
  async function resolveSecretKey() {
    if (sk) return sk;

    if (!meta.passwordProtected || !skPackage) {
      throw new Error("Missing decryption key.");
    }
    const password = passwordEl ? passwordEl.value : "";
    if (!password) {
      throw new Error("Link password is required.");
    }
    const unwrapped = await SenditCrypto.unwrapSecretKeyWithPassword(skPackage, password);
    sk = unwrapped;

    // Decrypt send name once key is available (password-protected path).
    if (meta.encryptedLabel && !sendName) {
      try {
        const nameBytes = await SenditCrypto.decryptWithSecretKey(meta.encryptedLabel, sk);
        sendName = new TextDecoder().decode(nameBytes);
        // Refresh meta card heading only (page h1 stays Reveal secret until success).
        renderMetaPanel(null);
      } catch {
        sk.fill(0);
        sk = null;
        throw new Error("Incorrect password or decryption key.");
      }
    }
    if (passwordEl) passwordEl.value = "";
    return sk;
  }

  async function reveal() {
    setRevealBusy(true);
    try {
      if (meta.passwordProtected) {
        const password = passwordEl ? passwordEl.value : "";
        if (!password) {
          setAlert(alertEl, "error", "Link password is required.");
          setRevealBusy(false);
          if (passwordEl) {
            try {
              passwordEl.focus();
            } catch {
              /* ignore */
            }
          }
          return;
        }
      }

      // Lock password + actions for unlock/PoW/decrypt so fields cannot change mid-flight.
      // Status messages stay on the alert banner only (button label does not change).
      const unlockUi =
        typeof SenditApp.lockInteractive === "function"
          ? SenditApp.lockInteractive(confirmBox || document.querySelector(".wrap"))
          : function () {};
      let key;
      let payload;
      let plain;
      try {
        if (meta.passwordProtected) {
          setAlert(alertEl, "info", "Unlocking key…");
        } else {
          setAlert(alertEl, "info", "Performing proof-of-work…");
        }
        key = await resolveSecretKey();

        // Fresh PoW at reveal; refreshes challenges 5s before TTL until solved.
        setAlert(alertEl, "info", "Performing proof-of-work…");
        const solve =
          typeof SenditApp.solvePow === "function"
            ? SenditApp.solvePow
            : SenditPow.solveRefreshing.bind(SenditPow);
        const solution = await solve(
          function () {
            return SenditApi.secretPowChallenge(id);
          },
          {
            root: confirmBox,
            onProgress: function (_tries, attempt) {
              var base = "Performing proof-of-work…";
              var label =
                typeof SenditPow !== "undefined" &&
                typeof SenditPow.statusLabel === "function"
                  ? SenditPow.statusLabel(base, attempt)
                  : attempt > 1
                    ? base + " (" + attempt + ")"
                    : base;
              setAlert(alertEl, "info", label);
            },
          }
        );
        setAlert(alertEl, "info", "Decrypting…");
        payload = await SenditApi.secretGet(id, solution);
        plain = await SenditCrypto.decryptWithSecretKey(payload, key);
      } finally {
        unlockUi();
      }
      key.fill(0);
      sk = null;

      confirmBox.classList.add("hidden");
      setPageHeading("Secret");
      if (meta.oneTime) {
        setAlert(alertEl, "warn", "Decrypted. This one-time secret has been destroyed on the server.");
      } else {
        setAlert(alertEl, "ok", "Decrypted successfully.");
      }

      const isFile =
        payload.filename &&
        payload.contentType &&
        payload.contentType !== "text/plain";

      const metaOpts = meta.oneTime ? { hideExpires: true } : {};

      if (isFile) {
        const blob = new Blob([plain], { type: payload.contentType });
        const url = URL.createObjectURL(blob);
        const name = payload.filename || meta.filename || "download";
        renderMetaPanel(
          "<div class='actions secret-actions'>" +
            "<a class='btn' download='" +
            escapeHtml(name) +
            "' href='" +
            url +
            "'>Download</a>" +
            "</div>",
          metaOpts
        );
      } else {
        const text = new TextDecoder().decode(plain);
        const hide = !!(payload.hideTextByDefault || meta.hideTextByDefault);
        renderMetaPanel(
          secretTextBlockHtml("secret-text-out", "secret-copy-btn", {
            hideByDefault: hide,
            toggleBtnId: "secret-reveal-btn",
          }),
          metaOpts
        );
        wireSecretTextBlock(
          "secret-text-out",
          "secret-copy-btn",
          text,
          { hideByDefault: hide, toggleBtnId: "secret-reveal-btn" },
          alertEl
        );
      }
    } catch (err) {
      if (sk) {
        sk.fill(0);
        sk = null;
      }
      setRevealBusy(false);
      const msg = (err && err.message) || "Could not decrypt secret.";
      if (/password is required/i.test(msg)) {
        setAlert(alertEl, "error", msg);
        return;
      }
      // Keep confirm UI for retry on wrong password (do not wipe whole page).
      if (meta.passwordProtected && /password|key|decrypt|OperationError/i.test(msg)) {
        setAlert(alertEl, "error", "Incorrect password or decryption key.");
        if (passwordEl) {
          passwordEl.value = "";
          try {
            passwordEl.focus();
          } catch {
            /* ignore */
          }
        }
        setRevealBusy(true);
        return;
      }
      // Consumed between meta and reveal, or 404 — dashboard only if signed in.
      if (
        (err && err.status === 404) ||
        (typeof isShareGoneMessage === "function" && isShareGoneMessage(msg))
      ) {
        await failGone(msg);
        return;
      }
      fail(
        err && err.message && /decrypt|key|OperationError|password/i.test(err.message)
          ? "Incorrect decryption key."
          : msg
      );
    }
  }

  if (meta.oneTime) {
    confirmBox.classList.remove("hidden");
    setAlert(
      alertEl,
      "warn",
      "This secret can only be displayed once. If you open it, it will be permanently deleted from the server."
    );
    revealBtn.addEventListener("click", reveal);
  } else {
    confirmBox.classList.remove("hidden");
    if (meta.maxAccessCount) {
      const left = Math.max(0, meta.maxAccessCount - (meta.accessCount || 0));
      setAlert(
        alertEl,
        "info",
        "This send allows up to " +
          meta.maxAccessCount +
          " opens (" +
          left +
          " remaining)."
      );
    }
    revealBtn.textContent = "Reveal secret";
    revealBtn.addEventListener("click", reveal);
  }

  // Enter in password field submits reveal.
  if (passwordEl) {
    passwordEl.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter") {
        ev.preventDefault();
        reveal();
      }
    });
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
})();
