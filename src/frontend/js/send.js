/**
 * Create send (/send/new): encrypt in-browser, POST ciphertext, show share link.
 *
 * - Payload + optional send name: hybrid AES-GCM + X25519 to a fresh keypair (crypto.js).
 * - Optional link password: wraps the fragment sk with PBKDF2-SHA512 + AES-256-GCM;
 *   only a passwordProtected flag is sent to the API (never the password or package).
 * - Owner dashboard fields (label, private note): UDK-encrypted ciphertext only.
 */
(async function () {
  const {
    $,
    setAlert,
    requireAuth,
    paintNav,
    wireCopyButton,
    setButtonBusy,
    downloadText,
    bindContentKindToggle,
    readSecretInput,
    parseAllowedCidr,
    showProgressModal,
    scheduleScrollBelowHeader,
    wireLinkPasswordConfirm,
    blurActiveField,
    FIELD_LIMITS,
  } = SenditApp;
  const alertEl = $("#alert");
  const compose = $("#compose");
  const result = $("#result");
  const linkEl = $("#link");
  const pageTitle = $("#page-title");
  const pageLead = $("#page-lead");
  const oneTimeEl = $("#one-time");
  const maxAccessWrap = $("#max-access-wrap");
  const maxAccessEl = $("#max-access");

  const user = await requireAuth();
  if (!user) return;
  paintNav(user);

  // Allowed IPs: visible while ipRestrictionsEnabled (server default true).
  // Hidden only after Worker canary reports non-public IP or probe skip — see ClientIpCapability.
  // Re-fetch config after ~3.5s so a page load during the post-boot probe still updates.
  let ipRestrictionsEnabled = true;
  const allowedCidrWrap = $("#allowed-cidr-wrap");
  async function refreshIpRestrictionsUi() {
    try {
      const res = await fetch("/api/v1/branding/config", {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (res.ok) {
        const cfg = await res.json();
        if (cfg && typeof cfg.ipRestrictionsEnabled === "boolean") {
          ipRestrictionsEnabled = cfg.ipRestrictionsEnabled;
        }
      }
    } catch {
      // keep current (default enabled)
    }
    if (allowedCidrWrap) {
      allowedCidrWrap.classList.toggle("hidden", !ipRestrictionsEnabled);
    }
    if (!ipRestrictionsEnabled) {
      const cidrField = $("#allowed-cidr");
      if (cidrField) cidrField.value = "";
    }
  }
  await refreshIpRestrictionsUi();
  setTimeout(function () {
    refreshIpRestrictionsUi();
  }, 3500);

  bindContentKindToggle(document);

  const hideTextWrap = $("#hide-text-wrap");
  const hideTextEl = $("#hide-text");

  function syncHideTextVisibility() {
    const selected = document.querySelector('input[name="content-kind"]:checked');
    const isText = !selected || selected.value === "text";
    if (hideTextWrap) hideTextWrap.classList.toggle("hidden", !isText);
    if (!isText && hideTextEl) hideTextEl.checked = false;
  }
  document.querySelectorAll('input[name="content-kind"]').forEach(function (r) {
    r.addEventListener("change", syncHideTextVisibility);
  });
  syncHideTextVisibility();

  function syncMaxAccessVisibility() {
    const multi = oneTimeEl && oneTimeEl.value === "false";
    if (maxAccessWrap) maxAccessWrap.classList.toggle("hidden", !multi);
    if (!multi && maxAccessEl) maxAccessEl.value = "";
  }
  if (oneTimeEl) {
    oneTimeEl.addEventListener("change", syncMaxAccessVisibility);
    syncMaxAccessVisibility();
  }
  if (maxAccessEl) {
    maxAccessEl.addEventListener("input", function () {
      maxAccessEl.value = maxAccessEl.value.replace(/[^\d]/g, "");
    });
  }

  const linkPasswordEl = $("#link-password");
  const linkPasswordConfirmEl = $("#link-password-confirm");
  const linkPw =
    typeof wireLinkPasswordConfirm === "function"
      ? wireLinkPasswordConfirm()
      : null;

  // iOS can deliver two submit events for one tap; block concurrent creates.
  let createBusy = false;
  $("#send-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (createBusy) return;
    createBusy = true;

    setAlert(alertEl, null, null);

    const submitBtn = e.target && e.target.querySelector
      ? e.target.querySelector('button[type="submit"]')
      : null;
    if (submitBtn && typeof setButtonBusy === "function") setButtonBusy(submitBtn, true);
    else if (submitBtn) submitBtn.disabled = true;

    const label = $("#label").value.trim() || null;
    if (label && label.length > FIELD_LIMITS.name) {
      setAlert(
        alertEl,
        "error",
        "Send name is too long (max " + FIELD_LIMITS.name + " characters)."
      );
      createBusy = false;
      if (submitBtn && typeof setButtonBusy === "function") setButtonBusy(submitBtn, false);
      else if (submitBtn) submitBtn.disabled = false;
      return;
    }
    const oneTime = $("#one-time").value === "true";
    const expiryMinutes = parseInt($("#expiry").value, 10);
    const hideTextByDefault = !!(hideTextEl && hideTextEl.checked);
    const privateNotePlain = ($("#private-note") && $("#private-note").value.trim()) || "";
    if (privateNotePlain.length > FIELD_LIMITS.privateNote) {
      setAlert(
        alertEl,
        "error",
        "Private note is too long (max " + FIELD_LIMITS.privateNote + " characters)."
      );
      createBusy = false;
      if (submitBtn && typeof setButtonBusy === "function") setButtonBusy(submitBtn, false);
      else if (submitBtn) submitBtn.disabled = false;
      return;
    }

    const cidrField = $("#allowed-cidr");
    const cidrParsed = ipRestrictionsEnabled
      ? parseAllowedCidr(cidrField ? cidrField.value : "")
      : { ok: true, value: null };
    if (!cidrParsed.ok) {
      setAlert(alertEl, "error", cidrParsed.error);
      createBusy = false;
      if (submitBtn && typeof setButtonBusy === "function") setButtonBusy(submitBtn, false);
      else if (submitBtn) submitBtn.disabled = false;
      return;
    }

    let maxAccessCount = null;
    if (!oneTime && maxAccessEl && maxAccessEl.value.trim()) {
      const n = parseInt(maxAccessEl.value.trim(), 10);
      if (!Number.isFinite(n) || n < 1 || n > 100000) {
        setAlert(alertEl, "error", "Maximum access count must be a whole number from 1 to 100000.");
        createBusy = false;
        if (submitBtn && typeof setButtonBusy === "function") setButtonBusy(submitBtn, false);
        else if (submitBtn) submitBtn.disabled = false;
        return;
      }
      maxAccessCount = n;
    }

    // Validate / read secret *before* the progress modal so empty-secret errors
    // do not race with body.overflow lock and can scroll the banner under the nav.
    let progress = null;
    try {
      const { plain, contentType, filename } = await readSecretInput(document);

      if ((privateNotePlain || label) && typeof SenditUserDataKey === "undefined") {
        throw new Error("Encryption module failed to load. Hard-refresh the page.");
      }

      progress =
        typeof showProgressModal === "function"
          ? showProgressModal("Creating send")
          : null;
      if (progress) {
        progress.setStatus("Reading and encrypting…");
        progress.setProgress(null);
      }

      // Owner-only: UDK-encrypt send name (dashboard) like private note.
      let ownerLabelCiphertext = null;
      if (label) {
        ownerLabelCiphertext = await SenditUserDataKey.encryptWithUserDataKey(
          new TextEncoder().encode(label)
        );
      }

      let privateNoteCiphertext = null;
      if (privateNotePlain) {
        privateNoteCiphertext = await SenditUserDataKey.encryptWithUserDataKey(
          new TextEncoder().encode(privateNotePlain)
        );
      }

      // One keypair for payload + recipient-facing encrypted send name (same #sk=).
      const kp = SenditCrypto.generateKeyPair();
      const wire = await SenditCrypto.encryptForRecipient(plain, kp.publicKey);
      plain.fill?.(0);

      let encryptedLabel = null;
      if (label) {
        encryptedLabel = await SenditCrypto.encryptForRecipient(
          new TextEncoder().encode(label),
          kp.publicKey
        );
      }

      const linkPassword = linkPw
        ? linkPw.getPassword()
        : (linkPasswordEl && linkPasswordEl.value) || "";
      let passwordProtected = false;
      let fragment;
      if (linkPassword.length > 0) {
        if (linkPw) linkPw.assertMatch();
        else {
          const conf = (linkPasswordConfirmEl && linkPasswordConfirmEl.value) || "";
          if (linkPassword !== conf) {
            throw new Error("Link password and confirmation do not match.");
          }
        }
        if (linkPassword.length > FIELD_LIMITS.password) {
          throw new Error(
            "Link password is too long (max " + FIELD_LIMITS.password + " characters)."
          );
        }
        const pkg = await SenditCrypto.wrapSecretKeyWithPassword(
          kp.secretKey,
          linkPassword
        );
        fragment = SenditCrypto.buildPasswordProtectedFragment(pkg);
        passwordProtected = true;
        if (linkPw) linkPw.clear();
        else {
          if (linkPasswordEl) linkPasswordEl.value = "";
          if (linkPasswordConfirmEl) linkPasswordConfirmEl.value = "";
        }
      } else {
        fragment = SenditCrypto.buildFragment(kp.secretKey);
      }
      kp.secretKey.fill(0);

      if (progress) {
        progress.setTitle("Uploading");
        progress.setStatus("Uploading encrypted payload…");
        progress.setProgress(0);
      }

      const created = await SenditApi.createSecret(
        {
          ciphertext: wire.ciphertext,
          iv: wire.iv,
          wrappedKey: wire.wrappedKey,
          ephemeralPublicKey: wire.ephemeralPublicKey,
          contentType,
          filename,
          // Stored as UDK ciphertext for the owner dashboard only (never plaintext).
          label: ownerLabelCiphertext,
          oneTime,
          expiryMinutes,
          allowedCidr: cidrParsed.value,
          hideTextByDefault: hideTextByDefault && contentType === "text/plain",
          privateNoteCiphertext,
          maxAccessCount,
          encryptedLabel,
          passwordProtected,
        },
        {
          onUploadProgress: function (fraction) {
            if (progress) progress.setProgress(fraction);
          },
        }
      );

      if (progress) {
        progress.setProgress(1);
        progress.setStatus("Done");
      }

      const link =
        location.origin +
        "/send?id=" +
        encodeURIComponent(created.id) +
        fragment;
      // Full share URL including #sk= — copy button reads this node at tap time (iOS).
      if (linkEl) linkEl.textContent = link;

      // iOS: dismiss link-password keyboard so the first tap on Copy works.
      if (typeof blurActiveField === "function") blurActiveField();

      if (compose) compose.classList.add("hidden");
      if (pageTitle) pageTitle.textContent = "Link ready";
      if (pageLead) {
        pageLead.textContent = passwordProtected
          ? "Copy this link now. The decryption key is password-wrapped in the # fragment; share the password separately."
          : "Copy and store this link now. The decryption key is only in the # fragment and cannot be recovered later.";
      }
      result.classList.remove("hidden");
      setAlert(
        alertEl,
        "warn",
        passwordProtected
          ? "Save this link and share the password out of band. Sendit! never sees the password or unwrapped key."
          : "Save this link now! Link includes the decryption key in the # fragment. Sendit! cannot show the key again."
      );
      // Ensure "Link ready" heading clears the fixed nav (not only the banner).
      if (typeof scheduleScrollBelowHeader === "function") {
        scheduleScrollBelowHeader(pageTitle || alertEl);
      }
      wireCopyButton("#copy-link", link, {
        alertEl: alertEl,
        okMessage: "Link copied.",
        copyFrom: "#link",
      });
      const dlLink = $("#download-link");
      if (dlLink) {
        dlLink.onclick = function (ev) {
          if (ev) {
            ev.preventDefault();
            ev.stopPropagation();
          }
          downloadText("sendit-link-" + created.id + ".txt", link);
        };
      }
    } catch (err) {
      setAlert(alertEl, "error", err.message || String(err));
      createBusy = false;
      if (submitBtn && typeof setButtonBusy === "function") setButtonBusy(submitBtn, false);
      else if (submitBtn) submitBtn.disabled = false;
    } finally {
      if (progress) progress.close();
      // After modal unlocks body scroll, re-anchor under the nav.
      if (typeof scheduleScrollBelowHeader === "function") {
        scheduleScrollBelowHeader(pageTitle || alertEl);
      }
    }
  });
})();
