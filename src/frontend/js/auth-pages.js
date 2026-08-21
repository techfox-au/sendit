/**
 * Login (incl. auto-register), forgot/reset password, settings (password + TOTP).
 * User data key (UDK) is unwrapped only in the browser after password entry.
 * Legacy /register is a redirect stub and does not load this script.
 */
(function () {
  "use strict";

  const page = document.body.dataset.page;
  const {
    $,
    setAlert,
    paintNav,
    loadUser,
    requireAuth,
    normalizeTotpCode,
    normalizeOtpCode,
    bindOtpCodeInputs,
    lockInteractive,
    solvePow,
  } = SenditApp;
  // Loaded on login/reset/settings (not forgot). Forgot only needs api + pow + app.
  const UDK = typeof SenditUserDataKey !== "undefined" ? SenditUserDataKey : null;

  // Email OTP = 6 digits; authenticator TOTP = 8. Strip spaces (Bitwarden may insert them).
  if (typeof bindOtpCodeInputs === "function") {
    bindOtpCodeInputs(["#email-otp-code"], 6);
    bindOtpCodeInputs(
      ["#totp-code", "#totp-confirm-code", "#disable-code", "#change-password-totp"],
      8
    );
  }

  function onSubmit(formSel, handler) {
    const form = $(formSel);
    if (!form) {
      console.error("Sendit!: form not found:", formSel);
      return;
    }
    // Use an explicit Promise chain (not `async` listener body) so rejections
    // never surface as "Uncaught (in promise)" if a finally/unlock step fails.
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      e.stopPropagation();
      // Disable fields + buttons for the whole submit (including PoW). Status
      // text goes only on the alert banner — keep button labels stable.
      const unlock =
        typeof lockInteractive === "function"
          ? lockInteractive(form.closest(".auth-card") || form)
          : function () {};
      Promise.resolve()
        .then(function () {
          return handler(e, form);
        })
        .catch(function (err) {
          try {
            const alertEl = $("#alert");
            const msg =
              (err && err.message) ||
              (err && err.data && err.data.error) ||
              String(err || "Request failed");
            setAlert(alertEl, "error", msg);
          } catch (displayErr) {
            console.error("Sendit!: form handler failed", err, displayErr);
          }
        })
        .then(function () {
          try {
            unlock();
          } catch {
            /* ignore */
          }
        });
    });
  }

  // ----- Login / auto-register -----
  if (page === "login") {
    let totpTicket = null;
    let emailOtpTicket = null;
    let pendingPassword = null;
    const alertEl = $("#alert");

    /** Clear password / OTP fields so Back/bfcache never restores secrets. */
    function clearSensitiveLoginFields() {
      const pwd = $("#password");
      if (pwd) pwd.value = "";
      const pwdConfirm = $("#password-confirm");
      if (pwdConfirm) pwdConfirm.value = "";
      const emailOtp = $("#email-otp-code");
      if (emailOtp) emailOtp.value = "";
      const totp = $("#totp-code");
      if (totp) totp.value = "";
      pendingPassword = null;
    }

    /**
     * Copy login email into step forms so Bitwarden can associate TOTP / OTP
     * with the same vault entry (name=username + autocomplete=username).
     */
    function syncPasswordManagerUsername() {
      const emailEl = $("#email");
      const email = emailEl && emailEl.value ? emailEl.value.trim() : "";
      const otpUser = $("#email-otp-username");
      if (otpUser) otpUser.value = email;
      const totpUser = $("#totp-username");
      if (totpUser) totpUser.value = email;
    }

    /**
     * Full restart of the login/register flow (password mismatch, cancel, etc.).
     * Wipes tickets/secrets/UDK and hard-navigates to /login so the page is completely fresh.
     */
    function restartLoginFresh(errorMessage) {
      totpTicket = null;
      emailOtpTicket = null;
      clearSensitiveLoginFields();
      if (UDK && typeof UDK.clearUserDataKey === "function") {
        try {
          UDK.clearUserDataKey();
        } catch {
          /* ignore */
        }
      }
      try {
        sessionStorage.removeItem("sendit_pending_udk_setup");
      } catch {
        /* ignore */
      }
      const email = $("#email");
      if (email) email.value = "";
      // Hard reload so multi-step tickets and any in-memory state cannot linger.
      try {
        if (errorMessage) {
          sessionStorage.setItem("sendit_login_flash_error", errorMessage);
        } else {
          sessionStorage.removeItem("sendit_login_flash_error");
        }
      } catch {
        /* ignore */
      }
      location.replace("/login");
    }

    /** Show password step only (after back navigation / session check). */
    function resetLoginSteps() {
      totpTicket = null;
      emailOtpTicket = null;
      clearSensitiveLoginFields();
      const pwStep = $("#password-step");
      const emailStep = $("#email-otp-step");
      const totpStep = $("#totp-step");
      if (pwStep) pwStep.classList.remove("hidden");
      if (emailStep) emailStep.classList.add("hidden");
      if (totpStep) totpStep.classList.add("hidden");
      setAlert(alertEl, null, null);
    }

    /** If session cookie is valid, leave login (replace so Back does not return here). */
    async function redirectIfSignedIn() {
      try {
        const u = await loadUser();
        if (u) {
          clearSensitiveLoginFields();
          location.replace("/dashboard");
          return true;
        }
      } catch {
        /* not signed in */
      }
      paintNav(null);
      return false;
    }

    async function applyLoginResponse(res, password) {
      if (!UDK) throw new Error("Encryption module failed to load. Hard-refresh the page.");

      if (res.wrappedUserDataKey) {
        await UDK.unlockFromLoginResponse(res.wrappedUserDataKey, password);
      } else if (password) {
        // Legacy account without wrap package — create one after we have a session if possible.
        const udk = UDK.generateUserDataKey();
        const wrapped = await UDK.wrapUserDataKey(udk, password);
        UDK.storeUserDataKey(udk);
        if (!res.emailOtpRequired && !res.totpRequired) {
          try {
            await SenditApi.setupUserDataKey(wrapped);
          } catch {
            /* keep session UDK */
          }
        } else {
          sessionStorage.setItem("sendit_pending_udk_setup", wrapped);
        }
      }

      if (res.emailOtpRequired) {
        emailOtpTicket = res.emailOtpTicket;
        pendingPassword = password;
        // Wipe password from the visible form immediately.
        const pwd = $("#password");
        if (pwd) pwd.value = "";
        syncPasswordManagerUsername();
        $("#password-step").classList.add("hidden");
        $("#email-otp-step").classList.remove("hidden");
        $("#totp-step").classList.add("hidden");
        setAlert(alertEl, "info", "Enter the verification code sent to your email.");
        const otpCode = $("#email-otp-code");
        if (otpCode) {
          try {
            otpCode.focus();
          } catch {
            /* ignore */
          }
        }
        return;
      }

      if (res.totpRequired) {
        totpTicket = res.totpTicket;
        pendingPassword = password;
        const pwd = $("#password");
        if (pwd) pwd.value = "";
        syncPasswordManagerUsername();
        $("#password-step").classList.add("hidden");
        $("#email-otp-step").classList.add("hidden");
        $("#totp-step").classList.remove("hidden");
        setAlert(alertEl, "info", "Enter the code from your authenticator app.");
        const totpCode = $("#totp-code");
        if (totpCode) {
          try {
            totpCode.focus();
          } catch {
            /* ignore */
          }
        }
        return;
      }

      // Finish deferred UDK setup once we have a real session.
      const pendingWrap = sessionStorage.getItem("sendit_pending_udk_setup");
      if (pendingWrap && UDK.loadUserDataKey()) {
        try {
          await SenditApi.setupUserDataKey(pendingWrap);
        } catch {
          /* ignore */
        }
        sessionStorage.removeItem("sendit_pending_udk_setup");
      }

      if (!UDK.loadUserDataKey()) {
        throw new Error("Failed to unlock encryption key. Try signing in again.");
      }
      pendingPassword = null;
      clearSensitiveLoginFields();
      // replace — do not leave a filled login form in the history stack
      location.replace("/dashboard");
    }

    /**
     * Issue + solve auth PoW; shows status on the login alert.
     * Seamlessly refreshes challenges 5s before TTL; shows attempt count from 2+.
     * Uses solveRefreshing directly (no nested lockInteractive) — the form submit
     * handler already locks the card for the whole request.
     */
    async function solveAuthPow(fetchChallenge, busyLabel) {
      const base = busyLabel || "Performing proof-of-work…";
      setAlert(alertEl, "info", base);
      if (
        typeof SenditPow === "undefined" ||
        typeof SenditPow.solveRefreshing !== "function"
      ) {
        throw new Error("Proof-of-work module failed to load. Hard-refresh the page.");
      }
      return SenditPow.solveRefreshing(fetchChallenge, {
        onProgress: function (_tries, attempt) {
          var label =
            typeof SenditPow.statusLabel === "function"
              ? SenditPow.statusLabel(base, attempt)
              : attempt > 1
                ? base + " (" + attempt + ")"
                : base;
          setAlert(alertEl, "info", label);
        },
      });
    }

    onSubmit("#login-form", async () => {
      setAlert(alertEl, null, null);
      if (!UDK) throw new Error("Encryption module failed to load. Hard-refresh the page.");

      const email = $("#email").value.trim();
      const passwordEl = $("#password");
      const password = passwordEl ? passwordEl.value : "";
      if (password.length < 8) throw new Error("Password must be at least 8 characters.");
      if (password.length > 256) throw new Error("Password must be at most 256 characters.");

      // Always prepare a wrap package — used only if the server creates a new account.
      const udk = UDK.generateUserDataKey();
      const wrappedUserDataKey = await UDK.wrapUserDataKey(udk, password);

      // Clear the DOM field ASAP so Back/bfcache cannot restore the secret.
      if (passwordEl) passwordEl.value = "";

      // PoW before login/register so bots pay work before email OTP / password check.
      const pow = await solveAuthPow(
        () => SenditApi.loginPowChallenge(email),
        "Performing proof-of-work…"
      );
      setAlert(alertEl, "info", "Signing in…");
      let res;
      try {
        res = await SenditApi.login(email, password, wrappedUserDataKey, pow);
      } catch (err) {
        // SMTP/Mailgun failed after timeouts — full reset so the UI is not stuck mid-flow.
        if (err && err.data && err.data.code === "email_send_failed") {
          restartLoginFresh(
            (err && err.message) ||
              "Could not send verification email. Try again in a moment."
          );
          return;
        }
        throw err;
      }

      // If server used our new wrap (new account) or returned an existing wrap, unlock appropriately.
      if (res.emailOtpRequired) {
        // New or unconfirmed account: keep the UDK we just generated if server accepted wrap.
        if (res.wrappedUserDataKey === wrappedUserDataKey || res.wrappedUserDataKey) {
          try {
            await UDK.unlockFromLoginResponse(res.wrappedUserDataKey, password);
          } catch {
            UDK.storeUserDataKey(udk);
          }
        } else {
          UDK.storeUserDataKey(udk);
        }
      }

      await applyLoginResponse(res, password);
    });

    onSubmit("#email-otp-form", async () => {
      setAlert(alertEl, null, null);
      const confirmEl = $("#password-confirm");
      const confirmPassword = confirmEl ? confirmEl.value : "";
      // Reconfirm password so a typo on first entry does not lock in a wrong UDK wrap.
      if (!pendingPassword || confirmPassword !== pendingPassword) {
        restartLoginFresh(
          "Passwords do not match. Start again and re-enter your email and password carefully."
        );
        return;
      }

      const codeEl = $("#email-otp-code");
      const code = normalizeOtpCode
        ? normalizeOtpCode(codeEl ? codeEl.value : "", 6)
        : String(codeEl ? codeEl.value : "").replace(/\D/g, "").slice(0, 6);
      if (code.length !== 6) throw new Error("Enter the 6-digit email verification code.");
      if (!emailOtpTicket) {
        restartLoginFresh("Verification session expired. Sign in again.");
        return;
      }
      // PoW before OTP submit to slow bulk OTP guessing / registration completion spam.
      const pow = await solveAuthPow(
        () => SenditApi.loginEmailOtpPowChallenge(emailOtpTicket),
        "Performing proof-of-work…"
      );
      const res = await SenditApi.loginEmailOtp(emailOtpTicket, code, pow);
      // Clear secrets only after a successful verify (invalid codes keep the fields).
      if (confirmEl) confirmEl.value = "";
      if (codeEl) codeEl.value = "";
      await applyLoginResponse(res, pendingPassword);
    });

    onSubmit("#totp-form", async () => {
      setAlert(alertEl, null, null);
      const codeEl = $("#totp-code");
      const code = normalizeTotpCode(codeEl ? codeEl.value : "");
      if (code.length !== 8) throw new Error("Enter the 8-digit authenticator code.");
      if (codeEl) codeEl.value = "";
      // PoW before TOTP submit (same action-time pattern as email OTP).
      const pow = await solveAuthPow(
        () => SenditApi.loginTotpPowChallenge(totpTicket),
        "Performing proof-of-work…"
      );
      const res = await SenditApi.loginTotp(totpTicket, code, pow);
      if (!UDK.loadUserDataKey() && res.wrappedUserDataKey && pendingPassword) {
        await UDK.unlockFromLoginResponse(res.wrappedUserDataKey, pendingPassword);
      }
      await applyLoginResponse(res, pendingPassword);
    });

    // pageshow fires on first load and when restored from bfcache (Back button).
    window.addEventListener("pageshow", (ev) => {
      clearSensitiveLoginFields();
      if (ev.persisted) {
        // Full bfcache restore — reset multi-step UI and re-check session.
        resetLoginSteps();
      }
      void Promise.resolve(redirectIfSignedIn()).catch(function () {
        /* ignore session probe failures */
      });
    });

    // Initial check (pageshow also runs on first load in modern browsers; keep explicit call).
    clearSensitiveLoginFields();
    // Show flash error from a forced full restart (e.g. password reconfirm mismatch).
    try {
      const flash = sessionStorage.getItem("sendit_login_flash_error");
      if (flash) {
        sessionStorage.removeItem("sendit_login_flash_error");
        setAlert(alertEl, "error", flash);
      }
    } catch {
      /* ignore */
    }
    // Warn early when crypto.subtle is missing (common on http://LAN-IP from a phone).
    if (!(window.crypto && window.crypto.subtle)) {
      setAlert(
        alertEl,
        "error",
        "This origin is not a secure context, so login encryption is blocked. " +
          "Use https://… or open http://localhost on this machine. " +
          "For phone testing: ./scripts/run-lan-https.sh"
      );
    }
    void Promise.resolve(redirectIfSignedIn()).catch(function () {
      /* ignore session probe failures */
    });
    return;
  }

  // ----- Forgot password -----
  if (page === "forgot") {
    const alertEl = $("#alert");
    onSubmit("#forgot-form", async () => {
      setAlert(alertEl, null, null);
      const email = $("#email").value.trim();
      if (!email) throw new Error("Enter your email address.");
      setAlert(alertEl, "info", "Performing proof-of-work…");
      const solve =
        typeof solvePow === "function"
          ? solvePow
          : SenditPow.solveRefreshing
            ? SenditPow.solveRefreshing.bind(SenditPow)
            : null;
      if (!solve) {
        throw new Error("Proof-of-work module failed to load. Hard-refresh the page.");
      }
      const pow = await solve(
        function () {
          return SenditApi.forgotPasswordPowChallenge(email);
        },
        {
          root: document.querySelector(".auth-card"),
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
      setAlert(alertEl, "info", "Sending…");
      await SenditApi.forgotPassword(email, pow);
      setAlert(
        alertEl,
        "ok",
        "If an account exists for that email, a reset link has been sent."
      );
    });
    loadUser().then(paintNav).catch(() => paintNav(null));
    return;
  }

  // ----- Reset password -----
  if (page === "reset") {
    const alertEl = $("#alert");
    const panel = $("#reset-panel");
    const token = new URLSearchParams(location.search).get("token");
    // Avoid leaking ?token= via Referer if user navigates away.
    try {
      if (history.replaceState && token) {
        const u = new URL(location.href);
        // Keep token in memory/sessionStorage for submit; strip from address bar after load.
        sessionStorage.setItem("sendit_reset_token", token);
        u.searchParams.delete("token");
        history.replaceState({}, "", u.pathname + u.search + u.hash);
      }
    } catch {
      /* ignore */
    }

    function resetToken() {
      return (
        token ||
        sessionStorage.getItem("sendit_reset_token") ||
        new URLSearchParams(location.search).get("token")
      );
    }

    onSubmit("#reset-form", async () => {
      if (!UDK) throw new Error("Encryption module failed to load. Hard-refresh the page.");
      const password = $("#password").value;
      if (password.length < 8) throw new Error("Password must be at least 8 characters.");
      if (password.length > 256) throw new Error("Password must be at most 256 characters.");
      const tok = resetToken();
      if (!tok) throw new Error("Missing reset token. Open the link from your email.");

      const totpEl = $("#totp-code");
      let totpCode = totpEl && totpEl.value ? normalizeTotpCode(totpEl.value) : null;
      if (totpCode === "") totpCode = null;
      if (totpEl && totpEl.required && (!totpCode || totpCode.length !== 8)) {
        throw new Error("Enter the 8-digit authenticator code.");
      }

      // New UDK; all previous sends/collects for this account are deleted server-side.
      const udk = UDK.generateUserDataKey();
      const wrappedUserDataKey = await UDK.wrapUserDataKey(udk, password);

      let res;
      try {
        res = await SenditApi.resetPassword(tok, password, wrappedUserDataKey, totpCode);
      } catch (err) {
        // Server asks for TOTP when 2FA is enabled.
        if (err && err.data && err.data.totpRequired) {
          const wrap = $("#totp-wrap");
          if (wrap) wrap.classList.remove("hidden");
          if (totpEl) totpEl.required = true;
          throw new Error(err.message || "Authenticator code is required.");
        }
        throw err;
      }

      UDK.clearUserDataKey();
      try {
        sessionStorage.removeItem("sendit_reset_token");
      } catch {
        /* ignore */
      }

      setAlert(
        alertEl,
        "ok",
        res.message ||
          "Password reset. Previous sends and collects for this account were permanently deleted."
      );

      // Replace the form panel with a countdown, then go to login.
      // Footer already has "Back to sign in" — no second login link here.
      let remaining = 5;
      if (panel) {
        panel.innerHTML =
          '<p class="lead" style="margin:0">' +
          'Redirecting to log in in <strong id="reset-countdown">' +
          remaining +
          "</strong> second" +
          (remaining === 1 ? "" : "s") +
          "…</p>";
      }

      const tick = () => {
        remaining -= 1;
        const el = $("#reset-countdown");
        if (remaining <= 0) {
          location.assign("/login");
          return;
        }
        if (el) {
          el.textContent = String(remaining);
          const lead = panel && panel.querySelector(".lead");
          if (lead) {
            lead.innerHTML =
              "Redirecting to log in in <strong id=\"reset-countdown\">" +
              remaining +
              "</strong> second" +
              (remaining === 1 ? "" : "s") +
              "…";
          }
        }
        setTimeout(tick, 1000);
      };
      setTimeout(tick, 1000);
    });
    loadUser().then(paintNav).catch(() => paintNav(null));
    return;
  }

  // ----- Settings -----
  if (page === "settings") {
    (async () => {
      const user = await requireAuth();
      if (!user) return;
      paintNav(user);
      $("#email-display").textContent = user.email;

      // App version footer (bottom-right); single source of truth on SenditApp.
      const verEl = $("#app-version");
      if (verEl) {
        const v =
          (SenditApp && SenditApp.AppVersion) ||
          (typeof AppVersion !== "undefined" ? AppVersion : "v0.1-BETA");
        verEl.textContent = v;
      }

      // Bitwarden / password managers: username context on password + TOTP forms.
      function fillSettingsUsernameFields(email) {
        ["#change-password-username", "#totp-confirm-username", "#totp-disable-username"].forEach(
          function (sel) {
            const el = $(sel);
            if (el) el.value = email || "";
          }
        );
      }
      fillSettingsUsernameFields(user.email);

      function setTotpUi(enabled) {
        const st = $("#totp-status");
        st.textContent = enabled ? "Enabled" : "Disabled";
        st.classList.toggle("totp-status-on", !!enabled);
        st.classList.toggle("totp-status-off", !enabled);
        const enableSec = $("#totp-enable-section");
        const disableSec = $("#totp-disable-section");
        if (enableSec) enableSec.classList.toggle("hidden", !!enabled);
        if (disableSec) disableSec.classList.toggle("hidden", !enabled);
        // Reset enroll UI when hiding enable section.
        if (enabled) {
          const enroll = $("#totp-enroll");
          if (enroll) enroll.classList.add("hidden");
        }
      }
      setTotpUi(!!user.totpEnabled);

      // Change password requires authenticator when 2FA is on (same as reset).
      const changeTotpWrap = $("#change-password-totp-wrap");
      const changeTotpEl = $("#change-password-totp");
      if (changeTotpWrap && changeTotpEl) {
        if (user.totpEnabled) {
          changeTotpWrap.classList.remove("hidden");
          changeTotpEl.required = true;
        } else {
          changeTotpWrap.classList.add("hidden");
          changeTotpEl.required = false;
        }
      }

      // Notifications (both off by default; checked = on; PATCH saves immediately on change).
      const collectCb = $("#notify-collect-ready");
      const sendCb = $("#notify-send-opened");
      // Last known server values — used to revert the UI if PATCH fails (otherwise the
      // checkbox can stay checked while the DB still has the preference off).
      let savedCollect = !!user.notifyCollectReady;
      let savedSend = !!user.notifySendOpened;
      if (collectCb) collectCb.checked = savedCollect;
      if (sendCb) sendCb.checked = savedSend;

      async function saveNotifications() {
        if (!collectCb || !sendCb) return;
        const nextCollect = !!collectCb.checked;
        const nextSend = !!sendCb.checked;
        try {
          const res = await SenditApi.updateNotifications(nextCollect, nextSend);
          savedCollect = !!res.notifyCollectReady;
          savedSend = !!res.notifySendOpened;
          collectCb.checked = savedCollect;
          sendCb.checked = savedSend;
        } catch {
          // Silent revert — no banner; failed toggles snap back to last saved state.
          collectCb.checked = savedCollect;
          sendCb.checked = savedSend;
        }
      }
      if (collectCb) collectCb.addEventListener("change", saveNotifications);
      if (sendCb) sendCb.addEventListener("change", saveNotifications);

      onSubmit("#change-password-form", async () => {
        const currentPassword = $("#current-password").value;
        const newPassword = $("#new-password").value;
        if (newPassword.length < 8) throw new Error("Password must be at least 8 characters.");
        if (newPassword.length > 256) throw new Error("Password must be at most 256 characters.");
        if (currentPassword.length > 256)
          throw new Error("Current password must be at most 256 characters.");

        const changeTotpEl = $("#change-password-totp");
        let totpCode =
          changeTotpEl && changeTotpEl.value ? normalizeTotpCode(changeTotpEl.value) : null;
        if (totpCode === "") totpCode = null;
        if (changeTotpEl && changeTotpEl.required && (!totpCode || totpCode.length !== 8)) {
          throw new Error("Enter the 8-digit authenticator code.");
        }

        // In-page confirm: window.prompt is unreliable on iOS after async form submit.
        const ok =
          typeof SenditApp.confirmDialog === "function"
            ? await SenditApp.confirmDialog({
                title: "Change password?",
                message:
                  "Changing your password generates a new encryption key and " +
                  "PERMANENTLY DELETES all of your existing sends and collects in Sendit! " +
                  "(data encrypted with your old key cannot be recovered).",
                confirmLabel: "Change password",
                cancelLabel: "Cancel",
                danger: true,
                requireText: "CHANGE",
                inputLabel: "Type CHANGE to confirm",
                inputPlaceholder: "CHANGE",
              })
            : false;
        if (!ok) {
          throw new Error("Password change cancelled.");
        }

        const udk = UDK.generateUserDataKey();
        const wrappedUserDataKey = await UDK.wrapUserDataKey(udk, newPassword);
        let res;
        try {
          res = await SenditApi.changePassword(
            currentPassword,
            newPassword,
            wrappedUserDataKey,
            totpCode
          );
        } catch (err) {
          if (err && err.data && err.data.totpRequired) {
            const wrap = $("#change-password-totp-wrap");
            if (wrap) wrap.classList.remove("hidden");
            if (changeTotpEl) changeTotpEl.required = true;
            throw new Error(err.message || "Authenticator code is required.");
          }
          throw err;
        }
        UDK.clearUserDataKey();
        setAlert(
          $("#alert"),
          "ok",
          (res.message || "Password changed.") +
            (typeof res.deletedItems === "number"
              ? " Deleted items: " + res.deletedItems + "."
              : "") +
            " Please log in again."
        );
        setTimeout(() => location.assign("/login"), 1800);
      });

      const beginBtn = $("#totp-begin");
      if (beginBtn) {
        beginBtn.addEventListener("click", async () => {
          try {
            const res = await SenditApi.totpBegin();
            $("#totp-enroll").classList.remove("hidden");
            $("#otpauth-uri").textContent = res.otpauthUri;
            renderQr(res.otpauthUri);
            fillSettingsUsernameFields(user.email);
            const codeEl = $("#totp-confirm-code");
            if (codeEl) {
              try {
                codeEl.focus();
              } catch {
                /* ignore */
              }
            }
          } catch (err) {
            setAlert($("#alert"), "error", err.message || String(err));
          }
        });
      }

      onSubmit("#totp-confirm-form", async () => {
        const code = normalizeTotpCode($("#totp-confirm-code").value);
        if (code.length !== 8) throw new Error("Enter the 8-digit authenticator code.");
        const res = await SenditApi.totpConfirm(code);
        // Server wiped all sessions; clear UDK and force full login (password + TOTP).
        if (typeof UDK !== "undefined" && UDK.clearUserDataKey) {
          UDK.clearUserDataKey();
        }
        setAlert(
          $("#alert"),
          "ok",
          (res && res.message) ||
            "Two-factor authentication enabled. Please sign in again with your authenticator code."
        );
        setTimeout(() => location.assign("/login"), 1500);
      });

      onSubmit("#totp-disable-form", async () => {
        const code = normalizeTotpCode($("#disable-code").value);
        if (code.length !== 8) throw new Error("Enter the 8-digit authenticator code.");
        const disablePw = $("#disable-password").value;
        if (disablePw.length > 256)
          throw new Error("Password must be at most 256 characters.");
        await SenditApi.totpDisable(disablePw, code);
        setAlert($("#alert"), "ok", "Two-factor authentication disabled.");
        $("#disable-password").value = "";
        $("#disable-code").value = "";
        setTotpUi(false);
      });

      // Logout is handled globally via [data-logout] + SenditApp.doLogout / paintNav.
    })();
  }

  function renderQr(text) {
    const host = $("#totp-qr-host") || $("#qrcode");
    // Prefer an explicit global; never call a DOM node named qrcode (id clash).
    const makeQr =
      typeof globalThis.qrcode === "function"
        ? globalThis.qrcode
        : typeof window !== "undefined" && typeof window.qrcode === "function"
          ? window.qrcode
          : null;
    if (!host) return;
    if (!makeQr) {
      throw new Error(
        "QR code library failed to load. Hard-refresh the page (or rebuild public/vendor/qrcode.min.js)."
      );
    }
    host.innerHTML = "";
    const qr = makeQr(0, "M");
    qr.addData(text);
    qr.make();
    host.innerHTML = qr.createImgTag(4, 8);
  }
})();
