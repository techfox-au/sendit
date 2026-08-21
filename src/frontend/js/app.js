/**
 * Shared UI helpers: nav user state, flash messages, require-auth redirects.
 */
(function (global) {
  "use strict";

  /** Display / release version (settings footer, diagnostics). */
  var AppVersion = "v0.1-BETA";

  function $(sel, root) {
    return (root || document).querySelector(sel);
  }

  function show(el, on) {
    if (!el) return;
    el.classList.toggle("hidden", !on);
  }

  /** sessionStorage key: last known signed-in email for instant nav paint across MPA loads. */
  var NAV_EMAIL_KEY = "sendit_nav_email";

  function cacheNavEmail(email) {
    try {
      if (email) sessionStorage.setItem(NAV_EMAIL_KEY, String(email));
      else sessionStorage.removeItem(NAV_EMAIL_KEY);
    } catch {
      /* private mode / quota */
    }
  }

  /**
   * Paint nav email (and auth chrome) from session cache before /auth/me returns.
   * Prevents the empty→filled email / layout jump that makes the bar look like it redraws.
   */
  function paintNavFromCache() {
    var email = null;
    try {
      email = sessionStorage.getItem(NAV_EMAIL_KEY);
    } catch {
      return;
    }
    if (!email) return;
    document.querySelectorAll("[data-nav-email]").forEach(function (el) {
      if (!el.textContent) el.textContent = email;
    });
    // Assume still signed in until loadUser says otherwise (requireAuth redirects if not).
    document.querySelectorAll("[data-nav-auth]").forEach(function (el) {
      show(el, true);
    });
    document.querySelectorAll("header.app a.brand").forEach(function (el) {
      el.setAttribute("href", "/dashboard");
      el.removeAttribute("aria-disabled");
      el.classList.remove("brand-inert");
      el.removeAttribute("tabindex");
    });
  }

  /** Current page scroll top (Safari can disagree between body / documentElement). */
  function pageScrollTop() {
    var se = document.scrollingElement;
    var a = se && typeof se.scrollTop === "number" ? se.scrollTop : 0;
    var b = window.pageYOffset || window.scrollY || 0;
    var c =
      (document.documentElement && document.documentElement.scrollTop) || 0;
    var d = (document.body && document.body.scrollTop) || 0;
    return Math.max(a, b, c, d, 0);
  }

  function setPageScrollTop(y) {
    if (y < 0) y = 0;
    var se = document.scrollingElement;
    if (se) se.scrollTop = y;
    if (document.documentElement) document.documentElement.scrollTop = y;
    if (document.body) document.body.scrollTop = y;
    try {
      window.scrollTo(0, y);
    } catch (_) {
      /* ignore */
    }
  }

  /**
   * Bottom edge of fixed header.app in viewport coords (+ gap). Use bottom, not
   * height — on iOS with safe-area the bar may not start at y=0.
   */
  function fixedHeaderClearance() {
    var gap = 16;
    var header = document.querySelector("header.app");
    if (header) {
      var r = header.getBoundingClientRect();
      // Prefer bottom edge of the visible bar.
      if (r.bottom > 0) return Math.ceil(r.bottom) + gap;
      if (r.height > 0) return Math.ceil(r.height) + gap;
    }
    return 64 + gap;
  }

  /**
   * Instantly scroll so el’s top sits just below the fixed nav.
   * scrollIntoView + scroll-margin is unreliable on iOS (banner ends under the bar).
   * Smooth scroll is also avoided — it often undershoots on mobile Safari.
   */
  function scrollBelowFixedHeader(el) {
    if (!el || (el.classList && el.classList.contains("hidden"))) return;

    function apply() {
      if (!el || (el.classList && el.classList.contains("hidden"))) return;
      var clearance = fixedHeaderClearance();
      var rect = el.getBoundingClientRect();
      var viewBottom =
        window.innerHeight || document.documentElement.clientHeight || 0;
      // Fully visible below the nav — do nothing.
      if (rect.top >= clearance - 0.5 && rect.bottom <= viewBottom - 4) return;

      var target = pageScrollTop() + rect.top - clearance;
      setPageScrollTop(target);

      // Second pass after layout / address-bar resize (common on iOS).
      requestAnimationFrame(function () {
        if (!el || (el.classList && el.classList.contains("hidden"))) return;
        var c2 = fixedHeaderClearance();
        var r2 = el.getBoundingClientRect();
        if (r2.top < c2 - 0.5) {
          setPageScrollTop(pageScrollTop() + r2.top - c2);
        }
      });
    }

    apply();
  }

  /**
   * Prefer #page-title / main h1 so result pages ("Link ready") are not left
   * under the nav when only the alert was scrolled into view.
   * @param {Element|null|undefined} [hint] optional element (e.g. alert)
   */
  function pageTopScrollAnchor(hint) {
    var title =
      document.getElementById("page-title") ||
      document.querySelector(".wrap > h1");
    if (title && !(title.classList && title.classList.contains("hidden"))) {
      if (!hint) return title;
      // Title above the hint in the document → use title so heading stays visible.
      try {
        var tTop = title.getBoundingClientRect().top + pageScrollTop();
        var hTop = hint.getBoundingClientRect().top + pageScrollTop();
        if (tTop <= hTop + 1) return title;
      } catch (_) {
        return title;
      }
    }
    if (hint && !(hint.classList && hint.classList.contains("hidden"))) return hint;
    return title || hint || null;
  }

  /**
   * Scroll page top content (title, or hint) clear of the fixed header.
   * Retries after layout / progress-modal teardown / iOS viewport settle.
   * @param {Element|null|undefined} [hint]
   */
  function scheduleScrollBelowHeader(hint) {
    function run() {
      var el = pageTopScrollAnchor(hint);
      if (el) scrollBelowFixedHeader(el);
    }
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        run();
        setTimeout(run, 50);
        setTimeout(run, 200);
      });
    });
  }

  function setAlert(el, type, msg) {
    if (!el) return;
    if (!msg) {
      el.className = "alert hidden";
      el.textContent = "";
      return;
    }
    el.className = "alert " + (type || "info");
    el.textContent = msg;
    // error / warn / ok: scroll so title + banner clear the fixed nav.
    // Skip info (PoW progress spam while user may be mid-form).
    if (type === "error" || type === "warn" || type === "ok") {
      scheduleScrollBelowHeader(el);
    }
  }

  function isPrimaryGoldButton(el) {
    if (!el || !el.classList) return false;
    if (el.classList.contains("secondary") || el.classList.contains("danger"))
      return false;
    if (el.classList.contains("nav-menu-toggle")) return false;
    // button or a.btn gold primary (New send, Create, Reveal, …)
    return el.tagName === "BUTTON" || (el.tagName === "A" && el.classList.contains("btn"));
  }

  /**
   * Put label in <span class="btn-label"> (primary gold only) so iOS cannot
   * replace button text colour with system light grey.
   */
  function ensureButtonLabelSpan(el) {
    if (!el || el.dataset.labelWrapped === "1") return;
    if (
      el.childNodes.length === 1 &&
      el.firstChild.nodeType === 1 &&
      el.firstChild.classList &&
      el.firstChild.classList.contains("btn-label")
    ) {
      el.dataset.labelWrapped = "1";
      return;
    }
    var span = document.createElement("span");
    span.className = "btn-label";
    while (el.firstChild) span.appendChild(el.firstChild);
    el.appendChild(span);
    el.dataset.labelWrapped = "1";
  }

  /**
   * Busy / disabled look for primary actions (Reveal secret, New send, Create, …).
   * - Touch primary gold: .ui-busy + inline styles (iOS greys native :disabled text).
   * - Desktop primary / non-primary: native disabled on buttons; ui-locked on links.
   * @param {Element|null|undefined} el
   * @param {boolean} busy
   */
  function setButtonBusy(el, busy) {
    if (!el) return;
    var touchUi =
      typeof window.matchMedia === "function" &&
      window.matchMedia("(hover: none), (pointer: coarse)").matches;
    var primary = isPrimaryGoldButton(el);

    // Touch + primary gold (button or a.btn): shared path so New send == Reveal secret.
    if (primary && touchUi) {
      ensureButtonLabelSpan(el);
      if (busy) {
        el.classList.add("ui-busy");
        el.classList.remove("ui-locked");
        el.setAttribute("aria-disabled", "true");
        el.classList.remove("is-pressed");
        if (el.tagName === "BUTTON" || el.tagName === "INPUT") {
          // Keep enabled=false off so iOS does not force light-grey system text.
          if (el.disabled) el.disabled = false;
        }
        el.style.setProperty("background", "var(--primary)", "important");
        el.style.setProperty("color", "#0a0a0a", "important");
        el.style.setProperty("-webkit-text-fill-color", "#0a0a0a", "important");
        el.style.setProperty("opacity", "0.45", "important");
        var lab = el.firstElementChild;
        if (lab && lab.classList && lab.classList.contains("btn-label")) {
          lab.style.setProperty("color", "#0a0a0a", "important");
          lab.style.setProperty("-webkit-text-fill-color", "#0a0a0a", "important");
        }
      } else {
        el.classList.remove("ui-busy");
        el.classList.remove("ui-locked");
        el.removeAttribute("aria-disabled");
        el.style.removeProperty("color");
        el.style.removeProperty("-webkit-text-fill-color");
        el.style.removeProperty("opacity");
        el.style.removeProperty("background");
        var lab2 = el.firstElementChild;
        if (lab2 && lab2.classList && lab2.classList.contains("btn-label")) {
          lab2.style.removeProperty("color");
          lab2.style.removeProperty("-webkit-text-fill-color");
        }
      }
      return;
    }

    // Desktop / secondary: native disabled (buttons) or ui-locked (links).
    el.classList.remove("ui-busy");
    el.style.removeProperty("color");
    el.style.removeProperty("-webkit-text-fill-color");
    el.style.removeProperty("opacity");
    el.style.removeProperty("background");
    if (el.tagName === "BUTTON" || el.tagName === "INPUT") {
      el.disabled = !!busy;
      if (busy) el.setAttribute("aria-disabled", "true");
      else el.removeAttribute("aria-disabled");
    } else if (el.tagName === "A") {
      if (busy) {
        el.setAttribute("aria-disabled", "true");
        el.classList.add("ui-locked");
      } else {
        el.removeAttribute("aria-disabled");
        el.classList.remove("ui-locked");
      }
    }
  }

  /**
   * Disable controls under root while PoW / busy work runs.
   * Primary gold buttons → setButtonBusy; others → native disabled.
   * Hamburger is never locked (stays grey, not gold).
   * @param {ParentNode|Element|null|undefined} root
   * @returns {() => void}
   */
  function lockInteractive(root) {
    const scope =
      root && root.querySelector
        ? root
        : document.querySelector(".auth-card") ||
          document.querySelector(".wrap") ||
          document.body;
    const unlockers = [];
    const sel =
      "input:not([type='hidden']), textarea, select, button, a.btn, .auth-footer-link a";
    scope.querySelectorAll(sel).forEach(function (el) {
      if (
        el.closest(
          "#sendit-confirm-modal, #sendit-api-unreachable-modal, .pw-modal-overlay, .progress-modal-overlay"
        )
      ) {
        return;
      }
      if (el.classList && el.classList.contains("nav-menu-toggle")) {
        return;
      }
      if (el.tagName === "A") {
        if (el.dataset.uiLockHeld === "1" || el.getAttribute("aria-disabled") === "true") {
          return;
        }
        el.dataset.uiLockHeld = "1";
        const prevTab = el.getAttribute("tabindex");
        const onClick = function (ev) {
          ev.preventDefault();
          ev.stopPropagation();
        };
        el.setAttribute("tabindex", "-1");
        el.addEventListener("click", onClick, true);
        // Primary gold a.btn (New send): same touch busy path as Reveal secret button.
        if (isPrimaryGoldButton(el)) {
          setButtonBusy(el, true);
          unlockers.push(function () {
            setButtonBusy(el, false);
            el.removeEventListener("click", onClick, true);
            if (prevTab == null) el.removeAttribute("tabindex");
            else el.setAttribute("tabindex", prevTab);
            delete el.dataset.uiLockHeld;
          });
        } else {
          el.setAttribute("aria-disabled", "true");
          el.classList.add("ui-locked");
          unlockers.push(function () {
            el.removeEventListener("click", onClick, true);
            el.removeAttribute("aria-disabled");
            el.classList.remove("ui-locked");
            if (prevTab == null) el.removeAttribute("tabindex");
            else el.setAttribute("tabindex", prevTab);
            delete el.dataset.uiLockHeld;
          });
        }
        return;
      }
      if (el.tagName === "BUTTON") {
        if (el.dataset.uiLockHeld === "1") return;
        el.dataset.uiLockHeld = "1";
        if (isPrimaryGoldButton(el)) {
          setButtonBusy(el, true);
          unlockers.push(function () {
            setButtonBusy(el, false);
            delete el.dataset.uiLockHeld;
          });
        } else {
          if (el.disabled) {
            delete el.dataset.uiLockHeld;
            return;
          }
          el.disabled = true;
          unlockers.push(function () {
            el.disabled = false;
            delete el.dataset.uiLockHeld;
          });
        }
        return;
      }
      if (el.disabled || el.dataset.uiLockHeld === "1") return;
      el.disabled = true;
      el.dataset.uiLockHeld = "1";
      unlockers.push(function () {
        el.disabled = false;
        delete el.dataset.uiLockHeld;
      });
    });
    return function unlockInteractive() {
      for (let i = 0; i < unlockers.length; i++) unlockers[i]();
      unlockers.length = 0;
    };
  }

  /**
   * Solve PoW while locking UI.
   * - Pass a challenge object: solve that challenge only (abandons 5s before expiresAt).
   * - Pass an async fetchChallenge function: seamlessly request new challenges until solved.
   * onProgress(tries, attempt) — attempt ≥ 2 should show a counter in the UI.
   *
   * @param {object|function(): Promise<object>} challengeOrFetcher
   * @param {{ onProgress?: function, root?: Element|null, maxAttempts?: number }} [opts]
   */
  async function solvePow(challengeOrFetcher, opts) {
    opts = opts || {};
    if (typeof global.SenditPow === "undefined") {
      throw new Error("Proof-of-work module failed to load. Hard-refresh the page.");
    }
    const unlock = lockInteractive(opts.root || null);
    try {
      if (typeof challengeOrFetcher === "function") {
        if (typeof global.SenditPow.solveRefreshing !== "function") {
          throw new Error("Proof-of-work module failed to load. Hard-refresh the page.");
        }
        return await global.SenditPow.solveRefreshing(challengeOrFetcher, opts);
      }
      if (typeof global.SenditPow.solve !== "function") {
        throw new Error("Proof-of-work module failed to load. Hard-refresh the page.");
      }
      return await global.SenditPow.solve(challengeOrFetcher, opts);
    } finally {
      unlock();
    }
  }

  async function loadUser() {
    try {
      const me = await SenditApi.me();
      // /auth/me returns 200 with authenticated:false for guests (avoids console 401 noise).
      if (!me || me.authenticated === false || !me.email) return null;
      return me;
    } catch {
      return null;
    }
  }

  async function requireAuth(loginPath) {
    const user = await loadUser();
    if (!user) {
      location.href = loginPath || "/login";
      return null;
    }
    return user;
  }

  function setNavMenuOpen(open) {
    document.body.classList.toggle("nav-menu-open", !!open);
    document.querySelectorAll("[data-nav-menu-toggle]").forEach(function (btn) {
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      btn.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    });
  }

  function closeNavMenu() {
    setNavMenuOpen(false);
  }

  /**
   * Mobile hamburger: open/close drawer, backdrop, Escape, close on nav link click.
   */
  function wireNavMenu() {
    if (document.documentElement.dataset.navMenuWired === "1") return;
    document.documentElement.dataset.navMenuWired = "1";

    // One shared backdrop for the page (created once).
    var backdrop = document.querySelector(".nav-menu-backdrop");
    if (!backdrop) {
      backdrop = document.createElement("button");
      backdrop.type = "button";
      backdrop.className = "nav-menu-backdrop";
      backdrop.setAttribute("aria-label", "Close menu");
      backdrop.tabIndex = -1;
      document.body.appendChild(backdrop);
    }
    backdrop.addEventListener("click", function () {
      closeNavMenu();
    });

    document.querySelectorAll("[data-nav-menu-toggle]").forEach(function (btn) {
      if (btn.dataset.menuBound === "1") return;
      btn.dataset.menuBound = "1";
      btn.addEventListener("click", function (e) {
        e.preventDefault();
        e.stopPropagation();
        var open = !document.body.classList.contains("nav-menu-open");
        setNavMenuOpen(open);
      });
    });

    // Close when choosing a destination (logout keeps menu until confirm resolves).
    document.querySelectorAll("nav.links a[href]").forEach(function (a) {
      if (a.dataset.navCloseBound === "1") return;
      a.dataset.navCloseBound = "1";
      a.addEventListener("click", function () {
        closeNavMenu();
      });
    });

    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && document.body.classList.contains("nav-menu-open")) {
        closeNavMenu();
      }
    });

    // Desktop resize: never leave body stuck in open-menu mode.
    var mq = window.matchMedia ? window.matchMedia("(max-width: 640px)") : null;
    function onViewport() {
      if (mq && !mq.matches) closeNavMenu();
    }
    if (mq) {
      if (typeof mq.addEventListener === "function") mq.addEventListener("change", onViewport);
      else if (typeof mq.addListener === "function") mq.addListener(onViewport);
    }
  }

  function paintNav(user) {
    const auth = document.querySelectorAll("[data-nav-auth]");
    const email = document.querySelectorAll("[data-nav-email]");
    auth.forEach((el) => show(el, !!user));
    const nextEmail = user && user.email ? user.email : "";
    email.forEach((el) => {
      // Avoid needless textContent writes (can reflow the bar).
      if (el.textContent !== nextEmail) el.textContent = nextEmail;
    });
    cacheNavEmail(nextEmail || null);
    // Brand logo → /dashboard only when signed in (guests must not hit login via logo).
    document.querySelectorAll("header.app a.brand").forEach((el) => {
      if (user) {
        if (el.getAttribute("href") !== "/dashboard") el.setAttribute("href", "/dashboard");
        el.removeAttribute("aria-disabled");
        el.classList.remove("brand-inert");
        el.removeAttribute("tabindex");
      } else {
        el.setAttribute("href", "#");
        el.setAttribute("aria-disabled", "true");
        el.classList.add("brand-inert");
        el.setAttribute("tabindex", "-1");
      }
      if (el.dataset.brandBound === "1") return;
      el.dataset.brandBound = "1";
      el.addEventListener("click", (e) => {
        if (el.classList.contains("brand-inert") || el.getAttribute("aria-disabled") === "true") {
          e.preventDefault();
        }
      });
    });
    // Wire any logout controls once.
    document.querySelectorAll("[data-logout]").forEach((el) => {
      if (el.dataset.logoutBound === "1") return;
      el.dataset.logoutBound = "1";
      el.addEventListener("click", (e) => {
        e.preventDefault();
        closeNavMenu();
        // In-page confirm (same modal as dashboard delete) — not window.confirm
        // (unreliable on iOS after async work / outside a tight user gesture).
        void (async function () {
          const ok = await confirmDialog({
            title: "Log out",
            message: "Log out of this account?",
            confirmLabel: "Log out",
            cancelLabel: "Cancel",
          });
          if (!ok) return;
          await doLogout();
        })();
      });
    });
    wireNavMenu();
  }

  /**
   * End server session, clear user data key, go home.
   */
  async function doLogout() {
    try {
      await SenditApi.logout();
    } catch {
      // Still clear local state even if the network call fails.
    }
    if (global.SenditUserDataKey && typeof global.SenditUserDataKey.clearUserDataKey === "function") {
      global.SenditUserDataKey.clearUserDataKey();
    }
    cacheNavEmail(null);
    location.assign("/login");
  }

  function formatWhen(iso) {
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  }

  /**
   * Copy text to clipboard (iOS Safari + desktop).
   *
   * Collect / send links include a long <code>#sk=…</code> fragment. iOS is picky:
   * - Clipboard API (writeText) is preferred on HTTPS and must start in the gesture turn.
   * - On touch, also run execCommand in the same turn as a belt-and-braces path while
   *   user-activation is still live (writeText may reject after the keyboard dismisses).
   * - execCommand uses a real off-screen textarea (clipboard.js recipe); tiny/opacity-0
   *   nodes often return true without writing the pasteboard.
   * Always copies the full string including <code>#</code> and everything after it.
   */
  function copyText(text) {
    var value = text == null ? "" : String(text);
    if (!value) {
      return Promise.reject(new Error("Nothing to copy."));
    }

    var canAsync =
      typeof navigator !== "undefined" &&
      navigator.clipboard &&
      typeof navigator.clipboard.writeText === "function" &&
      (typeof window.isSecureContext === "undefined" || window.isSecureContext);

    var touchUi =
      typeof window.matchMedia === "function" &&
      window.matchMedia("(hover: none), (pointer: coarse)").matches;

    if (canAsync) {
      // Must start writeText synchronously from the tap/click handler (user activation).
      var writePromise = navigator.clipboard.writeText(value);
      // Touch: also try sync copy in this same turn (password-field keyboard / focus
      // often makes writeText reject after a microtask on iOS).
      var syncOk = false;
      if (touchUi) {
        try {
          syncOk = tryCopyViaExecCommand(value);
        } catch {
          syncOk = false;
        }
      }
      return writePromise.then(
        function () {
          /* writeText succeeded — full URL including #sk= is on the pasteboard */
        },
        function () {
          if (syncOk || tryCopyViaExecCommand(value)) return;
          throw new Error("Could not copy to clipboard.");
        }
      );
    }

    if (tryCopyViaExecCommand(value)) {
      return Promise.resolve();
    }
    return Promise.reject(new Error("Could not copy to clipboard."));
  }

  /**
   * Synchronous copy via temporary textarea + execCommand (clipboard.js-style).
   * Works for long strings and URLs that contain <code>#sk=…</code> on iOS.
   * @returns {boolean}
   */
  function tryCopyViaExecCommand(text) {
    var isRTL =
      document.documentElement &&
      document.documentElement.getAttribute("dir") === "rtl";
    var ta = document.createElement("textarea");
    // Prevent iOS zoom on focus
    ta.style.fontSize = "12pt";
    ta.style.border = "0";
    ta.style.padding = "0";
    ta.style.margin = "0";
    ta.style.position = "absolute";
    ta.style[isRTL ? "right" : "left"] = "-9999px";
    var y =
      (typeof window.pageYOffset === "number"
        ? window.pageYOffset
        : 0) ||
      (document.documentElement && document.documentElement.scrollTop) ||
      0;
    ta.style.top = y + "px";
    ta.setAttribute("readonly", "");
    ta.setAttribute("aria-hidden", "true");
    ta.value = text;
    // Ensure full value is present (some WebKits truncate value on assign for huge
    // strings when node is not in the document yet — set again after append).
    document.body.appendChild(ta);
    ta.value = text;

    var ok = false;
    try {
      ta.focus();
      ta.select();
      // iOS: setSelectionRange is required; use a large end so the full #sk= is covered.
      if (typeof ta.setSelectionRange === "function") {
        ta.setSelectionRange(0, text.length);
      }
      ok = document.execCommand("copy");
      // Some iOS builds return true without copying the full selection — retry once
      // with an explicit range if the value is long (fragment links).
      if (ok && text.length > 80) {
        try {
          var range = document.createRange();
          range.selectNodeContents(ta);
          var sel = window.getSelection && window.getSelection();
          if (sel) {
            sel.removeAllRanges();
            sel.addRange(range);
          }
          if (typeof ta.setSelectionRange === "function") {
            ta.setSelectionRange(0, text.length);
          }
          ok = document.execCommand("copy");
        } catch {
          /* keep first ok */
        }
      }
    } catch {
      ok = false;
    }

    try {
      document.body.removeChild(ta);
    } catch {
      /* ignore */
    }
    try {
      var sel2 = window.getSelection && window.getSelection();
      if (sel2) sel2.removeAllRanges();
    } catch {
      /* ignore */
    }
    return !!ok;
  }

  /**
   * Wire a button to copy text. Prefer a getter (or data-copy-from) so long
   * collect/send links with #sk= are read at tap time from the live DOM.
   *
   * @param {Element|string|null} elOrSel button or CSS selector
   * @param {string|function():string} textOrFn text or getter
   * @param {{
   *   alertEl?: Element|null,
   *   okMessage?: string,
   *   copyFrom?: string|Element|null,
   *   onOk?: function():void,
   *   onErr?: function(*):void
   * }} [opts]
   *   copyFrom: optional CSS selector or element whose textContent is copied
   *   (takes precedence over textOrFn when non-empty).
   */
  function wireCopyButton(elOrSel, textOrFn, opts) {
    opts = opts || {};
    var el =
      typeof elOrSel === "string"
        ? $(elOrSel)
        : elOrSel;
    if (!el) return;

    // Avoid stacking listeners if the result UI is rebuilt.
    if (el.dataset.copyWired === "1") return;
    el.dataset.copyWired = "1";

    var copyInFlight = false;
    var lastSuccessAt = 0;

    function resolveText() {
      // Prefer live DOM (displayed link), then getter/string.
      var from = opts.copyFrom;
      if (from) {
        var node = typeof from === "string" ? $(from) : from;
        if (node) {
          var live =
            typeof node.value === "string" && node.value
              ? node.value
              : (node.textContent || "").trim();
          if (live) return live;
        }
      }
      return typeof textOrFn === "function" ? textOrFn() : textOrFn;
    }

    function doCopy(ev) {
      if (ev) {
        if (typeof ev.preventDefault === "function") ev.preventDefault();
        if (typeof ev.stopPropagation === "function") ev.stopPropagation();
      }
      // Allow a second gesture event to retry if the first failed (e.g. iOS
      // pointerup while the link-password keyboard was still up). Only suppress
      // the click that follows a successful pointerup.
      if (copyInFlight) return;
      var now = Date.now();
      if (now - lastSuccessAt < 450) return;

      // Dismiss soft keyboard / password focus so clipboard APIs are allowed.
      try {
        var ae = document.activeElement;
        if (ae && ae !== el && ae.blur) ae.blur();
      } catch {
        /* ignore */
      }

      var text;
      try {
        text = resolveText();
      } catch (err) {
        if (opts.alertEl)
          setAlert(opts.alertEl, "error", "Could not copy: " + ((err && err.message) || err));
        if (opts.onErr) opts.onErr(err);
        return;
      }
      if (text == null || String(text).length === 0) {
        if (opts.alertEl) setAlert(opts.alertEl, "error", "Nothing to copy.");
        return;
      }

      // Start copy in this turn — no await beforehand.
      copyInFlight = true;
      copyText(String(text)).then(
        function () {
          copyInFlight = false;
          lastSuccessAt = Date.now();
          if (opts.alertEl)
            setAlert(opts.alertEl, "ok", opts.okMessage || "Copied.");
          if (opts.onOk) opts.onOk();
        },
        function (err) {
          copyInFlight = false;
          // Last resort: select the on-page link text so the user can Copy.
          trySelectSourceForManualCopy(opts.copyFrom);
          if (opts.alertEl)
            setAlert(
              opts.alertEl,
              "error",
              "Could not copy automatically. The link is selected — use Copy in the iOS menu, or Download .txt."
            );
          if (opts.onErr) opts.onErr(err);
        }
      );
    }

    // Touch: pointerup keeps user-activation; click covers mouse/keyboard and
    // the second tap after iOS dismisses the link-password keyboard.
    el.addEventListener(
      "pointerup",
      function (ev) {
        if (ev.pointerType === "mouse" && ev.button !== 0) return;
        if (ev.pointerType === "touch" || ev.pointerType === "pen") doCopy(ev);
      },
      false
    );
    el.addEventListener("click", doCopy, false);
  }

  /**
   * Blur focused inputs (dismiss iOS keyboard). Call when revealing "link ready"
   * UI so Copy link receives a real tap instead of only dismissing the keyboard.
   */
  function blurActiveField() {
    try {
      var ae = document.activeElement;
      if (ae && ae !== document.body && ae.blur) ae.blur();
    } catch {
      /* ignore */
    }
  }

  /** Select on-page link text so the user can system-copy if clipboard APIs fail. */
  function trySelectSourceForManualCopy(copyFrom) {
    if (!copyFrom) return;
    try {
      var node = typeof copyFrom === "string" ? $(copyFrom) : copyFrom;
      if (!node) return;
      // Prefer native select on input/textarea (reliable on iOS).
      if (typeof node.select === "function") {
        node.focus();
        node.select();
        if (typeof node.setSelectionRange === "function") {
          var len =
            typeof node.value === "string"
              ? node.value.length
              : (node.textContent || "").length;
          node.setSelectionRange(0, len);
        }
        return;
      }
      var range = document.createRange();
      range.selectNodeContents(node);
      var sel = window.getSelection && window.getSelection();
      if (!sel) return;
      sel.removeAllRanges();
      sel.addRange(range);
    } catch {
      /* ignore */
    }
  }

  /**
   * Trigger a text file download. Append the <a> to the document for iOS Safari.
   */
  function downloadText(filename, text) {
    const a = document.createElement("a");
    const url = URL.createObjectURL(
      new Blob([text == null ? "" : String(text)], { type: "text/plain" })
    );
    a.href = url;
    a.download = filename || "download.txt";
    a.rel = "noopener";
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    setTimeout(function () {
      try {
        document.body.removeChild(a);
      } catch {
        /* ignore */
      }
      URL.revokeObjectURL(url);
    }, 250);
  }

  function pathId() {
    // Last path segment that looks like a base64url id (fallback if ?id= missing).
    const parts = location.pathname.split("/").filter(Boolean);
    for (let i = parts.length - 1; i >= 0; i--) {
      if (/^[A-Za-z0-9_-]{16,32}$/.test(parts[i])) return parts[i];
    }
    const q = new URLSearchParams(location.search).get("id");
    return q;
  }

  /**
   * Wire Text/File radio buttons to show #panel-text or #panel-file.
   * Radios must use name="content-kind" with values "text" | "file".
   */
  /**
   * Shared send/collect create: show "Confirm link password" when the password
   * field is non-empty; require a match before create. Same UX on both pages.
   * @param {{ password?: Element|null, confirmWrap?: Element|null, confirm?: Element|null }|null} [els]
   *   Defaults to #link-password / #link-password-confirm-wrap / #link-password-confirm.
   * @returns {{ getPassword: function(): string, getConfirm: function(): string, clear: function(): void, assertMatch: function(): void }}
   */
  function wireLinkPasswordConfirm(els) {
    els = els || {};
    var passwordEl = els.password || $("#link-password");
    var confirmWrap = els.confirmWrap || $("#link-password-confirm-wrap");
    var confirmEl = els.confirm || $("#link-password-confirm");

    function sync() {
      var hasPw = !!(passwordEl && passwordEl.value.length > 0);
      if (confirmWrap) confirmWrap.classList.toggle("hidden", !hasPw);
      if (confirmEl) {
        if (hasPw) {
          confirmEl.setAttribute("required", "required");
          confirmEl.setAttribute("aria-required", "true");
        } else {
          confirmEl.removeAttribute("required");
          confirmEl.removeAttribute("aria-required");
          confirmEl.value = "";
        }
      }
    }

    if (passwordEl) {
      ["input", "change", "keyup", "paste", "blur"].forEach(function (ev) {
        passwordEl.addEventListener(ev, function () {
          // paste value applies after the event on some browsers
          if (ev === "paste") setTimeout(sync, 0);
          else sync();
        });
      });
      sync();
    }

    return {
      getPassword: function () {
        return (passwordEl && passwordEl.value) || "";
      },
      getConfirm: function () {
        return (confirmEl && confirmEl.value) || "";
      },
      clear: function () {
        if (passwordEl) passwordEl.value = "";
        if (confirmEl) confirmEl.value = "";
        sync();
      },
      /** Throws if password set and confirmation missing or mismatched. */
      assertMatch: function () {
        var pw = (passwordEl && passwordEl.value) || "";
        if (!pw.length) return;
        var conf = (confirmEl && confirmEl.value) || "";
        if (pw !== conf) {
          throw new Error("Link password and confirmation do not match.");
        }
      },
      sync: sync,
    };
  }

  function bindContentKindToggle(root) {
    const scope = root || document;
    const radios = scope.querySelectorAll('input[name="content-kind"]');
    const panelText = scope.querySelector("#panel-text") || $("#panel-text");
    const panelFile = scope.querySelector("#panel-file") || $("#panel-file");
    if (!radios.length || !panelText || !panelFile) return;

    function apply() {
      const selected = scope.querySelector('input[name="content-kind"]:checked');
      const kind = selected ? selected.value : "text";
      const isFile = kind === "file";
      show(panelText, !isFile);
      show(panelFile, isFile);
    }

    radios.forEach((r) => r.addEventListener("change", apply));
    apply();
    bindFilePickerName(scope);
  }

  /** Update #secret-file-name when a file is chosen. */
  function bindFilePickerName(root) {
    const scope = root || document;
    const input = scope.querySelector("#secret-file") || $("#secret-file");
    const nameEl = scope.querySelector("#secret-file-name") || $("#secret-file-name");
    if (!input || !nameEl) return;
    input.addEventListener("change", () => {
      const f = input.files && input.files[0];
      nameEl.textContent = f ? f.name : "No file chosen";
    });
  }

  /**
   * Read plaintext bytes from the Text/File UI.
   * Returns { plain, contentType, filename }.
   */
  async function readSecretInput(root) {
    const scope = root || document;
    const selected = scope.querySelector('input[name="content-kind"]:checked');
    const kind = selected ? selected.value : "text";
    const textEl = scope.querySelector("#secret-text") || $("#secret-text");
    const fileEl = scope.querySelector("#secret-file") || $("#secret-file");

    if (kind === "file") {
      const file = fileEl && fileEl.files && fileEl.files[0];
      if (!file) throw new Error("Choose a file to encrypt.");
      if (file.size > 100 * 1024 * 1024) throw new Error("File exceeds 100 MB limit.");
      const plain = new Uint8Array(await file.arrayBuffer());
      return {
        plain,
        contentType: file.type || "application/octet-stream",
        filename: file.name,
      };
    }

    const text = textEl ? textEl.value : "";
    if (!text) throw new Error("Enter a secret to encrypt.");
    if (text.length > FIELD_LIMITS.secretText) {
      throw new Error(
        "Secret text is too long (max " + FIELD_LIMITS.secretText + " characters)."
      );
    }
    return {
      plain: new TextEncoder().encode(text),
      contentType: "text/plain",
      filename: null,
    };
  }

  /** Inline SVG clipboard icon (16×16). */
  const COPY_ICON_SVG =
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>' +
    '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>' +
    "</svg>";

  const EYE_ICON_SVG =
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>' +
    '<circle cx="12" cy="12" r="3"></circle>' +
    "</svg>";

  const EYE_OFF_ICON_SVG =
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"></path>' +
    '<path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"></path>' +
    '<path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"></path>' +
    '<line x1="1" y1="1" x2="23" y2="23"></line>' +
    "</svg>";

  /**
   * Build HTML for a secret text block with toolbar (optional eye + copy).
   * Call {@link wireSecretTextBlock} after inserting into the DOM.
   * @param {string} textContainerId
   * @param {string} copyBtnId
   * @param {{ hideByDefault?: boolean, toggleBtnId?: string }} [opts]
   */
  function secretTextBlockHtml(textContainerId, copyBtnId, opts) {
    opts = opts || {};
    const toggleId = opts.toggleBtnId || "secret-reveal-btn";
    let tools =
      '<div class="secret-out-tools">' +
      (opts.hideByDefault
        ? '<button type="button" class="secret-tool-btn secret-reveal-btn" id="' +
          toggleId +
          '" title="Show secret" aria-label="Show secret" aria-pressed="false">' +
          EYE_ICON_SVG +
          "</button>"
        : "") +
      '<button type="button" class="secret-tool-btn secret-copy-btn" id="' +
      copyBtnId +
      '" title="Copy to clipboard" aria-label="Copy secret to clipboard">' +
      COPY_ICON_SVG +
      "</button>" +
      "</div>";
    return (
      '<div class="secret-out-wrap' +
      (opts.hideByDefault ? " secret-out-wrap-masked" : "") +
      '">' +
      tools +
      '<div class="secret-out" id="' +
      textContainerId +
      '"></div>' +
      "</div>"
    );
  }

  /**
   * Wire copy (+ optional eye toggle) for a secret text block.
   * Copy always uses the real plaintext, not the masked display.
   */
  function wireSecretTextBlock(textContainerId, copyBtnId, plainText, opts, alertEl) {
    opts = opts || {};
    const box = $("#" + textContainerId);
    const copyBtn = $("#" + copyBtnId);
    if (!box || !copyBtn) return;

    const hideByDefault = !!opts.hideByDefault;
    const toggleId = opts.toggleBtnId || "secret-reveal-btn";
    let visible = !hideByDefault;

    function mask(s) {
      if (!s) return "";
      // Preserve length so layout matches; use bullets for a clearer mask.
      return "•".repeat(s.length);
    }

    function paint() {
      box.textContent = visible ? plainText : mask(plainText);
      box.classList.toggle("secret-out-hidden", !visible);
      const t = $("#" + toggleId);
      if (t) {
        t.innerHTML = visible ? EYE_OFF_ICON_SVG : EYE_ICON_SVG;
        t.title = visible ? "Hide secret" : "Show secret";
        t.setAttribute("aria-label", t.title);
        t.setAttribute("aria-pressed", visible ? "true" : "false");
      }
    }
    paint();

    if (hideByDefault) {
      const t = $("#" + toggleId);
      if (t) {
        t.addEventListener("click", function () {
          visible = !visible;
          paint();
        });
      }
    }

    wireCopyButton(copyBtn, function () {
      return plainText;
    }, {
      alertEl: alertEl,
      okMessage: "Copied to clipboard.",
      onOk: function () {
        copyBtn.classList.add("copied");
        copyBtn.title = "Copied";
        setTimeout(function () {
          copyBtn.classList.remove("copied");
          copyBtn.title = "Copy to clipboard";
        }, 1500);
      },
    });
  }

  /** Shared form field limits (keep in sync with Sendit.Api FieldLimits). */
  var FIELD_LIMITS = {
    name: 256,
    password: 256,
    privateNote: 5000000,
    allowedIps: 5000000,
    secretText: 90000000,
  };
  var MAX_CIDR_INPUT = FIELD_LIMITS.allowedIps;
  var MAX_CIDR_ENTRIES = 250000;

  /**
   * Validate optional allowed IP / CIDR list for a send (mirrors server IpRestriction).
   * Comma-separated single IPs and/or CIDRs; spaces around commas are OK.
   * @returns {{ ok: true, value: string|null } | { ok: false, error: string }}
   */
  function parseAllowedCidr(input) {
    if (input == null) return { ok: true, value: null };
    var s = String(input).trim();
    if (!s) return { ok: true, value: null };
    if (s.length > MAX_CIDR_INPUT)
      return { ok: false, error: "Allowed IP/CIDR list is too long." };
    if (s.indexOf("%") >= 0)
      return { ok: false, error: "IPv6 zone identifiers are not allowed." };

    var rawParts = s.split(",");
    var parts = [];
    for (var r = 0; r < rawParts.length; r++) {
      var t = rawParts[r].trim();
      if (t) parts.push(t);
    }
    if (!parts.length) return { ok: true, value: null };
    // "*" alone or with other entries = allow any IP
    for (var w = 0; w < parts.length; w++) {
      if (parts[w] === "*") return { ok: true, value: "*" };
    }
    if (parts.length > MAX_CIDR_ENTRIES)
      return { ok: false, error: "At most " + MAX_CIDR_ENTRIES + " IP/CIDR entries are allowed." };

    var normalized = [];
    var seen = Object.create(null);
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i];
      if (/\s/.test(part))
        return { ok: false, error: "Entry " + (i + 1) + ": IP/CIDR must not contain spaces." };
      var one = parseAllowedCidrOne(part);
      if (!one.ok)
        return { ok: false, error: "Entry " + (i + 1) + ": " + one.error };
      var key = one.value.toLowerCase();
      if (!seen[key]) {
        seen[key] = true;
        normalized.push(one.value);
      }
    }
    return { ok: true, value: normalized.join(",") };
  }

  /** Validate a single IP or CIDR (no commas). */
  function parseAllowedCidrOne(s) {
    var slash = s.indexOf("/");
    if (slash < 0) {
      var hostOnly = parseStrictIp(s);
      if (!hostOnly.ok) return hostOnly;
      return { ok: true, value: hostOnly.canonical };
    }
    if (s.split("/").length !== 2)
      return { ok: false, error: "CIDR must contain exactly one '/'." };

    var hostPart = s.slice(0, slash);
    var prefixPart = s.slice(slash + 1);
    if (!hostPart || !prefixPart)
      return { ok: false, error: "CIDR must be address/prefix (e.g. 192.168.0.0/24)." };
    if (!/^\d+$/.test(prefixPart))
      return { ok: false, error: "CIDR prefix must be a decimal integer." };
    var prefix = parseInt(prefixPart, 10);
    var host = parseStrictIp(hostPart);
    if (!host.ok) return host;
    var maxPrefix = host.family === 4 ? 32 : 128;
    if (prefix < 0 || prefix > maxPrefix) {
      return {
        ok: false,
        error:
          host.family === 4
            ? "IPv4 CIDR prefix must be between 0 and 32."
            : "IPv6 CIDR prefix must be between 0 and 128.",
      };
    }
    // Accept any host within the prefix (no host-bits-zero requirement).
    return { ok: true, value: host.canonical + "/" + prefix };
  }

  function parseStrictIp(host) {
    if (host.indexOf(":") >= 0) return parseStrictIPv6(host);
    return parseStrictIPv4(host);
  }

  function parseStrictIPv4(host) {
    var parts = host.split(".");
    if (parts.length !== 4) return { ok: false, error: "Invalid IPv4 address." };
    var bytes = [];
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(parts[i])) return { ok: false, error: "Invalid IPv4 address." };
      var n = parseInt(parts[i], 10);
      if (n > 255 || String(n) !== parts[i])
        return { ok: false, error: "Invalid IPv4 address (use dotted decimal, e.g. 192.168.1.1)." };
      bytes.push(n);
    }
    return { ok: true, family: 4, bytes: bytes, canonical: bytes.join(".") };
  }

  function parseStrictIPv6(host) {
    // Reject IPv4-mapped (::ffff:1.2.3.4) and IPv4-embedded.
    if (host.indexOf(".") >= 0)
      return { ok: false, error: "Use a plain IPv4 address, not an IPv4-mapped IPv6 form." };
    if (!/^[0-9A-Fa-f:]+$/.test(host)) return { ok: false, error: "Invalid IPv6 address." };
    var dbl = host.indexOf("::");
    if (dbl !== host.lastIndexOf("::")) return { ok: false, error: "Invalid IPv6 address." };

    var head;
    var tail;
    if (dbl >= 0) {
      head = host.slice(0, dbl) ? host.slice(0, dbl).split(":") : [];
      tail = host.slice(dbl + 2) ? host.slice(dbl + 2).split(":") : [];
    } else {
      head = host.split(":");
      tail = [];
    }
    if (head.length + tail.length > 8) return { ok: false, error: "Invalid IPv6 address." };
    if (dbl < 0 && head.length !== 8) return { ok: false, error: "Invalid IPv6 address." };
    var mid = dbl >= 0 ? 8 - head.length - tail.length : 0;
    if (dbl >= 0 && mid <= 0 && !(head.length + tail.length < 8))
      return { ok: false, error: "Invalid IPv6 address." };

    var groups = [];
    function pushGroup(g) {
      if (!g || !/^[0-9A-Fa-f]{1,4}$/.test(g)) return false;
      groups.push(parseInt(g, 16));
      return true;
    }
    for (var i = 0; i < head.length; i++) if (!pushGroup(head[i])) return { ok: false, error: "Invalid IPv6 address." };
    for (var z = 0; z < mid; z++) groups.push(0);
    for (var j = 0; j < tail.length; j++) if (!pushGroup(tail[j])) return { ok: false, error: "Invalid IPv6 address." };
    if (groups.length !== 8) return { ok: false, error: "Invalid IPv6 address." };

    var bytes = [];
    for (var g = 0; g < 8; g++) {
      bytes.push((groups[g] >> 8) & 0xff);
      bytes.push(groups[g] & 0xff);
    }
    return { ok: true, family: 6, bytes: bytes, canonical: compressIPv6(groups) };
  }

  function compressIPv6(groups) {
    // Find longest zero run for ::
    var bestStart = -1;
    var bestLen = 0;
    var i = 0;
    while (i < 8) {
      if (groups[i] !== 0) {
        i++;
        continue;
      }
      var j = i;
      while (j < 8 && groups[j] === 0) j++;
      var len = j - i;
      if (len > bestLen) {
        bestStart = i;
        bestLen = len;
      }
      i = j;
    }
    var parts = [];
    i = 0;
    while (i < 8) {
      if (bestLen >= 2 && i === bestStart) {
        parts.push("");
        if (i === 0) parts.push("");
        i += bestLen;
        if (i >= 8) parts.push("");
        continue;
      }
      parts.push(groups[i].toString(16));
      i++;
    }
    return parts.join(":").replace(/^:$/, "::");
  }

  /**
   * OTP codes: strip spaces and non-digits; cap length (6 email OTP, 8 TOTP).
   */
  function normalizeOtpCode(raw, maxLen) {
    const n = maxLen > 0 ? maxLen | 0 : 8;
    return String(raw == null ? "" : raw).replace(/\D/g, "").slice(0, n);
  }

  /** TOTP: 8 digits. */
  function normalizeTotpCode(raw) {
    return normalizeOtpCode(raw, 8);
  }

  /**
   * Restrict OTP inputs to digits only (live filter on input/paste/blur).
   * @param {string|Element|Array|NodeList} targets
   * @param {number} [digitCount=8] 6 for email OTP, 8 for authenticator TOTP
   */
  function bindOtpCodeInputs(targets, digitCount) {
    const digits = digitCount > 0 ? digitCount | 0 : 8;
    const list = [];
    const arr =
      typeof targets === "string" || (targets && targets.nodeType === 1)
        ? [targets]
        : targets
          ? Array.prototype.slice.call(targets)
          : [];
    arr.forEach(function (t) {
      if (!t) return;
      if (typeof t === "string") {
        document.querySelectorAll(t).forEach(function (el) {
          list.push(el);
        });
      } else if (t.nodeType === 1) {
        list.push(t);
      }
    });
    list.forEach(function (el) {
      if (!el || el.dataset.otpDigitsBound === "1") return;
      el.dataset.otpDigitsBound = "1";
      el.classList.add("otp-code-input");
      el.setAttribute("inputmode", "numeric");
      el.setAttribute("autocomplete", "one-time-code");
      el.setAttribute("pattern", "[0-9]{" + digits + "}");
      el.setAttribute("minlength", String(digits));
      el.setAttribute("maxlength", String(digits));
      el.setAttribute("autocapitalize", "off");
      el.setAttribute("autocorrect", "off");
      el.setAttribute("spellcheck", "false");
      function sanitize() {
        const next = normalizeOtpCode(el.value, digits);
        if (el.value !== next) el.value = next;
      }
      el.addEventListener("input", sanitize);
      el.addEventListener("blur", sanitize);
      el.addEventListener("paste", function () {
        setTimeout(sanitize, 0);
      });
    });
  }

  /**
   * In-page confirm (replaces window.confirm / window.prompt). Prefer this on iOS:
   * async click/submit handlers lose the user-gesture for native dialogs and appear
   * to do nothing.
   *
   * @param {{
   *   title?: string,
   *   message?: string,
   *   confirmLabel?: string,
   *   cancelLabel?: string,
   *   danger?: boolean,
   *   requireText?: string,
   *   inputLabel?: string,
   *   inputPlaceholder?: string
   * }} [opts]
   *   requireText: if set, user must type this exact string to enable Confirm
   *   (replaces window.prompt for "type CHANGE to confirm" flows).
   * @returns {Promise<boolean>}
   */
  function confirmDialog(opts) {
    opts = opts || {};
    return new Promise(function (resolve) {
      const prev = document.getElementById("sendit-confirm-modal");
      if (prev) prev.remove();

      const requireText =
        opts.requireText != null && String(opts.requireText).length > 0
          ? String(opts.requireText)
          : null;

      const overlay = document.createElement("div");
      overlay.id = "sendit-confirm-modal";
      overlay.className = "pw-modal-overlay";
      overlay.setAttribute("role", "dialog");
      overlay.setAttribute("aria-modal", "true");
      overlay.setAttribute("aria-label", opts.title || "Confirm");

      const card = document.createElement("div");
      card.className = "pw-modal-card";

      const title = document.createElement("h2");
      title.className = "pw-modal-title";
      title.textContent = opts.title || "Confirm";

      const msg = document.createElement("p");
      msg.className = "pw-modal-msg";
      msg.style.whiteSpace = "pre-wrap";
      msg.textContent = opts.message || "Are you sure?";

      let input = null;
      let form = null;
      if (requireText) {
        form = document.createElement("form");
        form.className = "pw-modal-form";
        form.method = "post";
        form.action = "#";
        form.autocomplete = "off";

        const label = document.createElement("label");
        label.setAttribute("for", "sendit-confirm-input");
        label.textContent = opts.inputLabel || "Type " + requireText + " to confirm";

        input = document.createElement("input");
        input.id = "sendit-confirm-input";
        input.type = "text";
        input.name = "confirm-text";
        input.autocomplete = "off";
        input.autocapitalize = "characters";
        input.spellcheck = false;
        input.required = true;
        if (opts.inputPlaceholder) input.placeholder = opts.inputPlaceholder;
        else input.placeholder = requireText;

        form.appendChild(label);
        form.appendChild(input);
      }

      const actions = document.createElement("div");
      actions.className = "pw-modal-actions";

      // Same classes as dashboard New send / New collect (btn + optional secondary/danger).
      const cancelBtn = document.createElement("button");
      cancelBtn.type = "button";
      cancelBtn.className = "btn secondary";
      cancelBtn.textContent = opts.cancelLabel || "Cancel";

      const okBtn = document.createElement("button");
      okBtn.type = requireText ? "submit" : "button";
      okBtn.className = opts.danger ? "btn danger" : "btn";
      okBtn.textContent = opts.confirmLabel || "OK";

      function setOkBusy(busy) {
        if (typeof setButtonBusy === "function" && isPrimaryGoldButton(okBtn)) {
          setButtonBusy(okBtn, !!busy);
        } else {
          okBtn.disabled = !!busy;
        }
      }

      function setModalButtonsBusy(busy) {
        setOkBusy(busy);
        // Secondary Cancel: native disabled (outline button, no gold text-grey issue).
        cancelBtn.disabled = !!busy;
        if (busy) cancelBtn.setAttribute("aria-disabled", "true");
        else cancelBtn.removeAttribute("aria-disabled");
      }

      if (requireText) setOkBusy(true);

      function cleanup(result) {
        document.removeEventListener("keydown", onKey);
        if (input) input.value = "";
        overlay.remove();
        resolve(!!result);
      }

      function syncRequire() {
        if (!requireText || !input) return;
        setOkBusy(input.value.trim() !== requireText);
      }

      function tryConfirm() {
        if (requireText) {
          if (!input || input.value.trim() !== requireText) return;
        }
        // Dim both actions like New send while the dialog closes / caller runs work.
        setModalButtonsBusy(true);
        cleanup(true);
      }

      function onKey(ev) {
        if (ev.key === "Escape") {
          ev.preventDefault();
          if (cancelBtn.disabled) return;
          cleanup(false);
        }
      }

      cancelBtn.addEventListener("click", function () {
        if (cancelBtn.disabled) return;
        cleanup(false);
      });
      if (!requireText) {
        okBtn.addEventListener("click", function () {
          if (
            okBtn.disabled ||
            okBtn.getAttribute("aria-disabled") === "true" ||
            okBtn.classList.contains("ui-busy")
          ) {
            return;
          }
          tryConfirm();
        });
      } else if (form && input) {
        input.addEventListener("input", syncRequire);
        form.addEventListener("submit", function (ev) {
          ev.preventDefault();
          if (
            okBtn.disabled ||
            okBtn.getAttribute("aria-disabled") === "true" ||
            okBtn.classList.contains("ui-busy")
          ) {
            return;
          }
          tryConfirm();
        });
      }
      overlay.addEventListener("click", function (ev) {
        if (ev.target === overlay) cleanup(false);
      });
      document.addEventListener("keydown", onKey);

      actions.appendChild(cancelBtn);
      actions.appendChild(okBtn);
      card.appendChild(title);
      card.appendChild(msg);
      if (form) {
        form.appendChild(actions);
        card.appendChild(form);
      } else {
        card.appendChild(actions);
      }
      overlay.appendChild(card);
      document.body.appendChild(overlay);
      setTimeout(function () {
        try {
          if (input) input.focus();
          else okBtn.focus();
        } catch {
          /* ignore */
        }
      }, 0);
    });
  }

  /** True while the API-unreachable dialog is open (avoid stacking). */
  var apiUnreachableModalOpen = false;

  /**
   * Modal when the API cannot be reached (confirmed network/gateway failure).
   * SenditApi only opens this after a delayed /health probe fails, so rapid taps
   * and nginx rate limits (429) do not false-trigger it.
   * Same chrome as logout / confirm dialogs.
   */
  function notifyApiUnreachable() {
    if (apiUnreachableModalOpen) return;
    if (document.getElementById("sendit-api-unreachable-modal")) return;
    apiUnreachableModalOpen = true;

    const overlay = document.createElement("div");
    overlay.id = "sendit-api-unreachable-modal";
    overlay.className = "pw-modal-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-label", "API Uncontactable");

    const card = document.createElement("div");
    card.className = "pw-modal-card";

    const title = document.createElement("h2");
    title.className = "pw-modal-title";
    title.textContent = "API Uncontactable";

    const msg = document.createElement("p");
    msg.className = "pw-modal-msg";
    msg.style.whiteSpace = "pre-wrap";
    msg.textContent =
      "Sendit! could not reach the API. The service may be down, restarting, or your connection may be interrupted.\n\n" +
      "Use Retry when the API is back.";

    const status = document.createElement("p");
    status.className = "pw-modal-msg";
    status.style.marginTop = "0.5rem";
    status.style.minHeight = "1.25em";
    status.textContent = "";

    const actions = document.createElement("div");
    actions.className = "pw-modal-actions";

    const retryBtn = document.createElement("button");
    retryBtn.type = "button";
    retryBtn.className = "btn";
    retryBtn.textContent = "Retry";

    function cleanup() {
      overlay.remove();
      apiUnreachableModalOpen = false;
    }

    // Focus for keyboard Enter without the UA blue :focus ring (focusVisible: false).
    function focusRetryQuiet() {
      try {
        retryBtn.focus({ preventScroll: true, focusVisible: false });
      } catch {
        try {
          retryBtn.focus();
        } catch {
          /* ignore */
        }
      }
    }

    // No Dismiss / Escape / overlay click — only a successful Retry (health + reload) closes.
    retryBtn.addEventListener("click", function () {
      void (async function () {
        if (
          retryBtn.disabled ||
          retryBtn.getAttribute("aria-disabled") === "true" ||
          retryBtn.classList.contains("ui-busy")
        ) {
          return;
        }
        // Same busy path as New send / confirm primary (no iOS grey :disabled text).
        setButtonBusy(retryBtn, true);
        status.textContent = "Checking API…";
        try {
          if (global.SenditApi && typeof global.SenditApi.health === "function") {
            await global.SenditApi.health();
          } else {
            const res = await fetch("/api/v1/health", {
              credentials: "same-origin",
              headers: { Accept: "application/json" },
            });
            if (!res.ok) throw new Error("HTTP " + res.status);
          }
          cleanup();
          // Reload so pages re-fetch /me, branding, and clear stale error UI.
          location.reload();
        } catch {
          status.textContent = "Still unreachable. Try again in a moment.";
          setButtonBusy(retryBtn, false);
          focusRetryQuiet();
        }
      })();
    });

    actions.appendChild(retryBtn);
    card.appendChild(title);
    card.appendChild(msg);
    card.appendChild(status);
    card.appendChild(actions);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
    setTimeout(focusRetryQuiet, 0);
  }

  /**
   * Blocking progress modal (dims the page). Use for large encrypt + upload jobs.
   * @returns {{ setStatus: function(string): void, setProgress: function(number|null): void, close: function(): void }}
   * setProgress(null) = indeterminate; setProgress(0..1) = determinate bar.
   */
  function showProgressModal(title) {
    const prev = document.getElementById("sendit-progress-modal");
    if (prev) prev.remove();

    const overlay = document.createElement("div");
    overlay.id = "sendit-progress-modal";
    overlay.className = "progress-modal-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-busy", "true");
    overlay.setAttribute("aria-label", title || "Working");

    const card = document.createElement("div");
    card.className = "progress-modal-card";

    const h = document.createElement("h2");
    h.className = "progress-modal-title";
    h.textContent = title || "Working…";

    const status = document.createElement("p");
    status.className = "progress-modal-status";
    status.textContent = "Please wait…";

    const track = document.createElement("div");
    track.className = "progress-bar-track";
    track.setAttribute("role", "progressbar");
    track.setAttribute("aria-valuemin", "0");
    track.setAttribute("aria-valuemax", "100");

    const fill = document.createElement("div");
    fill.className = "progress-bar-fill progress-bar-indeterminate";

    const pct = document.createElement("p");
    pct.className = "progress-modal-pct";
    pct.textContent = "";

    track.appendChild(fill);
    card.appendChild(h);
    card.appendChild(status);
    card.appendChild(track);
    card.appendChild(pct);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
    document.body.classList.add("progress-modal-open");

    return {
      setTitle: function (t) {
        h.textContent = t || "Working…";
        overlay.setAttribute("aria-label", t || "Working");
      },
      setStatus: function (msg) {
        status.textContent = msg || "";
      },
      /**
       * @param {number|null} fraction 0..1, or null for indeterminate
       */
      setProgress: function (fraction) {
        if (fraction == null || !isFinite(fraction)) {
          fill.classList.add("progress-bar-indeterminate");
          fill.style.width = "40%";
          track.removeAttribute("aria-valuenow");
          pct.textContent = "";
          return;
        }
        const f = Math.max(0, Math.min(1, fraction));
        fill.classList.remove("progress-bar-indeterminate");
        fill.style.width = Math.round(f * 100) + "%";
        track.setAttribute("aria-valuenow", String(Math.round(f * 100)));
        pct.textContent = Math.round(f * 100) + "%";
      },
      close: function () {
        overlay.remove();
        document.body.classList.remove("progress-modal-open");
      },
    };
  }

  /**
   * True for share/collect errors that mean the item is gone (404-style).
   * Matches API ShareNotFound wording.
   */
  function isShareGoneMessage(msg) {
    return /not found|already consumed|no longer available/i.test(String(msg || ""));
  }

  /**
   * Show an error; countdown-redirect to /dashboard only when the viewer is signed in.
   * Guests stay on the page (they have no dashboard).
   *
   * @param {HTMLElement|null} alertEl
   * @param {string} message
   * @param {{ hide?: function(): void, seconds?: number, user?: object|null }} [opts]
   *   opts.user — if set (including null), skip re-fetching /auth/me.
   */
  async function failMaybeDashboard(alertEl, message, opts) {
    opts = opts || {};
    if (typeof opts.hide === "function") {
      try {
        opts.hide();
      } catch {
        /* ignore */
      }
    }
    var user = opts.user;
    if (user === undefined) {
      try {
        user = await loadUser();
      } catch {
        user = null;
      }
    }
    if (!user) {
      setAlert(alertEl, "error", message);
      return;
    }
    var total = typeof opts.seconds === "number" && opts.seconds > 0 ? opts.seconds : 5;
    var left = total;
    function paint() {
      setAlert(
        alertEl,
        "error",
        message + " Redirecting to dashboard in " + left + "s…"
      );
    }
    paint();
    var timer = setInterval(function () {
      left -= 1;
      if (left <= 0) {
        clearInterval(timer);
        location.assign("/dashboard");
        return;
      }
      paint();
    }, 1000);
  }

  global.SenditApp = {
    $,
    AppVersion: AppVersion,
    setAlert,
    scrollBelowFixedHeader,
    scheduleScrollBelowHeader,
    loadUser,
    requireAuth,
    paintNav,
    doLogout,
    formatWhen,
    copyText,
    wireCopyButton,
    blurActiveField,
    downloadText,
    pathId,
    wireLinkPasswordConfirm,
    bindContentKindToggle,
    readSecretInput,
    secretTextBlockHtml,
    wireSecretTextBlock,
    parseAllowedCidr,
    FIELD_LIMITS,
    normalizeOtpCode,
    normalizeTotpCode,
    bindOtpCodeInputs,
    showProgressModal,
    confirmDialog,
    notifyApiUnreachable,
    lockInteractive,
    setButtonBusy,
    solvePow,
    isShareGoneMessage,
    failMaybeDashboard,
  };

  /**
   * Reliable press feedback on touch (and mouse).
   * iOS Safari often never applies CSS :active on <button> unless a touch/pointer
   * listener exists; we toggle .is-pressed for the same visual as desktop click.
   */
  function wirePressFeedback() {
    var SELECTOR =
      "button, .btn, a.btn, label.file-picker-btn, .nav-menu-toggle, " +
      ".secret-tool-btn, .secret-copy-btn, .secret-reveal-btn";

    function clearAll() {
      document.querySelectorAll(".is-pressed").forEach(function (el) {
        el.classList.remove("is-pressed");
      });
    }

    function targetFromEvent(ev) {
      var t = ev.target;
      if (!t || !t.closest) return null;
      var el = t.closest(SELECTOR);
      if (!el) return null;
      if (el.disabled || el.getAttribute("aria-disabled") === "true") return null;
      if (el.classList.contains("ui-locked") || el.classList.contains("ui-busy")) return null;
      return el;
    }

    document.addEventListener(
      "pointerdown",
      function (ev) {
        // Primary button / touch / pen only
        if (ev.pointerType === "mouse" && ev.button !== 0) return;
        var el = targetFromEvent(ev);
        if (!el) return;
        el.classList.add("is-pressed");
      },
      true
    );

    document.addEventListener("pointerup", clearAll, true);
    document.addEventListener("pointercancel", clearAll, true);
    document.addEventListener(
      "pointerleave",
      function (ev) {
        var el = targetFromEvent(ev);
        if (el) el.classList.remove("is-pressed");
      },
      true
    );
    // If the finger scrolls away without pointerup on the button
    document.addEventListener(
      "touchmove",
      function () {
        clearAll();
      },
      { passive: true, capture: true }
    );
    window.addEventListener("blur", clearAll);
  }

  // Instant nav paint on every page (before page scripts await /auth/me).
  paintNavFromCache();
  wireNavMenu();
  wirePressFeedback();

  // api.js may have failed before this file defined the modal handler.
  try {
    if (
      global.SenditApi &&
      typeof global.SenditApi.consumePendingApiUnreachable === "function" &&
      global.SenditApi.consumePendingApiUnreachable()
    ) {
      notifyApiUnreachable();
    }
  } catch {
    /* ignore */
  }
})(typeof window !== "undefined" ? window : globalThis);
