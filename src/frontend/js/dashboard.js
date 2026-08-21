/**
 * Dashboard: list sends/collects as responsive cards (no horizontal scroll)
 * and poll for status changes every 5 seconds.
 */
(async function () {
  const {
    $,
    setAlert,
    requireAuth,
    paintNav,
    formatWhen,
    wireCopyButton,
    confirmDialog,
    setButtonBusy,
    scrollBelowFixedHeader,
  } = SenditApp;
  const alertEl = $("#alert");
  const listEl = $("#items-list");

  const user = await requireAuth();
  if (!user) {
    // requireAuth navigates to /login; avoid leaving "Loading…" if navigation is slow (iOS).
    if (listEl) {
      listEl.innerHTML = '<div class="dash-empty">Redirecting to sign in…</div>';
    }
    return;
  }
  paintNav(user);
  const POLL_MS = 5000;
  const PAGE_SIZE = 100;
  /** px from bottom of document before loading the next page */
  const LOAD_MORE_THRESHOLD_PX = 480;
  /** Max older pages to fetch when resolving ?focus= from the audit log. */
  const FOCUS_MAX_APPENDS = 30;

  /** @type {string} last rendered status fingerprint to avoid useless DOM thrash */
  let lastFingerprint = "";
  let pollTimer = null;
  let refreshInFlight = false;
  /** True once UDK is available in this tab (sessionStorage or unlock prompt). */
  let udkReady = false;

  /** Accumulated items currently shown (newest → older via infinite scroll). */
  let loadedItems = [];
  let hasMore = false;
  let loadingMore = false;
  /** Focus target from /dashboard?focus=… (audit → dashboard deep link). */
  let focusId = "";
  let focusDone = false;
  try {
    focusId = (new URLSearchParams(location.search).get("focus") || "").trim();
  } catch {
    focusId = "";
  }

  /**
   * New send / New collect are real <button>s (same control type as Reveal secret)
   * so setButtonBusy / :disabled / .ui-busy paint identically. Busy is applied
   * before navigation, with a double-rAF so iOS flushes the disabled look first.
   */
  function wireDashNavButtons() {
    document.querySelectorAll(".actions-dash button.btn[data-nav]").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.preventDefault();
        if (
          btn.dataset.navPending === "1" ||
          btn.disabled ||
          btn.getAttribute("aria-disabled") === "true" ||
          btn.classList.contains("ui-busy")
        ) {
          return;
        }
        var href = btn.getAttribute("data-nav");
        if (!href) return;
        btn.dataset.navPending = "1";
        if (typeof setButtonBusy === "function") {
          setButtonBusy(btn, true);
        } else {
          btn.disabled = true;
        }
        // Two frames: first applies busy styles, second navigates (iOS often
        // skips a single paint if location changes in the same turn as the click).
        requestAnimationFrame(function () {
          requestAnimationFrame(function () {
            location.assign(href);
          });
        });
      });
    });

    // bfcache restore (iOS/Safari): clear busy if user navigates back.
    window.addEventListener("pageshow", function (ev) {
      if (!ev.persisted) return;
      document.querySelectorAll(".actions-dash button.btn[data-nav]").forEach(function (btn) {
        delete btn.dataset.navPending;
        if (typeof setButtonBusy === "function") setButtonBusy(btn, false);
        else btn.disabled = false;
      });
    });
  }
  wireDashNavButtons();

  function escape(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function fingerprint(items) {
    return (items || [])
      .map(function (i) {
        return [
          i.id,
          i.kind,
          i.status,
          i.expiresAt,
          i.label || "",
          !!i.collectSecretKeyCiphertext,
          i.accessCount || 0,
          i.maxAccessCount || "",
          i.privateNoteCiphertext || "",
          !!i.passwordProtected,
          !!i.ipRestricted,
        ].join(":");
      })
      .join("|");
  }

  /**
   * Owner labels/notes are base64url(iv‖AES-GCM). Short names still produce ~40+ char
   * strings — never treat those as legacy plaintext.
   */
  function looksLikeUdKCiphertext(s) {
    if (!s || typeof s !== "string") return false;
    if (s.length < 40) return false;
    return /^[A-Za-z0-9_-]+$/.test(s);
  }

  /** First owner ciphertext we can use to verify a stored UDK. */
  function firstOwnerCiphertext(items) {
    for (let n = 0; n < items.length; n++) {
      const i = items[n];
      if (i.privateNoteCiphertext) return i.privateNoteCiphertext;
      if (i.collectSecretKeyCiphertext) return i.collectSecretKeyCiphertext;
      if (i.label && looksLikeUdKCiphertext(i.label)) return i.label;
    }
    return null;
  }

  /**
   * Ensure UDK is unlocked for this tab.
   * - If sessionStorage has a key, verify it against a real ciphertext (stale keys are cleared).
   * - Otherwise (or after clear) prompt for account password via requireUserDataKey.
   */
  async function ensureDashboardUdk(items) {
    if (udkReady) return true;
    if (typeof SenditUserDataKey === "undefined") {
      setAlert(alertEl, "error", "Encryption module failed to load. Hard-refresh the page.");
      return false;
    }

    const sample = firstOwnerCiphertext(items || []);

    async function storedKeyWorks() {
      const k = SenditUserDataKey.loadUserDataKey();
      if (!k) return false;
      if (!sample) return true; // nothing to verify against
      try {
        await SenditUserDataKey.decryptWithUserDataKey(sample, k);
        return true;
      } catch {
        // Stale/wrong UDK in sessionStorage — force a fresh unlock prompt.
        SenditUserDataKey.clearUserDataKey();
        return false;
      }
    }

    if (await storedKeyWorks()) {
      udkReady = true;
      return true;
    }

    try {
      // force:true so we always show the password modal after a failed/stale key.
      await SenditUserDataKey.requireUserDataKey({ force: true });
      if (sample) {
        const k = SenditUserDataKey.loadUserDataKey();
        if (!k) throw new Error("Unlock failed.");
        await SenditUserDataKey.decryptWithUserDataKey(sample, k);
      }
      udkReady = true;
      setAlert(alertEl, null, null);
      return true;
    } catch (err) {
      udkReady = false;
      setAlert(
        alertEl,
        "warn",
        (err && err.message) ||
          "Unlock encryption with your account password to view names and private notes."
      );
      return false;
    }
  }

  /** Decrypt UDK-wrapped owner field (send name or private note). */
  async function decryptOwnerField(cipherB64) {
    if (!cipherB64 || typeof SenditUserDataKey === "undefined") return null;
    try {
      const bytes = await SenditUserDataKey.decryptWithUserDataKey(cipherB64);
      return new TextDecoder().decode(bytes);
    } catch {
      return null;
    }
  }

  /**
   * Resolve display title: UDK-decrypt label for sends and collects when possible.
   * Legacy rows may still have short plaintext labels (not base64url ciphertext).
   */
  async function resolveOwnerTitle(item) {
    if (!item.label) return "";
    if (udkReady) {
      const dec = await decryptOwnerField(item.label);
      if (dec != null) return dec;
    }
    // Only treat as legacy plaintext when it does not look like UDK ciphertext.
    if (!looksLikeUdKCiphertext(item.label)) return item.label;
    return null;
  }

  function setListMessage(text) {
    listEl.innerHTML =
      '<div class="dash-empty">' + escape(text || "No sends or collects yet.") + "</div>";
  }

  /**
   * Paint cards. Renders immediately (even if names are locked), then optionally
   * unlocks UDK and re-paints — never leaves the list stuck on "Loading…".
   */
  async function renderItems(items) {
    if (!items.length) {
      setListMessage("No sends or collects yet.");
      return;
    }

    const needsUdk = items.some(function (i) {
      return !!(i.label || i.privateNoteCiphertext || i.collectSecretKeyCiphertext);
    });

    // First paint right away so iOS never sits on "Loading…" while the unlock modal is up.
    await paintItemCards(items);

    if (needsUdk && !udkReady) {
      try {
        const ok = await ensureDashboardUdk(items);
        if (ok) await paintItemCards(items);
      } catch {
        // ensureDashboardUdk already sets an alert; keep locked cards visible.
      }
    }
  }

  function findCardById(id) {
    if (!id || !listEl) return null;
    const cards = listEl.querySelectorAll(".dash-item[data-id]");
    for (let i = 0; i < cards.length; i++) {
      if (cards[i].getAttribute("data-id") === id) return cards[i];
    }
    return null;
  }

  /**
   * Scroll so the card’s top sits just under the fixed nav (first fully visible
   * entry if the list is long). Does not reorder. Loads older pages until found.
   */
  async function focusDashboardItem(id) {
    if (!id || focusDone) return;
    let card = findCardById(id);
    let appends = 0;
    while (!card && hasMore && appends < FOCUS_MAX_APPENDS) {
      appends += 1;
      await refresh({ append: true });
      card = findCardById(id);
    }
    focusDone = true;
    if (!card) {
      setAlert(
        alertEl,
        "warn",
        "That item is not on your dashboard (deleted, expired, or not yours)."
      );
      return;
    }
    card.classList.add("dash-item-focus");
    if (typeof scrollBelowFixedHeader === "function") {
      scrollBelowFixedHeader(card);
      // Re-apply after layout / UDK re-paint settles.
      setTimeout(function () {
        scrollBelowFixedHeader(card);
      }, 50);
      setTimeout(function () {
        scrollBelowFixedHeader(card);
      }, 200);
    } else {
      try {
        card.scrollIntoView({ block: "start" });
      } catch {
        /* ignore */
      }
    }
    setTimeout(function () {
      card.classList.remove("dash-item-focus");
    }, 2400);
  }

  async function paintItemCards(items) {
    listEl.innerHTML = "";
    for (const item of items) {
      const card = document.createElement("article");
      card.className = "dash-item card";
      card.dataset.kind = item.kind;
      card.dataset.status = item.status;
      if (item.id) card.dataset.id = item.id;

      const isSend = item.kind === "send" || item.kind === "share";
      const isCollect = item.kind === "collect" || item.kind === "request";
      let titleText = item.label || "";
      if (item.label && (isSend || isCollect)) {
        const resolved = await resolveOwnerTitle(item);
        titleText =
          resolved == null
            ? "(unlock encryption to view name)"
            : resolved;
      }

      const mode = item.oneTime ? "one-time" : "multi";
      // Wire may still say share/request; display product terms send/collect.
      const kindLabel = isSend
        ? "send"
        : item.kind === "request" || item.kind === "collect"
          ? "collect"
          : item.kind;
      // Tooltips use “send” or “collect” to match the card type.
      const kindNoun = isCollect ? "collect" : "send";
      const modeTitle = item.oneTime
        ? "This " + kindNoun + " can only be viewed once"
        : "This " + kindNoun + " can be accessed multiple times";
      const passwordTitle =
        "This " + kindNoun + " is protected by a password";
      const ipTitle = "This " + kindNoun + " is IP address restricted";

      const head = document.createElement("div");
      head.className = "dash-item-head";
      // Title wraps freely; id chip + status sit together on the right.
      head.innerHTML =
        '<div class="dash-item-title">' +
        escape(titleText) +
        "</div>" +
        '<div class="dash-item-head-tags">' +
        // data-tooltip (not title): custom CSS tooltip at ~500ms ≈ half native delay
        '<span class="dash-chip dash-chip-id mono" data-tooltip="ID">' +
        '<span class="dash-chip-id-text">' +
        escape(item.id || "") +
        "</span></span>" +
        '<span class="badge ' +
        escape(item.status) +
        '">' +
        escape(item.status) +
        "</span>" +
        "</div>";
      card.appendChild(head);

      const meta = document.createElement("div");
      meta.className = "dash-item-meta";
      let metaHtml =
        '<span class="dash-chip">' +
        escape(kindLabel) +
        "</span>" +
        '<span class="dash-chip" data-tooltip="' +
        escape(modeTitle) +
        '">' +
        escape(mode) +
        "</span>";
      if ((isSend || isCollect) && item.passwordProtected) {
        metaHtml +=
          '<span class="dash-chip dash-chip-password" data-tooltip="' +
          escape(passwordTitle) +
          '">Password</span>';
      }
      if ((isSend || isCollect) && item.ipRestricted) {
        metaHtml +=
          '<span class="dash-chip dash-chip-ip" data-tooltip="' +
          escape(ipTitle) +
          '">IP</span>';
      }
      if (
        (item.kind === "send" ||
          item.kind === "share" ||
          item.kind === "collect" ||
          item.kind === "request") &&
        !item.oneTime
      ) {
        const acc = item.accessCount || 0;
        if (item.maxAccessCount != null && item.maxAccessCount !== "") {
          metaHtml +=
            '<span class="dash-chip dash-chip-access">' +
            escape(String(acc) + "/" + item.maxAccessCount + " opens") +
            "</span>";
        } else if (acc > 0) {
          metaHtml +=
            '<span class="dash-chip dash-chip-access">' +
            escape(String(acc) + (acc === 1 ? " open" : " opens")) +
            "</span>";
        }
      }
      metaHtml +=
        '<span class="dash-meta-expires">Expires ' +
        escape(formatWhen(item.expiresAt)) +
        "</span>";
      meta.innerHTML = metaHtml;
      card.appendChild(meta);

      if ((isSend || isCollect) && item.privateNoteCiphertext) {
        const noteEl = document.createElement("div");
        noteEl.className = "dash-private-note";
        const labelHtml =
          '<span class="dash-private-note-label">Private note:</span> ';
        if (!udkReady) {
          noteEl.innerHTML =
            labelHtml +
            escape("(unlock encryption with your account password)");
          noteEl.classList.add("dash-private-note-error");
        } else {
          noteEl.innerHTML = labelHtml + "…";
          decryptOwnerField(item.privateNoteCiphertext).then(function (text) {
            if (text == null) {
              noteEl.innerHTML =
                labelHtml +
                escape(
                  "(could not decrypt — unlock encryption with your password)"
                );
              noteEl.classList.add("dash-private-note-error");
            } else {
              noteEl.innerHTML = labelHtml + escape(text);
            }
          });
        }
        card.appendChild(noteEl);
      }

      const actions = document.createElement("div");
      actions.className = "dash-item-actions";

      // Collect button for collect items that still have an owner key (only when ready).
      if (
        (item.kind === "request" || item.kind === "collect") &&
        item.collectSecretKeyCiphertext
      ) {
        const canCollect = item.status === "ready";
        const isDisabled = !canCollect;

        const openCollect = async () => {
          if (!canCollect) return;
          try {
            const plain = await SenditUserDataKey.decryptWithUserDataKey(
              item.collectSecretKeyCiphertext
            );
            let fragment;
            if (item.passwordProtected) {
              // Stored blob is UTF-8 JSON password-wrap package (same as link #sk).
              const pkgJson = new TextDecoder().decode(plain);
              fragment = SenditCrypto.buildPasswordProtectedFragment(pkgJson);
            } else if (plain.length === 32) {
              fragment = SenditCrypto.buildFragment(plain);
            } else {
              // Legacy / unexpected length — try as raw key material anyway.
              fragment = "#sk=" + SenditCrypto.b64urlEncode(plain);
            }
            plain.fill(0);
            const collectUrl =
              location.origin +
              "/collect?id=" +
              encodeURIComponent(item.id) +
              fragment;
            // Same-tab navigation: iOS Safari blocks window.open() after async work
            // (decrypt / password unlock), so a new-tab open appears to do nothing.
            location.assign(collectUrl);
          } catch (err) {
            setAlert(
              alertEl,
              "error",
              err.message ||
                "Could not open collect link. Log in again if your session key was cleared."
            );
          }
        };

        const collectBtn = document.createElement("button");
        collectBtn.type = "button";
        collectBtn.className = "secondary";
        collectBtn.textContent = "Collect";
        collectBtn.disabled = isDisabled;
        if (item.status === "pending") {
          collectBtn.title = "Waiting for upload";
        } else if (item.status === "consumed") {
          collectBtn.title = "Already collected (will be removed when purged)";
        } else if (item.status === "expired") {
          collectBtn.title = "Expired (will be removed when purged)";
        } else if (canCollect) {
          collectBtn.title = "Open collect page";
        } else {
          collectBtn.title = "Not ready to collect";
        }
        collectBtn.addEventListener("click", (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          openCollect();
        });
        actions.appendChild(collectBtn);

        if (canCollect) {
          card.classList.add("dash-item-clickable");
          card.title = "Open collect page";
          card.addEventListener("click", (ev) => {
            if (ev.target.closest("button, a")) return;
            openCollect();
          });
        }
      }

      if (
        (item.kind === "request" || item.kind === "collect") &&
        item.status === "pending"
      ) {
        const upload = location.origin + "/upload?id=" + encodeURIComponent(item.id);
        const b = document.createElement("button");
        b.type = "button";
        b.className = "secondary";
        b.textContent = "Copy upload link";
        wireCopyButton(b, upload, {
          alertEl: alertEl,
          okMessage: "Upload link copied.",
        });
        actions.appendChild(b);
      }

      const del = document.createElement("button");
      del.type = "button";
      del.className = "danger";
      del.textContent = "Delete";
      // Do not use window.confirm in an async click handler — iOS Safari often
      // swallows it (same class of user-gesture issues as Collect + window.open).
      del.addEventListener("click", (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        void (async function () {
          if (typeof confirmDialog !== "function") {
            setAlert(
              alertEl,
              "error",
              "Confirmation UI failed to load. Hard-refresh the page and try again."
            );
            return;
          }
          const ok = await confirmDialog({
            title: "Delete item",
            message: "Delete this item? This cannot be undone.",
            confirmLabel: "Delete",
            cancelLabel: "Cancel",
            danger: true,
          });
          if (!ok) return;
          try {
            if (typeof setButtonBusy === "function") setButtonBusy(del, true);
            else del.disabled = true;
            if (item.kind === "share" || item.kind === "send")
              await SenditApi.secretDelete(item.id);
            else await SenditApi.requestDelete(item.id);
            await refresh({ force: true, quiet: true });
          } catch (err) {
            if (typeof setButtonBusy === "function") setButtonBusy(del, false);
            else del.disabled = false;
            setAlert(alertEl, "error", err.message || String(err));
          }
        })();
      });
      actions.appendChild(del);

      card.appendChild(actions);
      listEl.appendChild(card);
    }
  }

  function setLoadStatus(text, visible) {
    let el = document.getElementById("dash-load-status");
    if (!visible || !text) {
      if (el) {
        el.hidden = true;
        el.textContent = "";
      }
      return;
    }
    if (!el) {
      el = document.createElement("div");
      el.id = "dash-load-status";
      el.className = "dash-load-status";
      listEl.appendChild(el);
    }
    el.hidden = false;
    el.textContent = text;
  }

  function nearBottom() {
    const doc = document.documentElement;
    const scrollBottom =
      (window.scrollY || doc.scrollTop) +
      (window.innerHeight || doc.clientHeight);
    const docHeight = Math.max(doc.scrollHeight, document.body.scrollHeight);
    return docHeight - scrollBottom <= LOAD_MORE_THRESHOLD_PX;
  }

  /**
   * @param {{ force?: boolean, quiet?: boolean, append?: boolean }} [opts]
   * force: re-render even if fingerprint unchanged
   * append: load next older page (infinite scroll)
   * quiet: suppress top-level error banner on poll failures
   */
  async function refresh(opts) {
    opts = opts || {};
    if (opts.append) {
      if (loadingMore || refreshInFlight || !hasMore || !loadedItems.length)
        return;
      loadingMore = true;
      setLoadStatus("Loading more…", true);
      try {
        const last = loadedItems[loadedItems.length - 1];
        const data = await SenditApi.myItems({
          limit: PAGE_SIZE,
          beforeCreatedAt: last.createdAt,
          beforeId: last.id,
        });
        const page = data && Array.isArray(data.items) ? data.items : [];
        hasMore = !!(data && data.hasMore);
        if (page.length) {
          loadedItems = loadedItems.concat(page);
          lastFingerprint = fingerprint(loadedItems);
          await renderItems(loadedItems);
        }
        setLoadStatus(hasMore ? "" : "End of list", !hasMore);
      } catch (err) {
        setLoadStatus(
          "Could not load more: " + ((err && err.message) || String(err)),
          true
        );
      } finally {
        loadingMore = false;
      }
      return;
    }

    if (refreshInFlight) return;
    refreshInFlight = true;
    try {
      // Reload newest window covering everything already loaded (status poll / force).
      const want = Math.max(PAGE_SIZE, loadedItems.length || PAGE_SIZE);
      const data = await SenditApi.myItems({ limit: Math.min(want, 2000) });
      const items = data && Array.isArray(data.items) ? data.items : [];
      hasMore = !!(data && data.hasMore);
      // If user had scrolled past one API max page, hasMore from a top-N fetch is still correct
      // when ordered list length > want; server reports hasMore from last returned row.
      const fp = fingerprint(items);
      if (opts.force || fp !== lastFingerprint) {
        lastFingerprint = fp;
        loadedItems = items;
        await renderItems(items);
      }
      if (!items.length) {
        loadedItems = [];
        hasMore = false;
      }
    } catch (err) {
      if (!opts.quiet) {
        setAlert(alertEl, "error", err.message || String(err));
      }
      // Never leave the initial "Loading…" forever (network hang recovery / hard fail).
      const stillLoading =
        listEl &&
        listEl.querySelector(".dash-empty") &&
        /Loading|Unlocking/i.test(listEl.textContent || "");
      if (stillLoading || (listEl && !listEl.querySelector(".dash-item"))) {
        setListMessage(
          (err && err.message) || "Could not load items. Pull to refresh or try again."
        );
      }
      if (err && err.status === 401) {
        stopPolling();
      }
    } finally {
      refreshInFlight = false;
    }
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(function () {
      if (document.hidden) return;
      refresh({ quiet: true });
    }, POLL_MS);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  let scrollTick = false;
  function onScrollOrResize() {
    if (scrollTick || loadingMore || refreshInFlight || !hasMore) return;
    scrollTick = true;
    requestAnimationFrame(function () {
      scrollTick = false;
      if (nearBottom()) refresh({ append: true });
    });
  }

  window.addEventListener("scroll", onScrollOrResize, { passive: true });
  window.addEventListener("resize", onScrollOrResize, { passive: true });

  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) refresh({ quiet: true });
  });
  window.addEventListener("beforeunload", stopPolling);

  try {
    await refresh({ force: true });
    if (focusId) await focusDashboardItem(focusId);
    startPolling();
    if (hasMore && nearBottom()) await refresh({ append: true });
  } catch (err) {
    setListMessage(
      (err && err.message) || "Could not load dashboard. Hard-refresh and try again."
    );
    setAlert(alertEl, "error", (err && err.message) || "Dashboard failed to load.");
  }
})();
