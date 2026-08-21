/**
 * Cross-document @view-transition (style.css) can reject with
 * AbortError "Transition was skipped" when navigation is immediate
 * (e.g. Settings → Dashboard). Harmless; keep the continuous header
 * and silence DevTools noise.
 *
 * Loaded first in <head> (before other scripts) so handlers are registered
 * before the browser settles the transition.
 */
(function () {
  "use strict";

  function swallow(p) {
    if (p && typeof p.catch === "function") p.catch(function () {});
  }

  function onViewTransition(e) {
    if (!e || !e.viewTransition) return;
    swallow(e.viewTransition.finished);
    swallow(e.viewTransition.ready);
    swallow(e.viewTransition.updateCallbackDone);
  }

  addEventListener("pageswap", onViewTransition);
  addEventListener("pagereveal", onViewTransition);
  addEventListener("unhandledrejection", function (e) {
    var r = e.reason;
    if (!r) return;
    var msg = String(r.message || r || "");
    if (r.name === "AbortError" && /transition was skipped/i.test(msg)) {
      e.preventDefault();
    }
  });
})();
