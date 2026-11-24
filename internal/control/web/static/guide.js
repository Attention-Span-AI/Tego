// SPDX-License-Identifier: Apache-2.0
// The guide follows only the server's guide facts. No click ticks a stop.
(function () {
  'use strict';
  var busy = false, leaving = false, moveTimer = null, moveNext = "";
  function wire() { if (frame() && !document.querySelector('script[src="/static/copy.js"]')) {
    var copy = document.createElement('script'); copy.src = '/static/copy.js'; document.head.appendChild(copy);
  }}
  function frame() { return document.querySelector('.gf'); }
  function cancelMove() {
    clearTimeout(moveTimer); moveTimer = null; moveNext = '';
  }
  function reading(f) { return f && f.contains(document.activeElement); }
  function move() {
    var f = frame(), next = f && f.dataset.guideMove;
    var message = f && f.querySelector('#gf-move-message');
    if (!next || leaving || document.hidden || reading(f)) {
      if (message) message.textContent = 'The run ended. Step 4 is ready.';
      cancelMove(); return;
    }
    var u = new URL(next, location.href);
    if (u.origin !== location.origin || u.pathname !== '/guide') { cancelMove(); return; }
    var changed = message && message.textContent !== 'The run ended. Moving to step 4.';
    if (changed) message.textContent = 'The run ended. Moving to step 4.';
    if (moveTimer !== null && moveNext === next && !changed) return;
    cancelMove(); moveNext = next;
    // Keep the ended sentence in the polite live region long enough to announce.
    moveTimer = setTimeout(function () {
      moveTimer = null;
      if (!frame() || frame().dataset.guideMove !== next || leaving || document.hidden || reading(frame())) { cancelMove(); return; }
      leaving = true; location.replace(u.href);
    }, 2000);
  }
  function check() {
    if (busy || leaving || document.hidden || !frame() || reading(frame()) || !window.tegoLive) return;
    var region = document.querySelector('[data-live="r-guide"]');
    if (!region) return;
    busy = true;
    var here = location.href, ctl = new AbortController(), timer = setTimeout(function () { ctl.abort(); }, 10000);
    fetch(here, {credentials:'same-origin', cache:'no-store', signal:ctl.signal, headers:{'X-Tego-Regions':'r-guide:'+region.dataset.h}})
      .then(function (r) { if (!r.ok || r.status === 204) return ''; return r.text(); })
      .then(function (html) {
        if (!html || here !== location.href || leaving || reading(frame())) return;
        var doc = new DOMParser().parseFromString(html, 'text/html'), fresh = doc.querySelector('template[data-live="r-guide"]');
        if (!fresh) return;
        var holder = document.createElement('div'); holder.appendChild(fresh.content.cloneNode(true));
        window.tegoLive.merge(region, holder); region.dataset.h = fresh.dataset.h;
        document.dispatchEvent(new CustomEvent('tego:merged')); move();
      }).catch(function () { /* The native reload link remains available. */ })
      .finally(function () { clearTimeout(timer); busy = false; });
  }
  document.addEventListener('tego:leave', function () { leaving = true; cancelMove(); });
  document.addEventListener('tego:enter', function () { leaving = false; wire(); move(); });
  document.addEventListener('tego:merged', move);
  document.addEventListener('focusin', move);
  document.addEventListener('focusout', function () { setTimeout(move, 0); });
  document.addEventListener('visibilitychange', move);
  setInterval(check, 3000);
  wire(); move();
})();
