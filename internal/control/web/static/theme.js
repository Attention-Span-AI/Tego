// SPDX-License-Identifier: Apache-2.0
// theme.js: the Auto / Light / Dark switch. Loaded in <head> without defer, so the saved choice is on <html> as
// data-theme before the first paint (no flash of the wrong theme). Auto removes data-theme and lets the
// prefers-color-scheme rule in tokens.css decide. The choice is kept in localStorage, which may be blocked or empty
// (private window, cleared site data): every access is in try/catch and the page works without it.
(function () {
  'use strict';
  var KEY = 'tego-theme', root = document.documentElement;
  function saved() {
    try {
      var v = localStorage.getItem(KEY);
      return v === 'light' || v === 'dark' ? v : 'auto';
    } catch (e) { return 'auto'; }
  }
  function apply(v) {
    if (v === 'light' || v === 'dark') root.setAttribute('data-theme', v);
    else root.removeAttribute('data-theme');
  }
  apply(saved());
  function wire() {
    var wrap = document.getElementById('theme-w'), sel = document.getElementById('theme');
    if (!wrap || !sel) return;
    sel.value = saved();
    wrap.hidden = false; // without script the switch would do nothing, so it starts hidden
    sel.addEventListener('change', function () {
      apply(sel.value);
      try {
        if (sel.value === 'auto') localStorage.removeItem(KEY);
        else localStorage.setItem(KEY, sel.value);
      } catch (e) { /* the choice holds until the page is left */ }
      // Focus leaves the switch once it is used, so nothing on the page treats it as a field being filled in.
      sel.blur();
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();
})();
