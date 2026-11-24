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
  var chromeMetas = Array.from(document.querySelectorAll('meta[name="theme-color"]')), chromeFallback = {};
  chromeMetas.forEach(function (m) { chromeFallback[m.media.indexOf(': dark') >= 0 ? 'dark' : 'light'] = m.content; });
  function chromeColor() {
    var mode = root.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    var color = getComputedStyle(root).getPropertyValue('--c-bg').trim() || chromeFallback[mode];
    if (color) chromeMetas.forEach(function (m) { m.content = color; });
  }
  function apply(v) {
    if (v === 'light' || v === 'dark') root.setAttribute('data-theme', v);
    else root.removeAttribute('data-theme');
    chromeColor();
  }
  apply(saved());
  function wire() {
    var wrap = document.getElementById('theme-w'), sel = document.getElementById('theme');
    if (!wrap || !sel) return;
    wrap.hidden = false; // without script the switch would do nothing, so it starts hidden
    if (sel.dataset.themeWired) return;
    sel.value = saved();
    sel.dataset.themeWired = 'true';
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
  // The single switch lives on More on phones and returns to the desktop header.
  function place() {
    chromeColor();
    var wrap = document.getElementById('theme-w'), slot = document.getElementById('phone-theme');
    var top = document.querySelector('.top-right');
    if (!wrap || !top) return;
    if (matchMedia('(max-width: 600px)').matches && slot) slot.appendChild(wrap);
    else top.appendChild(wrap);
    wire();
  }
  document.addEventListener('DOMContentLoaded', place);
  document.addEventListener('tego:enter', place);
  matchMedia('(max-width: 600px)').addEventListener('change', place);
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', chromeColor);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();
})();
