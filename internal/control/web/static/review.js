// SPDX-License-Identifier: Apache-2.0
// review.js: the reviewed marks of the Detections triage (Investigate's "Keep blocked"), kept in this browser only
// (localStorage), so a person working down the High list sees what they already looked at. Nothing is sent anywhere,
// and a browser that keeps no storage simply shows no marks. The rows a filter click (place.js) or a live update
// (live.js) brings are the server's, which holds no marks, so each merge marks them again.
(function () {
  var KEY = 'tego.reviewed';
  function load() {
    try { return JSON.parse(localStorage.getItem(KEY) || '{}') || {}; } catch (e) { return {}; }
  }
  function save(m) {
    try { localStorage.setItem(KEY, JSON.stringify(m)); } catch (e) { /* no storage: no marks */ }
  }
  document.addEventListener('click', function (ev) {
    var a = ev.target.closest && ev.target.closest('[data-review]');
    if (!a) return;
    var m = load();
    m[a.getAttribute('data-review')] = Date.now();
    save(m);
  });
  function mark() {
    var m = load(), done = 0, high = 0;
    document.querySelectorAll('tr[data-review-key]').forEach(function (tr) {
      var hi = tr.getAttribute('data-sev') === 'High';
      if (hi) high++;
      if (m[tr.getAttribute('data-review-key')]) {
        tr.classList.add('is-reviewed');
        if (hi) done++;
      }
    });
    var p = document.getElementById('dt-progress');
    if (p && high) {
      p.textContent = done + ' of ' + high + ' High reviewed';
      p.hidden = false;
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mark); else mark();
  document.addEventListener('tego:enter', mark);
  document.addEventListener('tego:merged', mark);
})();
