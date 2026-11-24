// SPDX-License-Identifier: Apache-2.0
// Keep a selected late tab reachable without changing the page's scroll position.
(function () {
  'use strict';
  function current() {
    var tabs = document.querySelector('.run-content nav.tabs');
    var tab = tabs && tabs.querySelector('[aria-current="page"]');
    if (!tab) return;
    var left = tab.offsetLeft - tabs.offsetLeft;
    if (left < tabs.scrollLeft) tabs.scrollLeft = left;
    else if (left + tab.offsetWidth > tabs.scrollLeft + tabs.clientWidth) tabs.scrollLeft = left + tab.offsetWidth - tabs.clientWidth;
  }
  // A timeline row's details open in place, under the row (the same panel as an opened Logs row, GET /logs/line), not on
  // a page of their own. The row's link stays a link to the line's page: it is what a script-less browser, a middle
  // click, a new-tab click and "Open line N" use. A click on it opens the panel and moves focus to it; Close (or Escape)
  // closes it and returns focus to the link; the browser's Back closes it too (one history entry per opened panel).
  // An open panel asks for its line again when the ledger moves, with the revision it shows (If-None-Match), and merges
  // a changed answer in place.
  var open = null; // { link, panel, body, rev }
  var LINE = /^\/runs\/([^/]+)\/lines\/(\d+)$/;
  function isOpen() { return open && open.panel.isConnected; }
  function url(o) { return '/logs/line?run=' + encodeURIComponent(o.run) + '&seq=' + encodeURIComponent(o.seq); }
  function close(restore) {
    if (!open) return;
    var o = open;
    open = null;
    o.link.removeAttribute('aria-expanded');
    o.link.removeAttribute('aria-controls');
    if (o.panel.parentNode) o.panel.remove();
    if (restore && o.link.isConnected) o.link.focus({ preventScroll: true });
  }
  function dismiss() { // Close and Escape: through Back when this panel pushed an entry, so the history stays one step per panel
    if (!isOpen()) return close(false);
    if (history.state && history.state.tlLine === open.seq) history.back(); else close(true);
  }
  function start(link, m) {
    var o = { link: link, run: decodeURIComponent(m[1]), seq: m[2] }, row = link.closest('.tl');
    if (!row) return false;
    var panel = document.createElement('div'), head = document.createElement('div'), x = document.createElement('button'), body = document.createElement('div');
    panel.className = 'tl-detail';
    panel.id = 'tl-detail-' + o.seq;
    panel.setAttribute('role', 'region');
    panel.setAttribute('aria-label', 'Details of line ' + o.seq);
    panel.tabIndex = -1;
    head.className = 'tl-detail-head';
    x.type = 'button';
    x.className = 'btn btn-sm tl-detail-x';
    x.textContent = 'Close';
    x.setAttribute('aria-label', 'Close the details of line ' + o.seq);
    body.className = 'tl-detail-body';
    body.setAttribute('aria-busy', 'true');
    body.textContent = 'Reading the line…';
    head.appendChild(x);
    panel.append(head, body);
    row.after(panel);
    link.setAttribute('aria-expanded', 'true');
    link.setAttribute('aria-controls', panel.id);
    o.panel = panel;
    o.body = body;
    close(false);
    open = o;
    try { history.pushState({ tlLine: o.seq }, '', location.href); } catch (e) { /* no history: Close and Escape still close it */ }
    panel.focus({ preventScroll: true });
    fetch(url(o), { credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error(r.status);
      return r.text().then(function (html) { return { r: r, html: html }; });
    }).then(function (x) {
      if (open !== o) return;
      var t = document.createElement('template');
      t.innerHTML = x.html;
      body.textContent = '';
      body.appendChild(t.content);
      o.rev = x.r.headers.get('ETag') || '';
    }).catch(function () {
      if (open !== o) return;
      body.textContent = '';
      var a = document.createElement('a');
      a.className = 'link';
      a.href = link.href;
      a.textContent = 'The line could not be read here. Open its page.';
      body.appendChild(a);
    }).then(function () { body.removeAttribute('aria-busy'); });
    return true;
  }
  document.addEventListener('click', function (e) {
    var t = e.target instanceof Element ? e.target : null, link = t && t.closest('#tl-rows a.run-event-row, #tl-rows a.seq'), m;
    if (t && t.closest('.tl-detail-x')) { e.preventDefault(); return dismiss(); }
    if (t && isOpen() && t.closest('.tl-detail .lx-copy')) return copy(t.closest('.lx-copy'));
    if (!link || e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || !window.fetch) return;
    m = LINE.exec(new URL(link.href, location.href).pathname);
    if (!m) return;
    e.preventDefault();
    if (isOpen() && open.link === link) return dismiss();
    start(link, m);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && isOpen() && !e.defaultPrevented && document.querySelector('#tl-rows') && (document.activeElement === document.body || open.panel.contains(document.activeElement) || open.link === document.activeElement)) dismiss();
  });
  window.addEventListener('popstate', function () { close(true); }); // Back, or dismiss() going back
  function copy(btn) {
    var raw = btn.parentNode.querySelector('template.lx-raw'), text = raw ? raw.content.textContent : '', was = btn.textContent;
    function done(ok) {
      btn.textContent = ok ? 'Copied' : 'Copy failed: select the line on its page';
      setTimeout(function () { btn.textContent = was; }, 2000);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
    else done(false);
  }
  function follow() {
    if (!isOpen() || !open.rev || !window.tegoLive) return;
    var o = open, sel = window.getSelection();
    fetch(url(o), { credentials: 'same-origin', cache: 'no-store', headers: { 'If-None-Match': o.rev } }).then(function (r) {
      if (r.status === 304 || !r.ok) return;
      return r.text().then(function (html) {
        if (open !== o || (sel && !sel.isCollapsed && o.body.contains(sel.anchorNode))) return;
        var t = document.createElement('template'), n, was = document.activeElement, cur = o.body.firstElementChild;
        t.innerHTML = html;
        n = t.content.firstElementChild;
        if (!n || !cur || cur.className !== n.className) return;
        window.tegoLive.attrs(cur, n);
        window.tegoLive.merge(cur, n);
        var raw = cur.querySelector('template.lx-raw'), fresh = n.querySelector('template.lx-raw');
        if (raw && fresh) raw.innerHTML = fresh.innerHTML;
        o.rev = r.headers.get('ETag') || '';
        if (was && was !== document.body && !was.isConnected) o.panel.focus({ preventScroll: true });
      });
    }).catch(function () { /* the next move asks again */ });
  }
  document.addEventListener('tego:moved', follow);
  document.addEventListener('tego:changes', follow);
  new MutationObserver(function () { if (open && !open.panel.isConnected) open = null; else if (open && !open.link.isConnected) close(false); })
    .observe(document.body, { childList: true, subtree: true });
  document.addEventListener('tego:merged', current);
  document.addEventListener('tego:enter', current);
  current();
}());
// The run timeline's model-step headers (<p class="tl-step" data-sk=key>). Each row of a group has the group's key in
// data-sk and the first row of each run of consecutive rows of one key has the header; a line the record
// ties to no step has the key "none" and a folded row the key "folded", so neither sits under the header of a step. New rows arrive on top and an older row of a folded group leaves, so
// live.js asks for the headers before the change and has them drawn again from the rows' keys after it.
(function () {
  'use strict';
  window.tegoSteps = {
    // heads is every header now on the page or in the fragment, by key: the words a regrouped run of rows takes.
    heads: function (rows, fresh) {
      var heads = {};
      [rows, fresh].forEach(function (root) {
        root.querySelectorAll('.tl-step').forEach(function (h) { heads[h.dataset.sk] = h; });
      });
      return heads;
    },
    regroup: function (rows, heads) {
      var open = '', made = {};
      rows.querySelectorAll('.tl-step').forEach(function (h) { h.remove(); });
      // Every row of the run timeline, as GroupSteps sees them: a row with no key (a page that carries none) closes the
      // group, so a row is never left under the header of a step it has no tie to.
      rows.querySelectorAll('.tl.run-tl').forEach(function (row) {
        var k = row.dataset.sk || '';
        if (k === '') { open = ''; return; }
        if (k === open) return;
        open = k;
        if (!heads[k]) return;
        var h = made[k] ? made[k].cloneNode(true) : heads[k];
        made[k] = h;
        row.parentNode.insertBefore(h, row);
      });
    }
  };
}());
