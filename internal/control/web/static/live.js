// SPDX-License-Identifier: Apache-2.0
// live.js: the dashboard's live updates, in place and dependency-free. Every page works without it (a meta refresh in
// <noscript> takes over and every form posts as a plain form). It never reloads the page:
// - it follows the live state (live.go) over one Server-Sent Events stream, GET /events, reopened with backoff, and
//   polls GET /status.json every 2 s while it has no stream; a hidden tab closes its stream and polls every 5 s, since a
//   browser opens only 6 connections to the dashboard and each open stream holds one (so ~6 tabs would leave none for
//   fetches, posts and page loads), and opens it again when it is shown;
// - the waiting-ask count goes into the title, "(1) Tego", even in a background tab;
// - when the state changes it fetches the page's changed live regions (regions.go: the page's own address with the
//   header X-Tego-Regions naming each region shown and its hash) and merges each into the page node by node, so the
//   scroll position, focus, open <details>, a text selection and a form being filled in stay (new rows: .live-new);
// - on a live run's timeline (#tl-rows[data-rows]) it puts only the rows after its last line at the top (newest 200);
// - every second it rewrites each "asked 8 s ago" ([data-ago]) and each running run's time so far ([data-since]);
// - Allow, Deny, Block, Remove and the rule forms (Never allow, Undo, Save, Create) post in the background with
//   X-Tego-Inline: the answer is a plain form's 303 line (flash.go) as JSON, said in a toast, and the regions refresh
//   in place; its "here" (this page with the result) goes in the address bar first, its "go" (as Stop's) is a page
//   opened with the toast. A data-page button (a YAML Check) posts as a plain form: its answer is a page.
// static/place.js, which this file loads, builds on its merge (window.tegoLive) to change a page's view in place,
// keeping the reader's place; hold() keeps the region and row fetches from merging a view the page is leaving.
(function () {
  'use strict';
  function ago() { // [data-ago]: "asked 8 s ago"; [data-since]: a run's time so far, in pages.go human()'s words
    document.querySelectorAll('[data-ago],[data-since]').forEach(function (n) {
      var a = n.dataset.ago, t = Date.parse(a || n.dataset.since), s = Math.max(0, (a ? Math.round : Math.floor)((Date.now() - t) / 1000));
      var txt = a ? 'asked ' + (s < 60 ? s + ' s' : Math.floor(s / 60) + ' m ' + (s % 60) + ' s') + ' ago' : s < 60 ? s + ' s' : s < 3600 ? Math.floor(s / 60) + ' m ' + (s % 60) + ' s' : s < 259200 ? Math.floor(s / 3600) + ' h ' + Math.floor(s % 3600 / 60) + ' m' : Math.floor(s / 86400) + ' d ' + Math.floor(s % 86400 / 3600) + ' h';
      if (!isNaN(t) && n.textContent !== txt) n.textContent = txt;
    });
    // Past the agent's own wait (data-late-at), the note says it has likely given up and when Tego refuses it.
    document.querySelectorAll('[data-late-at]').forEach(function (n) {
      var t = Date.parse(n.dataset.lateAt);
      if (!isNaN(t) && Date.now() >= t && n.textContent !== n.dataset.late) n.textContent = n.dataset.late;
    });
  }
  ago();
  setInterval(ago, 1000); // an ask a live region brings in later ticks too
  // A tab strip wider than the screen (phone width) scrolls: the open tab comes into view; its fade goes at the end.
  // strips runs again after a view change merged the page (a strip it already follows is left as it is).
  function strips() {
    document.querySelectorAll('.tabs').forEach(function (t) {
      var cur = t.querySelector('[aria-current="page"]'), end = function () { t.classList.toggle('at-end', t.scrollLeft + t.clientWidth >= t.scrollWidth - 4); };
      if (cur && (cur.offsetLeft + cur.offsetWidth > t.scrollLeft + t.clientWidth || cur.offsetLeft < t.scrollLeft)) t.scrollLeft = cur.offsetLeft - 16;
      if (!t.tegoStrip) { t.tegoStrip = true; t.addEventListener('scroll', end, { passive: true }); }
      end();
    });
  }
  strips();
  var body = document.body, d = body.dataset;
  // tegoLive is what static/place.js builds on: this file's merge for a whole view (no "new" mark, the forms taking the
  // new page's values), and hold, which keeps refresh and more from merging the regions or rows of a view being left.
  // A page with nothing to follow (MCP tools, Model routes: no signature) still changes its view in place.
  window.tegoLive = {
    merge: function (o, n) { navMode = true; try { kids(o, n); } finally { navMode = false; } },
    attrs: attrs,
    hold: function (on) { if (!d.sig) return; navigating = on; if (on) navGen++; else if (again) refresh(); },
    after: function () { if (d.sig) findFeed(); strips(); ago(); }, // the new view's timeline, tab strip and clocks
    toast: toast
  };
  (function () { // loaded from here, so every page's head still names live.js alone (theme_test, the locked goldens)
    var ps = document.createElement('script');
    ps.src = '/static/place.js';
    document.head.appendChild(ps);
  })();
  if (!d.sig) return; // the answer to a form, an error page, a page with no live regions: nothing to follow
  var rows = null, feed = null;
  function findFeed() { // a live run's timeline, found again after a view change (another tab has none)
    rows = document.getElementById('tl-rows');
    feed = rows && rows.dataset.rows ? rows : null;
  }
  findFeed();
  var sig = d.sig, rev = d.rev, MAX = 200;
  var backoff = 2000, poller = 0, every = 0, fetching = false, again = false, last = 0, feeding = false, feedAgain = false;
  var es = null, retry = 0;
  var navMode = false, navGen = 0, navigating = false; // a view change (place.js): kids merging it, its count, on its way

  function title(n) { document.title = (n > 0 ? '(' + n + ') ' : '') + d.title; }
  function conn(s) { body.setAttribute('data-conn', out ? 'out' : s); } // once signed out, it stays so

  // signedOut: a 401 means the dashboard restarted (each serve has a new token) or the session is gone. Following
  // stops (no stream, 2 s polling, region or row fetch: each could only fail again) and a banner says how to get back
  // in; its text is this constant only. One quiet check every 30 s notices a sign-in from another tab (the link sets
  // the same cookie), takes the banner down and follows again.
  var out = false, outCheck = 0, OUT_EVERY = 30000;
  function signedOut() {
    if (out) return;
    out = true;
    hang();
    polling(0);
    conn('out');
    var b = document.createElement('section'), page = document.querySelector('main .page') || body;
    b.className = 'banner banner-danger signed-out';
    b.id = 'signed-out';
    b.setAttribute('role', 'alert');
    b.innerHTML = '<div class="grow"><strong>Signed out: open the link from your terminal.</strong> The dashboard was restarted or this sign-in expired. The link <span class="mono">tego-control serve</span> printed signs this browser in again; this page carries on by itself once it is.</div>';
    page.insertBefore(b, page.firstChild);
    outCheck = setInterval(signedBack, OUT_EVERY);
  }
  function signedBack() {
    fetch('/status.json', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) {
        if (!r.ok || !out) return;
        out = false;
        clearInterval(outCheck);
        outCheck = 0;
        var b = document.getElementById('signed-out');
        if (b) b.remove();
        conn('ok');
        backoff = 2000;
        refresh();
        connect();
      })
      .catch(function () { /* not reachable yet: the next check asks again */ });
  }
  function gone(r) { if (r.status === 401) signedOut(); throw new Error(r.status); } // a failed answer

  function onState(s) {
    title(s.pending);
    var moved = s.rev !== rev;
    if (s.sig === sig && !moved) return;
    sig = s.sig;
    rev = s.rev;
    refresh();
    if (moved) { if (feed) more(); document.dispatchEvent(new CustomEvent('tego:moved')); } // and a page's own follower (logs.js)
  }

  function poll() {
    fetch('/status.json', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { if (!r.ok) gone(r); return r.json(); })
      .then(function (s) { conn('ok'); onState(s); })
      .catch(function () { conn('lost'); });
  }
  // polling(ms) polls every ms (0 stops it).
  function polling(ms) {
    if (poller && every !== ms) { clearInterval(poller); poller = 0; }
    if (ms && !poller) poller = setInterval(poll, ms);
    every = ms;
  }
  function hang() { // close the stream and drop a pending reopen
    if (es) { es.close(); es = null; }
    if (retry) { clearTimeout(retry); retry = 0; }
  }
  function connect() {
    retry = 0;
    if (out) return;
    if (document.hidden) return polling(5000);
    if (!window.EventSource) return polling(2000);
    var src = es = new EventSource('/events');
    src.addEventListener('state', function (e) {
      backoff = 2000;
      conn('ok');
      polling(0);
      try { onState(JSON.parse(e.data)); } catch (x) { /* a torn message: the next one carries the state */ }
    });
    src.addEventListener('lost', function () { conn('lost'); }); // the dashboard cannot read the ledger
    src.onerror = function () { // the stream ended or failed: poll, and open another later
      src.close();
      if (es !== src) return; // closed on purpose (hidden tab)
      es = null;
      polling(2000);
      retry = setTimeout(connect, backoff);
      backoff = Math.min(backoff * 2, 30000);
    };
  }
  document.addEventListener('visibilitychange', function () {
    if (out) return;
    hang();
    if (document.hidden) return polling(5000);
    backoff = 2000;
    poll(); // catch up at once, then follow the stream again
    connect();
  });

  // --- merging a fresh region into the page
  function key(n) { return n.nodeType === 1 ? (n.id || n.getAttribute('data-k') || '') : ''; }
  function selecting(el) {
    var s = window.getSelection();
    return !!s && !s.isCollapsed && s.rangeCount > 0 && el.contains(s.getRangeAt(0).commonAncestorContainer);
  }
  // busy: a form someone is using (focus in a field, a value changed, or its answer on the way) is left as it is.
  function busy(f) {
    var a = document.activeElement;
    if (f.dataset.sending || (a && f.contains(a) && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName))) return true;
    for (var i = 0; i < f.elements.length; i++) {
      var e = f.elements[i];
      if (e.type === 'checkbox' || e.type === 'radio') { if (e.checked !== e.defaultChecked) return true; }
      else if (e.tagName === 'SELECT') {
        var def = 0;
        for (var j = 0; j < e.options.length; j++) if (e.options[j].defaultSelected) def = j;
        if (e.selectedIndex !== def) return true;
      } else if ((e.tagName === 'TEXTAREA' || e.tagName === 'INPUT') && e.type !== 'hidden' && e.value !== e.defaultValue) return true;
    }
    return false;
  }
  function attrs(o, n) {
    var keep = o.tagName === 'DETAILS' ? 'open' : '', fresh = o.classList.contains('live-new'), i, a;
    for (i = o.attributes.length - 1; i >= 0; i--) {
      a = o.attributes[i].name;
      if (a !== keep && !n.hasAttribute(a)) o.removeAttribute(a);
    }
    for (i = 0; i < n.attributes.length; i++) {
      a = n.attributes[i];
      if (a.name !== keep && o.getAttribute(a.name) !== a.value) o.setAttribute(a.name, a.value);
    }
    if (fresh) o.classList.add('live-new');
  }
  function node(o, n) {
    if (o.nodeType !== 1) {
      if (o.nodeValue !== n.nodeValue) o.nodeValue = n.nodeValue;
      return;
    }
    if (o.tagName === 'FORM' && !navMode && busy(o)) return; // a view change replaces the forms, as a page load would
    attrs(o, n);
    kids(o, n);
  }
  // kids makes op's children those of np: a node with an id or data-k matches the old node with the same, others
  // match in order; what matches is updated in place, the rest is added (marked new when keyed) or removed.
  function kids(op, np) {
    var byKey = {}, c, k, m, cur, nx;
    for (c = op.firstChild; c; c = c.nextSibling) if ((k = key(c))) byKey[c.nodeName + '#' + k] = c;
    cur = op.firstChild;
    Array.prototype.slice.call(np.childNodes).forEach(function (n) {
      k = key(n);
      m = null;
      if (k) {
        m = byKey[n.nodeName + '#' + k] || null;
        delete byKey[n.nodeName + '#' + k];
      } else if (cur && !key(cur) && cur.nodeType === n.nodeType && cur.nodeName === n.nodeName) m = cur;
      if (m) {
        if (m === cur) cur = cur.nextSibling; else op.insertBefore(m, cur);
        node(m, n);
      } else {
        op.insertBefore(n, cur);
        if (k && n.nodeType === 1 && !navMode) mark(n); // a view change's rows are the view, not news
      }
    });
    while (cur) { nx = cur.nextSibling; drop(op, cur); cur = nx; }
  }
  // drop removes n from op. The floating ask banner (mvp.css, fixed: it takes no space) fades out first; a banner
  // that comes back meanwhile is matched by its id, loses .ab-leave and stays.
  function drop(op, n) {
    if (n.nodeType === 1 && n.classList.contains('ab-leave')) return; // already on its way out
    if (n.nodeType === 1 && n.classList.contains('banner-ask') && getComputedStyle(n).position === 'fixed' &&
        !(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches)) {
      n.classList.add('ab-leave');
      setTimeout(function () { if (n.classList.contains('ab-leave') && n.parentNode) n.parentNode.removeChild(n); }, 200);
      return;
    }
    op.removeChild(n);
  }
  function mark(el) {
    el.classList.add('live-new');
    setTimeout(function () { el.classList.remove('live-new'); }, 2600);
  }

  function shown() {
    var top = window.scrollY - (window.tegoRoom || 0) < 120 && !/[?&]before=/.test(location.search), out = [];
    document.querySelectorAll('[data-live]').forEach(function (el) {
      if (!el.hasAttribute('data-top') || top) out.push(el.dataset.live + ':' + (el.dataset.h || ''));
    });
    return out;
  }
  // refresh fetches the changed regions, at most once a second, and merges them.
  function refresh() {
    if (out) return;
    if (fetching || navigating) { again = true; return; } // a view change on its way: its page is fresher
    var wait = last + 1000 - Date.now(), have = shown();
    if (wait > 0) { fetching = true; setTimeout(function () { fetching = false; refresh(); }, wait); return; }
    if (!have.length) return;
    fetching = true;
    again = false;
    last = Date.now();
    var gen = navGen;
    fetch(location.pathname + location.search, { credentials: 'same-origin', cache: 'no-store', headers: { 'X-Tego-Regions': have.join(',') } })
      .then(function (r) { if (!r.ok) gone(r); return r.text(); })
      .then(function (html) {
        if (gen !== navGen) { again = true; return; } // the regions of a view the page has left: ask the new one's
        var t = document.createElement('template'), retry = false, had = document.activeElement;
        t.innerHTML = html;
        t.content.querySelectorAll('template[data-live]').forEach(function (f) {
          var el = document.querySelector('[data-live="' + f.dataset.live + '"]');
          if (!el) return;
          if (selecting(el) || (window.tegoLive.steady && window.tegoLive.steady(el))) { retry = true; return; } // someone is selecting text in it, or reaching for a row: later
          kids(el, f.content);
          el.dataset.h = f.dataset.h;
        });
        ago(); // the region came with the time it was rendered at
        document.dispatchEvent(new CustomEvent('tego:merged')); // a page's own script (review.js) marks the new rows
        // The focused control went with its region (an answered ask's Deny): the focus goes to <main>, not to nothing,
        // so the next Tab starts in the page (main:focus shows no ring).
        if (had && had !== body && !had.isConnected) document.querySelector('main').focus({ preventScroll: true });
        if (retry) setTimeout(refresh, 2000);
      })
      .catch(function () { /* the next change asks again */ })
      .then(function () { fetching = false; if (again) refresh(); });
  }

  // more puts the rows after feed's cursor at the top: a folded refusal group's older row is dropped when its group
  // arrives again with the whole count, and the list is cut to the newest MAX, the Older link moving with it.
  function more() {
    if (out || !feed) return;
    if (feeding || navigating) { feedAgain = true; return; } // a line came while the rows were on the way: ask again after
    feeding = true;
    feedAgain = false;
    var gen = navGen, rows = feed; // this view's timeline: a view change finds the next one's (findFeed)
    fetch(feed.dataset.rows + feed.dataset.after, { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) {
        if (!r.ok) gone(r);
        return r.text().then(function (html) { return { r: r, html: html }; });
      })
      .then(function (x) {
        if (gen !== navGen || rows !== feed) return; // rows of a view the page has left
        feed.dataset.after = x.r.headers.get('X-Tego-After') || feed.dataset.after;
        var t = document.createElement('template');
        t.innerHTML = x.html;
        var fresh = t.content;
        fresh.querySelectorAll('[data-k]').forEach(function (n) {
          var old = rows.querySelector('[data-k="' + n.dataset.k + '"]');
          if (old) old.remove();
        });
        fresh.querySelectorAll('.tl').forEach(mark);
        var empty = rows.querySelector('.tl-empty');
        if (x.html && empty) empty.remove();
        rows.insertBefore(fresh, rows.firstChild);
        var cut = false;
        while (rows.children.length > MAX) { rows.lastElementChild.remove(); cut = true; }
        var older = document.getElementById('tl-older'), end = rows.lastElementChild;
        if (cut && older && end && end.id.charAt(0) === 'l') {
          older.href = older.href.replace(/before=\d*/, 'before=' + end.id.slice(1));
          older.hidden = false;
        }
        if (x.r.headers.get('X-Tego-Live') === '0') { // the run ended: stop following, drop its Block links
          rows.removeAttribute('data-rows');
          rows.querySelectorAll('.act-block').forEach(function (a) { a.remove(); });
          feed = null;
          refresh();
        }
      })
      .catch(function () { setTimeout(function () { feedAgain = true; rowsAgain(); }, 2000); })
      .then(function () { feeding = false; rowsAgain(); });
  }
  function rowsAgain() { // fetch the rows again when a line came (or the fetch failed) while one was on the way
    if (!feeding && feedAgain && feed) more();
  }

  // --- answering in place
  // toast says a, the line an action left ({ok, text, link, link_text}: flash.go's inlineAnswer). A toast of a kind
  // (every answer to a request is one kind; another action's kind is its path) takes the place of the one before it,
  // so a Deny's notice and a later Allow once's never stack: at most one per kind.
  function toast(a, kind) {
    var box = document.getElementById('toasts');
    if (!box) {
      box = document.createElement('div');
      box.id = 'toasts';
      box.className = 'toasts';
      box.setAttribute('role', 'status');
      box.setAttribute('aria-live', 'polite');
      body.appendChild(box);
    }
    var t = document.createElement('div'), p = document.createElement('span'), x = document.createElement('button');
    t.className = 'toast ' + (a.ok ? 'toast-ok' : 'toast-err');
    if (kind) {
      box.querySelectorAll('.toast[data-kind]').forEach(function (o) { if (o.dataset.kind === kind) o.remove(); });
      t.dataset.kind = kind;
    }
    p.textContent = a.text || (a.ok ? 'Done.' : 'Not done.'); // text, never markup: it can carry agent-written targets
    if (a.link && /^\/(?!\/)/.test(a.link)) { // its next step, a page of this dashboard only
      var l = document.createElement('a');
      l.className = 'link';
      l.href = a.link;
      l.textContent = a.link_text || a.link;
      p.append(' · ', l);
    }
    x.type = 'button';
    x.className = 'toast-x';
    x.setAttribute('aria-label', 'Dismiss');
    x.textContent = '×';
    x.addEventListener('click', function () { t.remove(); });
    t.append(p, x);
    box.appendChild(t);
    if (a.ok && !a.link) setTimeout(function () { t.remove(); }, 6000);
  }
  try { // a stop's toast, carried to the run page it opened
    var carried = sessionStorage.getItem('tego-toast');
    if (carried) { sessionStorage.removeItem('tego-toast'); toast(JSON.parse(carried)); }
  } catch (x) { /* no storage, or not ours: no carried toast */ }

  var kbd = false; // the last move was a key, not a pointer: only then does a focus put back show (focus-visible)
  document.addEventListener('keydown', function () { kbd = true; }, true);
  document.addEventListener('pointerdown', function () { kbd = false; }, true);
  var INLINE = /^\/(approvals\/answer|runs\/[^/]+\/(block|unblock|stop|lines\/\d+)|rules\/(change|revert|new))$/;
  document.addEventListener('submit', function (e) {
    var f = e.target, sub = e.submitter, path;
    if (!(f instanceof HTMLFormElement) || !window.URLSearchParams || e.defaultPrevented) return;
    if (f.method !== 'post') return; // a GET form: place.js's
    path = new URL(f.action, location.href).pathname;
    if (!INLINE.test(path) || (sub && sub.hasAttribute('data-page'))) return; // a plain post (place.js keeps its place)
    e.preventDefault();
    if (f.dataset.sending) return;
    var data = new URLSearchParams(new FormData(f)), stop = /\/stop$/.test(path), btns = f.querySelectorAll('button'), foc = document.activeElement;
    var kind = path === '/approvals/answer' ? 'answer' : path;
    if (sub && sub.name) data.append(sub.name, sub.value);
    f.dataset.sending = '1';
    btns.forEach(function (b) { b.disabled = true; });
    if (stop) toast({ ok: true, text: 'Stopping the run…' }, kind);
    fetch(f.action, { method: 'POST', body: data, credentials: 'same-origin', cache: 'no-store', headers: { 'X-Tego-Inline': '1' } })
      .then(function (r) {
        if (r.status === 401) signedOut();
        if (r.ok && /^application\/json/.test(r.headers.get('Content-Type') || '')) return r.json();
        return r.text().then(function (html) { // refused before the action ran (a bad token, an error page): not done
          var doc = new DOMParser().parseFromString(html, 'text/html'), b = doc.querySelector('main .empty[role=alert]');
          return { ok: false, text: b ? b.textContent.replace(/\s+/g, ' ').trim() : 'Not done: ' + (doc.body.textContent || '').trim().slice(0, 200) };
        });
      })
      .then(function (a) {
        var own = /^\/(?!\/)/, to = a.ok && (a.go || (stop && path.replace(/\/stop$/, '')));
        if (a.ok && own.test(a.here || '')) { history.replaceState(history.state, '', a.here); document.dispatchEvent(new CustomEvent('tego:here')); }
        if (!to || !own.test(to)) return toast(a, kind);
        try { sessionStorage.setItem('tego-toast', JSON.stringify(a)); } catch (y) { /* the page opens without it */ }
        location.assign(to);
      })
      .catch(function () { toast({ ok: false, text: 'Not done: the dashboard could not be reached.' }, kind); })
      .then(function () {
        delete f.dataset.sending;
        btns.forEach(function (b) { b.disabled = false; });
        // A disabled button drops the focus: a keyboard's goes back to it (refresh moves it to <main> if it goes).
        if (kbd && (!document.activeElement || document.activeElement === body) && foc && foc.isConnected) foc.focus({ preventScroll: true });
        refresh();
      });
  });

  conn('ok');
  connect();
})();
