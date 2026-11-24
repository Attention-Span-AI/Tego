// SPDX-License-Identifier: Apache-2.0
(function () {
  'use strict';
  function ago() { // [data-ago]: "asked 8 s ago"; [data-since]: a run's time so far, in pages.go human()'s words
    document.querySelectorAll('[data-ago],[data-since],[data-started]').forEach(function (n) {
      if (n.closest('#ask-banner,[data-approval-hold]:is(:hover,:focus-within)')) return; // keep held controls still
      var a = n.dataset.ago, started = n.dataset.started, t = Date.parse(a || started || n.dataset.since), s = Math.max(0, (a ? Math.round : Math.floor)((Date.now() - t) / 1000));
      var txt = a ? 'asked ' + (s < 60 ? s + ' s' : Math.floor(s / 60) + ' m ' + (s % 60) + ' s') + ' ago' : s < 60 ? s + ' s' : s < 3600 ? Math.floor(s / 60) + ' m ' + (s % 60) + ' s' : s < 259200 ? Math.floor(s / 3600) + ' h ' + Math.floor(s % 3600 / 60) + ' m' : Math.floor(s / 86400) + ' d ' + Math.floor(s % 86400 / 3600) + ' h';
      if (started) txt = s < 60 ? 'Just now' : new Intl.RelativeTimeFormat(undefined, {numeric: 'always'}).format(-Math.floor(s / (s < 3600 ? 60 : s < 86400 ? 3600 : 86400)), s < 3600 ? 'minute' : s < 86400 ? 'hour' : 'day');
      if (!isNaN(t) && n.textContent !== txt) n.textContent = txt;
    });
    document.querySelectorAll('[data-late-at]').forEach(function (n) {
      var t = n.closest('[data-approval-hold]:is(:hover,:focus-within)') ? NaN : Date.parse(n.dataset.lateAt);
      if (!isNaN(t) && Date.now() >= t && n.textContent !== n.dataset.late) n.textContent = n.dataset.late;
    });
  }
  ago();
  setInterval(ago, 1000); // an ask a live region brings in later ticks too
  var initialNav = document.querySelector('.nav[data-ask-keys]');
  var body = document.body, d = body.dataset;
  window.tegoLive = {
    merge: function (o, n) { navMode = true; try { kids(o, n); } finally { navMode = false; } },
    attrs: attrs,
    initialAskKeys: initialNav ? initialNav.dataset.askKeys : '',
    hold: function (on) { if (!d.sig) return; navigating = on; if (on) navGen++; else if (again) refresh(); },
    after: function () { if (d.sig) findFeed(); ago(); }, // the new view's timeline and clocks
    toast: toast
  };
  (function () { // loaded from here, so every page's head still names live.js alone (theme_test, the locked goldens)
    var ps = document.createElement('script');
    ps.src = '/static/place.js';
    document.head.appendChild(ps);
    var gs = document.createElement('script'); gs.src = '/static/guide.js'; document.head.appendChild(gs);
  })();
  if (!d.sig) return; // the answer to a form, an error page, a page with no live regions: nothing to follow
  var rows = null, feed = null;
  function findFeed() { // a live run's timeline, found again after a view change (another tab has none)
    rows = document.getElementById('tl-rows');
    feed = rows && rows.dataset.rows ? rows : null;
  }
  findFeed();
  var sig = d.sig, rev = d.rev, renderedSig = sig, renderedRev = rev, MAX = 200;
  // The rule-change journal's revision (state.crev): a rule change writes no ledger line, so the rev above does not
  // move for it. A page that shows change rows names the one it rendered (data-crev); the others take the first state's.
  var cmark = document.querySelector('[data-crev]'), crev = cmark ? cmark.dataset.crev : undefined, renderedCrev = crev;
  var regionRetry = 0, regionBackoff = 1000, MAX_REGION_BACKOFF = 30000;
  var backoff = 2000, poller = 0, every = 0, fetching = false, again = false, last = 0, feeding = false, feedAgain = false;
  var es = null, retry = 0;
  var navMode = false, navGen = 0, navigating = false; // a view change (place.js): kids merging it, its count, on its way
  function title(waiting) { if (waiting) document.title = (waiting.show ? '(' + waiting.short + ') ' : '') + d.title; }
  function conn(s) { body.setAttribute('data-conn', out ? 'out' : s); } // once signed out, it stays so
  var out = false, outCheck = 0, OUT_EVERY = 30000;
  function signedOut() {
    if (out) return;
    out = true;
    if (regionRetry) { clearTimeout(regionRetry); regionRetry = 0; }
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
    title(s.waiting);
    var moved = s.rev !== rev, cmoved = s.crev !== undefined && crev !== undefined && s.crev !== crev;
    if (s.crev !== undefined) { if (crev === undefined) renderedCrev = s.crev; crev = s.crev; }
    if (cmoved) document.dispatchEvent(new CustomEvent('tego:changes')); // a rule changed: logs.js places the change rows
    if (s.sig === sig && !moved) {
      // A rule change moves only crev; a region left out (Logs' rows while the reader is lower down) is asked again too.
      if ((renderedSig !== sig || renderedRev !== rev || renderedCrev !== crev) && !regionRetry) refresh();
      return;
    }
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
  function key(n) { return n.nodeType === 1 ? (n.id || n.getAttribute('data-k') || '') : ''; }
  function selecting(el) {
    var s = window.getSelection();
    return !!s && !s.isCollapsed && s.rangeCount > 0 && el.contains(s.getRangeAt(0).commonAncestorContainer);
  }
  var askHeld = false;
  function usingAsk(el) {
    if ((el.dataset.live !== 'r-banner' && el.dataset.live !== 'content') || (navMode && el.dataset.live === 'content')) return false;
    return Array.from(el.querySelectorAll('#ask-banner,[data-approval-hold]')).some(function (band) {
      return band.getClientRects().length && (band.matches(':hover') || band.contains(document.activeElement));
    });
  }
  function leaveAsk(e) {
    var band = e.target.closest && e.target.closest('#ask-banner,[data-approval-hold]');
    if (!askHeld || !band || band.contains(e.relatedTarget)) return;
    setTimeout(refresh, 0); // focus and :hover settle after their departure event
  }
  document.addEventListener('pointerout', leaveAsk);
  document.addEventListener('focusout', leaveAsk);
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
    if (d.sig && usingAsk(o)) { askHeld = true; return; }
    if (o.tagName === 'FORM' && !navMode && busy(o)) return; // a view change replaces the forms, as a page load would
    attrs(o, n);
    kids(o, n);
  }
  function same(a, b) { return a.nodeType === 1 && b.nodeType === 1 && a.nodeName === b.nodeName && a.className === b.className; } // the same kind of block
  function kids(op, np) {
    var byKey = {}, c, k, m, cur, nx, fresh = Array.prototype.slice.call(np.childNodes);
    for (c = op.firstChild; c; c = c.nextSibling) if ((k = key(c))) byKey[c.nodeName + '#' + k] = c;
    cur = op.firstChild;
    fresh.forEach(function (n, i) {
      k = key(n);
      m = null;
      if (k) {
        m = byKey[n.nodeName + '#' + k] || null;
        delete byKey[n.nodeName + '#' + k];
      } else if (cur && !key(cur) && cur.nodeType === n.nodeType && cur.nodeName === n.nodeName) {
        m = cur;
        // A block that grew in front (a note, a late line) must not hand this one's place to the next block: match a
        // block to the same kind (its class), and take its place by position only when no later one is of its kind.
        if (n.nodeType === 1 && cur.className !== n.className) {
          for (c = cur.nextSibling, m = null; c; c = c.nextSibling) if (!key(c) && same(c, n)) { m = c; break; }
          if (!m && !fresh.slice(i + 1).some(function (x) { return !key(x) && same(x, cur); })) m = cur;
        }
      }
      if (m) {
        if (m === cur) cur = cur.nextSibling; else op.insertBefore(m, cur);
        node(m, n);
      } else {
        op.insertBefore(n, cur);
        if (k && n.nodeType === 1 && !navMode) mark(n); // a view change's rows are the view, not news
      }
    });
    while (cur) { nx = cur.nextSibling; op.removeChild(cur); cur = nx; }
  }
  function mark(el) {
    if (el.closest('#ask-banner')) return; // its waiting background must keep contrast with the answer controls
    el.classList.add('live-new');
    setTimeout(function () { el.classList.remove('live-new'); }, 2600);
  }
  var heldTop = false; // a top-only region (Logs' groups) was left out of the last ask: scrolling back to the top asks again
  function shown() {
    var top = window.scrollY < 120 && !/[?&]before=/.test(location.search), out = [];
    heldTop = false;
    document.querySelectorAll('[data-live]').forEach(function (el) {
      if (!el.hasAttribute('data-top') || top) out.push(el.dataset.live + ':' + (el.dataset.h || ''));
      else heldTop = true;
    });
    return out;
  }
  window.addEventListener('scroll', function () { if (heldTop && window.scrollY < 120 && !/[?&]before=/.test(location.search)) refresh(); }, { passive: true });
  function refresh() {
    if (out) return;
    if (fetching || navigating) { again = true; return; } // a view change on its way: its page is fresher
    var wait = last + 1000 - Date.now(), have = shown();
    if (wait > 0) { fetching = true; setTimeout(function () { fetching = false; refresh(); }, wait); return; }
    if (!have.length) return;
    fetching = true;
    again = false;
    last = Date.now();
    var gen = navGen, wantSig = sig, wantRev = rev, wantCrev = crev;
    if (regionRetry) { clearTimeout(regionRetry); regionRetry = 0; }
    fetch(location.pathname + location.search, { credentials: 'same-origin', cache: 'no-store', headers: { 'X-Tego-Regions': have.join(',') } })
      .then(function (r) { if (!r.ok) gone(r); return r.text(); })
      .then(function (html) {
        if (gen !== navGen) { again = true; return; } // the regions of a view the page has left: ask the new one's
        var t = document.createElement('template'), retry = false, had = document.activeElement;
        t.innerHTML = html;
        t.content.querySelectorAll('template[data-live]').forEach(function (f) {
          var el = document.querySelector('[data-live="' + f.dataset.live + '"]');
          if (!el) return;
          if (usingAsk(el)) { askHeld = true; retry = true; return; }
          if (el.dataset.live === 'r-banner') askHeld = false;
          // The guide must not replace any control while the person is using its step.
          if (el.dataset.live === 'r-guide' && el.contains(document.activeElement)) { retry = true; return; }
          if (selecting(el) || (window.tegoLive.steady && window.tegoLive.steady(el))) { retry = true; return; } // someone is selecting text in it, or reaching for a row: later
          kids(el, f.content);
          el.dataset.h = f.dataset.h;
        });
        ago(); // the region came with the time it was rendered at
        document.dispatchEvent(new CustomEvent('tego:merged')); // a page's own script (review.js) marks the new rows
        if (had && had !== body && !had.isConnected) document.querySelector('main').focus({ preventScroll: true });
        if (retry) setTimeout(refresh, 2000);
        else { renderedSig = wantSig; renderedRev = wantRev; renderedCrev = wantCrev; }
        regionBackoff = 1000;
      })
      .catch(function () {
        if (out || regionRetry) return;
        regionRetry = setTimeout(function () { regionRetry = 0; refresh(); }, regionBackoff);
        regionBackoff = Math.min(regionBackoff * 2, MAX_REGION_BACKOFF);
      })
      .then(function () { fetching = false; if (again) refresh(); });
  }

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
        var steps = window.tegoSteps, heads = steps && steps.heads(rows, fresh); // model-step headers (run.js)
        fresh.querySelectorAll('[data-k]').forEach(function (n) {
          var old = rows.querySelector('[data-k="' + n.dataset.k + '"]');
          if (old) old.remove();
        });
        fresh.querySelectorAll('.tl').forEach(mark);
        var empty = rows.querySelector('.tl-empty');
        if (x.html && empty) empty.remove();
        rows.insertBefore(fresh, rows.firstChild);
        if (steps) steps.regroup(rows, heads);
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
  // A time limit's "until" is read in the zone it was typed in. The form has no way to say it, so each form with one
  // carries a hidden [data-zone] field, which the browser fills as the form's data is made (a post, a preview's link
  // or the script's own FormData): the offset, in minutes west of UTC as getTimezoneOffset says it, at the date typed,
  // since a limit past a clock change has another offset than today. With no script the field stays empty and the
  // dashboard reads the time in its own zone.
  document.addEventListener('formdata', function (e) {
    var f = e.target;
    if (!(f instanceof HTMLFormElement) || !f.querySelector('[data-zone]')) return;
    var typed = e.formData.get('until'), at = typed ? new Date(typed) : new Date();
    if (isNaN(at.getTime())) at = new Date();
    e.formData.set('tz', String(Math.round(at.getTimezoneOffset())));
  });
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
        if (kbd && (!document.activeElement || document.activeElement === body) && foc && foc.isConnected) foc.focus({ preventScroll: true });
        refresh();
      });
  });

  conn('ok');
  connect();
})();
