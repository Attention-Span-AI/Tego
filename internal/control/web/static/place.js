// SPDX-License-Identifier: Apache-2.0
// place.js: keeping the reader's place, on top of live.js (it merges with window.tegoLive) and of a page that works
// without either: every view is a plain link or GET form, and every action a plain form.
(function () {
  'use strict';
  // A filter chip, a facet, a tab, a pager or a GET form changes the view of the page it is on (the same address with
  // another query, or a run page's tab). Loading that page anew put the reader back at the top. Instead a plain
  // left-click on such a link, or the form's submit, inside <main> fetches the view's page and merges its <main> into
  // this one node by node, as live.js merges a live region (with no "new" mark, and the forms taking the new page's
  // values), and the layout's live regions outside <main> with it. The address goes in history (pushState), so the
  // view is still a link to share and Back brings the earlier one back at its own scroll (popstate). The control stays
  // where it stood in the window (when what is above it changed height, the page scrolls by the difference), keeps
  // the focus, and a polite live region says the new count. A link with a modifier key, another button, a target, a
  // download (CSV, JSONL), a #place or another page's address keeps the browser's own behaviour; a fetch that fails or
  // stalls, a redirect or an answer that is not a dashboard page loads the page as a plain link would. Without
  // JavaScript the links and forms load their page as they always did. A page live.js follows nothing on (MCP tools,
  // Model routes: no live regions) changes its view in place the same way.
  var L = window.tegoLive, body = document.body;
  if (!L) return; // no live.js on this page: nothing to build on
  var navGen = 0, navCtl = null, view = location.pathname + location.search, navT = 0, manual = false, STALL = 10000;
  // spot is the history state of this view: the page's scroll, so Back and Forward can bring it back.
  function spot() { return { tego: 1, y: Math.round(window.scrollY) }; }
  function keepSpot() { try { history.replaceState(spot(), ''); } catch (x) { /* too many calls: the next one keeps it */ } }
  // A link that changes this page's view: the same path (a chip, a facet, a pager), or a tab of the page's tab strip. A
  // data-page link or form (a Revoke whose confirmation opens at the top) loads its page as a link does.
  function viewLink(e) {
    if (e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return null;
    var a = e.target instanceof Element ? e.target.closest('a[href]') : null;
    if (!(a instanceof HTMLAnchorElement) || !a.closest('main')) return null;
    if (a.hasAttribute('download') || a.hasAttribute('data-page') || (a.target && a.target !== '_self') || a.getAttribute('href').charAt(0) === '#') return null;
    var u = new URL(a.href, location.href), page = function (p) { return p.split('/').slice(0, 3).join('/'); };
    if (u.origin !== location.origin) return null;
    if (u.pathname !== location.pathname && !(a.closest('.tabs') && page(u.pathname) === page(location.pathname))) return null; // a run's tabs
    if (u.hash) return null; // a link to a place on a page (Never allow's #act-check): the browser loads it and goes there
    return u;
  }
  document.addEventListener('click', function (e) {
    var u = viewLink(e);
    if (!u) return;
    e.preventDefault();
    go(u, { ctrl: e.target.closest('a') });
  });
  function viewForm(e, f, sub) {
    var u = new URL((sub && sub.getAttribute('formaction')) || f.action, location.href);
    if (!f.closest('main') || u.origin !== location.origin || u.pathname !== location.pathname) return;
    if ((f.target && f.target !== '_self') || (sub && sub.formTarget && sub.formTarget !== '_self') || f.hasAttribute('data-page') || (sub && sub.hasAttribute('data-page'))) return;
    var fd = new FormData(f);
    if (sub && sub.name) fd.append(sub.name, sub.value);
    var q = new URLSearchParams(fd).toString();
    u.search = q ? '?' + q : '';
    u.hash = '';
    e.preventDefault();
    var a = document.activeElement, mine = a && a !== body && f.contains(a);
    // typed: the text of the field being typed in as sent, so what is typed while the view loads is kept (put).
    go(u, { ctrl: mine ? a : (sub || f), typed: mine && /^(INPUT|TEXTAREA)$/.test(a.tagName) ? { el: a, val: a.value } : null });
  }
  // where is el's place in <main>: its id, or the child indexes from <main> down, with its tag and text, so a view
  // change that rebuilt it finds its twin.
  function where(el) {
    var m = document.querySelector('main'), path = [], n = el;
    for (; n && n !== m && n.parentElement; n = n.parentElement) path.unshift(Array.prototype.indexOf.call(n.parentElement.children, n));
    return { id: el.id || '', path: n === m ? path : null, tag: el.tagName, text: (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 80) };
  }
  function twin(w) {
    if (!w) return null;
    if (w.id) return document.getElementById(w.id);
    var n = document.querySelector('main');
    for (var i = 0; n && w.path && i < w.path.length; i++) n = n.children[w.path[i]];
    if (n && w.path && n.tagName === w.tag) return n;
    var all = document.querySelectorAll('main ' + w.tag.toLowerCase());
    for (var j = 0; j < all.length; j++) if ((all[j].textContent || '').replace(/\s+/g, ' ').trim().slice(0, 80) === w.text) return all[j];
    return null;
  }
  // sheets loads the new view's stylesheets (a run page's Receipt tab has its own) before it is merged, so it never
  // shows unstyled.
  function sheets(doc) {
    var have = {}, wait = [];
    document.querySelectorAll('link[rel="stylesheet"]').forEach(function (l) { have[l.href] = true; });
    doc.querySelectorAll('main link[rel="stylesheet"]').forEach(function (l) {
      var h = new URL(l.getAttribute('href'), location.href).href, n;
      if (have[h] || new URL(h).origin !== location.origin) return;
      have[h] = true;
      n = document.createElement('link');
      n.rel = 'stylesheet';
      n.href = h;
      wait.push(new Promise(function (ok) { n.onload = n.onerror = ok; setTimeout(ok, 1500); }));
      document.head.appendChild(n);
    });
    return Promise.all(wait);
  }
  // pending shows that a view is on its way: after a moment, a thin bar at the top and the control dimmed.
  function pending(on, ctrl) {
    clearTimeout(navT);
    document.querySelectorAll('.nav-on').forEach(function (n) { n.classList.remove('nav-on'); });
    body.classList.remove('nav-busy');
    if (!on) return document.querySelector('main').removeAttribute('aria-busy');
    document.querySelector('main').setAttribute('aria-busy', 'true');
    navT = setTimeout(function () { body.classList.add('nav-busy'); if (ctrl && ctrl.isConnected) ctrl.classList.add('nav-on'); }, 150);
  }
  function go(u, o) {
    if (navCtl) navCtl.abort();
    var ctl = navCtl = window.AbortController ? new AbortController() : null, gen = ++navGen, stalled = false;
    // From the first view change on, this document's history entries keep their scroll in their state: the browser's
    // own restore would scroll a popstate's old content before its view is fetched. A page load keeps the browser's
    // (leave() sets it back), which restores from the first paint, before this file runs.
    if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
    manual = true;
    if (!o.pop) keepSpot(); // this view's scroll, for Back
    L.hold(true);
    pending(true, o.ctrl);
    // A dashboard that stops answering would leave the busy bar on and the live updates held: after STALL the fetch is
    // given up and the page loaded as the link would (the catch below).
    var slow = ctl ? setTimeout(function () { if (gen === navGen) { stalled = true; ctl.abort(); } }, STALL) : 0;
    o.slow = slow;
    fetch(u.pathname + u.search, { credentials: 'same-origin', cache: 'no-store', signal: ctl ? ctl.signal : undefined })
      .then(function (r) {
        if (r.status === 401 || !r.ok || r.redirected || !/^text\/html/.test(r.headers.get('Content-Type') || '')) throw new Error('a page');
        return r.text();
      })
      .then(function (html) {
        if (gen !== navGen) return;
        var doc = new DOMParser().parseFromString(html, 'text/html');
        // A page of the same kind: followed live (a signature) as this one is, or not (MCP tools, Model routes).
        if (!doc.querySelector('main') || !doc.body.dataset.sig !== !body.dataset.sig) throw new Error('a page');
        return sheets(doc).then(function () { if (gen === navGen) put(doc, u, o); });
      })
      .catch(function (x) {
        if (gen !== navGen || (x && x.name === 'AbortError' && !stalled)) return; // a newer view is on its way
        clearTimeout(slow);
        navCtl = null;
        L.hold(false);
        pending(false);
        if (o.pop) location.replace(u.href); else location.assign(u.href); // the page, as the link would load it
      });
  }
  function put(doc, u, o) {
    var om = document.querySelector('main'), nm = doc.querySelector('main'), root = document.documentElement;
    var ctrl = o.ctrl && o.ctrl.isConnected ? o.ctrl : null, w = ctrl ? where(ctrl) : null;
    // A pager's next page is read from its first row: the list it pages stays where it stood, or comes up to the top
    // of the window when its top was above it. Any other control stays where it stood.
    var pager = ctrl && (ctrl.closest('.runs-pager') || ctrl.id === 'tl-older') ? ctrl.closest('section, .panel') : null;
    var pw = pager ? where(pager) : null, ptop = pager ? pager.getBoundingClientRect().top : 0;
    var before = ctrl ? ctrl.getBoundingClientRect().top : null, focused = ctrl && document.activeElement === ctrl;
    var same = u.pathname + u.search === view, anc = [], n, typing = document.activeElement, typed = null;
    clearTimeout(o.slow);
    // The control's ancestors in <main>, nearest first, with their place: when the control goes with the view (the
    // last query chip's ×, Clear filters), the nearest one the merge kept holds the place and the focus instead.
    for (n = ctrl && ctrl.parentElement; n && n !== om && om.contains(n); n = n.parentElement) anc.push({ el: n, top: n.getBoundingClientRect().top });
    // Text typed in the search field while the view was on its way is the reader's, not the server's older value.
    if (o.typed && typing === o.typed.el && typing.value !== o.typed.val) typed = typing.value;
    document.dispatchEvent(new CustomEvent('tego:leave')); // a page's own script (logs.js) lets go of the old view
    root.style.overflowAnchor = 'none'; // the place is kept here, not by the browser's scroll anchoring as well
    var soft = softKeys(om, nm);
    L.merge(om, nm);
    soft.forEach(function (d) { if (d.isConnected) d.removeAttribute('data-k'); });
    L.attrs(om, nm);
    document.querySelectorAll('[data-live]').forEach(function (el) { // the layout's regions outside <main>
      if (om.contains(el)) return;
      var n = doc.querySelector('[data-live="' + el.dataset.live + '"]');
      if (n) { L.merge(el, n); el.dataset.h = n.dataset.h; }
    });
    var gs = document.querySelector('header .gsearch'), ngs = doc.querySelector('header .gsearch');
    if (gs && ngs) { L.merge(gs, ngs); gs.reset(); }
    om.querySelectorAll('form').forEach(function (f) { f.reset(); }); // the new view's values, as a page load shows them
    if (typed !== null && typing.isConnected) typing.value = typed;
    document.title = doc.title;
    if (doc.body.dataset.title) body.dataset.title = doc.body.dataset.title; // live.js's "(1) …" title reads it
    view = u.pathname + u.search;
    if (!o.pop) history[same ? 'replaceState' : 'pushState'](spot(), '', u.pathname + u.search + u.hash);
    L.after();
    var el = ctrl && ctrl.isConnected ? ctrl : twin(w), list = pager && (pager.isConnected ? pager : twin(pw));
    var kept = null;
    for (var i = 0; !el && i < anc.length; i++) if (anc[i].el.isConnected && om.contains(anc[i].el)) { kept = anc[i]; break; }
    if (o.pop) window.scrollTo(0, o.y || 0);
    else if (list) window.scrollBy(0, list.getBoundingClientRect().top - Math.max(ptop, 0));
    else if (el && before !== null) window.scrollBy(0, el.getBoundingClientRect().top - before);
    else if (kept) window.scrollBy(0, kept.el.getBoundingClientRect().top - kept.top);
    keepSpot();
    requestAnimationFrame(function () { root.style.overflowAnchor = ''; });
    if (!o.pop) {
      // A pager's focus goes to the list it paged, which shows from its first row (its link's twin can stand thousands
      // of pixels below, where the next Tab or Enter would act out of sight); a control the view removed hands it to
      // the first field or link of the nearest part the merge kept, when that is in the window, or to <main>.
      if (list) { list.setAttribute('tabindex', '-1'); list.focus({ preventScroll: true }); }
      else if (el && (focused || el !== document.activeElement)) el.focus({ preventScroll: true });
      else if (!el && ctrl) near(kept && kept.el).focus({ preventScroll: true });
      if (!document.activeElement || document.activeElement === body) om.focus({ preventScroll: true });
    }
    say(list || el);
    navCtl = null;
    pending(false);
    document.dispatchEvent(new CustomEvent('tego:enter')); // and takes the new one
    L.hold(false);
  }
  // softKeys keys, for one merge, each <details> whose class names it alone in both views (Logs' Filters panel), so the
  // merge keeps the open one even when a sibling before it came or went (the query chips' row); returns the keyed old
  // ones, whose key is taken off after (the server's pages carry none).
  function softKeys(om, nm) {
    var out = [];
    om.querySelectorAll('details[class]:not([id]):not([data-k])').forEach(function (d) {
      var sel = 'details.' + d.className.trim().split(/\s+/).map(function (c) { return CSS.escape(c); }).join('.'), nd;
      if (om.querySelectorAll(sel).length !== 1 || nm.querySelectorAll(sel).length !== 1) return;
      nd = nm.querySelector(sel);
      if (nd.id || nd.hasAttribute('data-k') || nd.parentElement.tagName !== d.parentElement.tagName) return;
      d.setAttribute('data-k', '~' + d.className);
      nd.setAttribute('data-k', '~' + d.className);
      out.push(d);
    });
    return out;
  }
  // near is the first field, button or link in part that is in the window, or <main>.
  function near(part) {
    var m = document.querySelector('main'), c = part ? part.querySelectorAll('input:not([type="hidden"]), select, textarea, button, a[href]') : [];
    for (var i = 0; i < c.length; i++) {
      var r = c[i].getBoundingClientRect();
      if (!c[i].disabled && r.height > 0 && r.bottom > 0 && r.top < window.innerHeight) return c[i];
    }
    return m;
  }
  // say tells a screen reader the new view: the chosen item of the control's group and the page's count line.
  function say(el) {
    var box = document.getElementById('nav-say'), parts = [], g, cur, c;
    if (!box) {
      box = document.createElement('div');
      box.id = 'nav-say';
      box.className = 'sr';
      box.setAttribute('role', 'status');
      box.setAttribute('aria-live', 'polite');
      body.appendChild(box);
    }
    function words(n) { // its text pieces apart ("Allowed 151", not "Allowed151")
      var w = document.createTreeWalker(n, NodeFilter.SHOW_TEXT), out = [];
      while (w.nextNode()) out.push(w.currentNode.nodeValue);
      return out.join(' ').replace(/\s+/g, ' ').replace(/\s+([,.])/g, '$1').trim();
    }
    g = el && el.closest('nav, [role="group"], .chips, .tabs');
    cur = g && g.querySelector('[aria-current]:not([aria-current="false"])');
    if (cur) parts.push(words(cur));
    c = document.querySelector('main [data-say], #h-res, .runs-pager > .soft');
    if (!c && (c = document.getElementById('tl-older'))) c = c.parentElement.firstElementChild; // a run's timeline: its rows' range
    if (c && c.id !== 'tl-older') parts.push(words(c));
    if (!parts.length && (c = document.querySelector('main h1'))) parts.push(words(c));
    box.textContent = '';
    setTimeout(function () { box.textContent = parts.join('. '); }, 60); // a fresh text, so the same words are said again
  }
  window.addEventListener('popstate', function (e) {
    var s = e.state;
    if (!s || !s.tego) return; // a #place on the page: the browser's own
    if (location.pathname + location.search === view) return window.scrollTo(0, s.y || 0);
    go(new URL(location.href), { pop: true, y: s.y });
  });
  (function () { // a reload, or Back to this page from another, comes back at its scroll: the browser's own restore
    // does it at the first paint; this one is for an entry it did not (one a view change pushed, loaded anew), and
    // leaves a page the reader has already moved alone.
    var nt = window.performance && performance.getEntriesByType ? performance.getEntriesByType('navigation')[0] : null, s = history.state;
    if (s && s.tego && !location.hash && nt && (nt.type === 'reload' || nt.type === 'back_forward') && window.scrollY < 1) window.scrollTo(0, s.y || 0);
  })();
  // room: the floating ask banner (mvp.css) takes no space, so it lay over the top of the page for as long as an ask
  // waited. While it is up the page holds as much room above its content (--ask-room) and the window scrolls by the
  // same amount: nothing moves on the screen, and scrolling up shows what the banner covers. A page that loads with the
  // banner up gets the same room and the same scroll, so it opens as if the ask had come while it was open; a scroll
  // the browser restored holds the room already. Room the reader is looking at when the banner leaves cannot be scrolled
  // away, so it stays (spare) until the window has passed it. window.tegoRoom is the room, for the scripts that ask
  // whether the reader is at the top.
  var held = 0, spare = false;
  function room(e) {
    var b = document.getElementById('ask-banner'), up = b && !b.classList.contains('ab-leave') && getComputedStyle(b).position === 'fixed';
    var h = up ? Math.ceil(b.getBoundingClientRect().height) + 8 : 0, y = window.scrollY;
    spare = h < held && y < held - h;
    if (h === held || spare) return;
    document.documentElement.style.setProperty('--ask-room', h + 'px');
    window.scrollTo(0, e === true ? Math.max(y, h) : y + h - held);
    held = window.tegoRoom = h;
  }
  document.addEventListener('tego:merged', room);
  document.addEventListener('tego:enter', room);
  window.addEventListener('resize', room);
  window.addEventListener('scroll', function () { if (spare) room(); }, { passive: true });
  room(true);
  keepSpot();
  var spotT = 0;
  window.addEventListener('scroll', function () { clearTimeout(spotT); spotT = setTimeout(keepSpot, 250); }, { passive: true });
  // Leaving the page (a reload, a link, a form's post): the entry's scroll goes in its state and the browser restores
  // it itself on the way back, from the first paint (with 'manual' the top showed first, then a jump). Back to a page
  // kept whole (the back/forward cache) takes up 'manual' again for its own views.
  function leave() { keepSpot(); if ('scrollRestoration' in history) history.scrollRestoration = 'auto'; }
  window.addEventListener('beforeunload', leave); // before a reload takes the entry's state (pagehide is too late)
  window.addEventListener('pagehide', leave);
  window.addEventListener('pageshow', function (e) { if (e.persisted && manual && 'scrollRestoration' in history) history.scrollRestoration = 'manual'; });

  // A GET form changes the view; a form posted as a plain form keeps its place. live.js answers the forms it posts in
  // the background first (Allow once, Deny, Block now, the rule forms): those are defaultPrevented here.
  document.addEventListener('submit', function (e) {
    var f = e.target, sub = e.submitter;
    if (!(f instanceof HTMLFormElement) || e.defaultPrevented || !window.URLSearchParams) return;
    if (f.method === 'get') viewForm(e, f, sub);
    else if (f.method === 'post') keepPlace(f, sub);
  });
  document.addEventListener('tego:here', function () { view = location.pathname + location.search; keepSpot(); }); // an answer's page

  // keepPlace: a form posted as a plain form (Pause, Resume, Lift, MCP tools' and Model routes' forms)
  // answers 303 back to its page, which loaded at the top. Its place goes in this tab's sessionStorage first, and the
  // page it comes back to (the same path, within a few seconds) scrolls the form back to where it stood; the line the
  // action left is said in a toast when its banner is out of sight above.
  function keepPlace(f, sub) {
    if ((f.target && f.target !== '_self') || !f.closest('main')) return;
    var el = sub || f;
    try {
      sessionStorage.setItem('tego-place', JSON.stringify({ p: location.pathname, y: Math.round(window.scrollY), w: where(el), top: el.getBoundingClientRect().top, at: Date.now() }));
    } catch (x) { /* no storage: the page loads at the top, as without JavaScript */ }
  }
  (function () {
    var pl = null;
    try { pl = JSON.parse(sessionStorage.getItem('tego-place') || 'null'); sessionStorage.removeItem('tego-place'); } catch (x) { return; }
    if (!pl || pl.p !== location.pathname || location.hash || !(Date.now() - pl.at < 30000)) return;
    var el = twin(pl.w), fl = document.getElementById('flash');
    window.scrollTo(0, pl.y || 0);
    if (el) window.scrollBy(0, el.getBoundingClientRect().top - pl.top);
    keepSpot();
    if (fl && fl.getBoundingClientRect().bottom < 0) {
      var t = fl.querySelector('.grow strong'), l = fl.querySelector('.grow a.link');
      L.toast({ ok: fl.classList.contains('banner-ok'), text: t ? t.textContent : '', link: l ? l.getAttribute('href') : '', link_text: l ? l.textContent : '' }, 'flash');
    }
  })();

  // steady keeps the Overview's two lists, which grow at the top, from moving a row as it is reached for: live.js leaves
  // such a list alone while the pointer or the keyboard's focus is in it, for STEADY at most, so a pointer left resting
  // there does not stop the page following its runs.
  var STEADY = 5000;
  L.steady = function (el) {
    if (!/^r-ov-(recent|refusals)$/.test(el.dataset.live) || !(el.matches(':hover') || el.contains(document.activeElement))) { el.tegoWait = 0; return false; }
    el.tegoWait = el.tegoWait || Date.now();
    return Date.now() - el.tegoWait < STEADY;
  };
})();
