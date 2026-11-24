// SPDX-License-Identifier: Apache-2.0
(function () {
  'use strict';
  var L = window.tegoLive, body = document.body;
  if (!L) return; // no live.js on this page: nothing to build on
  function strips() {
    document.querySelectorAll('.tabs').forEach(function (t) {
      var cur = t.querySelector('[aria-current="page"]'), end = function () { t.classList.toggle('at-end', t.scrollLeft + t.clientWidth >= t.scrollWidth - 4); };
      if (cur && (cur.offsetLeft + cur.offsetWidth > t.scrollLeft + t.clientWidth || cur.offsetLeft < t.scrollLeft)) t.scrollLeft = cur.offsetLeft - 16;
      if (!t.tegoStrip) { t.tegoStrip = true; t.addEventListener('scroll', end, { passive: true }); }
      end();
    });
  }
  var liveAfter = L.after;
  L.after = function () { liveAfter(); strips(); };
  strips();
  var seenAsks = Object.create(null);
  (L.initialAskKeys || '').split(' ').forEach(function (k) { if (k) seenAsks[k] = true; });
  function askSay() {
    var nav = document.querySelector('.nav[data-ask-keys]'), say = document.getElementById('ask-say'), fresh = false;
    if (!nav) return; // a missing navigation strip is not an empty set of pending requests
    var pending = Object.create(null);
    nav.dataset.askKeys.split(' ').forEach(function (k) {
      if (!k) return;
      pending[k] = true;
      if (!seenAsks[k]) fresh = true;
    });
    seenAsks = pending; // retain only pending keys; a request that leaves and returns is a new arrival
    if (fresh && say) { say.textContent = ''; setTimeout(function () { say.textContent = 'A new request is waiting for you on Approvals.'; }, 60); }
  }
  askSay(); // catch arrivals while this script was loading, without announcing the first-painted requests
  document.addEventListener('tego:merged', askSay);
  document.addEventListener('tego:enter', askSay);
  var navGen = 0, navCtl = null, view = location.pathname + location.search, navT = 0, manual = false, STALL = 10000;
  function spot() { return { tego: 1, y: Math.round(window.scrollY) }; }
  function keepSpot() { try { history.replaceState(spot(), ''); } catch (x) { /* too many calls: the next one keeps it */ } }
  function viewLink(e) {
    if (e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return null;
    var a = e.target instanceof Element ? e.target.closest('a[href]') : null;
    if (!(a instanceof HTMLAnchorElement) || !a.closest('main')) return null;
    var filter = a.hasAttribute('data-filter-open') && document.querySelector('dialog.filter-sheet');
    if (filter && typeof filter.showModal === 'function') return null;
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
    go(u, { ctrl: mine ? a : (sub || f), typed: mine && /^(INPUT|TEXTAREA)$/.test(a.tagName) ? { el: a, val: a.value } : null });
  }
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
    if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
    manual = true;
    if (!o.pop) keepSpot(); // this view's scroll, for Back
    L.hold(true);
    pending(true, o.ctrl);
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
    var pager = ctrl && (ctrl.closest('.runs-pager') || ctrl.id === 'tl-older') ? ctrl.closest('section, .panel') : null;
    var pw = pager ? where(pager) : null, ptop = pager ? pager.getBoundingClientRect().top : 0;
    var before = ctrl ? ctrl.getBoundingClientRect().top : null, focused = ctrl && document.activeElement === ctrl;
    var same = u.pathname + u.search === view, anc = [], n, typing = document.activeElement, typed = null;
    clearTimeout(o.slow);
    for (n = ctrl && ctrl.parentElement; n && n !== om && om.contains(n); n = n.parentElement) anc.push({ el: n, top: n.getBoundingClientRect().top });
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
  function near(part) {
    var m = document.querySelector('main'), c = part ? part.querySelectorAll('input:not([type="hidden"]), select, textarea, button, a[href]') : [];
    for (var i = 0; i < c.length; i++) {
      var r = c[i].getBoundingClientRect();
      if (!c[i].disabled && r.height > 0 && r.bottom > 0 && r.top < window.innerHeight) return c[i];
    }
    return m;
  }
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
    var nt = window.performance && performance.getEntriesByType ? performance.getEntriesByType('navigation')[0] : null, s = history.state;
    if (s && s.tego && !location.hash && nt && (nt.type === 'reload' || nt.type === 'back_forward') && window.scrollY < 1) window.scrollTo(0, s.y || 0);
  })();
  keepSpot();
  var spotT = 0;
  window.addEventListener('scroll', function () { clearTimeout(spotT); spotT = setTimeout(keepSpot, 250); }, { passive: true });
  function leave() { keepSpot(); if ('scrollRestoration' in history) history.scrollRestoration = 'auto'; }
  window.addEventListener('beforeunload', leave); // before a reload takes the entry's state (pagehide is too late)
  window.addEventListener('pagehide', leave);
  window.addEventListener('pageshow', function (e) { if (e.persisted && manual && 'scrollRestoration' in history) history.scrollRestoration = 'manual'; });

  document.addEventListener('submit', function (e) {
    var f = e.target, sub = e.submitter;
    if (!(f instanceof HTMLFormElement) || e.defaultPrevented || !window.URLSearchParams) return;
    if (f.method === 'get') viewForm(e, f, sub);
    else if (f.method === 'post') keepPlace(f, sub);
  });
  document.addEventListener('tego:here', function () { view = location.pathname + location.search; keepSpot(); }); // an answer's page

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

  var STEADY = 5000;
  L.steady = function (el) {
    if (!/^r-ov-(recent|refusals)$/.test(el.dataset.live) || !(el.matches(':hover') || el.contains(document.activeElement))) { el.tegoWait = 0; return false; }
    el.tegoWait = el.tegoWait || Date.now();
    return Date.now() - el.tegoWait < STEADY;
  };
})();

(function () {
  'use strict';
  var opener = null;
  document.addEventListener('click', function (e) {
    var a = e.target.closest('[data-filter-open]');
    var sheet = document.querySelector('dialog.filter-sheet');
    if (a && sheet && typeof sheet.showModal === 'function' && !e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey && e.button === 0) {
      e.preventDefault(); opener = a; sheet.showModal();
    }
    if (e.target.closest('[data-filter-close]') && sheet) sheet.close();
  });
  document.addEventListener('close', function (e) {
    if (e.target.matches('dialog.filter-sheet') && opener && opener.isConnected) opener.focus();
  }, true);
  document.addEventListener('tego:leave', function () {
    var sheet = document.querySelector('dialog.filter-sheet[open]');
    if (sheet) sheet.close();
  });
})();

document.addEventListener('keydown', function (e) {
  var sheet = document.querySelector('dialog.filter-sheet[open]');
  if (!sheet || e.key !== 'Tab') return;
  var stops = Array.from(sheet.querySelectorAll('a[href],button,input,select,textarea,summary,[tabindex]')).filter(function (el) {
    if (el.disabled || el.tabIndex < 0 || !el.getClientRects().length) return false;
    for (var d = el.parentElement; d && d !== sheet; d = d.parentElement) {
      if (d.tagName === 'DETAILS' && !d.open && !d.querySelector('summary').contains(el)) return false;
    }
    return true;
  });
  var first = stops[0], last = stops[stops.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
});
