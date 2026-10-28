// SPDX-License-Identifier: Apache-2.0
// logs.js: the Logs page's own behaviour, on top of a page that works without it (a GET form, links, an Older lines
// link, each row's line link). It never reloads the page:
// - the live tail: when the ledger moves (live.js's "tego:moved" event) it asks GET /logs/rows for the rows newer than
//   the newest one shown and puts them at the top when the reader is there, or else counts them in a "N new lines"
//   pill that brings them in; with more than a page of new lines the pill loads the newest page instead. While it
//   follows, the rows region is its own (live.js no longer re-renders it), so rows opened in place stay open;
// - older lines come in place under the rows (the Older lines link, or on its own as it scrolls into view, up to
//   AUTO pages);
// - a row opens in place (its chevron, a click on the row, or Enter) with every field of its line from GET
//   /logs/line, and closes again (Escape);
// - j and k move through the rows, o opens the line's page, / goes to the query;
// - "Save this view" keeps the page's address under a name in this browser (localStorage), listed as chips.
// A filter, facet or chip changes the view in place (place.js, keeping the reader's place): place.js says tego:leave
// before it merges the new view and tego:enter after, and the rows' part (mount) lets go of the old view's rows (its
// listeners, its observer, its fetches on the way) and takes the new view's, so nothing is followed twice.
(function () {
  'use strict';
  var KEY = 'tego-logs-views', AUTO = 10, MAXROWS = 2000;

  // --- saved views: a name and the page's own address, kept in this browser only
  function views() {
    try { var v = JSON.parse(localStorage.getItem(KEY) || '[]'); return Array.isArray(v) ? v : []; } catch (e) { return []; }
  }
  function keep(v) { try { localStorage.setItem(KEY, JSON.stringify(v)); return true; } catch (e) { return false; } }
  function ownLogs(u) { return typeof u === 'string' && /^\/logs(\?|$)/.test(u); }
  function drawViews() {
    var row = document.getElementById('lq-saved');
    if (!row) return;
    var list = row.querySelector('.lq-saved-list'), here = location.pathname + location.search;
    list.textContent = '';
    views().forEach(function (v, i) {
      if (!v || !ownLogs(v.u) || typeof v.n !== 'string') return;
      var chip = document.createElement('span'), a = document.createElement('a'), x = document.createElement('button');
      chip.className = 'chip lq-view';
      a.href = v.u;
      a.textContent = v.n; // text, never markup
      if (v.u === here) a.setAttribute('aria-current', 'true');
      x.type = 'button';
      x.className = 'x';
      x.textContent = '×';
      x.title = 'Forget this view';
      x.setAttribute('aria-label', 'Forget the view ' + v.n);
      x.addEventListener('click', function () {
        var all = views();
        all.splice(i, 1);
        keep(all);
        drawViews();
      });
      chip.append(a, x);
      list.appendChild(chip);
    });
    row.hidden = false;
  }
  document.addEventListener('click', function (e) { // the button a view change may bring again: one listener for all
    if (!(e.target instanceof Element) || !e.target.closest('.lq-save')) return;
    var name = window.prompt('Name this view (kept in this browser only):', '');
    if (name === null) return;
    name = name.trim().slice(0, 60);
    if (!name) return;
    var all = views().filter(function (v) { return v && v.n !== name; });
    all.push({ n: name, u: location.pathname + location.search });
    if (!keep(all)) { window.alert('This browser does not let the page keep views. Keep the link instead.'); return; }
    drawViews();
  });
  try { drawViews(); } catch (e) { /* no storage: the built-in views and links still work */ }

  // --- "/" goes to the query from anywhere on the page
  function typing(t) { return t && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable); }
  document.addEventListener('keydown', function (e) {
    if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey || typing(e.target)) return;
    var q = document.querySelector('.lq-where input');
    if (!q) return;
    e.preventDefault();
    var sheet = q.closest('details');
    if (sheet && !sheet.open) sheet.open = true;
    q.focus();
    q.select();
  });

  // mount follows the rows of the view shown and returns what lets them go again, or null when the view has none
  // (grouped, or nothing matched).
  function mount() {
    var tbody = document.getElementById('lq-rows');
    document.documentElement.classList.toggle('lq-js', !!tbody);
    if (!tbody) return null;
    var dead = false, offs = []; // dead: this view was left (its fetches' answers are dropped); offs: its listeners
    function on(el, type, fn, opt) { el.addEventListener(type, fn, opt); offs.push(function () { el.removeEventListener(type, fn, opt); }); }
    var region = tbody.closest('[data-live]');
    var shownN = document.querySelector('.lq-shown'), totalN = document.querySelector('.lq-total');
    // grouped writes n as the page does (countWord): 15523 reads 15,523
    function grouped(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ','); }
    var pill = document.querySelector('.lq-pill'), pillT = pill && pill.querySelector('.lq-pill-t');
    var rowsW = document.querySelector('.lq-rows-w');
    var older = document.getElementById('lq-older');
    var waiting = null, waitingN = 0, more = false, busy = false, again = false, autoLoads = 0, cur = null;
    var onOlderPage = /[?&]before=/.test(location.search);

    function counts(total) {
      if (shownN) shownN.textContent = grouped(tbody.querySelectorAll('tr.lq-r').length);
      if (totalN && total !== null && total !== undefined && total !== '') totalN.textContent = grouped(total);
      // the word after the total follows it, as the page writes it (plural): 1 row, 3 rows
      if (rowsW && total !== null && total !== undefined && total !== '') rowsW.textContent = Number(total) === 1 ? 'row' : 'rows';
    }
    function frag(html) {
      var t = document.createElement('template');
      t.innerHTML = html;
      return t.content;
    }
    function get(url) {
      return fetch(url, { credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
        if (!r.ok) throw new Error(r.status);
        return r.text().then(function (html) {
          if (dead) throw new Error('the view was left'); // its answer is not this view's
          return { r: r, html: html };
        });
      });
    }
    function mark(el) {
      el.classList.add('live-new');
      setTimeout(function () { el.classList.remove('live-new'); }, 2600);
    }
    function atTop() { return window.scrollY - (window.tegoRoom || 0) < 120; }

    // the rows of box that are row n again: the same line, or the older row of n's folded refusal group (data-f
    // starts with the run, since a group never spans runs: another run's same refusal stays)
    function same(box, n) {
      var out = Array.prototype.slice.call(box.querySelectorAll('tr[data-k="' + n.dataset.k + '"]'));
      if (n.dataset.f) out = out.concat(Array.prototype.slice.call(box.querySelectorAll('tr[data-f="' + n.dataset.f + '"]')));
      return out.filter(function (o) { return o !== n; });
    }
    // put fresh rows at the top, dropping any row they show again
    function prepend(f) {
      var rows = Array.prototype.slice.call(f.querySelectorAll('tr.lq-r'));
      rows.forEach(function (n) {
        same(tbody, n).forEach(dropRow);
        mark(n);
      });
      tbody.insertBefore(f, tbody.firstChild);
      var all = tbody.querySelectorAll('tr.lq-r');
      for (var i = all.length - 1; i >= MAXROWS; i--) dropRow(all[i]);
      if (all.length > MAXROWS) { // a rule-change row below the last row kept went with the rows cut
        for (var n = all[MAXROWS - 1].nextElementSibling, x; n; n = x) { x = n.nextElementSibling; if (n.classList.contains('rc-row')) n.remove(); }
      }
      if (all.length > MAXROWS && older) { // the cut rows are older again: the link pages from the last row kept
        tbody.dataset.next = cursorOf(all[MAXROWS - 1]) || tbody.dataset.next;
        older.hidden = false;
      }
    }
    function dropRow(tr) {
      var p = panelOf(tr);
      if (p) p.remove();
      if (cur === tr) cur = null;
      tr.remove();
    }
    function cursorOf(tr) { return tr.dataset.c || ''; }
    function showPill() {
      if (!pill) return;
      pillT.textContent = more ? 'More than a page of new rows · show the newest' :
        waitingN + (waitingN === 1 ? ' new row' : ' new rows');
      pill.hidden = false;
    }
    // toTop brings the reader to the top, where the newest row is and the tail follows on its own (atTop). The page's
    // scroll anchoring is off for the jump: with it, Chrome kept the old rows in view while the new ones went in above
    // them, and the reader stayed down the page with the pill back at once.
    function toTop() {
      var root = document.documentElement;
      root.style.overflowAnchor = 'none';
      window.scrollTo({ top: 0, behavior: 'instant' });
      requestAnimationFrame(function () { root.style.overflowAnchor = ''; });
    }
    function takeWaiting() {
      if (pill) pill.hidden = true;
      if (more) { more = false; waiting = null; waitingN = 0; return newest(); }
      var jump = !atTop();
      if (waiting) {
        if (jump) document.documentElement.style.overflowAnchor = 'none';
        prepend(waiting);
      }
      waiting = null;
      waitingN = 0;
      counts();
      if (jump) toTop();
    }
    // newest loads the first page again, in place: after more than a page of new lines came at once
    function newest() {
      if (dead) return;
      return get(tbody.dataset.rows).then(function (x) {
        tbody.querySelectorAll('tr.lx-row').forEach(function (r) { r.remove(); });
        tbody.textContent = '';
        tbody.appendChild(frag(x.html));
        tbody.dataset.after = x.r.headers.get('X-Tego-After') || tbody.dataset.after;
        tbody.dataset.next = x.r.headers.get('X-Tego-Next') || '';
        if (older) older.hidden = !tbody.dataset.next;
        autoLoads = 0;
        counts(x.r.headers.get('X-Tego-Rows'));
        toTop();
      }).catch(function () { /* the next change asks again */ });
    }
    // tail asks for the rows after the newest one shown
    function tail() {
      if (dead) return;
      if (busy) { again = true; return; }
      if (!tbody.dataset.after || onOlderPage) return;
      busy = true;
      again = false;
      var u = tbody.dataset.rows + (tbody.dataset.rows.indexOf('?') < 0 ? '?' : '&') + 'after=' + encodeURIComponent(tbody.dataset.after);
      get(u).then(function (x) {
        var n = x.html ? frag(x.html) : null, k = n ? n.querySelectorAll('tr.lq-r').length : 0;
        tbody.dataset.after = x.r.headers.get('X-Tego-After') || tbody.dataset.after;
        if (x.r.headers.get('X-Tego-More') === '1') { more = true; showPill(); counts(x.r.headers.get('X-Tego-Rows')); return; }
        if (!k) return;
        if (atTop() && !waiting && !document.querySelector('tr.lx-row:not([hidden])')) {
          prepend(n);
        } else {
          if (!waiting) waiting = document.createDocumentFragment();
          n.querySelectorAll('tr.lq-r').forEach(function (r) { same(waiting, r).forEach(function (o) { o.remove(); }); });
          waiting.insertBefore(n, waiting.firstChild);
          waitingN = waiting.querySelectorAll('tr.lq-r').length;
          showPill();
        }
        counts(x.r.headers.get('X-Tego-Rows'));
      }).catch(function () { /* the next change asks again */ })
        .then(function () { busy = false; if (again) tail(); });
    }
    if (region && !onOlderPage) {
      // The rows are followed here: live.js leaves this region alone (it would re-render the rows and close the open
      // ones), and still refreshes the counts and facets around them.
      region.removeAttribute('data-live');
      on(document, 'tego:moved', tail);
    }
    if (pill) on(pill, 'click', takeWaiting);
    on(window, 'scroll', function () { if (atTop() && waiting && !more) takeWaiting(); }, { passive: true });

    // --- older lines, in place
    var loadingOlder = false;
    function loadOlder(auto) {
      if (dead || loadingOlder || !tbody.dataset.next) return;
      if (auto && autoLoads >= AUTO) return;
      loadingOlder = true;
      if (older) older.setAttribute('aria-busy', 'true');
      var u = tbody.dataset.rows + (tbody.dataset.rows.indexOf('?') < 0 ? '?' : '&') + 'before=' + encodeURIComponent(tbody.dataset.next);
      get(u).then(function (x) {
        var f = frag(x.html);
        f.querySelectorAll('tr.lq-r').forEach(function (n) {
          if (tbody.querySelector('tr[data-k="' + n.dataset.k + '"]')) n.remove();
        });
        tbody.appendChild(f);
        tbody.dataset.next = x.r.headers.get('X-Tego-Next') || '';
        if (auto) autoLoads++;
        if (older) {
          older.hidden = !tbody.dataset.next;
          if (tbody.dataset.next) older.href = older.href.replace(/before=[^&]*/, 'before=' + encodeURIComponent(tbody.dataset.next));
        }
        counts(x.r.headers.get('X-Tego-Rows'));
      }).catch(function () { /* the link still works as a page */ })
        .then(function () { loadingOlder = false; if (older) older.removeAttribute('aria-busy'); });
    }
    if (older) {
      on(older, 'click', function (e) { e.preventDefault(); autoLoads = 0; loadOlder(false); });
      if (window.IntersectionObserver) {
        var io = new IntersectionObserver(function (es) {
          es.forEach(function (en) { if (en.isIntersecting) loadOlder(true); });
        }, { rootMargin: '600px 0px' });
        io.observe(older);
        offs.push(function () { io.disconnect(); });
      }
    }

    // --- a row opened in place (its run and line are its data-k, run-seq)
    function lineOf(tr) {
      var k = tr.dataset.k, i = k.lastIndexOf('-');
      return { run: k.slice(0, i), seq: k.slice(i + 1) };
    }
    function pageOf(tr) { var a = tr.querySelector('a.lw-line'); return a ? a.href : ''; }
    function panelOf(tr) {
      var n = tr.nextElementSibling;
      return n && n.classList.contains('lx-row') ? n : null;
    }
    function closeRow(tr) {
      if (!tr) return;
      var p = panelOf(tr), b = tr.querySelector('.lx-tog');
      if (p) p.hidden = true;
      if (b) b.setAttribute('aria-expanded', 'false');
      tr.classList.remove('lx-open');
    }
    function openRow(tr) {
      var p = panelOf(tr), b = tr.querySelector('.lx-tog');
      if (b) b.setAttribute('aria-expanded', 'true');
      tr.classList.add('lx-open');
      if (p) { p.hidden = false; return; }
      p = document.createElement('tr');
      p.className = 'lx-row';
      p.id = 'lx-' + tr.dataset.k;
      var td = document.createElement('td');
      td.colSpan = tr.children.length;
      td.className = 'lx-cell';
      td.textContent = 'Reading the line…';
      p.appendChild(td);
      tr.after(p);
      if (b) b.setAttribute('aria-controls', p.id);
      var l = lineOf(tr);
      get('/logs/line?run=' + encodeURIComponent(l.run) + '&seq=' + encodeURIComponent(l.seq)).then(function (x) {
        td.textContent = '';
        td.appendChild(frag(x.html));
      }).catch(function () {
        td.textContent = '';
        var a = document.createElement('a');
        a.className = 'link';
        a.href = pageOf(tr);
        a.textContent = 'The line could not be read here. Open its page.';
        td.appendChild(a);
      });
    }
    function toggle(tr) {
      if (tr.classList.contains('lx-open')) closeRow(tr); else openRow(tr);
    }
    on(tbody, 'click', function (e) {
      var t = e.target, tr = t.closest('tr.lq-r');
      if (t.closest('.lx-copy')) return copy(t.closest('.lx-copy'));
      if (!tr) return;
      if (t.closest('.lx-tog')) { toggle(tr); current(tr, false); return; }
      if (t.closest('a, button, input, select, textarea, form, summary')) return;
      var s = window.getSelection();
      if (s && !s.isCollapsed) return; // selecting text, not opening
      toggle(tr);
      current(tr, false);
    });
    function copy(btn) {
      var raw = btn.parentNode.querySelector('template.lx-raw'), text = raw ? raw.content.textContent : '';
      function done(ok) {
        var was = btn.textContent;
        btn.textContent = ok ? 'Copied' : 'Copy failed: select the line on its page';
        setTimeout(function () { btn.textContent = was; }, 2000);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
      else done(false);
    }

    // --- j and k move through the rows; Enter opens one here, o opens its page, Escape closes it
    function current(tr, focus) {
      if (cur && cur !== tr) { cur.classList.remove('lq-cur'); cur.removeAttribute('tabindex'); }
      cur = tr;
      if (!tr) return;
      tr.classList.add('lq-cur');
      tr.setAttribute('tabindex', '-1');
      if (focus) {
        tr.focus({ preventScroll: true });
        var r = tr.getBoundingClientRect(), top = 120;
        if (r.top < top || r.bottom > window.innerHeight - 40) window.scrollBy({ top: r.top - window.innerHeight / 3 });
      }
    }
    on(document, 'keydown', function (e) {
      if (e.ctrlKey || e.metaKey || e.altKey || typing(e.target)) return;
      var rows, i;
      switch (e.key) {
        case 'j': case 'k':
          rows = Array.prototype.slice.call(tbody.querySelectorAll('tr.lq-r'));
          if (!rows.length) return;
          i = cur ? rows.indexOf(cur) : -1;
          i = e.key === 'j' ? Math.min(rows.length - 1, i + 1) : Math.max(0, i < 0 ? 0 : i - 1);
          current(rows[i], true);
          if (e.key === 'j' && i >= rows.length - 3) loadOlder(true);
          e.preventDefault();
          break;
        case 'Enter':
          if (!cur || e.target !== cur) return;
          toggle(cur);
          e.preventDefault();
          break;
        case 'o':
          if (cur && pageOf(cur)) location.assign(pageOf(cur));
          break;
        case 'Escape':
          if (cur && cur.classList.contains('lx-open')) { closeRow(cur); cur.focus({ preventScroll: true }); }
          break;
      }
    });
    counts();
    return function () { // the view is left: drop its listeners and its observer; answers on the way are dropped
      dead = true;
      offs.forEach(function (off) { off(); });
      offs = [];
    };
  }
  var unmount = mount();
  document.addEventListener('tego:leave', function () { if (unmount) unmount(); unmount = null; });
  document.addEventListener('tego:enter', function () {
    try { drawViews(); } catch (e) { /* no storage */ }
    unmount = mount();
  });
})();
