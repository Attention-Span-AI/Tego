/* SPDX-License-Identifier: Apache-2.0 */
/* Line numbers beside the raw contract editors (C126). A textarea marked data-lines gets a gutter of line numbers that
   follows its scrolling, the number of the line the cursor is on marked, and a "Line L of N, column C" status under it;
   a diagnostic's "line N" link moves the cursor to that line. Without this script the editor is the plain textarea and
   the Check's own list of the lines it names (rc-lines) is still on the page. Nothing here sends or changes the text. */
(() => {
  'use strict';
  const MAX_LINES = 10000; // a longer text keeps the status line and no gutter
  function lineCount(v) { let n = 1; for (let i = v.indexOf('\n'); i >= 0; i = v.indexOf('\n', i + 1)) n++; return n; }
  function lineAt(v, pos) { let n = 1; for (let i = v.indexOf('\n'); i >= 0 && i < pos; i = v.indexOf('\n', i + 1)) n++; return n; }
  function lineStart(v, n) { let p = 0; for (let k = 1; k < n; k++) { const i = v.indexOf('\n', p); if (i < 0) return p; p = i + 1; } return p; }
  function enhance(ta) {
    if (!ta.dataset || ta.dataset.linesReady || !ta.parentNode) return;
    ta.dataset.linesReady = '1';
    const wrap = document.createElement('span'), gut = document.createElement('span'), status = document.createElement('span');
    wrap.className = 'ln-wrap'; gut.className = 'ln-gutter'; gut.setAttribute('aria-hidden', 'true');
    status.className = 'ln-status soft'; status.id = (ta.id || 'editor') + '-pos';
    ta.parentNode.insertBefore(wrap, ta); wrap.append(gut, ta);
    wrap.after(status);
    let count = 0, cur = 0, spans = [];
    function build(n) {
      count = n; spans = []; gut.textContent = '';
      if (n > MAX_LINES) { wrap.classList.add('ln-off'); return; }
      wrap.classList.remove('ln-off');
      const frag = document.createDocumentFragment();
      for (let i = 1; i <= n; i++) { const s = document.createElement('span'); s.textContent = String(i); frag.append(s); spans.push(s); }
      gut.append(frag); cur = 0;
    }
    function metrics() {
      const cs = getComputedStyle(ta), bw = parseFloat(cs.borderTopWidth) + parseFloat(cs.borderBottomWidth);
      gut.style.fontSize = cs.fontSize; gut.style.lineHeight = cs.lineHeight; gut.style.paddingTop = cs.paddingTop;
      // The textarea's own horizontal scrollbar takes height the gutter must keep, or the last numbers never scroll into view.
      const gw = wrap.classList.contains('ln-off') ? 0 : gut.offsetWidth;
      ta.style.marginLeft = gw + 'px'; ta.style.width = 'calc(100% - ' + gw + 'px)';
      gut.style.paddingBottom = (parseFloat(cs.paddingBottom) + Math.max(0, ta.offsetHeight - ta.clientHeight - bw)) + 'px';
    }
    function sync() { gut.scrollTop = ta.scrollTop; }
    function mark() {
      const v = ta.value, n = lineAt(v, ta.selectionStart), col = ta.selectionStart - lineStart(v, n) + 1;
      if (spans.length) {
        if (cur && spans[cur - 1]) spans[cur - 1].classList.remove('ln-cur');
        if (spans[n - 1]) spans[n - 1].classList.add('ln-cur');
        cur = n;
      }
      status.textContent = 'Line ' + n + ' of ' + count + ', column ' + col;
    }
    function update() { const n = lineCount(ta.value); if (n !== count) build(n); metrics(); sync(); mark(); }
    ta.addEventListener('input', update);
    ta.addEventListener('scroll', sync);
    ['keyup', 'click', 'focus'].forEach(k => ta.addEventListener(k, mark));
    if (typeof ResizeObserver === 'function') new ResizeObserver(() => { metrics(); sync(); }).observe(ta);
    update();
  }
  // goto moves the cursor to the start of line n of ta and scrolls it into view; it reports whether it could.
  function goto(ta, n) {
    const v = ta.value;
    if (!(n >= 1) || n > lineCount(v)) return false;
    const p = lineStart(v, n), end = v.indexOf('\n', p);
    ta.focus(); ta.setSelectionRange(p, end < 0 ? v.length : end);
    const lh = parseFloat(getComputedStyle(ta).lineHeight) || 20;
    ta.scrollTop = Math.max(0, (n - 1) * lh - ta.clientHeight / 3);
    ta.dispatchEvent(new Event('scroll'));
    ta.dispatchEvent(new Event('keyup')); // setSelectionRange fires no event the status line listens to
    return true;
  }
  function attach() { document.querySelectorAll('textarea[data-lines]').forEach(enhance); }
  attach();
  if (document.documentElement.dataset.linesLoaded) return; // a view entered again runs this file again: wire once
  document.documentElement.dataset.linesLoaded = '1';
  document.addEventListener('click', e => {
    const a = e.target.closest && e.target.closest('a[data-goto-line]');
    if (!a) return;
    const ta = document.getElementById(a.getAttribute('data-goto-for') || '');
    if (ta && ta.dataset.linesReady && goto(ta, parseInt(a.getAttribute('data-goto-line'), 10))) e.preventDefault();
  });
  document.addEventListener('tego:here', attach);
  document.addEventListener('tego:enter', attach);
  document.addEventListener('tego:merged', attach);
})();
