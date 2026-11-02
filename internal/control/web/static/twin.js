// SPDX-License-Identifier: Apache-2.0
// twin.js: the run page's Block now panel (run.tmpl blockbody) says in its terminal twin the command its form makes.
// The page writes the twin with placeholders, tego block <run> <exec|net|path> <value>. Once the form holds a value
// (typed, or filled in by a timeline row's Block link) this script writes the form's kind, value and time limit in
// their place, each word quoted by internal/shellword's rule, so the line can be pasted as it stands and does what the
// form does. The placeholders stay while the form names no command yet (no value; for… or until… with its field
// empty), for a path that is not absolute (the form refuses one, and tego block would read it against the terminal's
// folder), and for a value holding a character record.Printable escapes for a terminal: a control, which the page
// does not show, or an invisible character such as a bidi override, which it shows as ⟦U+…⟧ (shown.go; a zero-width
// joiner as it is). The line read would not be the line pasted, and a terminal could act on such a character. A live
// update (live.js) or a view change (place.js) merges the server's twin back in, so each is followed by another fill.
// The twin is written only when its words change, so a selection in it outlives the live updates that leave it as it
// is. Without JavaScript the placeholders stay.
(function () {
  'use strict';
  // BARE is a word shellword.Quote leaves as it is: ASCII letters, digits and / . _ - : @ , + =, not starting with =
  // (zsh reads =name as a program's path). ESC is what it writes outside the single quotes of any other word, each
  // after a \ as word() does: a ' or a \ (fish reads \' and \\ inside single quotes as escapes). UNSAFE is a
  // character record.Printable escapes for a terminal: a C0 or C1 control or DEL, a format character (Cf), a line or
  // paragraph separator, or one of the tag block. TestTwinJSRules holds all three, and word(), to the Go side.
  var BARE = /^[\w\/.:@,+-][\w\/.:@,+=-]*$/, ESC = /['\\]/g, UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\u{E0000}-\u{E007F}]/u;
  function word(s) { return BARE.test(s) ? s : "'" + s.replace(ESC, "'\\$&'") + "'"; }
  // limit is the flag of the form's time limit (forselect, rules-parts.tmpl): ' --for 15m', ' --until …', '' for none
  // (the rest of the run, or permanently, whose policy edit has no terminal twin), null while for… or until… has
  // nothing in its field.
  function limit(f) {
    var t = f.namedItem('for'), v = t ? t.value : 'run', s;
    if (/^\d+[mhdw]$/.test(v)) return ' --for ' + v; // a fixed span (forSpans), in --for's syntax already
    if (v === 'for') return (s = f.namedItem('span').value).trim() && !UNSAFE.test(s) ? ' --for ' + word(s.trim()) : null;
    // until…'s field reads 2026-11-14T17:00; --until reads 2026-11-14 17:00, in this machine's zone as the form's is.
    if (v === 'until') return (s = f.namedItem('until').value) ? ' --until ' + word(s.replace(/T(\d\d:\d\d).*$/, ' $1')) : null;
    return '';
  }
  function fill() {
    document.querySelectorAll('code[data-twin]').forEach(function (c) {
      var form = document.getElementById(c.dataset.twin), f = form && form.elements, raw = f ? f.namedItem('value').value : '';
      var k = f ? f.namedItem('kind').value : '', v = raw.trim(), l = f ? limit(f) : null, line = '', s, held;
      if (c.tegoPlaceholders === undefined) c.tegoPlaceholders = c.textContent; // the server's twin
      // The value is tested before it is trimmed: trim() and Go's TrimSpace differ only on U+FEFF and U+0085, both of
      // them unsafe, so a value that passes trims as the dashboard and tego block trim it. A value of a kind other than
      // exec and net names a path, and must be absolute. One that starts with - goes after --, the time limit before it,
      // as changeWords (actions.go) writes it: tego block reads a flag anywhere before --.
      if (v && l !== null && !UNSAFE.test(raw) && (k === 'exec' || k === 'net' || v.charAt(0) === '/')) {
        line = c.dataset.cmd + ' ' + word(k) + (v.charAt(0) === '-' ? l + ' -- ' + word(v) : ' ' + word(v) + l);
      }
      line = line || c.tegoPlaceholders;
      // A write drops a selection in the twin, even of the same words, and tego:merged follows every live update,
      // most of which leave this panel as it is (live.js merges no region a selection is in). So the twin is written
      // only when its words change, and words that change under a selection are selected in turn: a copy then takes
      // the command the form makes now.
      if (c.textContent === line) return;
      s = window.getSelection();
      held = !!s && !s.isCollapsed && s.rangeCount > 0 && c.contains(s.getRangeAt(0).commonAncestorContainer);
      c.textContent = line;
      if (held) s.selectAllChildren(c);
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fill); else fill();
  ['input', 'change', 'tego:merged', 'tego:enter'].forEach(function (k) { document.addEventListener(k, fill); });
})();
