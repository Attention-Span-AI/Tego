// SPDX-License-Identifier: Apache-2.0
// Copy buttons (the line page): a <button class="copy-btn" data-copy="<id>"> copies the text of the element with that
// id, or, when the page has a <template id="<id>-exact">, that template's text: the line exactly as written, where
// the element shows its invisible characters as ⟦U+…⟧ (shown.go visibleHTML). The buttons are hidden until this
// script runs (the has-copy class on <html>), so a page without JavaScript shows plain selectable text and no button
// that does nothing. One click listener on the document serves buttons a live region swaps in later. The clipboard
// API needs a secure context; on plain http to a LAN address it is missing, so the fallback selects the text and asks
// the browser to copy the selection.
(function () {
  "use strict";
  document.documentElement.classList.add("has-copy");

  function said(btn, text) {
    var label = btn.querySelector(".copy-lbl") || btn;
    var was = label.getAttribute("data-was") || label.textContent;
    label.setAttribute("data-was", was);
    label.textContent = text;
    window.setTimeout(function () { label.textContent = was; }, 1600);
  }

  function selectText(el) {
    var range = document.createRange();
    range.selectNodeContents(el);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    return sel;
  }

  function fallback(btn, el) {
    var sel = selectText(el);
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    if (ok) { sel.removeAllRanges(); said(btn, "Copied"); } else { said(btn, "Selected: press Ctrl+C"); }
  }

  document.addEventListener("click", function (ev) {
    var btn = ev.target && ev.target.closest ? ev.target.closest("button.copy-btn[data-copy]") : null;
    if (!btn) { return; }
    var el = document.getElementById(btn.getAttribute("data-copy"));
    if (!el) { return; }
    ev.preventDefault();
    var exact = document.getElementById(el.id + "-exact");
    var text = exact && exact.content ? exact.content.textContent : el.textContent;
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { said(btn, "Copied"); }, function () { fallback(btn, el); });
    } else {
      fallback(btn, el);
    }
  });
})();
