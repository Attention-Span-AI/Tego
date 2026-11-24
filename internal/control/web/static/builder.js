/* SPDX-License-Identifier: Apache-2.0 */
/* Server forms remain the source of truth. The enhancement refreshes only a compiled preview. */
(() => {
  'use strict';
  let dirty = false, controller, generation = 0;
  function invalidatePreview() { generation++; if (controller) controller.abort(); controller = undefined; }
  document.addEventListener('click', e => {
    const a = e.target.closest('a');
    if (dirty && a && !a.getAttribute('href')?.startsWith('#') && !window.confirm('Leave this draft without saving?')) { e.preventDefault(); e.stopImmediatePropagation(); }
  }, true);
  window.addEventListener('beforeunload', e => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
  document.addEventListener('submit', e => {
    if (e.target.closest('#builder-save')) { dirty = false; invalidatePreview(); }
  });
  function focusErrorAfterLoad() {
    const firstError = document.querySelector('[aria-invalid="true"]');
    if (!firstError || firstError.dataset.builderFocused) return;
    firstError.dataset.builderFocused = '1';
    const focus = () => { if (firstError.isConnected) firstError.focus(); };
    if (document.readyState === 'complete') focus();
    else window.addEventListener('load', focus, { once: true });
  }
  function attach() {
    const form = document.getElementById('builder-edit');
    if (!form) { focusErrorAfterLoad(); return; }
    if (form.dataset.reviewReady) return;
    form.dataset.reviewReady = '1';
    form.addEventListener('focusin', e => {
      if (matchMedia('(max-width:600px)').matches) e.target.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    });
    form.addEventListener('input', () => {
      dirty = true; invalidatePreview();
      document.querySelectorAll('#builder-save button, #builder-change-save button[value=save]').forEach(b => { b.disabled = true; });
    });
    form.addEventListener('submit', () => { dirty = false; invalidatePreview(); });
    form.addEventListener('change', async () => {
      const result = document.getElementById('builder-result'), say = document.getElementById('builder-updates');
      if (!result || form.querySelector('[name="current-view"]').value !== 'simple') return;
      if (controller) controller.abort();
      const own = new AbortController(), reviewedGeneration = ++generation; controller = own;
      const data = new URLSearchParams(new FormData(form)); data.set('step', 'preview');
      if (say) say.textContent = 'Checking choices…';
      try {
        const response = await fetch(form.action, { method: 'POST', body: data, signal: own.signal, credentials: 'same-origin' });
        if (!response.ok) throw new Error('check refused');
        const doc = new DOMParser().parseFromString(await response.text(), 'text/html');
        const updated = doc.getElementById('builder-result');
        if (!updated) throw new Error('preview unavailable');
        if (controller !== own || generation !== reviewedGeneration || !form.isConnected) return;
        // Follow the server's fresh draft so an active editor does not expire from its own checks.
        const nextDraft = doc.getElementById('builder-edit')?.querySelector('[name="draft"]'), currentDraft = form.querySelector('[name="draft"]');
        if (currentDraft && nextDraft?.value) currentDraft.value = nextDraft.value;
        result.replaceWith(updated);
        const oldProblems = document.getElementById('builder-problems'), problems = doc.getElementById('builder-problems');
        if (oldProblems) oldProblems.remove();
        if (problems) form.before(problems);
        form.querySelectorAll('[id][aria-invalid]').forEach(field => {
          const fresh = doc.getElementById(field.id);
          if (!fresh) return;
          field.setAttribute('aria-invalid', fresh.getAttribute('aria-invalid'));
          (field.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean).forEach(id => {
            const shown = document.getElementById(id), message = doc.getElementById(id);
            if (shown && message) { shown.textContent = message.textContent; shown.hidden = message.hidden; }
          });
          if (fresh.getAttribute('aria-invalid') === 'true') {
            const section = field.closest('details'); if (section) section.open = true;
          }
        });
        if (say) say.textContent = problems ? 'Fix the problems before saving.' : 'Choices checked. Review the YAML, then Save.';
        setupYAML();
      } catch (e) {
        if (controller === own && generation === reviewedGeneration && e.name !== 'AbortError' && say) say.textContent = 'Preview could not update. Use Check choices.';
      }
    });
    setupYAML();
    // The shell restores a native POST's place while its script loads. Focus the error after
    // that restoration; an in-place view has already restored its place before attach runs.
    focusErrorAfterLoad();
  }
  function setupYAML() {
    const yaml = document.querySelector('.builder-yaml');
    if (yaml && matchMedia('(max-width:600px)').matches) yaml.open = false;
  }
  attach();
  document.addEventListener('tego:leave', invalidatePreview);
  document.addEventListener('tego:here', attach);
  document.addEventListener('tego:enter', attach);
  document.addEventListener('tego:merged', attach);
})();
