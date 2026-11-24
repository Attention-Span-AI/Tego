# Dashboard asset implementation notes

These notes retain the explanations for the shared assets without sending them on every page request. The source files keep readable declarations and statements. Feature rules live with their owning pages. Moving these notes changes no executable statement or CSP directive. The summary-age presentation change is described in ADR 0123.

Quoted comments below preserve earlier ownership notes. The current shared mvp.css
file still supplies common table, form, list and chart rules, including the existing
builder pages. Page-owned rules are delivered with their pages as described below.

## tokens.css

```text
/* tokens.css: two designed palettes. Orange means a request waiting for a person.
   Refused and protected read allowed share red; dashed outline and filled shapes
   distinguish them. Routine actions and navigation use navy. Legacy names remain
   aliases by value so existing pages inherit the same meanings. */
/* type: the system text stacks, and one headline face shipped in the binary (fonts/anton.woff2, OFL 1.1) */
/* space: 4 px base */
/* radius */
/* lines */
/* size */
/* component sizes and layout columns (media-query breakpoints stay literal: CSS cannot read a variable there) */
/* motion: answers a person's action only; zero under reduced motion (app.css) */
/* live.js's toasts */
/* grounds and ink */
/* phone amendment: one token per meaning, at every width */
/* elevation: a white panel on the paper lifts by a hairline and a long, faint navy shadow (the site's) */
/* Chart marks have labels and a distinct pattern as well as color. */
```

## app.css

```text
/* app.css: the dashboard's shell and components (the v0.2.0 design system). tokens.css custom properties only: no
   literal colour (colour_lint_test.go) but forced-colours system names. Class names and hooks are today's where
   today has one (live.js, the Go tests). Section 19 fits today's page markup into the shell; mvp.css holds today's
   other page rules. */
/* ---------- 0. the headline face (OFL 1.1, LICENSES/Anton.txt; default-src 'self' covers fonts) ---------- */
/* ---------- 1. base ---------- */
/* an object's own title (a run, a line): its name is data, so it is set in the text face, not the headline face */
/* ---------- 2. shell: top bar, side nav, main, record line ---------- */
/* the switch keeps its place, unseen, until theme.js shows it, so its coming moves nothing in the top bar */
/* the page is a column with one gap, which also spaces the children of live-region wrappers (.lr is display: contents) */
/* ---------- 3. page head: where you are, what this is, the one next step ---------- */
/* ---------- 4. buttons: navy primary, secondary, quiet, danger ---------- */
/* ---------- 5. state chips: every state has an icon and a word ---------- */
/* ---------- 6. chips (filters), tabs, the Simple and Full switch ---------- */
/* ---------- 7. panels and tables ---------- */
/* a name is never cut: it wraps at its hyphens (the markup puts a <wbr> after each), and the row grows (SPEC section 3) */
/* ---------- 8. the ledger strip (tiles): one panel cut by hairlines, figures that line up ---------- */
/* ---------- 9. the command block (quiet ground), Copy and "Copied" ---------- */
/* ---------- 10. banners: the ask (the loudest thing on any page), problems, notices, flash ---------- */
/* outside Overview the compact band wraps only when needed: icon, who wants what, Allow once, Deny, More; the full card is on Approvals */
/* ---------- 11. fields, field errors, switches ---------- */
/* ---------- 12. empty states, untrusted text, paths ---------- */
/* agent text is shown exactly: monospace, spaces kept, isolated so right-to-left text cannot reorder ours */
/* ---------- 13. timeline rows (the run page, the logs): one line, 30 px, a verdict at the end ---------- */
/* ---------- 14. the ask card (Approvals and a run's page) ---------- */
/* ---------- 15. setup steps (Overview), the agent stage strip (Agents) ---------- */
/* the agent's place on the path, as one line of words; the five-step strip is for the agent's own page */
/* ---------- 16. live region marks, toasts, Copied ---------- */
/* ---------- 17. responsive: tablet, phone, zoom ---------- */
/* Keep the base's narrow desktop content budget before the top navigation strip takes over. */
/* phone rows: each label and its value on one line of a two-column grid, tops aligned, no fixed height (no text can print over the next) */
/* 400 % zoom and short screens: nothing sticks, so no bar covers the content or a focused control (WCAG 1.4.10, 2.4.11) */
/* ---------- 19. compatibility: today's page markup in this shell (A1-1). Each block names the package that deletes
   it; A1-5 checks none is left. Today's other page rules are in mvp.css. ---------- */
/* C1 (A1-2, A1-3, A1-4): the old breadcrumb, nav.crumbs, a row of links (the new one is ol.crumb) */
/* C2 (A1-2, A1-3, A1-4): a title that is data (an agent, a path, a finding) in the text face, as h1.h1-obj */
/* C3 (A1-2): the Overview's old tiles (label, value, meta) in the ledger strip's places (k, v, s) */
/* Auto-fit can pack more legacy tiles than the old two-column layout. Keep the record value readable. */
/* C4 (A1-2, A1-3): historical asks stay neutral; protected reads that went through stay red. */
/* A1-3: the shell must not make legacy What values clip more at desktop widths either.
   Auto layout keeps a What column when the declared widths of its neighbours exceed the page. */
/* A1-2, A1-3: compact table leading must not clip enlarged agent labels or run subtitles. */
/* C5 (A1-2, A1-3, A1-4): the old empty state's round glyph */
/* Logs owns a three-column card grid. Outrank the legacy table selectors
     so an implicit third column cannot narrow the What cell. */
/* ---------- 18. motion, forced colours, print ---------- */
/* a bare number marker (the "quantity" template, numbers.go) makes no box, so its words join the text around them
   as before the markers: in a flex container a span of its own would drop the space after the number */
```

## mvp.css

```text
/* mvp.css: the page rules of today's templates, kept until the page packages of the dashboard redesign replace them
   (V020-PLAN A1-2: Overview, Runs, a run and its tabs, a line, charts; A1-3: Logs, Detections, Approvals, Compare,
   Investigate; A1-4: Contracts, a rule, This machine, Glossary, the live fence, the preview layers). The shell and the
   components are app.css's (the design system); a rule here that names a shared component (.t, .tl, a field) is scoped
   to the old markup (.t:not(:has(.cv)), .tl:has(> .what), label.field), so a page's new markup is not touched by it.
   Each page package deletes the rules of its own templates as it lands; A1-5 deletes this file. Tokens only, no colour
   literals (colour_lint_test.go). */
/* ---------- from app.css (2026-11-11) ---------- */
/* ---------- from mvp.css (2026-11-11) ---------- */
```

## signal.css

```text
/* The story layer (story.go): the run's verdict banner, the Secrets chip, and the tail-keeping path shortener. */
/* A timeline row's first line is a flex row, so a long path shrinks its folder instead of the whole path being cut. */
/* On a phone a row wraps instead: the path flows as plain text, broken anywhere, so nothing is cut or overflows. */
/* Overview's half-width run tables also drop the Run column below 1600 px, so Agent and Secrets keep their width. */
/* Severity pills (ledgerview.Severity): one meaning per colour, red High, amber Medium, grey Low. */
/* The Overview's figure (overview.tmpl): detections by severity and channel. */
/* On a phone .t rows are stacks whose thead is hidden: a number keeps its column's name through data-label. */
/* The run page (run.tmpl): a gap before the destructive action, and a quiet Block now line when no block is in force. */
```

## phone.css

```text
/* The shared phone contract. Page packages use these classes; they do not add
   independent shell overrides. Tablet and desktop keep the approved geometry. */
/* Unbroken agent text must wrap inside the page column at every width. */
/* Native disclosures remain usable when ::details-content is unsupported. */
/* A native GET destination remains available before the modal enhancement runs. */
/* Keep the named region's heading and pending total in the accessibility tree. */
/* Shared interior primitives. Native details keep long values reachable without scripts. */
/* Opt-in ledger summaries for page packages. Preserve table headers and keyed
   tbody regions while giving every row one native detail destination. */
```

## live.js

```text
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
    // Past the agent's own wait (data-late-at), the note says it has likely given up and when Tego refuses it.
  // Snapshot before connecting: place.js may load after the first live request arrives.
  // tegoLive is what static/place.js builds on: this file's merge for a whole view (no "new" mark, the forms taking the
  // new page's values), and hold, which keeps refresh and more from merging the regions or rows of a view being left.
  // A page with nothing to follow (MCP tools, Model routes: no signature) still changes its view in place.
  // signedOut: a 401 means the dashboard restarted (each serve has a new token) or the session is gone. Following
  // stops (no stream, 2 s polling, region or row fetch: each could only fail again) and a banner says how to get back
  // in; its text is this constant only. One quiet check every 30 s notices a sign-in from another tab (the link sets
  // the same cookie), takes the banner down and follows again.
  // polling(ms) polls every ms (0 stops it).
  // Keep exact request controls while pointer or focus is inside, including after an answer.
  // busy: a form someone is using (focus in a field, a value changed, or its answer on the way) is left as it is.
    // A same-page filter also merges the banner wrapper. Keep its old hash so departure fetches the queued request.
  // kids makes op's children those of np: a node with an id or data-k matches the old node with the same, others
  // match in order; what matches is updated in place, the rest is added (marked new when keyed) or removed.
  // refresh fetches the changed regions, at most once a second, and merges them.
        // The focused control went with its region (an answered ask's Deny): the focus goes to <main>, not to nothing,
        // so the next Tab starts in the page (main:focus shows no ring).
  // more puts the rows after feed's cursor at the top: a folded refusal group's older row is dropped when its group
  // arrives again with the whole count, and the list is cut to the newest MAX, the Older link moving with it.
  // --- answering in place
  // toast says a, the line an action left ({ok, text, link, link_text}: flash.go's inlineAnswer). A toast of a kind
  // (every answer to a request is one kind; another action's kind is its path) takes the place of the one before it,
  // so a Deny's notice and a later Allow once's never stack: at most one per kind.
        // A disabled button drops the focus: a keyboard's goes back to it (refresh moves it to <main> if it goes).
```

## place.js

```text
// place.js: keeping the reader's place, on top of live.js (it merges with window.tegoLive) and of a page that works
// without either: every view is a plain link or GET form, and every action a plain form.
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
  // A tab strip wider than the screen (phone width) scrolls: the open tab comes into view; its fade goes at the end.
  // strips runs again after a view change merged the page (a strip it already follows is left as it is).
  // The polite region exists in the initial HTML; only newly arriving request keys change its text.
    // The compact band shows one request, but another request behind it still needs an announcement.
  // spot is the history state of this view: the page's scroll, so Back and Forward can bring it back.
  // A link that changes this page's view: the same path (a chip, a facet, a pager), or a tab of the page's tab strip. A
  // data-page link or form (a Revoke whose confirmation opens at the top) loads its page as a link does.
    // typed: the text of the field being typed in as sent, so what is typed while the view loads is kept (put).
  // where is el's place in <main>: its id, or the child indexes from <main> down, with its tag and text, so a view
  // change that rebuilt it finds its twin.
  // sheets loads the new view's stylesheets (a run page's Receipt tab has its own) before it is merged, so it never
  // shows unstyled.
  // pending shows that a view is on its way: after a moment, a thin bar at the top and the control dimmed.
    // From the first view change on, this document's history entries keep their scroll in their state: the browser's
    // own restore would scroll a popstate's old content before its view is fetched. A page load keeps the browser's
    // (leave() sets it back), which restores from the first paint, before this file runs.
    // A dashboard that stops answering would leave the busy bar on and the live updates held: after STALL the fetch is
    // given up and the page loaded as the link would (the catch below).
        // A page of the same kind: followed live (a signature) as this one is, or not (MCP tools, Model routes).
    // A pager's next page is read from its first row: the list it pages stays where it stood, or comes up to the top
    // of the window when its top was above it. Any other control stays where it stood.
    // The control's ancestors in <main>, nearest first, with their place: when the control goes with the view (the
    // last query chip's ×, Clear filters), the nearest one the merge kept holds the place and the focus instead.
    // Text typed in the search field while the view was on its way is the reader's, not the server's older value.
      // A pager's focus goes to the list it paged, which shows from its first row (its link's twin can stand thousands
      // of pixels below, where the next Tab or Enter would act out of sight); a control the view removed hands it to
      // the first field or link of the nearest part the merge kept, when that is in the window, or to <main>.
  // softKeys keys, for one merge, each <details> whose class names it alone in both views (Logs' Filters panel), so the
  // merge keeps the open one even when a sibling before it came or went (the query chips' row); returns the keyed old
  // ones, whose key is taken off after (the server's pages carry none).
  // near is the first field, button or link in part that is in the window, or <main>.
  // say tells a screen reader the new view: the chosen item of the control's group and the page's count line.
    // does it at the first paint; this one is for an entry it did not (one a view change pushed, loaded anew), and
    // leaves a page the reader has already moved alone.
  // Leaving the page (a reload, a link, a form's post): the entry's scroll goes in its state and the browser restores
  // it itself on the way back, from the first paint (with 'manual' the top showed first, then a jump). Back to a page
  // kept whole (the back/forward cache) takes up 'manual' again for its own views.
  // A GET form changes the view; a form posted as a plain form keeps its place. live.js answers the forms it posts in
  // the background first (Allow once, Deny, Block now, the rule forms): those are defaultPrevented here.
  // keepPlace: a form posted as a plain form (Pause, Resume, Lift, MCP tools' and Model routes' forms)
  // answers 303 back to its page, which loaded at the top. Its place goes in this tab's sessionStorage first, and the
  // page it comes back to (the same path, within a few seconds) scrolls the form back to where it stood; the line the
  // action left is said in a toast when its banner is out of sight above.
  // steady keeps the Overview's two lists, which grow at the top, from moving a row as it is reached for: live.js leaves
  // such a list alone while the pointer or the keyboard's focus is in it, for STEADY at most, so a pointer left resting
  // there does not stop the page following its runs.
// The Filter link has a native GET destination. Enhance only an available dialog.
// Keep Tab within the modal even when the browser would move focus to its chrome.
```

The final delivery pass also moves Logs table rules from mvp.css to logs.css,
comparison rules to compare.css (loaded by Runs too), and machine metadata rules
to support.css. These rules keep their previous order ahead of their owning page
styles. Shared chips wrap long text when spacing is enlarged.

Runs loads its comparison sheet in the head, after the shared phone sheet. It
uses the same bytes and cascade order. A body link could pause parsing after the
shell painted, before enough content existed to restore the browser's saved
scroll position. The reload and Back browser assertions cover the resulting
first-frame behavior without a timing retry or a longer sleep.

That head move alone did not prevent every partial first frame under load.
Runs also opts the existing deferred live script into `blocking="render"`.
Parsing completes before rendering starts, with no added CSS/JS source bytes.
The finish browser guard checks both scripts disabled and the script request
blocked, including the native filter form. Other pages keep their original tag.

## Manual browser audit

The `chrome` build tag contains the page packages' seven-width matrices and the
finish checks. Run their top-level tests in separate batches through the host's
resource wrapper, with an explicit timeout. The ordinary package race suite is
separate. the complete-source finish native check (retained separately) and the expanded A1/Interiors native
checks cover scripts on/off and complete keyboard cycles. The finish reflow check
uses 200%/400% CSS viewport/output-scale proxies and enlarged text spacing.

`FINISH_AUDIT` names an output directory for the shared instrument and independent
measurements on the same real document. `FINISH_SOURCE` records the measured
commit. `FINISH_CAPTURES=1` uses neutral host/login fixtures and task-local
file-descriptor paths, and refuses a capture containing the real host/account
identity. It does not edit screenshots. Each page closes after its checks; the
CDP helper refuses a fifth open page. Browser diagnostic buffers are synchronized.
These manual checks remain outside CI and the private gate (DASH-G16).

The integrated finishing matrices include fixtures for private layers and the
private audit instrument, so their files stay out of the public cut. Public shell
and phone browser guards remain selected. These boundaries do not change which
production page assets are public.

The quoted asset notes above describe their original revisions. Later native
recovery uses the manual Refresh control; the earlier meta-refresh note does
not describe the final behavior. Current asset measurements come from the
fix-round audit and its frozen source, rather than those historical sizes.
