// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

//go:embed static templates
var assets embed.FS

// cookiePrefix names the session cookie; the port follows it. Browsers keep cookies by host, not by port, so two
// dashboards on one machine that shared a name would each replace the other's and sign each other out.
const cookiePrefix = "tego_dash_"

// Config is what a Server needs: the ledger root it reads and the loopback port it is reached on.
type Config struct {
	Ledger string
	// Anchor is the chain anchor (chain.log) runs are verified against, the one `tego events --verify` reads;
	// empty leaves every chain unchecked.
	Anchor string
	Port   int
	// Token is the URL token; empty makes a random one.
	Token string
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Machine is the machine config the Rules page compiles contracts against; nil shows each contract uncompiled.
	Machine *config.Machine
	// StopWait bounds how long a Stop waits for the run to end before the page answers; 0 is 2 s. A run that takes
	// longer shows Stopping until its run_end, and the launcher's own stop_grace still ends it.
	StopWait time.Duration
	// Rules is the rule service (internal/control/rules) the event page's Act on this and the Change rules pages
	// ask (ActService, ChangeService); nil serves those pages' notices only.
	Rules RuleService
	// EventTick is how often a page's /events stream looks at the live state (live.go); 0 is 1 s.
	EventTick time.Duration
	// Setup is "Set up a new agent"'s service (rules_new.go, internal/control/rules); nil serves the page's notice only.
	Setup SetupService
	// Profiles resolves a rules file's extends when the Rules page checks it against a run (rulesview.Options);
	// nil checks no file that extends a profile, and such a run's rules show the run copy's line numbers.
	Profiles agent.ProfileSource
	// SeverityFile is where the person's own severity rules are kept (the Severity page); "" offers none.
	SeverityFile string
	// Preview lists the preview pages (MCP tools and Model routes, empty unless the run's contract uses capture or mcp,
	// and each layer's) in the nav; false leaves them out. Their addresses answer either way.
	Preview bool
}

// Server is the dashboard's handler.
type Server struct {
	cfg     Config
	token   string
	session string
	csrf    string // the per-session form token every POST carries (actions.go, rule.go)
	hosts   map[string]bool
	pages   map[string]*template.Template
	static  http.Handler
	host    string
	peer    func(*http.Request) error // who may connect: the serving user only (peer.go)
	// governed refuses a change (a POST, the ?t= sign-in) whose connection was made inside a tego run (governed.go).
	governed func(*http.Request) error
	tick     time.Duration // Config.EventTick, defaulted
	live     liveCache     // the live state the streams and /status.json share
	streams  atomic.Int32  // open /events streams
	// cookie is this server's session cookie name: cookiePrefix and the port.
	cookie string
	// flashes are the one-line results actions leave for the next page (flash.go).
	flashMu sync.Mutex
	flashes map[string]flashEntry
	// kepts are the result panels' data (flash.go, keep).
	keptMu sync.Mutex
	kepts  map[string]keptEntry
	// openCodes are the one-time codes OpenURL minted for the browser opener (opencode.go).
	openMu    sync.Mutex
	openCodes []openCode
	// sevRules are the person's severity rules in force (severity.go), read with every run's Signal; sevMu holds one
	// change at a time, and sevErr, under it, is why the file could not be read, "" when it could.
	sevRules atomic.Pointer[[]ledgerview.SevRule]
	sevMu    sync.Mutex
	sevErr   string
	// memos are the run pages' last region answers, for the 204 of an unchanged one (runkey.go).
	memos regionMemos
	// regionCache is each address's region render of the last second, shared by every viewer (regioncache.go).
	regionCache regionCache
}

// New builds a Server.
func New(cfg Config) (*Server, error) {
	s := &Server{cfg: cfg, token: cfg.Token, peer: procPeer().owns, governed: procGoverned().refuse}
	if s.cfg.Now == nil {
		s.cfg.Now = time.Now
	}
	if s.token == "" {
		s.token = randomHex(16)
	}
	s.loadSeverity()
	s.session = randomHex(32)
	// The CSRF token is tied to the session: an HMAC of the session cookie's value under a key that never leaves
	// this process, so a page that does not hold the session cannot make it, and a new server makes another.
	mac := hmac.New(sha256.New, []byte(randomHex(32)))
	mac.Write([]byte(s.session))
	s.csrf = hex.EncodeToString(mac.Sum(nil))
	if s.cfg.StopWait <= 0 {
		s.cfg.StopWait = 2 * time.Second
	}
	if s.tick = cfg.EventTick; s.tick <= 0 {
		s.tick = time.Second
	}
	p := strconv.Itoa(cfg.Port)
	s.cookie = cookiePrefix + p
	s.hosts = map[string]bool{"127.0.0.1:" + p: true, "localhost:" + p: true, "[::1]:" + p: true}
	if h, err := os.Hostname(); err == nil {
		s.host = h
	}
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	s.static = http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
	if s.pages, err = parsePages(); err != nil {
		return nil, err
	}
	return s, nil
}

// Prewarm reads the ledger once, starts checking the chains the overview shows and builds the overview once, unseen,
// so the first page a person opens is already warm (tego-control serve runs it in a goroutine as it starts). A page
// opened meanwhile shares the reads it needs instead of starting its own, and says "verifying" for a chain still
// being checked. It reports nothing: a page that reads the ledger says what went wrong. It returns when the chain
// checks are done or ctx ends.
func (s *Server) Prewarm(ctx context.Context) {
	snap, err := ledgerview.Load(s.cfg.Ledger)
	if err != nil || ctx.Err() != nil {
		return
	}
	var checked <-chan struct{} // nil without an anchor: nothing to wait for but ctx
	if s.cfg.Anchor != "" {
		checked = ledgerview.PrewarmChain(ctx, snap, s.cfg.Anchor)
	}
	// The overview's Signals, refusal folds and story are kept per run version: build them now, not on the first view.
	if r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil); err == nil {
		s.overview(&unseen{}, r)
	}
	if checked == nil {
		return
	}
	select {
	case <-checked:
	case <-ctx.Done():
	}
}

// unseen is a ResponseWriter that keeps nothing, for Prewarm's page.
type unseen struct{ h http.Header }

func (u *unseen) Header() http.Header {
	if u.h == nil {
		u.h = http.Header{}
	}
	return u.h
}
func (u *unseen) Write(b []byte) (int, error) { return len(b), nil }
func (u *unseen) WriteHeader(int)             {}

// Token is the URL token.
func (s *Server) Token() string { return s.token }

// URL is the address a person opens.
func (s *Server) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/?t=%s", s.cfg.Port, s.token)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("tego-control serve: no randomness: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Serve serves ln until ctx ends, then shuts down within a few seconds.
//
// Every request's context ends with ctx, so a page's open /events stream (live.go) ends at shutdown instead of holding
// it for its whole grace. The stream lifts the read and write timeouts for its own connection only.
func Serve(ctx context.Context, ln net.Listener, h http.Handler) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx }, ConnContext: withConnPeer}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return nil
	}
}

const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
	"form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"

// ServeHTTP applies the security checks, then routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	// same-origin, not no-referrer: under no-referrer a browser sends "Origin: null" on the dashboard's own form
	// posts, and the Origin check could not tell them from a cross-site post. Cross-origin requests still get no
	// Referer.
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	if !s.hosts[r.Host] {
		http.Error(w, "tego-control serve: wrong Host header; open the address tego-control serve printed", http.StatusMisdirectedRequest)
		return
	}
	if err := s.peerOnce(r); err != nil { // before the token and the cookie: another local uid gets neither (F21)
		s.notYours(w, err)
		return
	}
	post := r.Method == http.MethodPost
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !post {
		h.Set("Allow", "GET, HEAD, POST")
		http.Error(w, "tego-control serve: GET, HEAD and POST only", http.StatusMethodNotAllowed)
		return
	}
	t, o := r.URL.Query().Get("t"), r.URL.Query().Get("o")
	if post || t != "" || o != "" {
		// A change, or the sign-in that hands out the session a change needs: never from inside a run (governed.go).
		if err := s.governed(r); err != nil {
			s.governedRefused(w, err)
			return
		}
	}
	if (t != "" || o != "") && !post {
		// The token (?t=, reusable) or the opener's one-time code (?o=, opencode.go). A used or expired code from a
		// browser that already holds the session (the opener asked twice) only drops the code from the address.
		signedIn := t == "" && s.hasSession(r)
		ok := t != "" && subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1 ||
			t == "" && (signedIn || r.Method == http.MethodGet && s.takeOpenCode(o))
		if !ok {
			if t == "" && openCodeShape(o) {
				// A code of the opener's shape that does not sign in was used or has expired (or never was one: the
				// answer is the same, so it tells a guesser nothing). Say so instead of the generic page.
				s.refuse(w, r, signedOutCode)
				return
			}
			s.unauthorized(w, r)
			return
		}
		if !signedIn {
			http.SetCookie(w, &http.Cookie{Name: s.cookie, Value: s.session, Path: "/", HttpOnly: true,
				SameSite: http.SameSiteStrictMode})
		}
		q := r.URL.Query()
		q.Del("t")
		q.Del("o")
		dst := r.URL.Path
		if enc := q.Encode(); enc != "" {
			dst += "?" + enc
		}
		h.Set("Cache-Control", "no-store")
		http.Redirect(w, r, dst, http.StatusSeeOther)
		return
	}
	if (r.URL.Path == favicon || r.URL.Path == faviconICO) && !post && t == "" {
		// The tab's logo, before the session check, so the 401 page and a fresh tab show it too (favicon).
		h.Set("Cache-Control", "private, max-age=300")
		if r.URL.Path == faviconICO {
			r = r.Clone(r.Context())
			r.URL.Path, r.URL.RawPath = favicon, ""
		}
		s.static.ServeHTTP(w, r)
		return
	}
	if !s.hasSession(r) {
		s.unauthorized(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/static/") {
		// no-cache, not max-age: after an upgrade the page must not keep the old stylesheets for minutes; on loopback
		// fetching them again costs nothing.
		h.Set("Cache-Control", "private, no-cache")
		s.static.ServeHTTP(w, r)
		return
	}
	h.Set("Cache-Control", "no-store")
	if post {
		if s.postAllowed(w, r) {
			// A change can move what a page shows without moving the ledger: no region render from before it (or
			// begun while it ran) answers after it.
			s.regionCache.bump()
			if !s.mcpPost(w, r) && !s.routesPost(w, r) { // the MCP tools and Model routes pages' forms, after the same checks
				s.routePost(w, r)
			}
			s.regionCache.bump()
		}
		return
	}
	if v := r.Header.Get(regionHeader); v != "" {
		// A page asking for its changed live regions (regions.go, static/live.js): the same handler, answered with
		// the regions instead of the page. A flash in its address was shown with the page and is not taken again.
		have, ok := parseRegionHeader(v)
		if !ok {
			http.Error(w, "tego-control serve: unreadable "+regionHeader+" header", http.StatusBadRequest)
			return
		}
		h.Add("Vary", regionHeader)
		s.serveRegions(w, r, have) // a run page that has not moved answers 204 (runkey.go)
		return
	}
	if id := r.URL.Query().Get("flash"); id != "" && r.Method == http.MethodGet {
		if f := s.takeFlash(id); f != nil {
			w = &flashWriter{w, f}
		}
	}
	if s.mcpGet(w, r) || s.routesGet(w, r) { // the MCP tools page (mcp_tools.go), the Model routes page (model_routes.go)
		return
	}
	s.route(w, r)
}

// maxForm bounds a POST body: the forms carry a run id, an ask id, a word and the CSRF token (POST /rules/change
// takes maxRawForm).
const maxForm = 4 << 10

// postAllowed is the check every state-changing request passes after the Host and cookie checks: the request comes
// from the dashboard's own origin (Origin, or Referer when a browser sent no Origin; a request with neither is
// refused), a browser's Sec-Fetch-Site, when sent, is not another site, it is a form, and its csrf field is this
// session's token. It answers a refusal itself and reports whether to go on.
func (s *Server) postAllowed(w http.ResponseWriter, r *http.Request) bool {
	own := "http://" + r.Host
	if o := r.Header.Get("Origin"); o != "" {
		if o != own {
			http.Error(w, "tego-control serve: a change must come from the dashboard's own page (Origin "+strconv.Quote(o)+")", http.StatusForbidden)
			return false
		}
	} else if ref := r.Header.Get("Referer"); ref != own && !strings.HasPrefix(ref, own+"/") {
		http.Error(w, "tego-control serve: a change must come from the dashboard's own page (no Origin, and no Referer of it)", http.StatusForbidden)
		return false
	}
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
		http.Error(w, "tego-control serve: a change must come from the dashboard's own page (Sec-Fetch-Site "+strconv.Quote(sfs)+")", http.StatusForbidden)
		return false
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		http.Error(w, "tego-control serve: a change is a form post", http.StatusUnsupportedMediaType)
		return false
	}
	limit := int64(maxForm)
	if r.URL.Path == "/rules/change" {
		limit = maxRawForm // the advanced editor posts a whole contract (rules_change.go)
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "tego-control serve: unreadable form", http.StatusBadRequest)
		return false
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(s.csrf)) != 1 {
		http.Error(w, "tego-control serve: the form's token is missing or stale; reload the page and try again", http.StatusForbidden)
		return false
	}
	return true
}

// hasSession reports whether r carries this server's session cookie.
func (s *Server) hasSession(r *http.Request) bool {
	c, err := r.Cookie(s.cookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.session)) == 1
}

// signedOutWhy is why a request has no session, which picks the sign-in page's lead and the plain line.
type signedOutWhy int

const (
	// signedOutNone: no session, no valid token (a fresh tab, a restarted dashboard, a wrong ?t=).
	signedOutNone signedOutWhy = iota
	// signedOutCode: a ?o= code of the opener's shape that did not sign in: used, expired, or never minted.
	signedOutCode
)

// unauthorized answers a request without this server's session (signedOutNone).
func (s *Server) unauthorized(w http.ResponseWriter, r *http.Request) { s.refuse(w, r, signedOutNone) }

// refuse answers 401 for why. A browser asking for a page (Accept names text/html) gets the sign-in page, which
// says the one way in, since after a restart (a new token) an open tab's next page load lands here; every other
// client, live.js's fetches and curl among them, gets the plain line. The page is self-contained: its one style is
// allowed by its hash (signedOutCSP), it loads nothing but the favicon, runs no script, and says nothing about the
// ledger. Its text is constants only: nothing from the request is reflected.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, why signedOutWhy) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", signedOutCSP)
		w.WriteHeader(http.StatusUnauthorized)
		page := signedOutPage
		if why == signedOutCode {
			page = signedOutCodePage
		}
		_, _ = fmt.Fprint(w, page)
		return
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	line := "tego-control serve: this dashboard needs the link tego-control serve printed (it carries ?t=<token>)."
	if why == signedOutCode {
		line = "tego-control serve: " + codeUsedWords + "."
	}
	_, _ = fmt.Fprintln(w, line)
}

// codeUsedWords is what a used or expired one-time open code is told (opencode.go).
const codeUsedWords = "This one-time open link was used or expired; open the link tego-control serve printed (?t=…)"

// signedOutStyle is the sign-in page's only style, inline so the page needs no file the missing session would
// refuse. Its colours are tokens.css's (light, and dark under prefers-color-scheme).
const signedOutStyle = `:root{color-scheme:light dark;--bg:#FAFAF9;--fg:#2D3142;--soft:#4F5767;--card:#FFFFFF;--line:#E7E5E0;--code:#F4F3F0;--warn:#865700;--warn-soft:#FBF4E4}` +
	`@media (prefers-color-scheme:dark){:root{--bg:#0E131C;--fg:#E9EBEF;--soft:#B3BAC6;--card:#151B26;--line:#283143;--code:#1B2230;--warn:#E5B54E;--warn-soft:#29231A}}` +
	`body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);` +
	`font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Ubuntu Sans","Noto Sans",sans-serif;padding:16px;box-sizing:border-box}` +
	`main{width:min(100%,480px);background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px 24px;box-sizing:border-box}` +
	`.brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:20px;margin-bottom:18px}.brand img{width:30px;height:30px}` +
	`h1{font-size:18px;line-height:1.35;margin:0 0 10px}p{margin:0 0 12px;color:var(--soft)}` +
	`.note{color:var(--fg);background:var(--warn-soft);border-left:3px solid var(--warn);border-radius:6px;padding:8px 12px;overflow-wrap:anywhere}` +
	`.lbl{display:block;font-size:13px;color:var(--soft);margin:0 0 4px}` +
	`code{display:block;font:13px/1.6 ui-monospace,"SF Mono","Ubuntu Sans Mono","DejaVu Sans Mono",Menlo,monospace;background:var(--code);` +
	`border:1px solid var(--line);border-radius:8px;padding:10px 12px;color:var(--fg);overflow-wrap:anywhere;margin:0 0 12px;` +
	`user-select:all;-webkit-user-select:all;cursor:text}`

// signedOutHead and signedOutTail frame the sign-in page; signedOutLead is its usual first paragraph.
const (
	signedOutHead = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark"><title>Sign in · Tego</title>
<link rel="icon" href="/static/favicon.svg" type="image/svg+xml"><style>` + signedOutStyle + `</style></head>
<body><main role="main"><div class="brand"><img src="/static/favicon.svg" alt="">tego</div>
<h1>Open the dashboard from the link in your terminal</h1>
`
	signedOutLead = `<p>When <b>tego-control serve</b> starts it prints a link with <b>?t=</b>; opening it signs this browser in. ` +
		`If the dashboard was restarted, its new link is the one that works.</p>
`
	signedOutTail = `<span class="lbl">Not running any more? Start it again and it opens the dashboard for you (one click selects the command):</span>
<code>tego-control serve --open</code>
<p>Nothing was changed. Each start of the dashboard prints a new link, and the old one stops working.</p>
</main></body></html>
`
)

// signedOutPage is the sign-in page a browser gets without a session; signedOutCodePage the one a used or expired
// one-time open code gets (refuse).
const (
	signedOutPage     = signedOutHead + signedOutLead + signedOutTail
	signedOutCodePage = signedOutHead + `<p class="note">` + codeUsedWords + `.</p>
` + signedOutLead + signedOutTail
)

// signedOutCSP is the 401 page's policy: csp's, with its one inline style allowed by hash and nothing else inline.
var signedOutCSP = func() string {
	sum := sha256.Sum256([]byte(signedOutStyle))
	return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; img-src 'self'; " +
		"form-action 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
}()

// favicon is the one file served without the session: the logo a browser shows on the tab, the 401 page's
// included. It is the public mark, the same in every build, and says nothing about this computer.
const favicon = "/static/favicon.svg"

// faviconICO is where a browser asks for a tab's logo by itself, on a page that links none (a plain-text error such
// as a bogus URL's 404). It is the same file, served as favicon is, with the SVG's own type.
const faviconICO = "/favicon.ico"
