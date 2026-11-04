// SPDX-License-Identifier: Apache-2.0

//go:build integration

// These tests run demo.sh, the supply-chain demo's one command per step, against a real tego. The binaries are
// built with -tags tegotesthooks, so the chain anchor and the own log stay in the test's directory, and every
// test runs under a machine config, ledger, stage, HOME and set of ports of its own: nothing here reads or
// writes the invoking user's ~/.tego, ~/.codex, ~/tego-demo* or a user's tego-sc-* units and ports 8801 to
// 8803. The three fake servers run as systemd user units named tego-sctest-<random>-*, stopped on cleanup.
// Codex is a stub (no model call): a script that answers `codex login status` and, when started, writes its
// environment into the project.
//
// Run: go test -tags integration ./examples/supply-chain-demo/   (needs python3, systemd --user and Landlock)
package supplychain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

const (
	contractName = "supply-chain-codex-chatgpt"
	oldMark      = ".moved-by-demo-sh" // demo.sh's OLD_MARK: the file naming the folder reset moved a ledger to
)

var (
	buildOnce sync.Once
	binDir    string
	buildErr  error
)

func TestMain(m *testing.M) {
	code := testutil.GuardedMain(m)
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// binaries builds tego (with the test hooks) and tego-control once for the whole run.
func binaries(t *testing.T) (tego, ctl string) {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "supplychain-bin-")
		if err != nil {
			buildErr = err
			return
		}
		binDir = dir
		for _, b := range []struct{ out, pkg, tags string }{
			{"tego", "github.com/attention-span-ai/tego/cmd/tego", "tegotesthooks"},
			{"tego-control", "github.com/attention-span-ai/tego/cmd/tego-control", "tegotesthooks"}, // the anchor stays the test's (anchor_testhook.go)
		} {
			args := []string{"build", "-o", filepath.Join(dir, b.out)}
			if b.tags != "" {
				args = append(args, "-tags", b.tags)
			}
			cmd := exec.Command("go", append(args, b.pkg)...)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				buildErr = fmt.Errorf("go build %s: %w\n%s", b.pkg, err, out)
				return
			}
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return filepath.Join(binDir, "tego"), filepath.Join(binDir, "tego-control")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// world is one isolated demo: its own tego, config, ledger, stage, HOME, ports and unit prefix.
type world struct {
	t       *testing.T
	base    string
	stage   string
	ledger  string
	cfg     string
	stub    string
	bin     string
	ctl     string
	prefix  string
	sdRun   string
	left    int
	right   int
	api     int
	dash    int
	envList []string
}

func (w *world) unit(kind string, port int) string {
	return w.prefix + "-" + kind + "-" + strconv.Itoa(port)
}

// newWorld makes the isolated world and skips where the machine cannot run it (no python3, no user systemd, no
// Landlock), like the demo kit's own tests.
func newWorld(t *testing.T) *world {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	sdRun := fmt.Sprintf("/run/user/%d", os.Getuid())
	probe := exec.Command("systemctl", "--user", "show-environment")
	probe.Env = append(os.Environ(), "XDG_RUNTIME_DIR="+sdRun)
	if err := probe.Run(); err != nil {
		t.Skipf("no systemd user manager (systemctl --user): %v", err)
	}
	bin, ctl := binaries(t)
	base, err := filepath.EvalSymlinks(t.TempDir()) // the script resolves paths, so the test compares resolved ones
	if err != nil {
		t.Fatal(err)
	}
	// the machine config's directory must not be group-writable
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	stub := filepath.Join(base, "stub")
	for _, d := range []string{home, stub} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Outside tego-own/, which the agent is denied (TegoEnv keeps the chain anchor and its runtime there).
	script := map[string]string{
		"codex": `#!/bin/sh
case "$1" in
  login) [ -s "${CODEX_HOME:-/nonexistent}/auth.json" ]; exit $? ;;
  --no-daemon) env >tmp/codex-env.txt; echo "stub codex ran"; exit 0 ;;
esac
exit 0
`,
		"claude":               "#!/bin/sh\nenv >tmp/claude-env.txt; echo \"stub claude ran\"; exit 0\n",
		"codex-code-mode-host": "#!/bin/sh\nexit 0\n",
		"notify-send":          "#!/bin/sh\nexit 0\n",
	}
	for name, body := range script {
		if err := os.WriteFile(filepath.Join(stub, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	auth := filepath.Join(base, "auth.json")
	if err := os.WriteFile(auth, []byte(`{"stub":"login"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var rnd [3]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatal(err)
	}
	w := &world{
		t: t, base: base, stage: filepath.Join(base, "stage"), ledger: filepath.Join(base, "ledger"),
		cfg: filepath.Join(base, "tego-demo.yaml"), stub: stub, bin: bin, ctl: ctl,
		prefix: "tego-sctest-" + hex.EncodeToString(rnd[:]), sdRun: sdRun,
		left: freePort(t), right: freePort(t), api: freePort(t), dash: freePort(t),
	}
	w.envList = testutil.TegoEnv(t, base,
		"HOME="+home,
		"PATH="+stub+":"+filepath.Dir(bin)+":/usr/local/bin:/usr/bin:/bin",
		"LANG=C.UTF-8", "TERM=dumb",
		"TEGO="+bin, "TEGO_CONTROL="+ctl,
		"DEMO_STAGE="+w.stage, "DEMO_CONFIG="+w.cfg, "DEMO_LEDGER="+w.ledger, "DEMO_CODEX_AUTH="+auth,
		"DEMO_PORT_LEFT="+strconv.Itoa(w.left), "DEMO_PORT_RIGHT="+strconv.Itoa(w.right), "DEMO_PORT_API="+strconv.Itoa(w.api),
		"DEMO_DASH_ADDR=127.0.0.1:"+strconv.Itoa(w.dash), "DEMO_UNIT_PREFIX="+w.prefix,
		"DEMO_SYSTEMD_RUNTIME="+sdRun, "DEMO_OFFLINE=1", "DEMO_BACKUP_KEEP_LOGS=1",
		"MY_REAL_AWS_SECRET_TOKEN=not-a-fake-value-from-the-presenters-shell",
	)
	// The demo's own config is left to `demo.sh setup` to write; doctor gets one of its own.
	probeCfg := filepath.Join(base, "doctor.yaml")
	if err := os.WriteFile(probeCfg, []byte("version: 0\nledger_root: "+filepath.Join(base, "doctor-ledger")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doctor := exec.Command(bin, "doctor", "--require", "landlock")
	doctor.Env = append(append([]string{}, w.envList...), "TEGO_CONFIG="+probeCfg)
	testutil.RequireTier(t, doctor, "landlock")
	t.Cleanup(func() { _, _ = w.demoEnv(nil, "reset", "--stop") })
	return w
}

// demoEnv runs `sh demo.sh args` with the world's environment plus extra (later entries win) and returns its
// combined output and exit code (-1 when it could not run).
func (w *world) demoEnv(extra []string, args ...string) (string, int) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", append([]string{"demo.sh"}, args...)...)
	cmd.Env = append(append([]string{}, w.envList...), extra...)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	default:
		return string(out), -1
	}
}

func (w *world) demo(args ...string) (string, int) { return w.demoEnv(nil, args...) }

func (w *world) mustDemo(args ...string) string {
	w.t.Helper()
	out, code := w.demo(args...)
	if code != 0 {
		w.t.Fatalf("demo.sh %s: exit %d\n%s", strings.Join(args, " "), code, out)
	}
	return out
}

func (w *world) filled() string { return filepath.Join(w.stage, "with", "codex-chatgpt.filled.yaml") }

func (w *world) systemctl(args ...string) {
	w.t.Helper()
	cmd := exec.Command("systemctl", append([]string{"--user"}, args...)...)
	cmd.Env = append(os.Environ(), "XDG_RUNTIME_DIR="+w.sdRun)
	_ = cmd.Run() // a stop of a unit that is already gone is not a failure
}

func (w *world) unitActive(name string) bool {
	cmd := exec.Command("systemctl", "--user", "is-active", "--quiet", name)
	cmd.Env = append(os.Environ(), "XDG_RUNTIME_DIR="+w.sdRun)
	return cmd.Run() == nil
}

func mustContain(t *testing.T, what, out string, want ...string) {
	t.Helper()
	for _, s := range want {
		if !strings.Contains(out, s) {
			t.Errorf("%s: missing %q in:\n%s", what, s, out)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// event is the part of a ledger line these tests read.
type event struct {
	Kind, Verdict, Reason, Op, Target, Path, Rule, Agent string
}

// runEvents returns the events of every run in the ledger, by run id.
func runEvents(t *testing.T, ledger string) map[string][]event {
	t.Helper()
	dirs, err := os.ReadDir(ledger)
	if err != nil {
		t.Fatalf("ledger %s: %v", ledger, err)
	}
	out := map[string][]event{}
	for _, d := range dirs {
		b, err := os.ReadFile(filepath.Join(ledger, d.Name(), "events.jsonl"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			var e event
			if json.Unmarshal([]byte(line), &e) == nil {
				out[d.Name()] = append(out[d.Name()], e)
			}
		}
	}
	return out
}

// enforcedAndWatched picks the enforced run (the contract's own name) and the watched one (watch-<program>).
func enforcedAndWatched(t *testing.T, runs map[string][]event) (enforced, watched []event) {
	t.Helper()
	ids := make([]string, 0, len(runs))
	for id := range runs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		evs := runs[id]
		if len(evs) == 0 {
			continue
		}
		switch {
		case evs[0].Agent == contractName:
			enforced = evs
		case strings.HasPrefix(evs[0].Agent, "watch-"):
			watched = evs
		}
	}
	if enforced == nil || watched == nil {
		t.Fatalf("the ledger holds %d run(s); want one enforced (%s) and one watched (watch-*)", len(runs), contractName)
	}
	return enforced, watched
}

func hasEvent(evs []event, pred func(event) bool) bool {
	for _, e := range evs {
		if pred(e) {
			return true
		}
	}
	return false
}

// TestSupplyChainContractFills: setup fills every placeholder, the file is mode 0644, it compiles, and
// the compiled table holds the rules the README names: the key never readable, the token and
// confidential/ asked about, held/ asked about on write, python3 and the Codex helper runnable, and the project's
// API the only loopback address reachable.
func TestSupplyChainContractFills(t *testing.T) {
	w := newWorld(t)
	out := w.mustDemo("setup")
	mustContain(t, "setup", out, "$ systemd-run --user", "next: ./demo.sh check")

	filled := readFile(t, w.filled())
	if m := regexp.MustCompile(`@@[A-Z_]+@@`).FindString(filled); m != "" {
		t.Errorf("the placeholder %s is left in the filled contract", m)
	}
	if fi, err := os.Stat(w.filled()); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("the filled contract's mode is %v (%v), want 0644", fi, err)
	}
	if fi, err := os.Stat(w.cfg); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("setup should write the machine config with mode 0600: %v (%v)", fi, err)
	}
	if got := readFile(t, w.cfg); !strings.Contains(got, "ledger_root: "+w.ledger) {
		t.Errorf("the machine config does not name the demo ledger:\n%s", got)
	}
	if fi, err := os.Stat(w.ledger); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the ledger should be mode 0700: %v (%v)", fi, err)
	}
	with := filepath.Join(w.stage, "with")
	pyreal, err := filepath.EvalSymlinks(mustLookPath(t, "python3"))
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, "filled contract", filled,
		`deny_read: ["`+with+`/home/.ssh/"]`,
		`ask_read: ["`+with+`/home/.config/telemetry/", "./confidential/"]`,
		`ask: ["./held/"]`,
		`"`+pyreal+`"`,
		`"`+w.stub+`/codex-code-mode-host"`,
		`allow: ["127.0.0.1:`+strconv.Itoa(w.api)+`"`,
		`CODEX_HOME: "`+with+`/codex-home"`)
	if strings.Contains(filled, strconv.Itoa(w.right)) || strings.Contains(filled, strconv.Itoa(w.left)) {
		t.Errorf("the filled contract names a sink port; the attackers must be on no line")
	}

	// the compiled table
	cmd := exec.Command(w.bin, "compile", "--offline", "--json", w.filled())
	cmd.Dir = filepath.Join(with, "proj")
	cmd.Env = append(w.envList, "TEGO_CONFIG="+w.cfg)
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("tego compile: %v", err)
	}
	var tbl struct {
		FS []struct {
			Path    string `json:"path"`
			Kind    string `json:"kind"`
			AskRead bool   `json:"ask_read"`
			Builtin bool   `json:"builtin"`
		} `json:"fs"`
		Exec []struct {
			Basename string `json:"basename"`
		} `json:"exec"`
		Net []struct {
			Raw string `json:"raw"`
		} `json:"net"`
	}
	if err := json.Unmarshal(b, &tbl); err != nil {
		t.Fatal(err)
	}
	var sshDenied, tokenAsked, confidentialAsked bool
	for _, e := range tbl.FS {
		switch {
		case e.Kind == "deny_read" && !e.AskRead && e.Path == with+"/home/.ssh":
			sshDenied = true
		case e.Kind == "deny_read" && e.AskRead && e.Path == with+"/home/.config/telemetry":
			tokenAsked = true
		case e.Kind == "deny_read" && e.AskRead && e.Path == with+"/proj/confidential":
			confidentialAsked = true
		}
	}
	if !sshDenied || !tokenAsked || !confidentialAsked {
		t.Errorf("the compiled table lacks the key (denied: %v), the token (asked: %v) or confidential/ (asked: %v)", sshDenied, tokenAsked, confidentialAsked)
	}
	execs := map[string]bool{}
	for _, e := range tbl.Exec {
		execs[e.Basename] = true
	}
	for _, want := range []string{"python3", "codex-code-mode-host", "bash", "git"} {
		if !execs[want] {
			t.Errorf("the compiled table does not let the agent run %s", want)
		}
	}
	var nets []string
	for _, n := range tbl.Net {
		nets = append(nets, n.Raw)
	}
	if !contains(nets, "127.0.0.1:"+strconv.Itoa(w.api)) {
		t.Errorf("net.allow %v lacks the project's API", nets)
	}
	for _, n := range nets {
		if strings.HasPrefix(n, "127.0.0.1:") && n != "127.0.0.1:"+strconv.Itoa(w.api) {
			t.Errorf("net.allow names the loopback address %s, which only the API may be", n)
		}
	}

	if out, code := w.demo("check"); code != 0 || !strings.Contains(out, "READY") {
		t.Errorf("check after setup: exit %d\n%s", code, out)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func mustLookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSupplyChainProtected: the poisoned package's own tests, the same twice, with no agent. Watched,
// the key is read and the attacker is reached; enforced, the key is refused, the token ask is denied, the send to
// the attacker is refused, the attacker's log stays empty and the tests are still green.
func TestSupplyChainProtected(t *testing.T) {
	w := newWorld(t)
	w.mustDemo("setup")
	out := w.mustDemo("backup")
	mustContain(t, "backup", out, "denied the ask q-", "Ran 2 tests", "OK",
		"[telemetry_helper] could NOT read your SSH key", "tests exit 0", "the attacker received 0 request(s), 1 ask(s) denied")
	mustContain(t, "backup (watched side)", out, "[telemetry_helper] exfiltrated")
	if strings.Contains(out, "MY_REAL_AWS_SECRET_TOKEN") || strings.Contains(out, "not-a-fake-value") {
		t.Errorf("the poisoned dependency named or sent a variable of the presenter's real shell:\n%s", out)
	}

	enforced, watched := enforcedAndWatched(t, runEvents(t, w.ledger))
	keyRefused := hasEvent(enforced, func(e event) bool {
		return e.Kind == "refused" && e.Reason == "read-denied" && strings.HasSuffix(e.Target, "/with/home/.ssh/id_rsa") && strings.HasPrefix(e.Rule, "fs.deny_read[")
	})
	tokenDenied := hasEvent(enforced, func(e event) bool {
		return e.Kind == "refused" && e.Reason == "ask-denied" && strings.HasSuffix(e.Target, "/with/home/.config/telemetry/token")
	})
	sendRefused := hasEvent(enforced, func(e event) bool {
		return e.Kind == "refused" && e.Reason == "net-not-allowed" && e.Target == "127.0.0.1:"+strconv.Itoa(w.right)
	})
	if !keyRefused || !tokenDenied || !sendRefused {
		t.Errorf("enforced run: key refused %v, token ask denied %v, send to the attacker refused %v; events: %+v", keyRefused, tokenDenied, sendRefused, enforced)
	}
	if !hasEvent(watched, func(e event) bool {
		return e.Verdict == "observed" && strings.HasSuffix(e.Path, "/without/home/.ssh/id_rsa")
	}) {
		t.Errorf("watched run: the key read is not recorded as observed")
	}
	if hasEvent(watched, func(e event) bool { return e.Kind == "refused" }) {
		t.Errorf("watched run: tego watch refused something")
	}

	if b := readFile(t, filepath.Join(w.stage, "with", "sink.log")); strings.Contains(b, "reached the sink") {
		t.Errorf("the right attacker received a request:\n%s", b)
	}
	left := readFile(t, filepath.Join(w.stage, "without", "sink.log"))
	mustContain(t, "left attacker log", left, "POST /beacon", "POST /env", "POST /exfil")
	mustContain(t, "project API log", readFile(t, filepath.Join(w.stage, "api.log")), "token OK")
}

// TestRetakeRestoresContract: a "Never allow" during a take rewrites the filled contract so the
// token read is denied outright. The next take then never shows the 0:15 ask. reset fills the contract again from
// the template and moves the ledger (its .rule-changes journal with it), check says why before it does, and
// reset keeps only the newest three old ledgers it moved. It used to delete every <ledger>.old-* folder past the
// newest three, so a folder of that name it never made went too; now such a folder, or a copy of a moved one, stays.
func TestRetakeRestoresContract(t *testing.T) {
	w := newWorld(t)
	w.mustDemo("setup")
	original := readFile(t, w.filled())
	with := filepath.Join(w.stage, "with")
	token := with + "/home/.config/telemetry/"

	// what Never allow does to the file: the token's ask_read entry becomes a deny_read entry
	edited := strings.Replace(original, `ask_read: ["`+token+`", `, `ask_read: [`, 1)
	edited = strings.Replace(edited, `deny_read: ["`+with+`/home/.ssh/"]`, `deny_read: ["`+with+`/home/.ssh/", "`+token+`"]`, 1)
	if edited == original {
		t.Fatalf("the test could not apply the Never allow edit to:\n%s", original)
	}
	if err := os.WriteFile(w.filled(), []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := w.demo("check")
	if code == 0 {
		t.Fatalf("check passed on a contract that no longer asks about the token:\n%s", out)
	}
	mustContain(t, "check", out, "the contract was changed (by Never allow?)", "fix: run: ./demo.sh reset")
	out, code = w.demo("backup")
	if code == 0 {
		t.Errorf("backup passed with no token ask to deny:\n%s", out)
	}
	mustContain(t, "backup on the edited contract", out, "no ask appeared for the token read")

	// the journal the dashboard's rule edits keep in the ledger, and old ledgers to prune
	journal := filepath.Join(w.ledger, ".rule-changes", "journal.jsonl")
	if err := os.MkdirAll(filepath.Dir(journal), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Four old ledgers reset moved, each marked with the folder it was moved to, and, older than all of them, two it
	// did not make: a folder of that name made by hand, and a copy of a moved one (its mark names the original).
	oldLedger := func(name, mark string, age time.Duration) string {
		d := w.ledger + ".old-" + name
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if mark != "" {
			if err := os.WriteFile(filepath.Join(d, oldMark), []byte(mark+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		past := time.Now().Add(-age)
		if err := os.Chtimes(d, past, past); err != nil {
			t.Fatal(err)
		}
		return d
	}
	for i := 1; i <= 4; i++ {
		name := fmt.Sprintf("0%d", i)
		oldLedger(name, w.ledger+".old-"+name, time.Duration(10-i)*time.Hour)
	}
	handMade := oldLedger("x", "", 20*time.Hour)
	copied := oldLedger("copy", w.ledger+".old-01", 21*time.Hour)

	w.mustDemo("reset")
	if got := readFile(t, w.filled()); got != original {
		t.Errorf("reset did not restore the contract:\n%s", got)
	}
	if out, code := w.demo("check"); code != 0 || !strings.Contains(out, "READY") {
		t.Errorf("check after reset: exit %d\n%s", code, out)
	}
	if entries, err := os.ReadDir(w.ledger); err != nil || len(entries) != 1 || entries[0].Name() != ".tego-supply-chain-ledger" {
		t.Errorf("the new ledger should hold only its setup marker: %v (%v)", entries, err)
	}
	olds, _ := filepath.Glob(w.ledger + ".old-*")
	var marked []string // the ones reset moved: each mark names its own folder
	for _, d := range olds {
		if b, err := os.ReadFile(filepath.Join(d, oldMark)); err == nil && string(b) == d+"\n" {
			marked = append(marked, d)
		}
	}
	if len(marked) != 3 {
		t.Errorf("reset keeps the newest 3 old ledgers it moved; found %v of %v", marked, olds)
	}
	moved := false
	for _, d := range marked {
		if _, err := os.Stat(filepath.Join(d, ".rule-changes", "journal.jsonl")); err == nil {
			moved = true
		}
	}
	if !moved {
		t.Errorf("the .rule-changes journal is in no old ledger marked as moved: %v of %v", marked, olds)
	}
	for _, gone := range []string{w.ledger + ".old-01", w.ledger + ".old-02"} {
		if _, err := os.Stat(gone); err == nil {
			t.Errorf("%s should have been pruned", gone)
		}
	}
	for _, kept := range []string{handMade, copied} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("reset deleted %s, a folder it did not move: %v", kept, err)
		}
	}
	// and the ask is back
	out = w.mustDemo("backup")
	mustContain(t, "backup after reset", out, "1 ask(s) denied")
}

// TestCheckNamesEachFailure: check exits non-zero, says what is wrong and how to fix it, for each way a take can
// start broken. READY comes only when nothing is.
func TestCheckNamesEachFailure(t *testing.T) {
	w := newWorld(t)
	w.mustDemo("setup")
	if out, code := w.demo("check"); code != 0 || !strings.HasSuffix(strings.TrimSpace(out), "READY") {
		t.Fatalf("a fresh setup is not READY: exit %d\n%s", code, out)
	}
	expect := func(name string, extra []string, want ...string) {
		t.Helper()
		out, code := w.demoEnv(extra, "check")
		if code != 1 {
			t.Errorf("%s: check exited %d, want 1\n%s", name, code, out)
		}
		if strings.Contains(out, "READY") {
			t.Errorf("%s: check printed READY\n%s", name, out)
		}
		mustContain(t, name, out, want...)
		mustContain(t, name, out, "fix:")
	}
	restore := func() { w.mustDemo("reset") }

	t.Run("busy port", func(t *testing.T) {
		w.systemctl("stop", w.unit("sink", w.right))
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(w.right))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close(); restore() }()
		expect("busy port", nil, "port "+strconv.Itoa(w.right)+" is busy", "ss -ltnp")
	})
	t.Run("inactive unit", func(t *testing.T) {
		w.systemctl("stop", w.unit("api", w.api))
		defer restore()
		expect("inactive unit", nil, w.unit("api", w.api)+" is not running")
	})
	t.Run("stale dashboard", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(w.dash))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		expect("stale dashboard", nil, "something already listens on the dashboard address")
	})
	t.Run("missing auth.json", func(t *testing.T) {
		auth := filepath.Join(w.stage, "without", "codex-home", "auth.json")
		if err := os.Remove(auth); err != nil {
			t.Fatal(err)
		}
		defer restore()
		expect("missing auth", nil, "no Codex login in "+auth)
	})
	t.Run("missing codex", func(t *testing.T) {
		expect("missing codex", []string{"PATH=" + filepath.Dir(w.bin) + ":/usr/local/bin:/usr/bin:/bin"}, "codex is not on PATH", "Install Codex")
	})
	t.Run("broken contract", func(t *testing.T) {
		if err := os.WriteFile(w.filled(), []byte("version: 0\nname: [\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		defer restore()
		expect("broken contract", nil, "the filled contract does not compile", "the contract was changed")
	})
	t.Run("changed contract", func(t *testing.T) {
		b := readFile(t, w.filled())
		if err := os.WriteFile(w.filled(), []byte(b+"# edited\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		defer restore()
		expect("changed contract", nil, "the contract was changed (by Never allow?)", "run: ./demo.sh reset")
	})
	t.Run("untrusted config", func(t *testing.T) {
		if err := os.Chmod(w.base, 0o775); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(w.base, 0o755) }()
		expect("untrusted config", nil, "is untrusted", "chmod go-w")
	})
	t.Run("version mismatch", func(t *testing.T) {
		dir := t.TempDir()
		fake := filepath.Join(dir, "tego")
		body := "#!/bin/sh\nif [ \"$1\" = version ]; then echo commit=0123456789abcdef0123456789abcdef01234567; exit 0; fi\nexec '" + w.bin + "' \"$@\"\n"
		if err := os.WriteFile(fake, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		expect("version mismatch", []string{"TEGO=" + fake}, "bin/tego is stale", "run: make build")
	})
	t.Run("stage under the ledger root", func(t *testing.T) {
		expect("stage under the ledger", []string{"DEMO_LEDGER=" + w.base}, "is inside the ledger root")
	})
	// after all of that, a reset leaves a demo that is READY again
	restore()
	if out, code := w.demo("check"); code != 0 || !strings.Contains(out, "READY") {
		t.Errorf("not READY after the failure cases: exit %d\n%s", code, out)
	}
}

// TestSetupRefusesAStageThatCannotHoldRules: the dashboard's rule edits refuse a contract inside the ledger root or
// tego's home, so setup says so up front instead of leaving every rule write "not writable".
func TestSetupRefusesAStageThatCannotHoldRules(t *testing.T) {
	w := newWorld(t)
	home := filepath.Join(w.base, "home")
	for name, c := range map[string]struct{ stage, want string }{
		"ledger root": {filepath.Join(w.ledger, "stage"), "is inside the ledger root"},
		"tego home":   {filepath.Join(home, ".tego", "stage"), "is inside tego's home"},
	} {
		t.Run(name, func(t *testing.T) {
			out, code := w.demoEnv([]string{"DEMO_STAGE=" + c.stage}, "setup")
			if code == 0 {
				t.Fatalf("setup accepted the stage %s:\n%s", c.stage, out)
			}
			mustContain(t, "setup", out, c.want)
			if w.unitActive(w.unit("sink", w.left)) {
				t.Errorf("setup started a unit although it refused the stage")
			}
		})
	}
}

// TestSetupRemovesOnlyItsOwnState: a folder named with/ that is not a demo side (no proj/ and codex-home/) belongs to
// someone else and is never removed, whatever stage the settings point at.
func TestSetupRemovesOnlyItsOwnState(t *testing.T) {
	w := newWorld(t)
	precious := filepath.Join(w.stage, "with", "precious.txt")
	if err := os.MkdirAll(filepath.Dir(precious), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(precious, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := w.demo("setup")
	if code == 0 {
		t.Fatalf("setup removed a folder that is not a demo side:\n%s", out)
	}
	mustContain(t, "setup", out, "it is not a demo side")
	if _, err := os.Stat(precious); err != nil {
		t.Errorf("the other folder's file is gone: %v", err)
	}
}

// TestResetStopsOnlyItsOwnUnits: reset --stop stops the three units it names and never a neighbour, not even one
// under the same prefix on another port (a user's tego-sc-* units stay up while a test resets).
func TestResetStopsOnlyItsOwnUnits(t *testing.T) {
	w := newWorld(t)
	w.mustDemo("setup")
	neighbour := w.unit("sink", w.left+1) // the same prefix, another port
	other := w.prefix + "-other"
	for _, u := range []string{neighbour, other} {
		cmd := exec.Command("systemd-run", "--user", "--unit="+u, "--collect", "-q", "sleep", "300")
		cmd.Env = append(os.Environ(), "XDG_RUNTIME_DIR="+w.sdRun)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("systemd-run %s: %v\n%s", u, err, out)
		}
		t.Cleanup(func() { w.systemctl("stop", u) })
	}
	w.mustDemo("reset", "--stop")
	for _, u := range []string{w.unit("sink", w.left), w.unit("sink", w.right), w.unit("api", w.api)} {
		if w.unitActive(u) {
			t.Errorf("%s is still running after reset --stop", u)
		}
	}
	for _, u := range []string{neighbour, other} {
		if !w.unitActive(u) {
			t.Errorf("reset --stop stopped %s, which is not one of its three units", u)
		}
	}
	if _, err := os.Stat(filepath.Join(w.stage, "with")); err == nil {
		t.Errorf("reset --stop left the generated state")
	}
}

// TestLeftAndRightStartWithOnlyTheFakeVariables: both terminals start through env -i. A variable of the
// presenter's real shell never reaches the agent, on the watched side or the enforced one, and the enforced side's
// contract drops even the demo's fake AWS and GitHub values. The command and its environment are printed.
func TestLeftAndRightStartWithOnlyTheFakeVariables(t *testing.T) {
	w := newWorld(t)
	w.mustDemo("setup")
	dump := func(side string) string {
		return readFile(t, filepath.Join(w.stage, side, "proj", "tmp", "codex-env.txt"))
	}

	out := w.mustDemo("left")
	mustContain(t, "left", out, "env -i", "HOME="+w.stage+"/without/home", "SC_SINK=http://127.0.0.1:"+strconv.Itoa(w.left), " watch --record full -- codex --no-daemon", "stub codex ran")
	env := dump("without")
	mustContain(t, "left environment", env, "AWS_SECRET_ACCESS_KEY=AKIA_FAKE_DEMO_SECRET_0000", "GITHUB_TOKEN=ghp_FAKE_DEMO_GITHUB_0000", "SERVICE_TOKEN=svc_demo_FAKE_SERVICE_TOKEN_0000")
	if strings.Contains(env, "MY_REAL_") || strings.Contains(out, "MY_REAL_") {
		t.Errorf("the presenter's real variable reached the watched side:\n%s", env)
	}

	out = w.mustDemo("right")
	mustContain(t, "right", out, "env -i", "HOME="+w.stage+"/with/home", "SC_SINK=http://127.0.0.1:"+strconv.Itoa(w.right), filepath.Base(w.filled()), "stub codex ran")
	env = dump("with")
	mustContain(t, "right environment", env, "SERVICE_TOKEN=svc_demo_FAKE_SERVICE_TOKEN_0000", "SC_API=http://127.0.0.1:"+strconv.Itoa(w.api))
	for _, bad := range []string{"MY_REAL_", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"} {
		if strings.Contains(env, bad) {
			t.Errorf("%s reached the enforced side:\n%s", bad, env)
		}
	}
}

// TestClaudeAgent: DEMO_AGENT=claude fills claude-code.yaml, readies Claude Code's own folder in each side, and starts
// the stub claude on both sides with the login from the shell, which reaches the agent and is never printed.
func TestClaudeAgent(t *testing.T) {
	w := newWorld(t)
	const login = "sk-ant-oat-STUB-LOGIN-0000"
	claude := []string{"DEMO_AGENT=claude"}
	run := func(env []string, args ...string) string {
		t.Helper()
		out, code := w.demoEnv(env, args...)
		if code != 0 {
			t.Fatalf("DEMO_AGENT=claude demo.sh %s: exit %d\n%s", strings.Join(args, " "), code, out)
		}
		return out
	}
	mustContain(t, "setup", run(claude, "setup"), "claude-home", "before left and right: run claude setup-token")
	filled := readFile(t, filepath.Join(w.stage, "with", "claude-code.filled.yaml"))
	if m := regexp.MustCompile(`@@[A-Z_]+@@`).FindString(filled); m != "" {
		t.Errorf("the placeholder %s is left in the filled contract", m)
	}
	with := filepath.Join(w.stage, "with")
	mustContain(t, "filled contract", filled, "name: supply-chain-claude-code",
		`deny_read: ["`+with+`/home/.ssh/"]`, `CLAUDE_CONFIG_DIR: "`+with+`/claude-home"`, "tcp://api.anthropic.com:443",
		fmt.Sprintf(`"/run/user/%d/cc-socks/"`, os.Getuid()))
	mustContain(t, "settings", readFile(t, filepath.Join(with, "claude-home", "settings.json")), `"bypassPermissions"`)
	mustContain(t, "claude.json", readFile(t, filepath.Join(with, "claude-home", ".claude.json")), `"`+with+`/proj": {"hasTrustDialogAccepted": true}`)

	if out, code := w.demoEnv(claude, "left"); code == 0 || !strings.Contains(out, "no Claude Code login in this shell") {
		t.Errorf("left without a login: exit %d\n%s", code, out)
	}
	if out, code := w.demoEnv(claude, "check"); code == 0 || !strings.Contains(out, "no Claude Code login in this shell") {
		t.Errorf("check without a login: exit %d\n%s", code, out)
	}
	withLogin := []string{"DEMO_AGENT=claude", "CLAUDE_CODE_OAUTH_TOKEN=" + login}
	if out := run(withLogin, "check"); !strings.Contains(out, "READY") {
		t.Errorf("check with a login is not READY:\n%s", out)
	}
	for _, side := range []string{"left", "right"} {
		out := run(withLogin, side)
		mustContain(t, side, out, "CLAUDE_CODE_OAUTH_TOKEN=...", "stub claude ran")
		if strings.Contains(out, login) {
			t.Errorf("%s printed the login:\n%s", side, out)
		}
	}
	env := readFile(t, filepath.Join(w.stage, "with", "proj", "tmp", "claude-env.txt"))
	mustContain(t, "right environment", env, "CLAUDE_CODE_OAUTH_TOKEN="+login, "CLAUDE_CONFIG_DIR="+with+"/claude-home", "SERVICE_TOKEN=svc_demo_FAKE_SERVICE_TOKEN_0000")
	for _, bad := range []string{"MY_REAL_", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"} {
		if strings.Contains(env, bad) {
			t.Errorf("%s reached the enforced side:\n%s", bad, env)
		}
	}
}

// TestPoisonedHelperNamesOnlyDemoVariables: the stand-in stealer sweeps and names only variables whose
// value says FAKE or DEMO. A credential-looking variable of a real shell is neither named nor sent.
func TestPoisonedHelperNamesOnlyDemoVariables(t *testing.T) {
	py := mustLookPath(t, "python3")
	pkg, err := filepath.Abs(filepath.Join("repo", "vendor", "telemetry-helper"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(py, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import telemetry_helper", pkg)
	home := t.TempDir()
	cmd.Env = []string{
		"HOME=" + home, "PATH=/usr/bin:/bin", "SC_SINK=http://127.0.0.1:1", // nothing listens: the sends fail
		"AWS_SECRET_ACCESS_KEY=AKIA_FAKE_DEMO_SECRET_0000",
		"MY_REAL_API_TOKEN=sk-live-0123456789abcdef", "CLAUDE_CODE_MESSAGING_TOKEN=real-looking-value",
	}
	out, _ := cmd.CombinedOutput()
	mustContain(t, "stealer", string(out), "AWS_SECRET_ACCESS_KEY")
	for _, bad := range []string{"MY_REAL_API_TOKEN", "CLAUDE_CODE_MESSAGING_TOKEN", "sk-live"} {
		if strings.Contains(string(out), bad) {
			t.Errorf("the stealer named %q, a variable of the presenter's real shell:\n%s", bad, out)
		}
	}
}

// TestProofPicksTheTakesRuns: proof used to show the newest enforced and watched runs, so a stray start after
// the take hid it. Here backup makes the take's pair, then left and right start the stub Codex, which reads nothing
// and makes two newer runs: proof names backup's enforced run (it holds the token's ask) and watched run (it read the
// key), and lists the newer ones on one line.
func TestProofPicksTheTakesRuns(t *testing.T) {
	w := newWorld(t)
	w.mustDemo("setup")
	w.mustDemo("backup")
	take := runEvents(t, w.ledger)
	w.mustDemo("right")
	w.mustDemo("left")
	all := runEvents(t, w.ledger)
	if len(all) != len(take)+2 {
		t.Fatalf("the ledger holds %d runs after left and right, want %d", len(all), len(take)+2)
	}
	var tookRight, tookLeft, newRight, newLeft string
	for id, evs := range all {
		if len(evs) == 0 {
			continue
		}
		_, inTake := take[id]
		switch {
		case evs[0].Agent == contractName && inTake:
			tookRight = id
		case evs[0].Agent == contractName:
			newRight = id
		case strings.HasPrefix(evs[0].Agent, "watch-") && inTake:
			tookLeft = id
		case strings.HasPrefix(evs[0].Agent, "watch-"):
			newLeft = id
		}
	}
	if tookRight == "" || tookLeft == "" || newRight == "" || newLeft == "" {
		t.Fatalf("runs: take right %q left %q, newer right %q left %q", tookRight, tookLeft, newRight, newLeft)
	}
	out := w.mustDemo("proof")
	mustContain(t, "proof", out,
		"RIGHT (the take's enforced run "+tookRight+": the newest with the token's ask): what Tego refused of the attack",
		"(other enforced runs in this ledger, newest first: "+newRight+")",
		"LEFT (the take's watched run "+tookLeft+": the newest that read the key): the key was read, the sends were observed",
		"(other watched runs in this ledger, newest first: "+newLeft+")",
		"open <stage>/with/home/.config/telemetry/token\n",
		"open <stage>/without/home/.ssh/id_rsa\n")
	if strings.Contains(out, "events "+newRight+" --kind refused") || strings.Contains(out, "events "+newLeft+"   (") {
		t.Errorf("proof printed a newer run's rows instead of the take's:\n%s", out)
	}
}

// TestKitIsRelocatable: nothing in the script, its settings or the docs is tied to one person's folders.
func TestKitIsRelocatable(t *testing.T) {
	userHome := regexp.MustCompile(`(?m)(?:^|[^\w./-])/home/[a-z_][a-z0-9_-]*`) // an absolute path, not a stage's with/home/
	for _, f := range []string{"demo.sh", "demo.env", "RUNBOOK.md", "README.md"} {
		if m := userHome.FindString(readFile(t, f)); m != "" {
			t.Errorf("%s names %s: paths must come from the script's location", f, m)
		}
	}
	if out, err := exec.Command("sh", "-n", "demo.sh").CombinedOutput(); err != nil {
		t.Errorf("demo.sh does not parse: %v\n%s", err, out)
	}
}

// TestSetupRunsTheSelfCheck: the setup never showed `tego test`, the command that shows, before a take and apart from
// the demo, that Tego refuses on this laptop. The setup block's bin/tego test line runs as written (bin/tego is this
// test's build) with a HOME, a TMPDIR and a $TEGO_CONFIG of its own, the config written as setup writes the demo's: it
// exits 0, its first line is the one the RUNBOOK quotes, and it leaves nothing in TMPDIR or in the config's ledger.
func TestSetupRunsTheSelfCheck(t *testing.T) {
	_, setup, _ := strings.Cut(readFile(t, "RUNBOOK.md"), "\n## 1. Setup")
	setup, _, _ = strings.Cut(setup, "\n## 2.")
	_, block, _ := strings.Cut(setup, "```sh\n")
	block, _, _ = strings.Cut(block, "```")
	var args []string
	for _, line := range strings.Split(block, "\n") {
		cmd, _, _ := strings.Cut(line, "#")
		if f := strings.Fields(cmd); len(f) > 1 && f[0] == "bin/tego" && f[1] == "test" {
			args = f[1:]
		}
	}
	if args == nil {
		t.Fatalf("RUNBOOK.md's setup block runs no bin/tego test:\n%s", block)
	}
	quote := regexp.MustCompile("`(Tego self-check: [^`]+)`").FindStringSubmatch(setup)
	if quote == nil {
		t.Fatal("RUNBOOK.md's setup does not quote tego test's first line (`Tego self-check: ...`)")
	}
	bin, _ := binaries(t)
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil { // the machine config's directory must not be group-writable
		t.Fatal(err)
	}
	home, tmp, ledger := filepath.Join(base, "home"), filepath.Join(base, "tmp"), filepath.Join(base, "ledger")
	for _, d := range []string{home, tmp, ledger} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(base, "tego-demo.yaml")
	if err := os.WriteFile(cfg, []byte("version: 0\nledger_root: "+ledger+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := testutil.TegoEnv(t, base, "HOME="+home, "TMPDIR="+tmp, "TEGO_CONFIG="+cfg)
	doctor := exec.Command(bin, "doctor", "--require", "landlock")
	doctor.Env = env
	testutil.RequireTier(t, doctor, "landlock")

	cmd := exec.Command(bin, args...)
	cmd.Env = env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bin/tego %s: %v\n%s\n%s", strings.Join(args, " "), err, out, stderr.String())
	}
	if first, _, _ := strings.Cut(string(out), "\n"); first != quote[1] {
		t.Errorf("tego test's first line is %q; RUNBOOK.md quotes %q", first, quote[1])
	}
	for _, d := range []string{tmp, ledger} {
		if left := dirNames(t, d); len(left) > 0 {
			t.Errorf("tego test left %v in %s", left, d)
		}
	}
}
