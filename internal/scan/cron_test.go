// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"github.com/attention-span-ai/tego/internal/scan/result"

	"golang.org/x/sys/unix"
)

func TestCronParser(t *testing.T) {
	users := map[string]uint32{"root": 0, "alice": 1001}
	for _, tc := range []struct {
		name, text string
		system     bool
		want       []cronEntry
		err        error
	}{
		{"system", "SHELL=/bin/sh\nPATH=/usr/bin\n17 * * * * alice /usr/bin/codex --token " + mcpCanary + "\n", true, []cronEntry{{1001, "codex-native"}}, nil},
		{"spool", "@reboot /opt/bin/claude --api-key=" + mcpCanary + "\n", false, []cronEntry{{1002, "claude-native"}}, nil},
		{"schedule", "*/10 1-23/2 1,15 jan-dec mon-fri root gemini\n", true, []cronEntry{{0, "gemini-native"}}, nil},
		{"quoted", "0 0 * * * root co\"dex\" 'literal $TOKEN' \"x; y\" \\; # " + mcpCanary + "\n", true, []cronEntry{{0, "codex-native"}}, nil},
		{"node", "0 0 * * * root node /opt/node_modules/@openai/codex/bin/codex.js --token " + mcpCanary + "\n", true, []cronEntry{{0, "codex-node"}}, nil},
		{"native-secret", "0 0 * * * root /usr/bin/codex --token=\"" + mcpCanary + "\"\n", true, []cronEntry{{0, "codex-native"}}, nil},
		{"plain-unrelated", "0 0 * * * root /usr/bin/backup --file /tmp/a\n", true, []cronEntry{}, nil},
		{"comments", "# " + mcpCanary + "\n\nENV_" + mcpCanary + "=\"" + mcpCanary + "\"\n", true, []cronEntry{}, nil},
		{"unknown-account", "0 0 * * * unknown codex\n", true, nil, errUnresolved},
		{"shell", "0 0 * * * root /bin/sh -c 'codex --token " + mcpCanary + "'\n", true, nil, errUnresolved},
		{"shell-list", "0 0 * * * root codex; /bin/echo '" + mcpCanary + "'\n", true, nil, errUnresolved},
		{"shell-redirection", "0 0 * * * root codex >/dev/null\n", true, nil, errUnresolved},
		{"shell-pipe", "0 0 * * * root codex | cat\n", true, nil, errUnresolved},
		{"shell-assignment", "0 0 * * * root TOKEN=" + mcpCanary + " codex\n", true, nil, errUnresolved},
		{"shell-secret-expansion", "0 0 * * * root node /opt/@openai/codex/bin/codex.js --token $(printf '" + mcpCanary + "')\n", true, nil, errUnresolved},
		{"literal-expansion", "0 0 * * * root codex \"\\$TOKEN\" '`literal`' \"*.txt\"\n", true, []cronEntry{{0, "codex-native"}}, nil},
		{"shell-backtick", "0 0 * * * root codex --token `printf '" + mcpCanary + "'`\n", true, nil, errUnresolved},
		{"shell-expansion", "0 0 * * * root codex --token $TOKEN\n", true, nil, errUnresolved},
		{"shell-command-substitution", "0 0 * * * root codex $(printf '" + mcpCanary + "')\n", true, nil, errUnresolved},
		{"percent-in-quotes", "0 0 * * * root codex 'x%" + mcpCanary + "'\n", true, nil, errUnresolved},
		{"percent-escaped", "0 0 * * * root codex x\\%y\n", true, []cronEntry{{0, "codex-native"}}, nil},
		{"glob-program", "0 0 * * * root /opt/*/codex\n", true, nil, errUnresolved},
		{"wrapper", "0 0 * * * root nice codex\n", true, nil, errUnresolved},
		{"argument-glob", "0 0 * * * root codex *.txt\n", true, nil, errUnresolved},
		{"shell-ksh", "0 0 * * * root ksh -c codex\n", true, nil, errUnresolved},
		{"quoted-shell", "SHELL=\"/bin/sh\"\n0 0 * * * root codex\n", true, []cronEntry{{0, "codex-native"}}, nil},
		{"unclosed-shell", "SHELL=\"/bin/sh\n0 0 * * * root codex\n", true, nil, errUnresolved},
		{"custom-shell", "SHELL=/bin/fish\n0 0 * * * root codex\n", true, nil, errUnresolved},
		{"unsupported-macro", "@every root codex\n", true, nil, errUnresolved},
		{"range", "60 * * * * root codex\n", true, nil, errUnsupported},
		{"random-range", "~ * * * * root codex\n", true, nil, errUnsupported},
		{"trailing-list", "1, * * * * root codex\n", true, nil, errUnsupported},
		{"empty-command", "0 0 * * * root\n", true, nil, errSyntax},
		{"quote-error", "0 0 * * * root codex '" + mcpCanary + "\n", true, nil, errSyntax},
		{"partial-discard", "0 0 * * * root codex\n0 0 * * * root sh -c '" + mcpCanary + "'\n", true, nil, errUnresolved},
		{"unterminated", "0 0 * * * root codex", true, nil, errSyntax},
		{"long-line", "#" + strings.Repeat("x", unitLineBytes) + "\n", true, nil, errSize},
		{"too-many-lines", strings.Repeat("#\n", unitTokenLimit+1), true, nil, errLimit},
		{"too-many-jobs", strings.Repeat("0 0 * * * root codex\n", unitExecLimit+1), true, nil, errLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := parseCron(context.Background(), strings.NewReader(tc.text), tc.system, 1002, users)
			if !errors.Is(e, tc.err) || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, %v; want %v, %v", got, e, tc.want, tc.err)
			}
			assertNoCanary(t, got)
			assertNoCanary(t, e)
		})
	}
}

func TestCronDistributionContents(t *testing.T) {
	for _, tc := range []struct {
		file              string
		bytes, lines, max int
		err               error
	}{
		{"crontab", 1136, 23, 94, errUnresolved},
		{"cron.d/.placeholder", 102, 2, 77, nil},
		{"cron.d/anacron", 224, 5, 144, errUnresolved},
		{"cron.d/e2scrub_all", 188, 2, 101, errUnresolved},
		{"cron.d/sysstat", 400, 9, 72, errUnresolved},
	} {
		t.Run(tc.file, func(t *testing.T) {
			b := fixtureContent(t, "cron-layouts/ubuntu-25.10/etc/"+tc.file)
			if len(b) != tc.bytes || strings.Count(string(b), "\n") != tc.lines {
				t.Fatal("distribution fixture changed")
			}
			maxLine := 0
			for _, line := range strings.Split(string(b), "\n") {
				maxLine = max(maxLine, len(line))
			}
			if maxLine != tc.max || unitLineBytes < 10*maxLine || manifestBytes < 10*len(b) || unitTokenLimit < 10*tc.lines {
				t.Fatal("bound lacks measured headroom")
			}
			got, e := parseCron(context.Background(), strings.NewReader(string(b)), true, 0, map[string]uint32{"root": 0})
			if !errors.Is(e, tc.err) || len(got) != 0 {
				t.Fatalf("got %v, %v; want %v", got, e, tc.err)
			}
		})
	}
}

func cronFixture(t testing.TB) (CronRoots, []localAccount, uint32) {
	t.Helper()
	root := t.TempDir()
	paths := CronRoots{filepath.Join(root, "etc/crontab"), filepath.Join(root, "etc/cron.d"), filepath.Join(root, "var/spool/cron"), filepath.Join(root, "var/spool/cron/crontabs")}
	for _, path := range []string{filepath.Dir(paths.Crontab), paths.Directory, paths.Spool, paths.Crontabs} {
		if e := os.MkdirAll(path, 0700); e != nil {
			t.Fatal(e)
		}
	}
	uid := uint32(os.Getuid())
	return paths, []localAccount{{Name: "root", UID: uid}, {Name: "alice", UID: uid}}, uid
}

func writeCron(t testing.TB, path, text string) {
	t.Helper()
	if e := os.WriteFile(path, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
}

func TestCronCollectionPrivacyAndFixedRoots(t *testing.T) {
	roots, accounts, uid := cronFixture(t)
	writeCron(t, roots.Crontab, "0 0 * * * root codex --token "+mcpCanary+"\n")
	writeCron(t, filepath.Join(roots.Directory, "agents"), "@reboot alice claude --password='"+mcpCanary+"'\n")
	writeCron(t, filepath.Join(roots.Spool, "alice"), "@daily opencode --key "+mcpCanary+"\n")
	writeCron(t, filepath.Join(roots.Crontabs, "alice"), "0 0 * * * gemini --header "+mcpCanary+"\n")
	// A file under an arbitrary nested folder is never a source.
	if e := os.Mkdir(filepath.Join(roots.Directory, "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	writeCron(t, filepath.Join(roots.Directory, "nested", "secret"), mcpCanary)
	budget := &contentBudget{remaining: 1 << 20}
	s := collectCronOwned(context.Background(), roots, accounts, budget, uid)
	if len(s.Items) != 4 || budget.files != 5 {
		t.Fatalf("items=%d attempts=%d sources=%v", len(s.Items), budget.files, s.Sources)
	}
	for _, item := range s.Items {
		if item.UID == nil || *item.UID != uid {
			t.Fatal("missing uid")
		}
	}
	assertNoCanary(t, s)
	b, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	assertNoCanary(t, b)
}

func TestCronCollectionRejectsUnsafeSources(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(testing.TB, string)
	}{
		{"symlink", "symlink", func(t testing.TB, p string) {
			if e := os.Remove(p); e != nil {
				t.Fatal(e)
			}
			if e := os.Symlink("../../outside", p); e != nil {
				t.Fatal(e)
			}
		}},
		{"hardlink", "type", func(t testing.TB, p string) {
			if e := os.Link(p, p+"-other"); e != nil {
				t.Fatal(e)
			}
		}},
		{"group-write", "mode", func(t testing.TB, p string) {
			if e := os.Chmod(p, 0664); e != nil {
				t.Fatal(e)
			}
		}},
		{"fifo", "type", func(t testing.TB, p string) {
			if e := os.Remove(p); e != nil {
				t.Fatal(e)
			}
			if e := unix.Mkfifo(p, 0600); e != nil {
				t.Fatal(e)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, accounts, uid := cronFixture(t)
			writeCron(t, roots.Crontab, "0 0 * * * root codex\n")
			tc.change(t, roots.Crontab)
			s := collectCronOwned(context.Background(), CronRoots{Crontab: roots.Crontab}, accounts, &contentBudget{remaining: 1 << 20}, uid)
			if len(s.Items) != 0 || len(s.Sources) != 1 || s.Sources[0].Reason != tc.reason || s.Sources[0].NotRead != 1 {
				t.Fatalf("unsafe source=%v", s)
			}
		})
	}
}

func TestCronSpoolDirectoryModes(t *testing.T) {
	for _, tc := range []struct {
		mode os.FileMode
		want string
	}{{0700, "none"}, {0710, "none"}, {0755, "none"}, {os.ModeSticky | 0730, "none"}, {0730, "mode"}, {os.ModeSticky | 0733, "mode"}} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			roots, accounts, uid := cronFixture(t)
			writeCron(t, filepath.Join(roots.Crontabs, "alice"), "@daily codex\n")
			if e := os.Chmod(roots.Crontabs, tc.mode); e != nil {
				t.Fatal(e)
			}
			s := collectCronOwned(context.Background(), CronRoots{Crontabs: roots.Crontabs}, accounts, &contentBudget{remaining: 1 << 20}, uid)
			if tc.want == "none" && len(s.Items) != 1 {
				t.Fatalf("ordinary spool refused: %v", s)
			}
			if tc.want != "none" && (len(s.Items) != 0 || len(s.Sources) != 1 || s.Sources[0].Reason != tc.want) {
				t.Fatalf("unsafe spool accepted: %v", s)
			}
		})
	}
}

func TestCronCollectionBudgets(t *testing.T) {
	roots, accounts, uid := cronFixture(t)
	writeCron(t, roots.Crontab, "0 0 * * * root codex\n")
	budget := &contentBudget{remaining: 8}
	s := collectCronOwned(context.Background(), CronRoots{Crontab: roots.Crontab}, accounts, budget, uid)
	if len(s.Items) != 0 || budget.remaining != 0 || s.Sources[0].State != "not-read" {
		t.Fatalf("byte bound: %v, %v", s, budget)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s = collectCronOwned(ctx, roots, accounts, &contentBudget{remaining: 1 << 20}, uid)
	if len(s.Items) != 0 {
		t.Fatal("canceled collection retained items")
	}
}

func FuzzCronFile(f *testing.F) {
	for _, seed := range []string{"0 0 * * * root codex\n", "@reboot root node /opt/@openai/codex/bin/codex.js --token " + mcpCanary + "\n", "TOKEN=" + mcpCanary + "\n0 0 * * * root claude\n", "0 0 * * * root sh -c '" + mcpCanary + "'\n", "0 0 * * * root codex 'x%y'\n"} {
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, raw string, system bool) {
		if len(raw) > manifestBytes+1 {
			return
		}
		x, e := parseCron(context.Background(), strings.NewReader(raw), system, 1000, map[string]uint32{"root": 0, "alice": 1000})
		if e != nil && len(x) != 0 {
			t.Fatal("partial evidence")
		}
		for _, row := range x {
			switch row.Program {
			case "claude-native", "codex-native", "gemini-native", "opencode-native", "claude-node", "codex-node", "gemini-node-bin", "gemini-node-dist", "opencode-node":
			default:
				t.Fatal("noncatalog command retained")
			}
			if row.UID != 0 && row.UID != 1000 {
				t.Fatal("unselected uid")
			}
		}
		assertNoCanary(t, x)
		assertNoCanary(t, e)
	})
}

func TestCronCollectionRetainedCaps(t *testing.T) {
	for _, tc := range []struct {
		name               string
		files, jobs, items int
	}{
		{"items", 6, unitExecLimit, 512},
		{"sources", 1801, 0, 0},
		{"directory", unitTotalEntries, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, accounts, uid := cronFixture(t)
			for i := 0; i < tc.files; i++ {
				writeCron(t, filepath.Join(roots.Directory, strconv.Itoa(i)), strings.Repeat("0 0 * * * root codex\n", tc.jobs))
			}
			b := &contentBudget{remaining: 6 << 20}
			s := collectCronOwned(context.Background(), CronRoots{Directory: roots.Directory}, accounts, b, uid)
			if len(s.Items) != tc.items || len(s.Sources) > 1801 {
				t.Fatalf("cap not held: items=%d sources=%d", len(s.Items), len(s.Sources))
			}
			last := s.Sources[len(s.Sources)-1]
			if last.Reason != "limit" || last.State != "not-read" {
				t.Fatalf("no unknown remainder: %v", last)
			}
			if tc.name == "directory" && b.files != 0 {
				t.Fatalf("overflow listing read content: %d", b.files)
			}
		})
	}
}

// The production collector requires real root. This test substitutes only fixed
// source ownership, then passes the retained facts through every public channel.
func TestCronAllOutputChannels(t *testing.T) {
	roots, accounts, uid := cronFixture(t)
	writeCron(t, roots.Crontab, "SHELL=/bin/sh\nTOKEN_"+mcpCanary+"="+mcpCanary+"\n0 0 * * * root codex --password "+mcpCanary+"\n")
	writeCron(t, filepath.Join(roots.Directory, "agents"), "@reboot alice node /opt/node_modules/@anthropic-ai/claude-code/cli.js --token="+mcpCanary+"\n")
	writeCron(t, filepath.Join(roots.Directory, "unsupported"), "0 0 * * * root sh -c '"+mcpCanary+"'\n")
	writeCron(t, filepath.Join(roots.Spool, "alice"), "@daily opencode --header "+mcpCanary+"\n")
	writeCron(t, filepath.Join(roots.Crontabs, "alice"), "0 0 * * * gemini --api-key "+mcpCanary+"\n")
	observed := collectCronOwned(t.Context(), roots, accounts, &contentBudget{remaining: 1 << 20}, uid)
	if len(observed.Items) != 4 {
		t.Fatalf("missing canary sources: %+v", observed)
	}
	assertNoCanary(t, observed)
	s := result.NewAdvanced(time.Date(2026, 11, 12, 15, 0, 0, 0, time.UTC), 0, uid, "dev")
	// A process check requires a boot identity even when this fixture has no A rows.
	s.Boot = result.Path("11111111-2222-4333-8444-555555555555")
	s.Status = "ok"
	for _, name := range []string{"claude", "codex", "gemini", "opencode"} {
		s.Rules = append(s.Rules, result.Rule{ID: "cron-" + name, Name: name, Origin: "catalog"})
	}
	sourceIDs := map[string]string{}
	for i, p := range observed.Sources {
		id := "source-" + strconv.Itoa(i+1)
		s.Sources = append(s.Sources, result.Source{ID: id, Kind: "cron", Locator: result.Path(p.Path), State: p.State, Reason: p.Reason, Read: p.Read, NotRead: p.NotRead})
		if p.State == "read" && p.Read == 1 {
			sourceIDs[p.Path] = id
		}
		if p.State == "not-read" || p.State == "partial" {
			s.Status = "partial"
		}
	}
	for i, p := range observed.Items {
		name, ok := catalog.ObservedName(p.Program)
		if !ok || sourceIDs[p.Path] == "" {
			t.Fatal("invalid retained cron evidence")
		}
		s.Items = append(s.Items, result.Item{ID: "item-" + strconv.Itoa(i+1), Kind: "cron", Name: name, Evidence: []result.Evidence{{RuleID: "cron-" + name, SourceID: sourceIDs[p.Path], Fact: "cron-command"}}, Detail: result.Detail(result.Cron{Path: result.Path(p.Path), UID: p.UID, Program: result.Path(p.Program)}), Caveats: []string{"configured-only", "name-collision"}})
		s.Counts.Cron++
	}
	if s.Status != "partial" {
		t.Fatal("unsupported source was lost")
	}
	assertNoCanary(t, s)
	for _, check := range []bool{false, true} {
		x := s
		if check {
			x.Check = "none-observed"
		}
		encoded, e := result.Encode(x)
		if e != nil {
			t.Fatalf("check %t: %v", check, e)
		}
		assertNoCanary(t, encoded)
		if _, e = result.Decode(encoded); e != nil {
			t.Fatal(e)
		}
		for _, jsonMode := range []bool{false, true} {
			for _, verbose := range []bool{false, true} {
				var stdout, stderr bytes.Buffer
				e := result.Render(&stdout, &stderr, x, jsonMode, verbose, nil)
				if e != nil {
					t.Fatal(e)
				}
				assertNoCanary(t, stdout.String())
				assertNoCanary(t, stderr.String())
				if !strings.Contains(stderr.String(), "could not be read") {
					t.Fatal("unreadable source footer missing")
				}
			}
		}
	}
	home := t.TempDir()
	if e := os.Mkdir(filepath.Join(home, ".tego"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := result.Save(home, uid, s); e != nil {
		t.Fatal(e)
	}
	cache := filepath.Join(home, ".tego/scan/last.json")
	b, e := os.ReadFile(cache)
	if e != nil {
		t.Fatal(e)
	}
	assertNoCanary(t, b)
	st, e := os.Stat(cache)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("private result mode: %v, %v", st, e)
	}
	if _, e = result.Decode(b); e != nil {
		t.Fatal(e)
	}
}
