// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Lists is what a run's contract names, read from the copy the run kept (<run>/contract.yaml), so the dashboard
// can say which list an action fell outside of instead of "unmatched". It is a plain reading of the file, not a
// compile: an entry an extends profile contributed is in the copy too (the copy is sealed), and a list the contract
// leaves out is empty.
type Lists struct {
	Write, Ask, AskRead, DenyRead, DenyWrite, Exec, Net []string
	// AskTimeout is how long the run holds a request before Tego refuses it: the copy's ask.timeout, else the
	// default agent.CompileAskConfig gives (4 m under ask.hold: request, 5 m otherwise). Zero when the copy was not read.
	AskTimeout time.Duration
	OK         bool // the copy was read
}

// A run's contract copy is written once, at run start, and the overview asks for the lists of every run with a
// refusal on each load, so a reading is kept per file and reused while the file has the same identity, size and
// mtime. A copy that changed in any of them is read again.
type listsKey struct {
	path     string
	dev, ino uint64
	size     int64
	mtime    int64
}

// maxLists bounds the cache, dropped wholesale past it.
const maxLists = 1 << 14

var (
	listsMu    sync.Mutex
	listsCache = map[string]struct {
		k listsKey
		l Lists
	}{}
)

// RunLists reads the run's contract copy under the ledger root. The Lists slices are shared and must not be
// modified. The run id comes from a request, so it is checked before it names a path; the copy is read as Load reads
// it (readCopy: no link followed, a regular file, at most agent.MaxContractSize bytes), never through a link a run
// directory might hold in its place (F20), and the cache key is the copy's own (Lstat), not a link's target.
func RunLists(root, run string) Lists {
	if !ledger.IsRunID(run) {
		return Lists{}
	}
	path := filepath.Join(root, run, ledger.ContractFile)
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return Lists{}
	}
	k := listsKey{path: path, size: fi.Size(), mtime: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		k.dev, k.ino = uint64(st.Dev), st.Ino //nolint:unconvert // Dev's type differs between platforms
	}
	listsMu.Lock()
	e, ok := listsCache[path]
	listsMu.Unlock()
	if ok && e.k == k {
		return e.l
	}
	l := readLists(path)
	listsMu.Lock()
	if len(listsCache) >= maxLists {
		clear(listsCache)
	}
	listsCache[path] = struct {
		k listsKey
		l Lists
	}{k, l}
	listsMu.Unlock()
	return l
}

func readLists(path string) Lists {
	b, err := readCopy(path)
	if err != nil {
		return Lists{}
	}
	var c struct {
		FS struct {
			Write     []string `yaml:"write"`
			Ask       []string `yaml:"ask"`
			AskRead   []string `yaml:"ask_read"`
			DenyRead  []string `yaml:"deny_read"`
			DenyWrite []string `yaml:"deny_write"`
		} `yaml:"fs"`
		Exec struct {
			Allow []string `yaml:"allow"`
		} `yaml:"exec"`
		Net struct {
			Allow []string `yaml:"allow"`
		} `yaml:"net"`
		// Ask is decoded on its own, so an ask block this reading does not expect costs only the timeout, never the lists.
		Ask yaml.Node `yaml:"ask"`
	}
	if config.GuardYAML(func() error { return yaml.Unmarshal(b, &c) }) != nil {
		return Lists{}
	}
	var ask struct {
		Hold    string `yaml:"hold"`
		Timeout string `yaml:"timeout"`
	}
	if c.Ask.Kind != 0 && config.GuardYAML(func() error { return c.Ask.Decode(&ask) }) != nil {
		ask.Hold, ask.Timeout = "", ""
	}
	return Lists{Write: c.FS.Write, Ask: c.FS.Ask, AskRead: c.FS.AskRead, DenyRead: c.FS.DenyRead, DenyWrite: c.FS.DenyWrite,
		Exec: c.Exec.Allow, Net: c.Net.Allow, AskTimeout: askTimeout(ask.Hold, ask.Timeout), OK: true}
}

// askTimeout is the hold a contract gives a request, with agent.CompileAskConfig's defaults for a key it leaves out.
// A value the compiler refuses cannot be in a run's copy (that run would not have started); it reads as the default.
func askTimeout(hold, timeout string) time.Duration {
	if d, err := agent.ParseDuration(timeout); err == nil && d > 0 && time.Duration(d) <= time.Hour {
		return time.Duration(d)
	}
	if agent.AskHold(hold) == agent.AskHoldRequest {
		return 4 * time.Minute
	}
	return 5 * time.Minute
}

// Explain is, for an action the contract's default decided (rule "unmatched"), a short label for why: the list it
// fell outside of, or that reads are open; "" when there is nothing more exact to say than the rule key.
func (l Lists) Explain(kind, op, verdict string) string {
	if !l.OK {
		return ""
	}
	refused := strings.HasPrefix(verdict, "refused") || kind == "refused"
	switch {
	case !refused && (op == "open" || op == "read" || kind == "fs" && op == ""):
		return "Open by default"
	case kind == "exec" || op == "exec":
		return "Program not in policy"
	case kind == "net" || op == "net" || op == "connect":
		return "Host not in policy"
	case refused:
		return "Outside writable folders"
	}
	return ""
}
