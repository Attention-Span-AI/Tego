// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// The run page's Processes tab (templates/procs.tmpl): the run's process tree from ledgerview.ProcessTree, which
// rebuilds it from exec_id and parent_exec_id, laid out for the page. This file only lays it out: which branches
// open, which like processes fold into one group, how many processes one page shows, and the words. The numbers are
// the tree's.

// pageParts are the template files a page parses besides the shared ones and its own.
var pageParts = map[string][]string{"run": {"templates/procs.tmpl"}}

// procsView is the Processes tab.
type procsView struct {
	Tree *ledgerview.ProcTree
	Root *procItem
	// Shown is the processes the page shows; Cut the ones it leaves out past procsShown (Logs has their lines).
	Shown, Cut int
	// Actions is the run's lines but the refusal notes (the tree's lines and the lines on no process); Notes is the
	// refusal notes, the kind=refused lines that mirror a refused action (pair.go). Together they are the run's lines,
	// the count the run's head shows.
	Actions, Notes int
}

// procsHold is how long a live run's Processes tab is laid out once and shown again as it was: the tree of a busy
// run changes with every line, and a region refresh (regions.go) that sent the whole tree each second sent hundreds
// of kilobytes a second. The same view renders the same bytes, so the region's hash holds and live.js is told
// nothing changed. An ended run is laid out fresh every time.
const procsHold = 5 * time.Second

// procsHeld is the last laid-out tab of each live run, by ledger root and run.
var procsHeld = struct {
	sync.Mutex
	m map[string]heldProcs
}{m: map[string]heldProcs{}}

type heldProcs struct {
	v  *procsView
	at time.Time
}

// maxHeldProcs bounds procsHeld; past it the map is dropped wholesale (a few live runs are open at a time).
const maxHeldProcs = 64

// procsFor is run's Processes tab as of now, the one laid out within procsHold when the run is live.
func procsFor(ledger string, run *ledgerview.Run, now time.Time) *procsView {
	key := ledger + "\x00" + run.ID
	live := run.State() == "running"
	if live {
		procsHeld.Lock()
		h, ok := procsHeld.m[key]
		procsHeld.Unlock()
		if ok && !now.Before(h.at) && now.Sub(h.at) < procsHold {
			return h.v
		}
	}
	v := procsOf(ledgerview.ProcessTree(run))
	evs := run.AllEvents()
	for i := range evs {
		if evs[i].Mirror {
			v.Notes++
		}
	}
	v.Actions = v.Tree.Lines + v.Tree.NoPID
	procsHeld.Lock()
	defer procsHeld.Unlock()
	if !live {
		delete(procsHeld.m, key)
		return v
	}
	if len(procsHeld.m) >= maxHeldProcs {
		procsHeld.m = map[string]heldProcs{}
	}
	procsHeld.m[key] = heldProcs{v: v, at: now}
	return v
}

// procItem is one process as the page shows it.
type procItem struct {
	N *ledgerview.ProcNode
	// Cmd is its command line, a shell launcher in front of a script elided (shellTail); Full is all the tree keeps.
	Cmd, Full string
	// Open opens its branch: near the root (depth below procsOpenDepth) or with a refusal in it.
	Open bool
	// Execs is every exec of it, shown when there is more than one or one was refused.
	Execs []procExec
	// Hosts names the hosts it reached, most first.
	Hosts string
	// Kids are its children, like ones folded into groups; More is how many are not shown (procsShown).
	Kids []procKid
	More int
	// Logs is the Logs address of the process's lines: the run, where pid:<pid>.
	Logs string
	// Tried is where a process that was not allowed to run tried its program, Tries how many times.
	Tried string
	Tries int
}

// procExec is one exec of a process as the page shows it.
type procExec struct {
	ledgerview.ProcExec
	// Cmd is the command as the row shows it (a shell launcher elided), Full as the tree keeps it.
	Cmd, Full string
	// Others is the folded execs past the first, with the paths a PATH search tried.
	Others int
	Paths  string
}

// procKid is a child: a process, or a group of like processes.
type procKid struct {
	Item  *procItem
	Group *procGroup
}

// procGroup is three or more processes of one parent that ran the same program and started nothing of their own
// (Codex's git status calls, a pipeline's subshells): one closed fold, opened when one of them ran its program and
// had something refused. A group whose processes were all refused their program stays closed and says so.
type procGroup struct {
	Key, Name     string
	Items         []*procItem
	Lines, Refuse int
	// Open opens the group when one of its processes ran and had something refused; NotRun says every one was
	// refused its program (lsb_release, getconf), which the closed line says.
	Open, NotRun bool
}

const (
	// procsShown bounds the processes one page shows: a run can start tens of thousands, and every one past this is
	// still counted and in Logs.
	procsShown = 600
	// procsOpenDepth opens the launcher, the agent and the agent's children; a branch with a refusal opens at any
	// depth.
	procsOpenDepth = 3
	// procsGroupMin is how many like leaves fold into a group.
	procsGroupMin = 3
)

// procsOf lays out run tree t for the page, breadth first, so the top of the tree is always shown and the cut
// falls on the deepest, latest processes.
func procsOf(t *ledgerview.ProcTree) *procsView {
	v := &procsView{Tree: t, Root: newProcItem(t.Root)}
	v.Shown = 1
	queue := []*procItem{v.Root}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		kids := it.N.Children
		room := max(procsShown-v.Shown, 0)
		if len(kids) > room {
			it.More = len(kids) - room
			v.Cut += it.More + below(kids[room:])
			kids = kids[:room]
		}
		v.Shown += len(kids)
		items := make([]*procItem, len(kids))
		for i, c := range kids {
			items[i] = newProcItem(c)
			queue = append(queue, items[i])
		}
		it.Kids = groupKids(it.N, items)
	}
	return v
}

// below is the processes under nodes ns.
func below(ns []*ledgerview.ProcNode) int {
	n := 0
	for _, c := range ns {
		n += c.Below.Procs
	}
	return n
}

func newProcItem(n *ledgerview.ProcNode) *procItem {
	it := &procItem{N: n, Open: n.Depth < procsOpenDepth || n.HasRefusal()}
	it.Full = n.Command()
	it.Cmd = shellTail(it.Full)
	if n.PID > 0 {
		it.Logs = "/logs?" + url.Values{"run": {n.Run}, "where": {"pid:" + strconv.Itoa(n.PID)}}.Encode()
	}
	switch {
	case len(n.Execs) > 1:
		for i := range n.Execs {
			x := &n.Execs[i]
			e := procExec{ProcExec: *x, Cmd: shellTail(x.Command()), Full: x.Command(), Others: x.Count - 1}
			if len(x.Paths) > 1 {
				e.Paths = strings.Join(x.Paths, ", ")
			}
			it.Execs = append(it.Execs, e)
		}
	case n.Refused && len(n.Execs) == 1:
		// One refused attempt, maybe at several paths of a PATH search: the row says where it was tried.
		it.Tried, it.Tries = strings.Join(n.Execs[0].Paths, ", "), n.Execs[0].Count
	}
	if len(n.Hosts) > 0 {
		hs := make([]string, len(n.Hosts))
		for i, h := range n.Hosts {
			hs[i] = h.Host
		}
		it.Hosts = strings.Join(hs, ", ")
		if more := n.Counts.Hosts - len(n.Hosts); more > 0 {
			it.Hosts += " and " + strconv.Itoa(more) + " more"
		}
	}
	return it
}

// groupKids folds parent's leaf children that ran the same program (or forked with no exec) into groups of
// procsGroupMin or more, each at its first member's place, so a run's thirty git calls read as one line.
func groupKids(parent *ledgerview.ProcNode, items []*procItem) []procKid {
	name := func(it *procItem) string {
		if len(it.N.Children) > 0 {
			return ""
		}
		if it.N.Unrecorded {
			return "\x00unrecorded"
		}
		return it.N.Name
	}
	count := map[string]int{}
	for _, it := range items {
		if k := name(it); k != "" {
			count[k]++
		}
	}
	groups := map[string]*procGroup{}
	out := make([]procKid, 0, len(items))
	for _, it := range items {
		k := name(it)
		if k == "" || count[k] < procsGroupMin {
			out = append(out, procKid{Item: it})
			continue
		}
		g := groups[k]
		if g == nil {
			g = &procGroup{Key: parent.Key() + "-g" + strconv.Itoa(len(groups)), Name: k, NotRun: true}
			if it.N.Unrecorded {
				g.Name = ""
			}
			groups[k] = g
			out = append(out, procKid{Group: g})
		}
		g.Items = append(g.Items, it)
		g.Lines += it.N.Counts.Lines
		g.Refuse += it.N.Counts.Refused
		g.Open = g.Open || it.N.HasRefusal() && !it.N.Refused
		g.NotRun = g.NotRun && it.N.Refused
	}
	return out
}
