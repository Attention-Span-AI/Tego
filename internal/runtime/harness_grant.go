// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The harness hook's exec grant (ADR 0064, agent-contract.md R27). Under an allow-list contract no exec rule the user
// wrote names the tego binary, so the hook a provision names (`tego hook claude-code --reason <path> ...`) would be a
// refused exec on every tool call. The launcher grants it on its own authority, as it grants the hook-state directory:
// the tego binary with the hook's exact argv and no other vector (agent.WithHarnessHook). It never grants a binary
// the agent could rewrite, and never a grant that would admit more than that argv.

// HookDecision is what a run does with a provision's hook (AdmitHook).
type HookDecision struct {
	// Table is the table the run carries on with: the run's own, or the copy that holds the grant.
	Table *agent.RuleTable
	// Granted says the launcher grants the hook's exact argv (Table holds agent.HarnessHookGrant's two rules).
	Granted bool
	// Why is the HarnessStart.Why of a hook the run does not admit, and Rule the rule that decided; both "" when
	// it admits the hook, or there is none. Detail says, for a grant that cannot be made, why not.
	Why, Rule, Detail string
}

// AdmitHook decides a provision's hook for a run of rt at tier, by the decision compile --test's exec row uses (the
// tier's floor, command rules included, then the gate: an exec the gate scores to ask is refused at run time). A
// hook the run's own exec rules admit is admitted as it is: a deny-list run's, or an allow-list run whose contract
// names the binary. Under an allow-list contract that does not, the launcher grants the hook's exact argv when its
// argv[0] is tegoExe, the tego binary the launcher runs as (harness.Run.TegoExe), unless:
//   - argv[0] is another program (record.HarnessWhyHookNotGranted): the launcher grants its own binary only;
//   - the binary, or its ELF loader, lies at or below a write entry or an fs.ask scope by any name the launcher can see
//     (record.HarnessWhyHookWritable): the agent could rewrite what the grant admits, or the Landlock builder refuses
//     the loader and with it the run. Its names are the hook's spelling, where it resolves, and every place the mount
//     table shows it (agent.MountOf: a bind mount of a directory above it). What lies beneath its filesystem is held
//     to the same entries, by covering or by lying beneath one (hookBeneath): an overlay's layers, a loop device's
//     backing file, an image the filesystem is mounted from. A file with more than one link, a mount table that cannot
//     be read or shows no mount holding the file, a stacking filesystem whose layers no option names (FUSE), and block
//     devices sysfs cannot show are not granted either: the launcher cannot see the file's other names;
//   - either lies at or below a deny_read entry by such a name (record.HarnessWhyHookRefused): the grant would open
//     what the entry denies (tier landlock unions an exec grant's READ_FILE with it), or refuse the whole run for the
//     loader;
//   - the grant cannot be exact (agent.ErrHarnessHookGrant, record.HarnessWhyHookNotGranted): the binary is no ELF
//     file, it has a set-id bit, or a bare exec.allow entry or an implicit grant keeps its name unconstrained;
//   - the granted table still does not admit the hook (record.HarnessWhyHookRefused): an exec.deny or exec.ask entry
//     names it, or the gate refuses or asks.
//
// rt is never mutated.
func AdmitHook(rt *agent.RuleTable, tier backend.Tier, tegoExe string, hook *harness.Hook) HookDecision {
	return admitHook(rt, tier, tegoExe, hook, hookHost{mounts: func() ([]byte, error) { return os.ReadFile(mountInfoPath) }, block: sysBlockPath})
}

// mountInfoPath is the mount table AdmitHook reads for the names a bind mount gives the hook's binary and its loader.
// The run's agent shares the launcher's mount namespace, and its filter refuses mount(2) and new mount namespaces.
const mountInfoPath = "/proc/self/mountinfo"

// sysBlockPath is sysfs's directory of block devices by number, where AdmitHook finds the loop devices beneath a
// filesystem and their backing files.
const sysBlockPath = "/sys/dev/block"

// hookHost is where admitHook reads the machine for the names of the hook's binary: the mount table, read only when
// a grant is considered, and sysfs's block directory (sysBlockPath).
type hookHost struct {
	mounts func() ([]byte, error)
	block  string
}

// admitHook is AdmitHook reading the machine through h.
func admitHook(rt *agent.RuleTable, tier backend.Tier, tegoExe string, hook *harness.Hook, h hookHost) HookDecision {
	d := HookDecision{Table: rt}
	if hook == nil {
		return d
	}
	if d.Why, d.Rule = hookRuled(rt, tier, hook); d.Why == "" || rt.ExecUnrestricted() {
		return d
	}
	if !sameFile(hook.Argv[0], tegoExe) {
		d.Why, d.Rule = record.HarnessWhyHookNotGranted, "exec."+agent.HarnessHookGrant
		d.Detail = fmt.Sprintf("%s is not the tego binary (%s), and the launcher grants only its own", hook.Argv[0], tegoExe)
		return d
	}
	names, beneath, unseen := h.names(hook.Argv[0])
	if entry, path, ok := hookCovered(rt, names); ok {
		d.Rule = entry.RuleName()
		if entry.Kind == agent.FSDenyRead {
			d.Why = record.HarnessWhyHookRefused
			d.Detail = fmt.Sprintf("%s lies at or below the deny_read entry %s, which a grant of it would let the agent read", path, rawOr(entry.Raw, entry.Path))
			return d
		}
		d.Why = record.HarnessWhyHookWritable
		d.Detail = fmt.Sprintf("%s lies at or below the %s entry %s, so the agent could rewrite what a grant admits", path, entry.Kind, rawOr(entry.Raw, entry.Path))
		return d
	}
	if entry, b, ok := beneathCovered(rt, beneath); ok {
		d.Why, d.Rule = record.HarnessWhyHookWritable, entry.RuleName()
		d.Detail = fmt.Sprintf("%s, beneath the filesystem holding %s, meets the %s entry %s, so the agent could rewrite what a grant admits",
			b.path, b.of, entry.Kind, rawOr(entry.Raw, entry.Path))
		return d
	}
	if unseen != "" {
		d.Why, d.Rule = record.HarnessWhyHookWritable, "exec."+agent.HarnessHookGrant
		d.Detail = unseen + ", so the launcher cannot see every name of what a grant admits, nor that none lies under a write entry"
		return d
	}
	granted, err := rt.WithHarnessHook(hook.Argv)
	if err != nil {
		d.Why, d.Rule, d.Detail = record.HarnessWhyHookNotGranted, "exec."+agent.HarnessHookGrant, err.Error()
		return d
	}
	if d.Why, d.Rule = hookRuled(granted, tier, hook); d.Why != "" {
		return d
	}
	return HookDecision{Table: granted, Granted: true}
}

// hookRuled is whether rt's exec rules admit hook's exact argv, as the supervisor's gateExec decides an exec: the
// tier's floor (the plane's at bpflsm, the policy model's otherwise, command rules included) and then the gate
// (agent.EvaluateGateRow). "" when they admit it; else record.HarnessWhyHookRefused and the rule that decided.
func hookRuled(rt *agent.RuleTable, tier backend.Tier, hook *harness.Hook) (why, rule string) {
	a := agent.Action{Kind: agent.ActionExec, Path: hook.Argv[0], Argv: hook.Argv}
	var floor agent.EvalResult
	if tier == backend.TierBPFLSM {
		floor = decide.NewPlaneEvaluator(rt).Evaluate(a, decide.Env{})
	} else {
		floor = decide.NewEvaluator(rt).EvaluateIn(a, tier, decide.Env{})
	}
	res := agent.EvaluateGateRow(rt, a, floor)
	if res.Verdict == agent.VerdictAllow {
		return "", ""
	}
	if res.Rule == "" {
		return record.HarnessWhyHookRefused, res.CommandRule
	}
	return record.HarnessWhyHookRefused, res.Rule
}

// names is every name the launcher can see of the hook's binary exe and of its ELF loader: the spelling the hook
// names, where it resolves, and every other place the mount table shows the resolved file (agent.MountOf, a bind mount
// of a directory above it). A file's names are what Landlock's path-based rights reach it by, so a grant is held to the
// entries by each. beneath is what lies beneath their filesystems, whose content those show (hookScan.under). unseen
// is "" when those are all; else it says why the launcher cannot see them all: a resolved file with more than one link
// (a hard link's other names cannot be listed) or that cannot be examined, a mount table it cannot read, or one that
// shows no mount holding a resolved file (its place within its filesystem is unknown, so a bind the table shows cannot
// be matched to it), or what hookScan.under cannot see. The mount table is read once, after the files resolve.
func (h hookHost) names(exe string) (names []string, beneath []beneathName, unseen string) {
	names = []string{exe}
	var resolved []string
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		names, resolved = append(names, r), append(resolved, r)
		if interp, err := agent.ReadInterp(r); err == nil && interp != "" {
			names = append(names, interp)
			if ld, err := filepath.EvalSymlinks(interp); err == nil {
				names, resolved = append(names, ld), append(resolved, ld)
			}
		}
	}
	s := &hookScan{h: h, visited: map[string]bool{}}
	for _, f := range resolved {
		s.links(f)
	}
	table, err := h.mounts()
	if err != nil {
		s.see(fmt.Sprintf("the mount table %s cannot be read (%v), so the names a bind mount gives a file are unknown", mountInfoPath, err))
		return names, nil, s.unseen
	}
	s.table = table
	for _, f := range resolved {
		fm := agent.MountOf(table, f)
		if !fm.Held {
			s.see(fmt.Sprintf("the mount table %s shows no mount holding %s, so the names a bind mount gives it are unknown", mountInfoPath, f))
			continue
		}
		names = append(names, fm.Aliases...)
		s.under(fm, f, 0)
	}
	return names, s.beneath, s.unseen
}

// beneathName is a layer, image or tree beneath the filesystem holding of, the hook's binary or its loader, whose
// content that filesystem shows (hookScan.under).
type beneathName struct{ path, of string }

// hookScan gathers what lies beneath the filesystems holding the hook's binary and its loader (hookHost.names).
type hookScan struct {
	h       hookHost
	table   []byte
	beneath []beneathName
	visited map[string]bool
	unseen  string
}

// maxBeneath bounds how many filesystems deep the scan follows one beneath another (an overlay's layer on a loop
// device's image ...); a deeper one is a name it cannot see.
const maxBeneath = 3

// maxBlockDepth bounds the walk from a block device down the devices it is built on (blockBacking).
const maxBlockDepth = 8

// see keeps the first reason the scan cannot see every name.
func (s *hookScan) see(why string) {
	if s.unseen == "" {
		s.unseen = why
	}
}

// links notes a resolved file with a name no table shows: more than one link, or a link count it cannot read.
func (s *hookScan) links(f string) {
	var st unix.Stat_t
	if err := unix.Stat(f, &st); err != nil {
		s.see(fmt.Sprintf("%s cannot be examined (%v), so its links cannot be counted", f, err))
	} else if st.Nlink != 1 {
		s.see(fmt.Sprintf("%s has %d links, whose other names cannot be listed", f, st.Nlink))
	}
}

// under adds what lies beneath fm, the filesystem holding of's file, depth filesystems down: an
// overlay's layer directories (its options name them), the backing files of the loop devices at or beneath its block
// device (the table's device, and the device its source names), and an image file or tree its source names. Each is
// a name of what the filesystem shows that no mount of its device lists, so the agent could rewrite the file through
// it. A stacking filesystem whose layers no option names (agent.FileMount.Unmapped) is one the scan cannot see beneath.
func (s *hookScan) under(fm agent.FileMount, of string, depth int) {
	if fm.Unmapped != "" {
		s.see(fmt.Sprintf("%s lies on %s, which shows another tree's files by names the mount table does not give", of, fm.Unmapped))
		return
	}
	for _, l := range fm.Layers {
		s.add(l, of, depth)
	}
	var devs []string
	if maj, _, ok := strings.Cut(fm.Device, ":"); ok && maj != "0" {
		devs = append(devs, fm.Device)
	}
	var st unix.Stat_t
	if filepath.IsAbs(fm.Source) && unix.Stat(fm.Source, &st) == nil {
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFBLK:
			if dev := fmt.Sprintf("%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev)); !slices.Contains(devs, dev) {
				devs = append(devs, dev)
			}
		case unix.S_IFREG, unix.S_IFDIR:
			s.add(fm.Source, of, depth)
		}
	}
	for _, dev := range devs {
		files, err := blockBacking(s.h.block, dev)
		if err != nil {
			s.see(fmt.Sprintf("the block devices beneath %s's filesystem (device %s) cannot be read in %s (%v)", of, dev, s.h.block, err))
			continue
		}
		for _, f := range files {
			s.add(f, of, depth)
		}
	}
}

// add holds p, a layer, image or tree beneath of's filesystem, to the entries, with the places the mount table shows
// it or part of it, and what lies beneath its own filesystem. A spelling no file of this mount namespace is reached by
// (it, or a directory on its way, is missing or unsearchable: an overlay's options name the mounter's paths, which a
// container may not have) is held as it is spelled, and nothing more is learned from it.
func (s *hookScan) add(p, of string, depth int) {
	p = filepath.Clean(p)
	if s.visited[p] {
		return
	}
	s.visited[p] = true
	s.beneath = append(s.beneath, beneathName{p, of})
	r, err := filepath.EvalSymlinks(p)
	switch {
	case errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, fs.ErrPermission):
		return
	case err != nil:
		s.see(fmt.Sprintf("%s, beneath the filesystem holding %s, cannot be resolved (%v)", p, of, err))
		return
	case r != p:
		s.add(r, of, depth)
		return
	case depth >= maxBeneath:
		s.see(fmt.Sprintf("%s lies more than %d filesystems deep beneath %s", p, maxBeneath, of))
		return
	}
	if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
		s.links(p)
	}
	fm := agent.MountOf(s.table, p)
	if !fm.Held {
		s.see(fmt.Sprintf("the mount table %s shows no mount holding %s, beneath the filesystem holding %s", mountInfoPath, p, of))
		return
	}
	for _, a := range append(fm.Aliases, fm.Beneath...) {
		if !s.visited[a] {
			s.visited[a] = true
			s.beneath = append(s.beneath, beneathName{a, of})
		}
	}
	s.under(fm, of, depth+1)
}

// blockBacking is the backing files of the loop devices at or beneath the block device dev (maj:min) that sysfs's
// block directory block shows: dev itself, the whole disk a partition is on, and the devices it is built on (slaves:
// a device-mapper or md device's), at most maxBlockDepth deep. A device block does not show is an error: the devices
// beneath it cannot be seen.
func blockBacking(block, dev string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		d, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return err
		}
		if seen[d] {
			return nil
		}
		seen[d] = true
		if depth > maxBlockDepth {
			return fmt.Errorf("device %s is built on devices more than %d deep", dev, maxBlockDepth)
		}
		if b, err := os.ReadFile(filepath.Join(d, "loop", "backing_file")); err == nil {
			out = append(out, strings.TrimSuffix(string(b), "\n"))
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if _, err := os.Stat(filepath.Join(d, "partition")); err == nil {
			if err := walk(filepath.Dir(d), depth+1); err != nil {
				return err
			}
		}
		slaves, err := os.ReadDir(filepath.Join(d, "slaves"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		for _, e := range slaves {
			if err := walk(filepath.Join(d, "slaves", e.Name()), depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return out, walk(filepath.Join(block, dev), 0)
}

// hookCovered is the entry of rt that forbids a grant of the hook's binary or of its ELF loader, by any of their names
// (hookHost.names), as the Landlock builder asks of a loader (governs): a write entry or an fs.ask scope (declared, or a
// grant the runtime made), whose contents the agent could replace, and an entry over any directory above the file
// covers the file, so it covers every rename that could put another file at its path; or a deny_read entry, which the
// grant's READ_FILE on the binary would open (tier landlock unions the two) and which refuses the loader, and with it
// the whole run, in the Landlock builder. path is the name the entry covers.
func hookCovered(rt *agent.RuleTable, files []string) (entry agent.FSRule, path string, ok bool) {
	for _, rules := range [][]agent.FSRule{rt.FS, rt.FSAsk} {
		for _, f := range rules {
			if f.Kind != agent.FSWrite && f.Kind != agent.FSAsk && f.Kind != agent.FSDenyRead {
				continue
			}
			for _, p := range files {
				if agent.Covers(f.Path, p) || agent.Covers(f.Governed(), p) {
					return f, p, true
				}
			}
		}
	}
	return agent.FSRule{}, "", false
}

// beneathCovered is the write entry or fs.ask scope of rt that meets a layer, image or tree beneath the hook's
// filesystems (hookHost.names): one at or above it, whose contents the agent could replace, or one beneath it, since
// which file of a layer the filesystem shows is the filesystem's to decide (an overlay's redirects and metacopy files
// lead to another path of the layer). A deny_read entry does not count: the grant's READ_FILE is on the binary's own
// names, not on what lies beneath them.
func beneathCovered(rt *agent.RuleTable, beneath []beneathName) (entry agent.FSRule, b beneathName, ok bool) {
	for _, rules := range [][]agent.FSRule{rt.FS, rt.FSAsk} {
		for _, f := range rules {
			if f.Kind != agent.FSWrite && f.Kind != agent.FSAsk {
				continue
			}
			for _, b := range beneath {
				for _, e := range []string{f.Path, f.Governed()} {
					if agent.Covers(e, b.path) || agent.Covers(b.path, e) {
						return f, b, true
					}
				}
			}
		}
	}
	return agent.FSRule{}, beneathName{}, false
}

// sameFile reports whether a and b name one file where they resolve: neither may be "" or fail to resolve.
func sameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ra, erra := filepath.EvalSymlinks(a)
	rb, errb := filepath.EvalSymlinks(b)
	return erra == nil && errb == nil && ra == rb
}
