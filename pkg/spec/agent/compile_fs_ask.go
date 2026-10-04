// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Ask scope stays outside the ordinary grants and their kernel/fanotify maps.
// The supervisor must freeze each actual target before asking and inject only
// the approved open descriptor, rather than extending the path's live rights.
func (k *compiler) fsAsk() {
	if k.c.FS == nil || len(k.c.FS.Ask) == 0 {
		return
	}
	if len(k.c.FS.Ask) > 256 {
		return
	}
	for _, raw := range k.c.FS.Ask {
		if len(raw) > 4096 || strings.ContainsAny(raw, "*?[") {
			return
		}
	}
	// Reuse the ordinary write compiler's protected-state checks and bounded
	// configuration search in a private table; no generated grant escapes it.
	c, fs, table, fork := *k.c, *k.c.FS, *k.rt, *k
	fs.Write, c.FS = k.c.FS.Ask, &fs
	c.origins = maps.Clone(k.c.origins)
	for i := range fs.Write {
		key := strconv.Itoa(i)
		c.origins["fs.write."+key] = k.pos("fs.ask." + key)
	}
	fork.c, fork.rt, fork.ds, fork.askScope = &c, &table, diags{}, true
	ledger := ""
	if k.m.LedgerRoot.Value != "" {
		ledger = k.abs(k.m.LedgerRoot.Value)
	}
	mt, _ := loadMountTable(k.o.mountInfo) // fs already reports unavailable metadata
	b := &fsBuilder{k: &fork, mt: mt}
	b.writes(fs.Write, ledger)
	for _, d := range fork.ds.list {
		d.Message, d.Fix = strings.ReplaceAll(d.Message, "fs.write", "fs.ask"), strings.ReplaceAll(d.Fix, "fs.write", "fs.ask")
		k.ds.list = append(k.ds.list, d)
	}
	k.rt.AskDenyWrite = slices.Concat(table.DenyWrite, k.askDenyWrite) // an fs.deny_write entry is never approved (ADR 0071)
	protected := make(map[string]bool, len(table.DenyWrite))
	for _, r := range table.DenyWrite {
		protected[r.Resolved] = true
	}
	for i, raw := range k.c.FS.Ask {
		pos := k.pos("fs.ask." + strconv.Itoa(i))
		if strings.ContainsAny(raw, "*?[") {
			k.ds.errorf(pos, CodeSchema, "fs.ask requires literal files or directory scopes")
			continue
		}
		path := k.abs(raw)
		resolved := k.resolve(path)
		k.rt.FSAsk = append(k.rt.FSAsk, FSRule{Raw: raw, Path: path, Resolved: resolved, Kind: FSAsk, Pos: pos})
		k.askInsideWrite(pos, raw, path, resolved)
		// A literal ask for .claude or a file inside it must not evade the
		// scanner by placing that protected name above the scope's root.
		for _, spelling := range []string{path, resolved} {
			for ancestor := filepath.Clean(spelling); ancestor != "/" && ancestor != "."; ancestor = filepath.Dir(ancestor) {
				parent := filepath.Dir(ancestor)
				for _, n := range denyWriteAtRoot {
					candidate := filepath.Join(parent, n.name)
					if !Covers(candidate, spelling) || protected[candidate] {
						continue
					}
					protected[candidate] = true
					k.rt.AskDenyWrite = append(k.rt.AskDenyWrite, FSRule{Path: candidate, Resolved: candidate, Kind: FSDenyWrite, BuiltIn: true})
				}
			}
		}
	}
}

// askInsideWrite warns about an fs.ask scope at or beneath a write entry (ADR 0057 D3): an ordinary grant takes
// precedence over an ask (SEMANTICS §6), so the write entry allows every write there and the scope never asks. It
// is a warning, not an error, because nothing is less protected than the write entry's author granted: the scope
// loses a question the grant already answered. The same nesting for an fs.ask_read entry is refused (fsAskRead),
// because there the entry is also the deny_read that keeps a secret, and Landlock would let the agent read it
// outright beneath the write grant: the protection itself would be lost, not just the question.
func (k *compiler) askInsideWrite(pos Pos, raw, path, resolved string) {
	for i := range k.rt.FS {
		r := &k.rt.FS[i]
		if r.Kind != FSWrite {
			continue
		}
		gov := r.Canonical()
		if gov == "" || !isAncestorOrSelf(gov, resolved) {
			continue
		}
		k.ds.warnf(pos, CodeRedundantRule, "fs.ask %q%s lies inside write entry %s%s, which already allows every write there: an ordinary grant takes precedence over an ask, so the scope never asks",
			raw, resolvedNote(path, resolved), rawOr(r.Raw, r.Path), resolvedNote(r.Path, gov)).
			fix("narrow the write entry so it no longer covers %s, or drop the fs.ask entry", raw)
		return
	}
}
