// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

// CronRoots selects only the documented machine crontab and direct directories.
// Its fields are explicit to keep fixture collection away from actual user data.
type CronRoots struct{ Crontab, Directory, Spool, Crontabs string }

type cronObservation struct {
	Path    string
	UID     *uint32
	Program string
}
type cronSnapshot struct {
	Items   []cronObservation
	Sources []processSource
}
type cronEntry struct {
	UID     uint32
	Program string
}

// parseCron keeps only a known local uid and catalog program id. Schedule,
// account spelling, environment and command values live only in the bounded line.
func parseCron(ctx context.Context, r io.Reader, system bool, owner uint32, accounts map[string]uint32) ([]cronEntry, error) {
	out := []cronEntry{}
	s := bufio.NewScanner(io.LimitReader(r, manifestBytes+1))
	s.Buffer(make([]byte, unitLineBytes), unitLineBytes+1)
	s.Split(func(data []byte, eof bool) (int, []byte, error) {
		if n := bytes.IndexByte(data, '\n'); n >= 0 {
			return n + 1, data[:n], nil
		}
		if eof && len(data) > 0 {
			// Cron does not install an unterminated final entry.
			return 0, nil, errSyntax
		}
		return 0, nil, nil
	})
	total, tokens, jobs := 0, 0, 0
	shellKnown := true
	for s.Scan() {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		line := s.Bytes()
		total += len(line) + 1
		tokens++
		if total > manifestBytes {
			return nil, errSize
		}
		if tokens > unitTokenLimit {
			return nil, errLimit
		}
		if !utf8.Valid(line) {
			return nil, errSyntax
		}
		for _, b := range line {
			if b < 0x20 && b != '\t' || b == 0x7f {
				return nil, errSyntax
			}
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if key, value, ok := cronEnvironment(line); ok {
			if bytes.Equal(key, []byte("SHELL")) {
				if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
					value = value[1 : len(value)-1]
				}
				shellKnown = bytes.Equal(value, []byte("/bin/sh")) || bytes.Equal(value, []byte("/bin/bash")) || bytes.Equal(value, []byte("/bin/dash"))
			}
			continue
		}
		if !shellKnown {
			return nil, errUnresolved
		}
		field, rest := cronField(line)
		if len(field) > 0 && field[0] == '@' {
			switch string(field) {
			case "@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly":
			default:
				return nil, errUnresolved
			}
		} else {
			for i := 0; i < 5; i++ {
				if !cronScheduleField(field, i) {
					return nil, errUnsupported
				}
				if i < 4 {
					field, rest = cronField(rest)
				}
			}
		}
		uid := owner
		if system {
			field, rest = cronField(rest)
			if len(field) == 0 || len(field) > 256 {
				return nil, errSyntax
			}
			var ok bool
			uid, ok = accounts[string(field)]
			if !ok {
				return nil, errUnresolved
			}
		}
		if len(rest) == 0 {
			return nil, errSyntax
		}
		jobs++
		if jobs > unitExecLimit {
			return nil, errLimit
		}
		x, e := parseCronCommand(rest)
		if e != nil {
			return nil, e
		}
		tokens += x.words
		if tokens > unitTokenLimit {
			return nil, errLimit
		}
		if x.Program != "" {
			out = append(out, cronEntry{uid, x.Program})
		}
	}
	if e := s.Err(); e != nil {
		if errors.Is(e, errSyntax) {
			return nil, errSyntax
		}
		return nil, errSize
	}
	return out, nil
}

func cronField(raw []byte) ([]byte, []byte) {
	raw = bytes.TrimLeft(raw, " \t")
	for i, b := range raw {
		if b == ' ' || b == '\t' {
			return raw[:i], bytes.TrimLeft(raw[i:], " \t")
		}
	}
	return raw, nil
}
func cronEnvironment(raw []byte) ([]byte, []byte, bool) {
	key, value, ok := bytes.Cut(raw, []byte{'='})
	key = bytes.TrimSpace(key)
	if !ok || len(key) == 0 {
		return nil, nil, false
	}
	for i, b := range key {
		if !(b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || i > 0 && b >= '0' && b <= '9') {
			return nil, nil, false
		}
	}
	return key, bytes.TrimSpace(value), true
}

func cronScheduleField(raw []byte, field int) bool {
	if len(raw) == 0 || len(raw) > unitLineBytes {
		return false
	}
	low := []int{0, 0, 1, 1, 0}[field]
	high := []int{59, 23, 31, 12, 7}[field]
	value := func(raw []byte) (int, bool) {
		if field == 3 || field == 4 {
			names := "janfebmaraprmayjunjulaugsepoctnovdec"
			if field == 4 {
				names = "sunmontuewedthufrisat"
			}
			if len(raw) == 3 {
				for i := 0; i < len(names); i += 3 {
					if bytes.EqualFold(raw, []byte(names[i:i+3])) {
						v := i / 3
						if field == 3 {
							v++
						}
						return v, true
					}
				}
			}
		}
		if len(raw) == 0 || len(raw) > 2 {
			return 0, false
		}
		for _, b := range raw {
			if b < '0' || b > '9' {
				return 0, false
			}
		}
		v, e := strconv.Atoi(string(raw))
		return v, e == nil && v >= low && v <= high
	}
	for len(raw) > 0 {
		part, remaining, more := bytes.Cut(raw, []byte{','})
		base, step, stepped := bytes.Cut(part, []byte{'/'})
		if stepped {
			if len(step) == 0 || len(step) > 2 {
				return false
			}
			for _, b := range step {
				if b < '0' || b > '9' {
					return false
				}
			}
			n, e := strconv.Atoi(string(step))
			if e != nil || n < 1 || n > high-low+1 {
				return false
			}
		}
		if !bytes.Equal(base, []byte{'*'}) {
			first, last, ranged := bytes.Cut(base, []byte{'-'})
			a, ok := value(first)
			if !ok {
				return false
			}
			if ranged {
				b, ok := value(last)
				if !ok || a > b {
					return false
				}
			}
		}
		if !more {
			return true
		}
		if len(remaining) == 0 {
			return false
		}
		raw = remaining
	}
	return false
}

func parseCronCommand(raw []byte) (unitExec, error) {
	// Cron interprets an unescaped percent before its shell sees quoting. The
	// following bytes are stdin data, which this scan never interprets.
	escaped := false
	for _, b := range raw {
		if b == '%' && !escaped {
			return unitExec{}, errUnresolved
		}
		if b == '\\' {
			escaped = !escaped
		} else {
			escaped = false
		}
	}
	return parseConfiguredCommand(raw, true)
}

func collectCron(ctx context.Context, roots CronRoots, accounts []localAccount, budget *contentBudget) cronSnapshot {
	return collectCronOwned(ctx, roots, accounts, budget, 0)
}

// systemUID is the owner expected for fixed machine sources. Production always
// supplies root; the seam lets nonroot tests use synthetic machine folders.
func collectCronOwned(ctx context.Context, roots CronRoots, accounts []localAccount, budget *contentBudget, systemUID uint32) cronSnapshot {
	out := cronSnapshot{Items: []cronObservation{}, Sources: []processSource{}}
	users := make(map[string]uint32, len(accounts))
	for _, a := range accounts {
		users[a.Name] = a.UID
	}
	sourceBytes, itemBytes, entriesLeft := 0, 0, unitTotalEntries
	limited := false
	addSource := func(v processSource) bool {
		if limited {
			return false
		}
		b, _ := json.Marshal(v)
		if len(out.Sources) >= 1800 || sourceBytes+len(b) > 400<<10 {
			out.Sources = append(out.Sources, projectSource("", errLimit))
			limited = true
			return false
		}
		sourceBytes += len(b)
		out.Sources = append(out.Sources, v)
		return true
	}
	readFile := func(path string, system bool, owner uint32) {
		if limited {
			return
		}
		root, _, e := metadataPath(ctx, filepath.Dir(path), false)
		if e != nil {
			addSource(projectSource(path, e))
			return
		}
		defer func() { _ = root.Close() }()
		var rootBefore unix.Stat_t
		e = root.Fstat(&rootBefore)
		if e == nil {
			e = cronDirectoryMode(rootBefore, !system, systemUID)
		}
		if e != nil {
			addSource(projectSource(path, e))
			return
		}
		var rows []cronEntry
		// The root-owned sticky spool is a selected machine source, not a
		// user-writable project parent. Keep its existing directory policy and
		// recheck its identity/mode on both sides of the bounded content read.
		rootMode := func(st unix.Stat_t) error { return cronDirectoryMode(st, !system, systemUID) }
		e = readContentWithRootMode(ctx, root, filepath.Base(path), owner, budget, rootMode, func(r io.Reader) error {
			var x error
			rows, x = parseCron(ctx, r, system, owner, users)
			return x
		})
		if e == nil {
			current, _, x := metadataPath(ctx, filepath.Dir(path), false)
			if x != nil {
				e = errChanged
			} else {
				var after unix.Stat_t
				x = current.Fstat(&after)
				_ = current.Close()
				if x != nil || !sameInode(rootBefore, after) {
					e = errChanged
				}
			}
		}
		if !addSource(projectSource(path, e)) || e != nil {
			return
		}
		for _, row := range rows {
			uid := row.UID
			v := cronObservation{path, &uid, row.Program}
			b, _ := json.Marshal(v)
			if len(out.Items) >= 512 || itemBytes+len(b) > 450<<10 {
				addSource(projectSource("", errLimit))
				limited = true
				return
			}
			itemBytes += len(b)
			out.Items = append(out.Items, v)
		}
	}
	if roots.Crontab != "" {
		readFile(roots.Crontab, true, systemUID)
	}
	for _, directory := range []struct {
		path   string
		system bool
	}{{roots.Directory, true}, {roots.Spool, false}, {roots.Crontabs, false}} {
		if limited {
			break
		}
		if directory.path == "" {
			continue
		}
		root, _, e := metadataPath(ctx, directory.path, false)
		if e != nil {
			addSource(projectSource(directory.path, e))
			continue
		}
		var st unix.Stat_t
		e = root.Fstat(&st)
		if e == nil && st.Uid != systemUID {
			e = errOwner
		}
		var names []string
		if e == nil {
			names, e = cronDirectoryNames(ctx, root, !directory.system, systemUID, &entriesLeft)
		}
		_ = root.Close()
		if e != nil {
			addSource(projectSource(directory.path, e))
			continue
		}
		addSource(processSource{Path: directory.path, State: "read", Reason: "none"})
		for _, name := range names {
			if limited {
				break
			}
			path := filepath.Join(directory.path, name)
			if !plainPath(path) {
				addSource(projectSource(directory.path, errUnsupported))
				continue
			}
			if !directory.system && path == roots.Crontabs {
				continue // The only selected spool subdirectory is listed separately.
			}
			owner := systemUID
			if !directory.system {
				var ok bool
				owner, ok = users[name]
				if !ok {
					addSource(projectSource(path, errUnresolved))
					continue
				}
			}
			readFile(path, directory.system, owner)
		}
	}
	return out
}

// Debian's root:crontab spool is 01730. The sticky bit permits that measured
// group-write layout; content still requires a regular single-link checked owner
// with no group or other write bit. Ordinary machine folders keep the D/E rule.
func cronDirectoryMode(st unix.Stat_t, spool bool, owner uint32) error {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errType
	}
	if st.Uid != owner {
		return errOwner
	}
	if st.Mode&0002 != 0 || st.Mode&0020 != 0 && (!spool || st.Mode&unix.S_ISVTX == 0) {
		return errProjectMode
	}
	return nil
}

func cronDirectoryNames(ctx context.Context, root *sys.FD, spool bool, owner uint32, remaining *int) ([]string, error) {
	var before unix.Stat_t
	if e := root.Fstat(&before); e != nil {
		return nil, e
	}
	if e := cronDirectoryMode(before, spool, owner); e != nil {
		return nil, e
	}
	fd, e := root.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f, e := fd.Release("scan-cron-directory")
	if e != nil {
		_ = fd.Close()
		return nil, e
	}
	defer func() { _ = f.Close() }()
	names, e := unitDirectoryNames(ctx, openCatalogDirectory{f}, remaining)
	if e != nil {
		return nil, e
	}
	var after unix.Stat_t
	if e = root.Fstat(&after); e != nil {
		return nil, e
	}
	if !sameInode(before, after) {
		return nil, errChanged
	}
	return names, nil
}
