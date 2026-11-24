// SPDX-License-Identifier: Apache-2.0

package selfbin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"
)

const accountFileLimit = 1 << 20

type groupUse struct {
	name    string
	foreign bool
	used    bool
	// password names the file whose entry lets an account that is not listed join the group with a password
	// (newgrp); "" when no usable password was seen.
	password string
}
type groupTrust struct {
	primary    uint32
	primaryOK  bool
	complete   bool
	incomplete string
	groups     map[uint32]groupUse
}

// accountEvidenceWait bounds the whole of one membership lookup: the four local account files together. Each is a
// local file of at most accountFileLimit bytes, and reading all of them takes tens of microseconds on a healthy
// machine, so two seconds is five orders of magnitude of room and still short enough that the hint or the refusal a
// person is waiting for appears. A file that gives no answer in that time (an /etc on a network mount that hangs)
// refuses the writable-group exception, and the refusal names the file. A variable so a test waits less.
var accountEvidenceWait = 2 * time.Second

// accountRead reads one account file; a test replaces it with a source that fails, or never answers.
var accountRead = readAccountFile

// systemGroupTrust is the machine's membership evidence, from the local account files alone and inside
// accountEvidenceWait. No name service is asked (ADR 0142, 2026-11-18, review finding 5): complete files-only
// evidence is the only evidence that keeps the exception, and it names the caller's primary group itself, so a
// lookup through NSS could add nothing and could wait without bound on a directory that does not answer.
func systemGroupTrust(uid int) groupTrust {
	ctx, cancel := context.WithTimeout(context.Background(), accountEvidenceWait)
	defer cancel()
	return loadGroupTrust(uid, withDeadline(ctx, accountEvidenceWait, accountRead))
}

// withDeadline is read given up on when ctx ends: the read runs on its own goroutine, and a read still blocked then
// is reported as the error "gave no answer within <wait>". The goroutine of a read that never returns stays with its
// blocked system call, one per file at most, for what is left of a short-lived command; nothing waits for it.
func withDeadline(ctx context.Context, wait time.Duration, read func(string) ([]byte, error)) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		type answer struct {
			data []byte
			err  error
		}
		done := make(chan answer, 1)
		go func() {
			data, err := read(path)
			done <- answer{data, err}
		}()
		select {
		case a := <-done:
			return a.data, a.err
		case <-ctx.Done():
			return nil, fmt.Errorf("it gave no answer within %s", wait)
		}
	}
}

// Reads are capped even on a corrupt or unexpectedly large local account file.
func readAccountFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, accountFileLimit+1))
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(b) > accountFileLimit {
		return nil, fmt.Errorf("account file exceeded the %d byte limit", accountFileLimit)
	}
	return b, nil
}

// groupFile and shadowGroupFile hold a group's password field. newgrp admits an account that is not a member when
// it gives the group's password, so a group with a usable password has no completely known membership.
const (
	groupFile       = "/etc/group"
	shadowGroupFile = "/etc/gshadow"
)

// joinable reports whether a group password field can admit an account. An empty field admits members only, and a
// field that starts with '!' or '*' equals no crypt(3) result (the locked forms). Anything else counts as usable.
func joinable(field string) bool {
	return field != "" && field[0] != '!' && field[0] != '*'
}

// NSS has no complete enumeration API. A privileged printed command requires
// complete files-only evidence, even for the caller's primary gid (ADR 0142, 2026-11-18).
func loadGroupTrust(uid int, read func(string) ([]byte, error)) groupTrust {
	p := groupTrust{groups: map[uint32]groupUse{}}
	names := map[string]uint32{}
	passwd, pe := read("/etc/passwd")
	group, ge := read("/etc/group")
	nss, ne := read("/etc/nsswitch.conf")
	if pe != nil {
		passwd = nil
	}
	if ge != nil {
		group = nil
	}
	for _, input := range []struct {
		path string
		data []byte
		err  error
	}{
		{"/etc/passwd", passwd, pe}, {"/etc/group", group, ge}, {"/etc/nsswitch.conf", nss, ne},
	} {
		why := ""
		switch {
		case input.err != nil:
			why = fmt.Sprintf("%s could not be read: %v", input.path, input.err)
		case len(input.data) > accountFileLimit:
			why = input.path + " exceeded the size limit"
		case len(input.data) > 0 && input.data[len(input.data)-1] != '\n':
			why = input.path + " is truncated (no final newline)"
		case bytes.IndexByte(input.data, 0) >= 0 || bytes.IndexByte(input.data, '\r') >= 0:
			why = input.path + " is malformed"
		}
		if why != "" && p.incomplete == "" {
			p.incomplete = why
		}
	}
	primaryUsers := map[uint32][]uint32{}
	valid := true
	for _, line := range strings.Split(string(passwd), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] == "" {
			valid = false
			continue
		}
		u, ok := accountID(fields[2])
		g, gok := accountID(fields[3])
		if !ok || !gok {
			valid = false
			continue
		}
		if existing, exists := names[fields[0]]; exists && existing != u {
			valid = false
			names[fields[0]] = ^uint32(0)
		} else {
			names[fields[0]] = u
		}
		primaryUsers[g] = append(primaryUsers[g], u)
		// The caller's primary group is the one its passwd record names: the only source consulted.
		if u == uint32(uid) {
			p.primary, p.primaryOK = g, true
		}
	}
	for _, line := range strings.Split(string(group), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 4 || fields[0] == "" {
			valid = false
			continue
		}
		g, ok := accountID(fields[2])
		if !ok {
			valid = false
			continue
		}
		use, duplicate := p.groups[g]
		use.name = fields[0]
		if duplicate {
			valid = false
		}
		// "x" sends the reader to the shadow group file, read below.
		if fields[1] != "x" && joinable(fields[1]) {
			use.password = groupFile
		}
		for _, u := range primaryUsers[g] {
			use.used = true
			use.foreign = use.foreign || u != 0 && u != uint32(uid)
		}
		if fields[3] != "" {
			use.used = true
			for _, name := range strings.Split(fields[3], ",") {
				u, found := names[name]
				use.foreign = use.foreign || !found || u != 0 && u != uint32(uid)
			}
		}
		p.groups[g] = use
	}
	// Even a missing group row cannot hide a known shared primary gid.
	for g, users := range primaryUsers {
		use, exists := p.groups[g]
		for _, u := range users {
			if u != 0 && u != uint32(uid) {
				use.foreign = true
			}
		}
		if exists || use.foreign {
			p.groups[g] = use
		}
	}
	if why := p.shadowGroups(uid, names, read); why != "" && p.incomplete == "" {
		p.incomplete = why
	}
	if !valid && p.incomplete == "" {
		p.incomplete = "local passwd or group records are malformed"
	}
	if !localAccountsOnly(nss) && p.incomplete == "" {
		p.incomplete = fmt.Sprintf("/etc/nsswitch.conf does not establish files-only passwd and group membership (%s)", accountSources(nss))
	}
	p.complete = p.incomplete == ""
	return p
}

// shadowGroups applies the shadow group file, which newgrp prefers over the group file for a group's password and
// member list. Only root can read it. A file that is absent or closed to the caller changes nothing: a normal user
// cannot see a group password an administrator set there (the residual ADR 0142 records). A file the caller can read
// must read whole: a usable password marks the group, a listed administrator or member counts as a member, and a
// failed, cut or malformed read is returned as the reason membership is not established.
func (p *groupTrust) shadowGroups(uid int, names map[string]uint32, read func(string) ([]byte, error)) string {
	data, err := read(shadowGroupFile)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, fs.ErrPermission):
		return ""
	case err != nil:
		return fmt.Sprintf("%s could not be read: %v", shadowGroupFile, err)
	case len(data) > accountFileLimit:
		return shadowGroupFile + " exceeded the size limit"
	case len(data) > 0 && data[len(data)-1] != '\n':
		return shadowGroupFile + " is truncated (no final newline)"
	case bytes.IndexByte(data, 0) >= 0 || bytes.IndexByte(data, '\r') >= 0:
		return shadowGroupFile + " is malformed"
	}
	byName := map[string][]uint32{}
	for g, use := range p.groups {
		if use.name != "" {
			byName[use.name] = append(byName[use.name], g)
		}
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 4 || fields[0] == "" || seen[fields[0]] {
			return shadowGroupFile + " is malformed"
		}
		seen[fields[0]] = true
		for _, g := range byName[fields[0]] {
			use := p.groups[g]
			if joinable(fields[1]) {
				use.password = shadowGroupFile
			}
			for _, list := range fields[2:] {
				if list == "" {
					continue
				}
				use.used = true
				for _, name := range strings.Split(list, ",") {
					u, found := names[name]
					use.foreign = use.foreign || !found || u != 0 && u != uint32(uid)
				}
			}
			p.groups[g] = use
		}
	}
	return ""
}

func accountSources(data []byte) string {
	var sources []string
	for _, line := range strings.Split(string(data), "\n") {
		key, _, ok := strings.Cut(line, ":")
		if ok && (strings.TrimSpace(key) == "passwd" || strings.TrimSpace(key) == "group") {
			if len(line) > 256 {
				line = line[:256] + "..."
			}
			sources = append(sources, line)
			if len(sources) == 4 {
				break
			}
		}
	}
	if len(sources) == 0 {
		return "passwd/group sources missing"
	}
	return strings.Join(sources, "; ")
}

func accountID(s string) (uint32, bool) {
	if s == "" || strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil
}

func localAccountsOnly(data []byte) bool {
	seen := map[string]bool{}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		text := strings.SplitN(string(line), "#", 2)[0]
		key, value, ok := strings.Cut(text, ":")
		key = strings.TrimSpace(key)
		if !ok || key != "passwd" && key != "group" {
			continue
		}
		if seen[key] || strings.TrimSpace(value) != "files" {
			return false
		}
		seen[key] = true
	}
	return seen["passwd"] && seen["group"]
}

func (p groupTrust) allows(gid uint32) bool {
	use, exists := p.groups[gid]
	if !p.complete || !exists || use.foreign || use.password != "" {
		return false
	}
	if p.primaryOK && gid == p.primary {
		return true
	}
	return p.complete && exists && !use.used
}
