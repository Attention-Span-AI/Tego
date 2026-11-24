// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"errors"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/runscope"
)

const (
	maxProcText   = 4 << 10
	maxArgvBytes  = 64 << 10
	maxArgvTokens = 256
	maxPIDs       = 32768
	maxThreads    = 256
)

// Parser errors are fixed codes. No input bytes may reach a diagnostic.
var (
	errSyntax  = errors.New("syntax")
	errSize    = errors.New("size")
	errChanged = errors.New("changed")
	errType    = errors.New("type")
	errOwner   = errors.New("owner")
	errLimit   = errors.New("limit")
)

type statusInfo struct {
	uids     [4]uint32
	nspids   int
	caps     uint64
	capsSeen int
}

func parseStatus(b []byte) (statusInfo, error) {
	var out statusInfo
	if len(b) > maxProcText {
		return out, errSize
	}
	if !utf8.Valid(b) {
		return out, errSyntax
	}
	seen := map[string]bool{}
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		key, v, ok := bytes.Cut(line, []byte{':'})
		if !ok {
			if len(line) != 0 {
				return statusInfo{}, errSyntax
			}
			continue
		}
		k := string(key)
		switch k {
		case "Uid", "NSpid", "CapInh", "CapPrm", "CapEff", "CapAmb":
		default:
			continue
		}
		if seen[k] {
			return statusInfo{}, errSyntax
		}
		seen[k] = true
		fields := bytes.Fields(v)
		switch k {
		case "Uid":
			if len(fields) != 4 {
				return statusInfo{}, errSyntax
			}
			for i, f := range fields {
				n, e := strconv.ParseUint(string(f), 10, 32)
				if e != nil || n == 4294967295 {
					return statusInfo{}, errSyntax
				}
				out.uids[i] = uint32(n)
			}
		case "NSpid":
			if len(fields) == 0 || len(fields) > 32 {
				return statusInfo{}, errSyntax
			}
			for _, f := range fields {
				n, e := strconv.ParseUint(string(f), 10, 31)
				if e != nil || n == 0 {
					return statusInfo{}, errSyntax
				}
			}
			out.nspids = len(fields)
		default:
			if len(fields) != 1 || len(fields[0]) > 16 {
				return statusInfo{}, errSyntax
			}
			n, e := strconv.ParseUint(string(fields[0]), 16, 64)
			if e != nil {
				return statusInfo{}, errSyntax
			}
			out.caps |= n
			out.capsSeen++
		}
	}
	if !seen["Uid"] {
		return statusInfo{}, errSyntax
	}
	return out, nil
}

type statInfo struct {
	pid, ppid int
	start     uint64
	tty       int64
	comm      string // match input only; never part of an observation
	state     byte
	flags     uint64
}

func parseStat(b []byte) (statInfo, error) {
	var out statInfo
	if len(b) > maxProcText {
		return out, errSize
	}
	if !utf8.Valid(b) {
		return out, errSyntax
	}
	open := bytes.IndexByte(b, '(')
	end := bytes.LastIndex(b, []byte(") "))
	if open < 2 || end < open || b[open-1] != ' ' {
		return out, errSyntax
	}
	n, e := strconv.ParseUint(strings.TrimSpace(string(b[:open])), 10, 31)
	if e != nil || n == 0 {
		return out, errSyntax
	}
	out.pid = int(n)
	out.comm = string(b[open+1 : end])
	fields := bytes.Fields(b[end+2:])
	if len(fields) < 20 || len(fields) > 128 || len(fields[0]) != 1 || !strings.ContainsRune("RSDZTtXxKWIPN", rune(fields[0][0])) {
		return statInfo{}, errSyntax
	}
	n, e = strconv.ParseUint(string(fields[1]), 10, 31)
	if e != nil {
		return statInfo{}, errSyntax
	}
	out.ppid = int(n)
	out.state = fields[0][0]
	out.flags, e = strconv.ParseUint(string(fields[6]), 10, 64)
	if e != nil {
		return statInfo{}, errSyntax
	}
	out.tty, e = strconv.ParseInt(string(fields[4]), 10, 32)
	if e != nil {
		return statInfo{}, errSyntax
	}
	out.start, e = strconv.ParseUint(string(fields[19]), 10, 64)
	if e != nil {
		return statInfo{}, errSyntax
	}
	return out, nil
}

func parseArgv(b []byte) ([]string, error) {
	if len(b) > maxArgvBytes {
		return nil, errSize
	}
	if len(b) == 0 {
		return nil, nil
	}
	if b[len(b)-1] != 0 || !utf8.Valid(b) {
		return nil, errSyntax
	}
	if bytes.Count(b, []byte{0}) > maxArgvTokens {
		return nil, errLimit
	}
	parts := bytes.Split(b[:len(b)-1], []byte{0})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > maxProcText {
			return nil, errSize
		}
		out = append(out, string(p))
	}
	return out, nil
}

type cgroupInfo struct {
	run      string
	userUnit bool
}

func parseCgroup(b []byte, uid uint32) (cgroupInfo, error) {
	if len(b) > maxProcText {
		return cgroupInfo{}, errSize
	}
	if !utf8.Valid(b) {
		return cgroupInfo{}, errSyntax
	}
	var out cgroupInfo
	seen := false
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return cgroupInfo{}, errSyntax
		}
		if parts[0] != "0" {
			if _, err := strconv.ParseUint(parts[0], 10, 31); err != nil {
				return cgroupInfo{}, errSyntax
			}
			continue
		}
		if seen || parts[1] != "" || !plainPath(parts[2]) || path.Clean(parts[2]) != parts[2] {
			return cgroupInfo{}, errSyntax
		}
		seen = true
		out.run = runscope.GovernedBy(parts[2])
		prefix := "/user.slice/user-" + strconv.FormatUint(uint64(uid), 10) + ".slice/user@" + strconv.FormatUint(uint64(uid), 10) + ".service/"
		if strings.HasPrefix(parts[2], prefix) {
			for _, component := range strings.Split(strings.TrimPrefix(parts[2], prefix), "/") {
				if strings.HasSuffix(component, ".service") && plainUnit(component) {
					out.userUnit = true
				}
			}
		}
	}
	if !seen {
		return cgroupInfo{}, errSyntax
	}
	return out, nil
}

func plainPath(s string) bool {
	if len(s) == 0 || len(s) > 4096 || s[0] != '/' || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) || r == utf8.RuneError {
			return false
		}
	}
	return true
}

func plainUnit(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.@:-", r)) {
			return false
		}
	}
	return true
}
