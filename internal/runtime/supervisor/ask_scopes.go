// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"golang.org/x/sys/unix"
)

type askScope struct {
	fd       int
	identity fileID
	// An absent literal leaf grants no subtree. Its existing parent is pinned.
	missing   string
	checkPath string
}

// pinAskScopes holds every fs.ask scope and fs.ask_read entry O_PATH before the agent runs, so an approval can
// check that the scope it lies in is still the one the run started with (askScopeValid).
func (l *Loop) pinAskScopes(rt *agent.RuleTable) error {
	rules := append(append([]agent.FSRule(nil), rt.FSAsk...), rt.AskReadRules()...)
	l.askScopes = make(map[string]askScope, len(rules))
	for _, rule := range rules {
		p := rule.Governed()
		if _, exists := l.askScopes[p]; exists {
			continue
		}
		s := askScope{fd: -1, checkPath: p}
		fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) {
			s.checkPath, s.missing = filepath.Dir(p), filepath.Base(p)
			fd, err = unix.Open(s.checkPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			l.closeAskScopes()
			return err
		}
		s.fd = fd
		var st unix.Stat_t
		if err = unix.Fstat(fd, &st); err != nil || st.Nlink == 0 || (st.Mode&unix.S_IFMT != unix.S_IFDIR && st.Mode&unix.S_IFMT != unix.S_IFREG) {
			_ = unix.Close(fd)
			l.closeAskScopes()
			if err == nil {
				err = unix.EOPNOTSUPP
			}
			return err
		}
		s.identity = fileID{dev: st.Dev, ino: st.Ino}
		l.askScopes[p] = s
	}
	return nil
}

func (l *Loop) closeAskScopes() {
	l.heldPins.close()
	for p, s := range l.askScopes {
		_ = unix.Close(s.fd)
		delete(l.askScopes, p)
	}
}

func (l *Loop) askScopeValid(rule *agent.FSRule, target string) bool {
	s, ok := l.askScopes[rule.Governed()]
	if !ok || (s.missing != "" && target != rule.Governed()) {
		return false
	}
	var held, current unix.Stat_t
	if unix.Fstat(s.fd, &held) != nil || held.Nlink == 0 || unix.Stat(s.checkPath, &current) != nil {
		return false
	}
	return held.Dev == s.identity.dev && held.Ino == s.identity.ino && current.Dev == s.identity.dev && current.Ino == s.identity.ino
}
