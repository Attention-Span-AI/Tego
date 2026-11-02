// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// maxSeverityFile is the largest rules file the dashboard takes: about a thousand rules, far more than a person keeps.
// Every refusal group of every run is matched against the rules and every Signal is keyed by them, so a bigger file
// costs every page that reads a run: 1 MB of rules held one for 30 s.
const maxSeverityFile = 64 << 10

// sevFileRule is one of a person's severity rules as the file keeps it.
type sevFileRule struct {
	Channel  string `json:"channel,omitempty"`
	Match    string `json:"match"`
	Severity string `json:"severity"`
}

// severityRules is the person's severity rules in force, first match first. A caller does not change them.
func (s *Server) severityRules() []ledgerview.SevRule {
	if p := s.sevRules.Load(); p != nil {
		return *p
	}
	return nil
}

// severityNote is the notice a page shows while the rules file cannot be read, "" while it can.
func (s *Server) severityNote() string {
	s.sevMu.Lock()
	defer s.sevMu.Unlock()
	if s.sevErr == "" {
		return ""
	}
	return "Severity rules not read: " + tilde(s.cfg.SeverityFile) + " · built-in rules in use"
}

// loadSeverity reads the person's severity rules from their file into force. A missing file is no rules. A file that
// cannot be read is no reason to stop the dashboard, which reports what happened whatever sorts it: the built-in rules
// apply and sevErr says so (severityNote).
func (s *Server) loadSeverity() {
	s.sevMu.Lock()
	defer s.sevMu.Unlock()
	s.readSeverity()
}

// readSeverity is loadSeverity with sevMu held.
func (s *Server) readSeverity() {
	rs, err := readSeverityFile(s.cfg.SeverityFile)
	s.sevErr = ""
	if err != nil {
		s.sevErr = err.Error()
	}
	s.sevRules.Store(&rs)
}

// readSeverityFile is the rules file's rules, none for a file that is not there. An entry with no match or no severity
// it knows is left out.
func readSeverityFile(file string) ([]ledgerview.SevRule, error) {
	if file == "" {
		return nil, nil
	}
	b, err := severityBytes(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rs []sevFileRule
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, err
	}
	var out []ledgerview.SevRule
	for _, r := range rs {
		if v, ok := ledgerview.ParseSeverity(r.Severity); ok && r.Match != "" {
			out = append(out, ledgerview.SevRule{Channel: r.Channel, Match: r.Match, Severity: v})
		}
	}
	return out, nil
}

// severityBytes is file's bytes, when it is a regular file of at most maxSeverityFile. The open does not wait: a named
// pipe at the path would otherwise hold the dashboard's start until something wrote to it.
func severityBytes(file string) ([]byte, error) {
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // opened to read: a close loses nothing
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", file)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSeverityFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSeverityFile {
		return nil, fmt.Errorf("%s is over %d bytes", file, maxSeverityFile)
	}
	return b, nil
}

// writeSeverityFile writes rs to file, which only its owner reads. It refuses a list readSeverityFile would not take:
// the rule that passed the limit would turn every other rule off.
func writeSeverityFile(file string, rs []ledgerview.SevRule) error {
	out := make([]sevFileRule, len(rs))
	for i, r := range rs {
		out[i] = sevFileRule{Channel: r.Channel, Match: r.Match, Severity: r.Severity.String()}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if len(b) > maxSeverityFile {
		return errors.New("too many rules")
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// severityData is the Severity page: the person's rules, and a new rule's fields prefilled from Investigate.
type severityData struct {
	Rules          []ledgerview.SevRule
	File           string // the rules file; rules live there and are not part of the record
	Match, Channel string
	Channels       []string
	Severities     []string
	Off            bool
}

// severity answers GET /severity.
func (s *Server) severity(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	s.loadSeverity() // a file fixed by hand counts from here, with no restart
	q := r.URL.Query()
	d := severityData{Rules: s.severityRules(), File: s.cfg.SeverityFile, Match: q.Get("match"), Channel: q.Get("ch"),
		Channels: []string{"Files", "Programs", "Network"}, Severities: []string{"High", "Medium", "Low"}, Off: s.cfg.SeverityFile == ""}
	c := s.chromeOf(snap, "Severity", "rules")
	if n := s.severityNote(); n != "" {
		c.Notes = append(c.Notes, n)
	}
	s.render(w, http.StatusOK, "severity", c, d)
}

// severityPost answers POST /severity/add and /severity/remove.
func (s *Server) severityPost(w http.ResponseWriter, r *http.Request, op string) {
	if s.cfg.SeverityFile == "" {
		s.fail(w, http.StatusNotFound, "Not found", "This dashboard keeps no severity rules.")
		return
	}
	s.sevMu.Lock()
	defer s.sevMu.Unlock()
	s.readSeverity()
	if s.sevErr != "" {
		// Saving now would replace a file someone's rules are in with the one rule this form holds.
		s.redirectBack(w, r, "/severity", flash{Text: "Not saved · fix or remove " + tilde(s.cfg.SeverityFile) + " first"})
		return
	}
	f := r.PostForm
	rs := slices.Clone(s.severityRules())
	var text string
	switch op {
	case "add":
		v, ok := ledgerview.ParseSeverity(f.Get("severity"))
		// Rules match absolute paths, so ~/work reads as the /work it is under any home.
		match := strings.TrimPrefix(strings.TrimSpace(f.Get("match")), "~")
		ch := f.Get("channel")
		if !ok || match == "" || (ch != "" && ch != "Files" && ch != "Programs" && ch != "Network") {
			s.redirectBack(w, r, "/severity", flash{Text: "Give a match and a severity"})
			return
		}
		rs = append([]ledgerview.SevRule{{Channel: ch, Match: match, Severity: v}}, rs...)
		text = "Saved: " + match + " is " + v.String()
	case "remove":
		// The form names the rule, not its place: a rule added or removed in another tab moves every place below it.
		v, _ := ledgerview.ParseSeverity(f.Get("severity"))
		want := ledgerview.SevRule{Channel: f.Get("channel"), Match: f.Get("match"), Severity: v}
		i := slices.Index(rs, want)
		if i < 0 {
			s.redirectBack(w, r, "/severity", flash{Text: "That rule is gone"})
			return
		}
		text = "Removed: " + rs[i].Match
		rs = append(rs[:i], rs[i+1:]...)
	}
	if err := writeSeverityFile(s.cfg.SeverityFile, rs); err != nil {
		s.redirectBack(w, r, "/severity", flash{Text: "Not saved: " + err.Error()})
		return
	}
	s.sevRules.Store(&rs)
	s.redirectBack(w, r, "/severity", flash{OK: true, Text: text, Link: "/detections", LinkText: "Detections"})
}
