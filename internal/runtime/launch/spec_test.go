// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/net/bpf"
)

// fakeHandle is an api.Handle for tests: an optional ruleset fd and an optional filter.
type fakeHandle struct {
	ruleset int
	prog    []bpf.RawInstruction
}

func (h fakeHandle) LandlockRuleset() (int, bool)                { return h.ruleset, h.ruleset >= 0 }
func (h fakeHandle) SeccompFilter() ([]bpf.RawInstruction, bool) { return h.prog, len(h.prog) > 0 }
func (fakeHandle) Attach(uint64) error                           { return nil }
func (fakeHandle) Detach() error                                 { return nil }
func (fakeHandle) Close() error                                  { return nil }

func validSpec() ChildSpec {
	return ChildSpec{
		RunID: "r-1", AgentID: "a", Command: []string{"/bin/true"}, Env: []string{"A=1"}, Dir: "/",
		Handle: fakeHandle{ruleset: -1},
	}
}

func TestChildSpecValidate(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*ChildSpec)
		ok   bool
	}{
		{"valid", func(*ChildSpec) {}, true},
		{"empty command", func(s *ChildSpec) { s.Command = nil }, false},
		{"empty argv0", func(s *ChildSpec) { s.Command = []string{""} }, false},
		{"nil handle", func(s *ChildSpec) { s.Handle = nil }, false},
		{"empty dir", func(s *ChildSpec) { s.Dir = "" }, false},
		{"privileged without ids", func(s *ChildSpec) { s.Privileged = true; s.TargetUID = -1 }, false},
		{"privileged with ids", func(s *ChildSpec) { s.Privileged = true; s.TargetUID = 1000; s.TargetGID = 1000 }, true},
		{"nul in env", func(s *ChildSpec) { s.Env = []string{"A=\x00"} }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := validSpec()
			tc.mut(&s)
			err := s.Validate()
			if (err == nil) != tc.ok {
				t.Fatalf("Validate = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrSpec) {
				t.Fatalf("error %v does not wrap ErrSpec", err)
			}
		})
	}
}

func TestWireRoundTrip(t *testing.T) {
	prog := []bpf.RawInstruction{{Op: 0x20, K: 4}, {Op: 0x06, K: 0x7fff0000}}
	tests := []struct {
		name       string
		spec       ChildSpec
		hasRuleset bool
		want       wireSpec
	}{
		{
			name: "unprivileged no enforcement",
			spec: validSpec(),
			want: wireSpec{RunID: "r-1", AgentID: "a", Command: []string{"/bin/true"}, Env: []string{"A=1"}, Dir: "/",
				UID: -1, GID: -1, ParentPID: 42, RulesetFD: -1},
		},
		{
			name: "privileged with ruleset and filter",
			spec: func() ChildSpec {
				s := validSpec()
				s.Privileged, s.TargetUID, s.TargetGID = true, 1000, 1001
				s.Handle = fakeHandle{ruleset: 9, prog: prog}
				s.LandlockFlags = 3
				return s
			}(),
			hasRuleset: true,
			want: wireSpec{RunID: "r-1", AgentID: "a", Command: []string{"/bin/true"}, Env: []string{"A=1"}, Dir: "/",
				UID: 1000, GID: 1001, Privileged: true, ParentPID: 42, RulesetFD: childRulesetFD, LandlockFlags: 3,
				Seccomp: prog},
		},
		{
			// runtime-launch.md E17: Command and Dir pass through as raw UTF-8 bytes, unmodified.
			name: "non-ASCII command and dir stay as given",
			spec: func() ChildSpec {
				s := validSpec()
				s.Command = []string{"/opt/agent-é", "naïve arg"}
				s.Dir = "/home/пользователь/проект"
				return s
			}(),
			want: wireSpec{RunID: "r-1", AgentID: "a", Command: []string{"/opt/agent-é", "naïve arg"}, Env: []string{"A=1"},
				Dir: "/home/пользователь/проект", UID: -1, GID: -1, ParentPID: 42, RulesetFD: -1},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.spec.toWire(42, tc.hasRuleset, false)
			if !reflect.DeepEqual(w, tc.want) {
				t.Fatalf("toWire = %+v\nwant     %+v", w, tc.want)
			}
			var buf bytes.Buffer
			if err := writeSpec(&buf, w); err != nil {
				t.Fatal(err)
			}
			got, err := readSpec(&buf)
			if err != nil {
				t.Fatal(err)
			}
			if got.Seccomp == nil {
				got.Seccomp = tc.want.Seccomp
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("round trip = %+v\nwant       %+v", got, tc.want)
			}
		})
	}
}

// TestWireKeepsNonUTF8Bytes: runtime-launch.md E17. The stage execs and chdirs from the wire spec, so an argv,
// env or dir byte that is not UTF-8 must cross the pipe as itself, not as U+FFFD.
func TestWireKeepsNonUTF8Bytes(t *testing.T) {
	s := validSpec()
	s.Command = []string{"/bin/echo", "a\xffb", "\xc3"}
	s.Env = []string{"BAD=\xfe\xff", "OK=1"}
	s.Dir = "/tmp/\x80dir"
	w := s.toWire(42, false, false)
	var buf bytes.Buffer
	if err := writeSpec(&buf, w); err != nil {
		t.Fatal(err)
	}
	got, err := readSpec(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Command, s.Command) || !reflect.DeepEqual(got.Env, s.Env) || got.Dir != s.Dir {
		t.Fatalf("bytes changed on the wire:\ncommand %q env %q dir %q\nwant    %q env %q dir %q",
			got.Command, got.Env, got.Dir, s.Command, s.Env, s.Dir)
	}
}

func TestReadSpecRejects(t *testing.T) {
	frame := func(n uint32, body string) []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, n)
		return append(b, body...)
	}
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty stream", nil, io.EOF},
		{"short header", []byte{1, 2}, io.ErrUnexpectedEOF},
		{"zero frame", frame(0, ""), ErrSpec},
		{"oversized frame", frame(maxSpecBytes+1, ""), ErrSpec},
		{"truncated body", frame(10, "{}"), io.ErrUnexpectedEOF},
		{"bad json", frame(2, "{x"), ErrSpec},
		{"empty command", frame(14, `{"command":[]}`), ErrSpec},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readSpec(bytes.NewReader(tc.in))
			if !errors.Is(err, tc.want) {
				t.Fatalf("readSpec = %v, want %v", err, tc.want)
			}
		})
	}
}

// FuzzReadSpec is the parent-to-child spec pipe's decoder over any bytes, the mirror of FuzzControlPipeDecode
// for the pipe that runs the other way: the child's side used to be the unfuzzed one.
// Whatever the child reads, readSpec refuses it as ErrSpec or a short read, or returns a spec with a command
// that writeSpec frames back to one message readSpec reads as the same spec; and it reads exactly its frame,
// never the ack byte the parent writes after it on the same pipe.
func FuzzReadSpec(f *testing.F) {
	frame := func(w wireSpec) []byte {
		var b bytes.Buffer
		if err := writeSpec(&b, w); err != nil {
			f.Fatal(err)
		}
		return b.Bytes()
	}
	priv := validSpec()
	priv.Privileged, priv.TargetUID, priv.TargetGID = true, 1000, 1001
	priv.Handle = fakeHandle{ruleset: 9, prog: []bpf.RawInstruction{{Op: 0x20, K: 4}, {Op: 0x06, K: 0x7fff0000}}}
	f.Add(append(frame(validSpec().toWire(42, false, false)), 1)) // a frame, then the ack
	f.Add(frame(priv.toWire(42, true, false)))
	f.Add([]byte{2, 0, 0, 0, '{', '}'})
	f.Add([]byte{14, 0, 0, 0, '{', '"', 'c', 'o', 'm', 'm', 'a', 'n', 'd', '"', ':', '[', ']', '}'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		w, err := readSpec(r)
		if err != nil {
			if !errors.Is(err, ErrSpec) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("readSpec: %v, which is neither ErrSpec nor a short read", err)
			}
			return
		}
		if n := int(binary.LittleEndian.Uint32(b)); len(b)-r.Len() != 4+n {
			t.Fatalf("readSpec read %d bytes of a %d-byte frame: the ack byte after it is not its to read", len(b)-r.Len(), 4+n)
		}
		if len(w.Command) == 0 || w.Command[0] == "" {
			t.Fatalf("readSpec accepted a spec with no command: %+v", w)
		}
		var once bytes.Buffer
		if err := writeSpec(&once, w); err != nil {
			if errors.Is(err, ErrSpec) {
				return // escaping grew the body past maxSpecBytes; writeSpec refuses to send it
			}
			t.Fatal(err)
		}
		w2, err := readSpec(bytes.NewReader(once.Bytes()))
		if err != nil {
			t.Fatalf("readSpec refused what writeSpec made of its own answer: %v", err)
		}
		var twice bytes.Buffer
		if err := writeSpec(&twice, w2); err != nil || !bytes.Equal(once.Bytes(), twice.Bytes()) {
			t.Fatalf("the spec changed across a round trip (%v):\n%s\n%s", err, once.Bytes(), twice.Bytes())
		}
	})
}

func BenchmarkWireRoundTrip(b *testing.B) {
	s := validSpec()
	s.Env = make([]string, 200)
	for i := range s.Env {
		s.Env[i] = "VARIABLE_NAME_" + string(rune('A'+i%26)) + "=some value of ordinary length for an environment"
	}
	s.Handle = fakeHandle{ruleset: 5, prog: make([]bpf.RawInstruction, 120)}
	w := s.toWire(1, true, false)
	var buf bytes.Buffer
	b.ReportAllocs()
	for b.Loop() {
		buf.Reset()
		if err := writeSpec(&buf, w); err != nil {
			b.Fatal(err)
		}
		if _, err := readSpec(&buf); err != nil {
			b.Fatal(err)
		}
	}
}

// TestResetSignalsCrossTheWire: the job-control stops a tier-2 launcher ignores (HoldJobControl) travel to
// the child stage in the spec, which resets them before it execs the agent (E40); a spec without them
// carries no key, so an older stage reads nothing new.
//
// Also pins runtime-launch.md R9a: wireSpec.reset_signals carries the ignored job-control stops to the stage.
func TestResetSignalsCrossTheWire(t *testing.T) {
	w := validSpec().toWire(42, false, false)
	w.ResetSignals = []int{int(syscall.SIGTSTP), int(syscall.SIGTTIN), int(syscall.SIGTTOU)}
	var buf bytes.Buffer
	if err := writeSpec(&buf, w); err != nil {
		t.Fatal(err)
	}
	got, err := readSpec(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.ResetSignals, w.ResetSignals) {
		t.Errorf("ResetSignals = %v, want %v", got.ResetSignals, w.ResetSignals)
	}
	buf.Reset()
	if err := writeSpec(&buf, validSpec().toWire(42, false, false)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "reset_signals") {
		t.Errorf("a spec with nothing to reset carries the key: %s", buf.String())
	}
}

// TestWireDeputyFD: the open deputy's control socket follows the inherited descriptors (fd 6 after a ruleset, fd 5
// without one), and a spec with no deputy carries none, which the stage reads as no deputy.
func TestWireDeputyFD(t *testing.T) {
	s := validSpec()
	for _, tc := range []struct {
		ruleset, deputy bool
		want            int
	}{{false, false, 0}, {true, false, 0}, {false, true, childRulesetFD}, {true, true, childRulesetFD + 1}} {
		if got := s.toWire(42, tc.ruleset, tc.deputy).DeputyFD; got != tc.want {
			t.Errorf("ruleset %t deputy %t: DeputyFD %d, want %d", tc.ruleset, tc.deputy, got, tc.want)
		}
	}
}
