// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"testing"
)

// A watched run read against the enforced run's contract: the project's own API (allowed there) is neither next to a
// secret nor a destination of the leak; the attacker's sink still is, and the cached Signal is left as it was.
func TestAgainstReference(t *testing.T) {
	root, left, right, lost := demoRuns(t)
	matched := *right
	right = &matched
	right.Cwd, right.Agent = left.Cwd, left.Agent
	s, err := Load(root)
	if s != nil {
		for i, r := range s.Runs {
			if r.ID == right.ID {
				s.Runs[i] = right
			}
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if ref := ReferenceRun(s.Runs, left); ref == nil || ref.ID != right.ID {
		t.Fatalf("reference %v, want the enforced run of the same program", ref)
	}
	if ReferenceRun(s.Runs, right) != nil || ReferenceRun(s.Runs, lost) != nil {
		t.Error("an enforced run got a reference")
	}

	own := Signal(left, Sensitive{Cwd: left.Cwd})
	api := func(sig *RunSignal) Dest {
		for _, d := range sig.Outbound {
			if d.Key == "127.0.0.1:59465" {
				return d
			}
		}
		t.Fatal("no API destination")
		return Dest{}
	}
	if d := api(own); !d.NearSecret || d.InContract {
		t.Fatalf("API %+v: the fixture wants it next to a secret before the reference", d)
	}
	refSig := Signal(right, Sensitive{Cwd: right.Cwd})
	got := own.Against(NewReference(right.ID, nil, refSig))
	if got.AllowedFrom != right.ID {
		t.Errorf("AllowedFrom %q, want %q", got.AllowedFrom, right.ID)
	}
	if d := api(got); d.NearSecret || !d.InContract {
		t.Errorf("API %+v, want allowed by the reference and not next to a secret", d)
	}
	v := RunVerdict(left, got)
	if v.Kind != VerdictLeak || !slices.Equal(v.Dests, []string{"127.0.0.1:45805"}) {
		t.Errorf("verdict %+v, want a leak to the sink only", v)
	}
	if d := api(Signal(left, Sensitive{Cwd: left.Cwd})); !d.NearSecret || d.InContract {
		t.Errorf("the cached Signal was changed: %+v", d)
	}
	// With no reference the watched run keeps its own Signal.
	if own.Against(Reference{}) != own {
		t.Error("an empty reference changed the Signal")
	}
}

// When nothing but the reference's API was next to the secret reads, the secrets are no longer exposed: a watched
// run that only talked to what the job needs is not a leak.
func TestAgainstClearsLeakToAllowedOnly(t *testing.T) {
	sig := &RunSignal{
		Secrets:  []SecretTouch{{Path: "/h/.ssh/id_rsa", Observed: 1, FirstSeq: 10, NearSend: true}},
		Outbound: []Dest{{Key: "127.0.0.1:8803", Observed: 1, FirstSeq: 12, NearSecret: true}},
	}
	got := sig.Against(Reference{Run: "r-enf", Net: []string{"127.0.0.1:8803"}})
	if got.Secrets[0].NearSend || got.Outbound[0].NearSecret {
		t.Errorf("signal %+v, want the API allowed and the key not next to a send", got)
	}
	if v := RunVerdict(&Run{Tier: "observe"}, got); v.Kind == VerdictLeak {
		t.Errorf("verdict %+v, want no leak", v)
	}
}

func TestReferenceAllows(t *testing.T) {
	ref := Reference{Run: "r", Net: []string{"tcp://chatgpt.com:443", "127.0.0.1:8803", "*.openai.com:443", "api.local", "unix:/var/run/nscd/socket"}}
	for key, want := range map[string]bool{
		"chatgpt.com:443":           true,
		"chatgpt.com:80":            false,
		"127.0.0.1:8803":            true,
		"127.0.0.1:8802":            false,
		"auth.openai.com:443":       true,
		"openai.com.evil.io:443":    false,
		"api.local:9000":            true,
		"unix:/var/run/nscd/socket": true,
	} {
		if got := ref.allows(&Dest{Key: key}); got != want {
			t.Errorf("allows(%q) = %v, want %v", key, got, want)
		}
	}
}

// TestProgram: a run's program is read from its recorded arguments, so a path that holds a space is one program; a
// run with no recorded arguments (a record too old to carry them) keeps the first word of its command text.
func TestProgram(t *testing.T) {
	for cmd, want := range map[string]string{"/usr/bin/codex --no-daemon": "codex", "codex": "codex", "": ""} {
		if got := (&Run{Command: cmd}).program(); got != want {
			t.Errorf("program of the text %q = %q, want %q", cmd, got, want)
		}
	}
	spaced := &Run{Command: "/opt/my tools/codex --no-daemon", command: []string{"/opt/my tools/codex", "--no-daemon"}}
	if got := spaced.program(); got != "codex" {
		t.Errorf("program of the recorded arguments = %q, want codex", got)
	}
	if !SameProgram(spaced, &Run{Command: "/usr/bin/codex"}) || SameProgram(spaced, &Run{Command: "/opt/my"}) {
		t.Error("SameProgram does not read the recorded program")
	}
}
