// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const testRun = RunID("r-0123abcd-0000000000000-abcdef")

// identity-config.md R4, R5, R6, R7, R8, R9 (env vars), I5 (no duplicate key), E6 (entry without =), E7 (trailing comma), E29 (stale OTEL member).
func TestEnvApply(t *testing.T) {
	full := Env{RunID: testRun, Agent: "retriever", ParentRun: "", LedgerDir: "/runs/x", Tier: "landlock"}
	cases := []struct {
		name string
		env  Env
		base []string
		want []string
	}{
		{
			name: "T-env-1 identity set appended in fixed order",
			env:  full,
			base: []string{"PATH=/bin"},
			want: []string{"PATH=/bin", "TEGO_RUN_ID=" + string(testRun), "TEGO_PARENT_RUN=", "TEGO_AGENT=retriever",
				"TEGO_LEDGER=/runs/x", "TEGO_TIER=landlock",
				"OTEL_RESOURCE_ATTRIBUTES=tego.run=" + string(testRun) + ",tego.agent=retriever",
				"PGAPPNAME=tego:" + string(testRun)},
		},
		{
			name: "T-env-2 runtime vars win over env.set in place (R3, I5)",
			env:  Env{RunID: testRun},
			base: []string{"A=1", "TEGO_RUN_ID=forged", "B=2", "TEGO_RUN_ID=forged-again", "PGAPPNAME=mine"},
			want: []string{"A=1", "TEGO_RUN_ID=" + string(testRun), "B=2", "PGAPPNAME=mine",
				"TEGO_PARENT_RUN=", "OTEL_RESOURCE_ATTRIBUTES=tego.run=" + string(testRun)},
		},
		{
			name: "T-env-3 OTEL appended to an existing value with percent encoding (R4)",
			env:  Env{RunID: testRun, Agent: "retriever"},
			base: []string{"OTEL_RESOURCE_ATTRIBUTES=service.name=x", "PGAPPNAME="},
			want: []string{"OTEL_RESOURCE_ATTRIBUTES=service.name=x,tego.run=" + string(testRun) + ",tego.agent=retriever",
				"PGAPPNAME=", "TEGO_RUN_ID=" + string(testRun), "TEGO_PARENT_RUN=", "TEGO_AGENT=retriever"},
		},
		{
			name: "E7 trailing comma is not normalized",
			env:  Env{Agent: "a"},
			base: []string{"OTEL_RESOURCE_ATTRIBUTES=k=v,"},
			want: []string{"OTEL_RESOURCE_ATTRIBUTES=k=v,,tego.agent=a", "TEGO_AGENT=a"},
		},
		{
			name: "E29 stale member with another value stays, fresh one appended",
			env:  Env{RunID: testRun},
			base: []string{"OTEL_RESOURCE_ATTRIBUTES=tego.run=r-old"},
			want: []string{"OTEL_RESOURCE_ATTRIBUTES=tego.run=r-old,tego.run=" + string(testRun),
				"TEGO_RUN_ID=" + string(testRun), "TEGO_PARENT_RUN=", "PGAPPNAME=tego:" + string(testRun)},
		},
		{
			name: "T-env-4 PGAPPNAME only when absent; empty counts as present (R5)",
			env:  Env{RunID: testRun},
			base: []string{"PGAPPNAME="},
			want: []string{"PGAPPNAME=", "TEGO_RUN_ID=" + string(testRun), "TEGO_PARENT_RUN=",
				"OTEL_RESOURCE_ATTRIBUTES=tego.run=" + string(testRun)},
		},
		{
			name: "T-env-5 no_proxy added lower-case when no NO_PROXY exists (R6)",
			env:  Env{},
			base: []string{"HTTPS_PROXY=http://p:3128"},
			want: []string{"HTTPS_PROXY=http://p:3128", "no_proxy=127.0.0.1,localhost"},
		},
		{
			name: "T-env-5b both cases appended when both present",
			env:  Env{},
			base: []string{"http_proxy=x", "NO_PROXY=.corp", "no_proxy=.corp,localhost"},
			want: []string{"http_proxy=x", "NO_PROXY=.corp,127.0.0.1,localhost", "no_proxy=.corp,localhost,127.0.0.1"},
		},
		{
			name: "T-env-5c only NO_PROXY present touches only NO_PROXY",
			env:  Env{},
			base: []string{"ALL_PROXY=x", "NO_PROXY="},
			want: []string{"ALL_PROXY=x", "NO_PROXY=127.0.0.1,localhost"},
		},
		{
			name: "T-env-noproxy-wildcard: SOCKS_PROXY qualifies by suffix (R6)",
			env:  Env{},
			base: []string{"socks_proxy=x"},
			want: []string{"socks_proxy=x", "no_proxy=127.0.0.1,localhost"},
		},
		{
			name: "no proxy variable: nothing added",
			env:  Env{},
			base: []string{"PROXY_URL=x", "A=b"},
			want: []string{"PROXY_URL=x", "A=b"},
		},
		{
			name: "T-env-6 forwarder vars overwrite, sorted when appended (R7)",
			env:  Env{ForwarderVars: map[string]string{EnvCodexHome: "/c", EnvAnthropicBaseURL: "http://127.0.0.1:1"}},
			base: []string{"ANTHROPIC_BASE_URL=https://api.anthropic.com"},
			want: []string{"ANTHROPIC_BASE_URL=http://127.0.0.1:1", "CODEX_HOME=/c"},
		},
		{
			name: "T-env-7 DOCKER_HOST set and DOCKER_CONTEXT removed (R8); containers and ray (R9)",
			env:  Env{DockerHost: "unix:///x/docker.sock", ContainersConf: "/x/c.conf", RayHook: "tego_ray:hook"},
			base: []string{"DOCKER_CONTEXT=stale", "DOCKER_HOST=old"},
			want: []string{"DOCKER_HOST=unix:///x/docker.sock", "CONTAINERS_CONF_OVERRIDE=/x/c.conf",
				"RAY_RUNTIME_ENV_HOOK=tego_ray:hook", "RAY_ENABLE_UV_RUN_RUNTIME_ENV=0"},
		},
		{
			name: "E6 entry without '=' untouched",
			env:  Env{Tier: "cgroup"},
			base: []string{"BROKEN", "=weird", "A=1"},
			want: []string{"BROKEN", "=weird", "A=1", "TEGO_TIER=cgroup"},
		},
		{
			name: "zero receiver is the identity function",
			env:  Env{},
			base: []string{"A=1"},
			want: []string{"A=1"},
		},
		{
			name: "nil base",
			env:  Env{Tier: "observe"},
			base: nil,
			want: []string{"TEGO_TIER=observe"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]string(nil), tc.base...)
			got := tc.env.Apply(tc.base)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Apply =\n %q\nwant\n %q", got, tc.want)
			}
			if !reflect.DeepEqual(tc.base, before) {
				t.Error("base mutated")
			}
			if again := tc.env.Apply(got); !reflect.DeepEqual(again, got) {
				t.Errorf("not idempotent:\n %q\n %q", again, got)
			}
			assertNoDuplicateKeys(t, got)
		})
	}
}

// I5: no duplicate KEY= prefix in the output.
func assertNoDuplicateKeys(t *testing.T, env []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, e := range env {
		k, ok := splitKey(e)
		if !ok {
			continue
		}
		if seen[k] {
			t.Errorf("duplicate key %q in %q", k, env)
		}
		seen[k] = true
	}
}

// E5 / T-env-3: env.pass naming TEGO_RUN_ID compiles and is discarded here without a warning.
// identity-config.md R3: Apply runs last and overwrites same-named entries from env.pass/set; E5 (no warning).
func TestEnvApplyDiscardsForgedIdentity(t *testing.T) {
	got := Env{RunID: testRun, Agent: "a", LedgerDir: "/l", Tier: "landlock"}.Apply([]string{
		"TEGO_AGENT=b", "TEGO_LEDGER=/other", "TEGO_TIER=bpflsm", "TEGO_PARENT_RUN=r-forged",
	})
	for _, want := range []string{"TEGO_AGENT=a", "TEGO_LEDGER=/l", "TEGO_TIER=landlock", "TEGO_PARENT_RUN="} {
		if !contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func TestPercentEncode(t *testing.T) {
	if got := percentEncode("a,b=c%"); got != "a%2Cb%3Dc%25" {
		t.Errorf("percentEncode = %q", got)
	}
}

// E22: linear in len(base).
// identity-config.md E22: a 10 000-entry base costs O(len(base)) per identity variable, no quadratic blowup.
func TestEnvApplyPathologicalBase(t *testing.T) {
	env := Env{RunID: testRun, Agent: "retriever", LedgerDir: "/runs/x", Tier: "landlock"}
	allocs := func(n int) float64 {
		base := make([]string, n)
		for i := range base {
			base[i] = "PASS_" + strconv.Itoa(i) + "=v"
		}
		return testing.AllocsPerRun(3, func() { env.Apply(base) })
	}
	small, big := allocs(1000), allocs(10000)
	if big > 20*small+100 {
		t.Errorf("allocations grew superlinearly: %v at 1000, %v at 10000", small, big)
	}
	base := make([]string, 10000)
	for i := range base {
		base[i] = "PASS_" + strconv.Itoa(i) + "=v"
	}
	out := env.Apply(base)
	if len(out) < len(base) {
		t.Fatalf("lost entries: %d", len(out))
	}
	assertNoDuplicateKeys(t, out)
}

// identity-config.md E22: Apply is O(len(base)) per identity variable.
func BenchmarkEnvApply(b *testing.B) {
	base := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		base = append(base, "VAR_"+strconv.Itoa(i)+"="+strings.Repeat("v", 20))
	}
	base = append(base, "HTTPS_PROXY=http://p", "OTEL_RESOURCE_ATTRIBUTES=service.name=x")
	env := Env{RunID: testRun, Agent: "retriever", LedgerDir: "/runs/x", Tier: "landlock",
		ForwarderVars: map[string]string{EnvAnthropicBaseURL: "http://127.0.0.1:1"}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if out := env.Apply(base); len(out) < len(base) {
			b.Fatal("lost entries")
		}
	}
}
