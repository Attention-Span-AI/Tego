// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// realisticTable is ADR 0028 S1's benchmark table: 47 entries of a contract run from a project under $HOME —
// write entries for the project, the caches and /tmp, the built-in deny_read list over ~/.ssh and its
// siblings, one .env file per project directory, the ledger's implicit entry and a watch entry.
func realisticTable(tier backend.Tier) *agent.RuleTable {
	const home = "/home/u"
	w := func(p string) agent.FSRule {
		return agent.FSRule{Kind: agent.FSWrite, Path: p, Raw: p, Resolved: p, Access: agent.AccessWriteSet}
	}
	d := func(p string, unenforced bool) agent.FSRule {
		return agent.FSRule{Kind: agent.FSDenyRead, Path: p, Raw: p, Resolved: p, Unenforced: unenforced}
	}
	fs := []agent.FSRule{
		w(home + "/proj"), w(home + "/.cache"), w("/tmp"), w(home + "/.npm"),
		{Kind: agent.FSImplicit, Path: home + "/.tego/ledger", Raw: home + "/.tego/ledger", Resolved: home + "/.tego/ledger"},
		{Kind: agent.FSWatch, Path: home + "/proj/logs", Raw: home + "/proj/logs", Resolved: home + "/proj/logs"},
	}
	for _, p := range []string{".ssh", ".aws", ".gnupg", ".config/gh", ".netrc", ".docker/config.json", ".kube",
		".tego", ".git-credentials", ".pypirc"} {
		fs = append(fs, d(home+"/"+p, false))
	}
	for i := 0; len(fs) < 47; i++ {
		fs = append(fs, d(home+"/proj/svc"+strconv.Itoa(i)+"/.env", true))
	}
	net := []agent.NetRule{
		{Raw: "api.example.com:443", Host: "api.example.com", Port: 443, Proto: agent.ProtoInet,
			IPs: []netip.Addr{netip.MustParseAddr("192.0.2.10")}},
		{Raw: "10.0.0.0/8:443", Port: 443, Proto: agent.ProtoInet, CIDR: ptr(netip.MustParsePrefix("10.0.0.0/8"))},
		{Raw: "10.1.0.0/16:443", Port: 443, Proto: agent.ProtoInet, CIDR: ptr(netip.MustParsePrefix("10.1.0.0/16"))},
	}
	return &agent.RuleTable{FS: fs, Net: net, Tier: tier, Record: agent.RecordFull}
}

func ptr[T any](v T) *T { return &v }

// The query paths the runtime asks per event, on the realistic table.
var (
	benchRead    = "/home/u/proj/src/pkg/main.go"
	benchDenied  = "/home/u/.ssh/id_ed25519"
	benchNested  = "/home/u/proj/svc3/.env"
	benchOutside = "/usr/share/zoneinfo/UTC"
)

// TestQueryPathsAllocateNothing is ADR 0028 S1's gate on the core's query path: the recorder's chooser, the
// supervisor's advisory verdict, the listener's open and exec decisions, the net matcher and the plane's
// reference walk allocate nothing per question.
func TestQueryPathsAllocateNothing(t *testing.T) {
	rt := realisticTable(backend.TierLandlock)
	tabs := NewAdvisoryTables(rt.FS)
	deny, readable, _ := listenerIndexes(rt)
	x := NewRootIndex(RootRows(rt))
	addr := netip.MustParseAddr("10.1.2.3")
	for name, fn := range map[string]func(){
		"FSDecider": func() {
			for _, p := range []string{benchRead, benchDenied, benchNested, benchOutside} {
				FSDecider(rt, p, true)
				FSDecider(rt, p, false)
			}
		},
		"AdvisoryFS": func() {
			for _, p := range []string{benchRead, benchDenied, benchNested, benchOutside} {
				AdvisoryFS(rt, tabs.Both, p, record.FSOpen, 0, false)
				AdvisoryFS(rt, tabs.Both, p, record.FSOpen, 1, false)
				AdvisoryFS(rt, tabs.Both, p, record.FSUnlink, 0, false)
			}
		},
		"ListenerOpen": func() {
			for _, p := range []string{benchRead, benchDenied, benchNested, benchOutside} {
				ListenerOpen(&deny, &readable, p)
			}
		},
		"MatchNetLPM": func() { MatchNetLPM(rt.Net, addr, 443, "tcp") },
		"RootWalk": func() {
			for _, p := range []string{benchRead, benchDenied, benchNested, benchOutside} {
				x.Walk(p, true)
				x.Walk(p, false)
			}
		},
	} {
		if n := testing.AllocsPerRun(100, fn); n != 0 {
			t.Errorf("%s makes %v allocations, want 0", name, n)
		}
	}
}

func BenchmarkFSDecider(b *testing.B) {
	rt := realisticTable(backend.TierCgroup)
	b.ReportAllocs()
	for b.Loop() {
		FSDecider(rt, benchRead, true)
		FSDecider(rt, benchDenied, true)
	}
}

func BenchmarkAdvisoryFS(b *testing.B) {
	rt := realisticTable(backend.TierLandlock)
	tabs := NewAdvisoryTables(rt.FS)
	b.ReportAllocs()
	for b.Loop() {
		AdvisoryFS(rt, tabs.Both, benchRead, record.FSOpen, 1, false)
		AdvisoryFS(rt, tabs.Both, benchDenied, record.FSOpen, 0, false)
	}
}

func BenchmarkListenerOpen(b *testing.B) {
	rt := realisticTable(backend.TierCgroup)
	deny, readable, _ := listenerIndexes(rt)
	b.ReportAllocs()
	for b.Loop() {
		ListenerOpen(&deny, &readable, benchRead)
		ListenerOpen(&deny, &readable, benchNested)
	}
}

func BenchmarkRootWalk(b *testing.B) {
	rt := realisticTable(backend.TierBPFLSM)
	x := NewRootIndex(RootRows(rt))
	b.ReportAllocs()
	for b.Loop() {
		x.Walk(benchRead, true)
		x.Walk(benchDenied, true)
	}
}

func BenchmarkEvaluate(b *testing.B) {
	rt := realisticTable(backend.TierLandlock)
	a := agent.Action{Kind: agent.ActionFSRead, Path: benchDenied}
	b.ReportAllocs()
	for b.Loop() {
		Evaluate(rt, a, backend.TierLandlock)
	}
}
