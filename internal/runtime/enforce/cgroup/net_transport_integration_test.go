// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestTransportSelectorsOnRealKernel starts from the scalar contract grammar,
// compiles it, compares the pure policy and installed rows, and exercises both
// TCP connects and addressed UDP on the same destination ports in a real cgroup.
// It runs only in the disposable privileged integration environment.
func TestTransportSelectorsOnRealKernel(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse-%v", reverse), func(t *testing.T) {
			ports := []int{listenLoopback(t, "tcp4", "127.0.0.1"), listenLoopback(t, "tcp4", "127.0.0.1"), listenLoopback(t, "tcp4", "127.0.0.1"), listenLoopback(t, "tcp4", "127.0.0.1")}
			raw := []string{fmt.Sprintf("tcp://127.0.0.1:%d", ports[0]), fmt.Sprintf("udp://127.0.0.1:%d", ports[1]), fmt.Sprintf("127.0.0.1:%d", ports[2]), fmt.Sprintf("tcp://127.0.0.0/8:%d", ports[3])}
			if reverse {
				raw[0], raw[1] = raw[1], raw[0]
			}
			root := t.TempDir()
			yaml := fmt.Sprintf("version: 0\nname: transport\ncommand: [/bin/true]\nrecord: summary\ncapture: off\ntier: cgroup\nfs: {deny_read: []}\nnet:\n  allow: [%q, %q, %q, %q]\n", raw[0], raw[1], raw[2], raw[3])
			c, ds, err := agent.LoadBytes(filepath.Join(root, "agent.yaml"), []byte(yaml), nil)
			if err != nil {
				t.Fatalf("Load: %v %v", err, ds)
			}
			m := config.Builtin()
			m.Home = root
			m.LedgerRoot = config.Setting[string]{Value: filepath.Join(root, "runs")}
			rt, ds, err := agent.Compile(c, m, agent.WithHome(root), agent.WithCwd(root), agent.WithPATH("/usr/bin:/bin"), agent.WithChainAnchor(filepath.Join(root, "chain.log")), agent.WithTiers(backend.TierCgroup))
			if err != nil {
				t.Fatalf("Compile: %v %v", err, ds)
			}
			h, dir, id := realRun(t, fmt.Sprintf("transport-%v", reverse), rt)
			g := h.NetworkGuarantees()
			if !g.TCPDestination || !g.UDPDestination {
				t.Fatalf("attached destination hooks not reported: %+v", g)
			}
			for i, port := range ports {
				for _, proto := range []string{agent.ProtoTCP, agent.ProtoUDP} {
					for _, host := range []string{"127.0.0.1", "::ffff:127.0.0.1"} {
						want := i == 2 || i == 0 && proto == agent.ProtoTCP || i == 1 && proto == agent.ProtoUDP || i == 3 && proto == agent.ProtoTCP
						a := agent.Action{Kind: agent.ActionNetConnect, Host: host, Port: port, Proto: proto}
						model := decide.Evaluate(rt, a, backend.TierCgroup)
						if (model.Verdict == agent.VerdictAllow) != want {
							t.Fatalf("model %+v = %+v want allow=%v", a, model, want)
						}
						mode, networks := "connect", []string{proto + "4"}
						if host != "127.0.0.1" {
							mode, networks = "connect-mapped", []string{proto + "6"}
							if proto == agent.ProtoUDP {
								networks = append(networks, "udp6-connected")
							}
						}
						dst := netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
						for _, network := range networks {
							got := runNetHelper(t, dir, mode, []string{network + " " + dst.String()})[0]
							if want && got != nil || !want && !errors.Is(got, unix.EPERM) {
								t.Fatalf("%s %s: %v want allow=%v", network, dst, got, want)
							}
							var br bpf.Breadcrumb
							if err := h.kern.(*bpfKernel).maps[bpf.MapReason].Lookup(&id, &br); err != nil {
								t.Fatal(err)
							}
							wantProto := bpf.ProtoTCP
							if proto == agent.ProtoUDP {
								wantProto = bpf.ProtoUDP
							}
							if br.Proto != wantProto || br.Port != uint16(port) || (bpf.Verdict(br.Verdict) == bpf.VerdictAllow) != want {
								t.Fatalf("breadcrumb %+v for %s %s", br, proto, dst)
							}
							if want && h.Rules().RuleName(br.RuleIdx) != model.Rule {
								t.Fatalf("kernel rule %s vs model %s on port %s", h.Rules().RuleName(br.RuleIdx), model.Rule, strconv.Itoa(port))
							}
						}
					}
				}
			}
		})
	}
}
