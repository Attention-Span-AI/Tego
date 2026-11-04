// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bytes"
	"errors"
	"strings"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// netOwnerUnixOnly is consumed by attachment only. No IP or socket-family
// program is attached for a no-net contract; its unix programs still decide.
const netOwnerUnixOnly uint32 = 1 << 31

func builtinUnixRows(rows map[bpf.UnixKey]bpf.NetVerdict, rt *agent.RuleTable, slot uint32, out *RuleMaps) error {
	b := rt.Builtins
	if b == nil {
		return nil
	}
	index := func(name string) uint16 {
		for i, s := range out.Rules {
			if s == name {
				return uint16(i)
			}
		}
		out.Rules = append(out.Rules, name)
		return uint16(len(out.Rules) - 1)
	}
	denied := func(name string) bpf.NetVerdict {
		return bpf.NetVerdict{Verdict: uint8(bpf.VerdictRefused), Reason: uint8(bpf.ReasonNetNotAllowed), RuleIdx: index(name)}
	}
	allow := bpf.NetVerdict{Verdict: uint8(bpf.VerdictAllow)}
	put := func(p string, tree bool, v bpf.NetVerdict) error {
		k, err := bpf.UnixPathKey(slot, p, tree)
		if errors.Is(err, bpf.ErrUnixName) {
			return nil
		}
		if err == nil {
			rows[k] = v
		}
		return err
	}
	// Remove every more-specific contractual or filesystem allow below the
	// immutable floor before installing prefix rows: longest-prefix lookup must
	// never let an explicit allow defeat a built-in refusal.
	for k := range rows {
		if k.Kind != bpf.UnixPath {
			continue
		}
		p := strings.TrimRight(string(bytes.TrimRight(k.Name[:], "\x00")), "/")
		if rule := rt.BuiltinUnixRule(p); rule != "" {
			rows[k] = denied(rule)
		}
	}
	if out.UnixOnly && rt.Contract != nil && rt.Contract.HostSockets {
		if err := put("/", true, allow); err != nil {
			return err
		}
	}
	dirs := append(append([]string{}, b.Runtime...), b.IPCDirs...)
	for _, d := range dirs {
		for _, tree := range []bool{false, true} {
			if err := put(d, tree, denied(agent.BuiltinHostIPC)); err != nil {
				return err
			}
		}
	}
	for _, d := range b.TegoDirs {
		for _, tree := range []bool{false, true} {
			if err := put(d, tree, denied(agent.BuiltinTegoSurface)); err != nil {
				return err
			}
		}
	}
	for _, p := range b.Nodes {
		if rule := rt.BuiltinUnixRule(p); rule != "" {
			if err := put(p, false, denied(rule)); err != nil {
				return err
			}
		}
	}
	for _, p := range b.ContainerAliases {
		if err := put(p, false, allow); err != nil {
			return err
		}
	}
	// Exact sockets already admitted by contract keep only the fixed exceptions.
	for _, r := range rt.Net {
		if r.Proto == agent.ProtoUnix && !r.Abstract && rt.BuiltinUnixRule(r.UnixPath) == "" {
			if err := put(r.UnixPath, false, bpf.NetVerdict{Verdict: uint8(bpf.VerdictAllow), RuleIdx: uint16(index(r.RuleName()))}); err != nil {
				return err
			}
		}
	}
	if out.UnixOnly && rt.Contract != nil && rt.Contract.HostSockets {
		for _, d := range b.Runtime {
			for _, s := range []string{"gnupg/S.gpg-agent.ssh", "openssh_agent", "ssh-agent.socket", "keyring/ssh", "gcr/ssh"} {
				if err := put(d+"/"+s, false, allow); err != nil {
					return err
				}
			}
		}
	}
	if b.OwnRuntime != "" {
		for _, tree := range []bool{false, true} {
			if err := put(b.OwnRuntime, tree, allow); err != nil {
				return err
			}
		}
	}
	return nil
}
