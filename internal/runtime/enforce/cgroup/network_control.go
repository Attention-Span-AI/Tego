// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type IngressRow struct {
	Key bpf.IngressKey
	Val bpf.NetVerdict
}

// NetworkControlMaps is one run's opt-in bind, packet and resource policy.
// Config presence is separate from flags: an explicit zero ceiling is a rule.
type NetworkControlMaps struct {
	RunIdx  uint32
	Config  bpf.NetControl
	Binds   []NetRow
	Ingress []IngressRow
	Rules   []string
}

func NetworkControlRequested(rt *agent.RuleTable) bool {
	if rt == nil {
		return false
	}
	l := rt.NetLimits
	return rt.Listen != nil || rt.Ingress != nil || l.Bytes != nil || l.DatagramsPerSecond != nil || l.Connections != nil || l.PendingConnects != nil
}

// BuildNetworkControl uses the existing ledger rule-index namespace. base is
// len(RuleMaps.Rules), whose index zero already means no declared entry.
func BuildNetworkControl(rt *agent.RuleTable, runIdx, gen uint32, base int) (*NetworkControlMaps, error) {
	if !NetworkControlRequested(rt) {
		return nil, nil
	}
	if runIdx >= bpf.MaxSlots || gen == 0 || base < 1 || base+len(rt.Listen) > bpf.MaxRules {
		return nil, fmt.Errorf("%w: invalid network-control slot/generation/rule indexes", ErrMapFull)
	}
	out := &NetworkControlMaps{RunIdx: runIdx, Config: bpf.NetControl{Gen: gen}}
	if rt.Listen != nil {
		out.Config.Flags |= bpf.NetControlListen
	}
	if rt.Ingress != nil {
		out.Config.Flags |= bpf.NetControlIngress
	}
	l := rt.NetLimits
	if l.Bytes != nil {
		if *l.Bytes < 0 {
			return nil, fmt.Errorf("network byte ceiling is negative")
		}
		out.Config.Flags |= bpf.NetControlBytes
		out.Config.Bytes = uint64(*l.Bytes)
	}
	if l.DatagramsPerSecond != nil {
		out.Config.Flags |= bpf.NetControlDatagrams
		out.Config.DatagramsPerSecond = *l.DatagramsPerSecond
	}
	if l.Connections != nil {
		out.Config.Flags |= bpf.NetControlConnections
		out.Config.Connections = *l.Connections
	}
	if l.PendingConnects != nil {
		out.Config.Flags |= bpf.NetControlPending
		out.Config.PendingConnects = *l.PendingConnects
	}
	bindIndexes := make(map[string]uint32)
	exact := make(map[bpf.NetKey]bpf.NetVerdict)
	for i, r := range rt.Listen {
		idx := uint16(base + i)
		out.Rules = append(out.Rules, r.RuleName())
		if r.Proto == agent.ProtoUnix {
			continue
		}
		proto, err := listenerProtocol(r.Proto)
		if err != nil {
			return nil, err
		}
		keys, err := bpf.NetKeys(runIdx, proto, r.Address, r.Port)
		if err != nil {
			return nil, err
		}
		// Exact and wildcard overlaps retain the first declared matching rule.
		for _, key := range keys {
			a, err := bpf.AddrFrom(key.Family, key.Addr)
			if err != nil {
				return nil, err
			}
			match, ok := agent.MatchBind(rt.Listen, netip.AddrPortFrom(a, key.Port), r.Proto)
			if !ok {
				return nil, fmt.Errorf("listener row has no matching declaration")
			}
			for j := range rt.Listen {
				if rt.Listen[j].RuleName() == match.RuleName() {
					idx = uint16(base + j)
					break
				}
			}
			exact[key] = bpf.NetVerdict{Verdict: uint8(bpf.VerdictAllow), RuleIdx: idx}
		}
		match, _ := agent.MatchBind(rt.Listen, netip.AddrPortFrom(r.Address, r.Port), r.Proto)
		for j := range rt.Listen {
			if rt.Listen[j].RuleName() == match.RuleName() {
				bindIndexes[listenerIdentity(r)] = uint32(base + j)
				break
			}
		}
	}
	out.Binds = sortedExact(exact)
	for _, r := range rt.Ingress {
		idx, ok := bindIndexes[listenerIdentity(r.To)]
		if !ok || !r.From.IsValid() {
			return nil, fmt.Errorf("ingress names no declared IP listener")
		}
		proto, err := listenerProtocol(r.To.Proto)
		if err != nil {
			return nil, err
		}
		addr, family, err := bpf.Addr16(r.From.Addr())
		if err != nil {
			return nil, err
		}
		var local [16]byte
		if !r.To.Address.IsUnspecified() {
			local, _, err = bpf.Addr16(r.To.Address)
			if err != nil {
				return nil, err
			}
		}
		out.Ingress = append(out.Ingress, IngressRow{Key: bpf.IngressKey{
			PrefixLen: bpf.IngressHeaderBits + uint32(r.From.Bits()), RunIdx: runIdx, BindRule: idx,
			Family: family, Proto: proto, Port: r.To.Port, Local: local, Addr: addr}, Val: bpf.NetVerdict{Verdict: uint8(bpf.VerdictAllow), RuleIdx: uint16(idx)}})
	}
	if len(out.Binds) > bpf.NetRowsMax || len(out.Ingress) > bpf.NetRowsMax {
		return nil, ErrMapFull
	}
	return out, nil
}

func listenerIdentity(r agent.ListenRule) string {
	return r.Proto + "/" + netip.AddrPortFrom(r.Address, r.Port).String()
}
func listenerProtocol(proto string) (uint8, error) {
	switch proto {
	case agent.ProtoTCP:
		return bpf.ProtoTCP, nil
	case agent.ProtoUDP:
		return bpf.ProtoUDP, nil
	}
	return 0, fmt.Errorf("unsupported IP listener protocol %q", proto)
}

func (k *bpfKernel) populateNetworkControl(control *NetworkControlMaps) error {
	if control == nil {
		return nil
	}
	for _, name := range bpf.NetControlMaps {
		if k.maps[name] == nil {
			return fmt.Errorf("%w: network control map %s missing", ErrProgramLoad, name)
		}
	}
	for _, row := range control.Binds {
		if err := k.maps[bpf.MapBindExact].Update(&row.Key, &row.Val, ebpf.UpdateAny); err != nil {
			return mapFull(bpf.MapBindExact, err)
		}
	}
	for _, row := range control.Ingress {
		if err := k.maps[bpf.MapIngress].Update(&row.Key, &row.Val, ebpf.UpdateAny); err != nil {
			return mapFull(bpf.MapIngress, err)
		}
	}
	zero := bpf.NetStats{}
	if err := k.maps[bpf.MapNetStats].Update(&control.RunIdx, &zero, ebpf.UpdateAny); err != nil {
		return mapFull(bpf.MapNetStats, err)
	}
	return k.maps[bpf.MapNetControl].Update(&control.RunIdx, &control.Config, ebpf.UpdateAny)
}

func (k *bpfKernel) purgeNetworkControl(slot uint32) error {
	var errs []error
	for _, name := range []string{bpf.MapNetControl, bpf.MapNetStats} {
		if m := k.maps[name]; m != nil {
			if err := m.Delete(&slot); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, err)
			}
		}
	}
	if m := k.maps[bpf.MapBindExact]; m != nil {
		errs = append(errs, purgeRowsOfSlot(m, bpf.MapBindExact, slot, func(key *bpf.NetKey) uint32 { return key.RunIdx }))
	}
	if m := k.maps[bpf.MapIngress]; m != nil {
		errs = append(errs, purgeRowsOfSlot(m, bpf.MapIngress, slot, func(key *bpf.IngressKey) uint32 { return key.RunIdx }))
	}
	for _, name := range []string{bpf.MapNetFlows, bpf.MapNetPending} {
		if m := k.maps[name]; m != nil {
			errs = append(errs, purgeRowsOfSlot(m, name, slot, func(key *bpf.NetFlowKey) uint32 { return key.RunIdx }))
		}
	}
	if m := k.maps[bpf.MapBindPending]; m != nil {
		errs = append(errs, purgeRowsOfSlot(m, bpf.MapBindPending, slot, func(key *bpf.BindAttemptKey) uint32 { return key.Socket.RunIdx }))
	}
	errs = append(errs, k.purgeApprovals(slot))
	for _, name := range []string{bpf.MapNetSockets, bpf.MapNetBinds} {
		if m := k.maps[name]; m != nil {
			errs = append(errs, purgeRowsOfSlot(m, name, slot, func(key *bpf.NetSocketKey) uint32 { return key.RunIdx }))
		}
	}
	return errors.Join(errs...)
}

// purgeApprovals removes the slot's one-shot grants, TCP and UDP (GrantConnect, GrantDatagram) and abstract unix (GrantUnix), of every
// gen: at Detach, when Prepare reclaims the slot, and from the reaper (purgeSlot over the pinned maps purgeDeadSlots
// loads, both grant maps among them). A grant a missed purge left names a gen no later run of the slot has, so it
// admits nothing; the purge keeps it off the map's shared budget.
func (k *bpfKernel) purgeApprovals(slot uint32) error {
	var errs []error
	if m := k.maps[bpf.MapConnectApprovals]; m != nil {
		errs = append(errs, purgeRowsOfSlot(m, bpf.MapConnectApprovals, slot, func(key *bpf.ConnectApprovalKey) uint32 { return key.RunIdx }))
	}
	if m := k.maps[bpf.MapUnixApprovals]; m != nil {
		errs = append(errs, purgeRowsOfSlot(m, bpf.MapUnixApprovals, slot, func(key *bpf.UnixApprovalKey) uint32 { return key.RunIdx }))
	}
	return errors.Join(errs...)
}

// Only requested mechanisms are attached. A missing required mechanism fails
// startup; unrelated ordinary contracts do not acquire optional packet hooks.
func (k *bpfKernel) attachNetworkControl(path string, owner bpf.NetOwner) error {
	configMap := k.maps[bpf.MapNetControl]
	if configMap == nil {
		return nil
	}
	var config bpf.NetControl
	if err := configMap.Lookup(&owner.RunIdx, &config); errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	for _, name := range RequiredNetworkPrograms(config.Flags) {
		prog := k.progs[name]
		if prog == nil {
			return fmt.Errorf("%w: required network program %s unavailable", ErrProgramLoad, name)
		}
		types := map[string]ebpf.AttachType{bpf.ProgNetIngress: ebpf.AttachCGroupInetIngress, bpf.ProgNetEgress: ebpf.AttachCGroupInetEgress,
			bpf.ProgNetSockOps: ebpf.AttachCGroupSockOps, bpf.ProgNetRelease: ebpf.AttachCgroupInetSockRelease,
			bpf.ProgPostBind4: ebpf.AttachCGroupInet4PostBind, bpf.ProgPostBind6: ebpf.AttachCGroupInet6PostBind}
		l, err := link.AttachCgroup(link.CgroupOptions{Path: path, Attach: types[name], Program: prog})
		if err != nil {
			return attachError(name, path, err)
		}
		k.cgroupLinks = append(k.cgroupLinks, l)
		if err := pinRunLink(k.runLinks, l, name); err != nil {
			return err
		}
		if k.netAttached == nil {
			k.netAttached = make(map[string]bool)
		}
		k.netAttached[name] = true
	}
	k.networkFlags = config.Flags
	return nil
}

func RequiredNetworkPrograms(flags uint32) []string {
	var out []string
	if flags&bpf.NetControlListen != 0 {
		out = append(out, bpf.ProgPostBind4, bpf.ProgPostBind6, bpf.ProgNetRelease, bpf.ProgNetSockOps)
	}
	if flags&bpf.NetControlIngress != 0 {
		out = append(out, bpf.ProgNetIngress, bpf.ProgNetRelease, bpf.ProgNetSockOps, bpf.ProgPostBind4, bpf.ProgPostBind6)
	}
	if flags&(bpf.NetControlIngress|bpf.NetControlBytes|bpf.NetControlDatagrams|bpf.NetControlConnections|bpf.NetControlPending) != 0 {
		out = append(out, bpf.ProgNetEgress)
	}
	if flags&(bpf.NetControlConnections|bpf.NetControlPending) != 0 {
		out = append(out, bpf.ProgNetIngress, bpf.ProgNetSockOps, bpf.ProgNetRelease)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Program selection is per load, while maps remain shared by the build. Legacy
// contracts do not depend on optional socket/packet program support. A contract
// requesting a mechanism gets a hard load/attach error if it is unavailable.
func selectNetworkControlPrograms(spec *ebpf.CollectionSpec, control *NetworkControlMaps) {
	flags := uint32(0)
	if control != nil {
		flags = control.Config.Flags
	}
	want := RequiredNetworkPrograms(flags)
	for _, name := range bpf.NetControlPrograms {
		if !slices.Contains(want, name) {
			delete(spec.Programs, name)
		}
	}
	if flags&bpf.NetControlListen == 0 {
		for name := range bpf.ListenerTracepoints {
			delete(spec.Programs, name)
		}
		for name := range bpf.ListenerURingPrograms {
			delete(spec.Programs, name)
		}
	}
}
