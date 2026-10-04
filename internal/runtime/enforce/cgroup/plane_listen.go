// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"sort"

	bpf "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"golang.org/x/sys/unix"
)

func planPlaneListenFill(plan *planeFillPlan, rows *decide.PlaneRows, held heldFD, id fdIdentity) error {
	if len(rows.Listen) > bpf.PlaneListenRowsMax {
		return fmt.Errorf("plane fill: %d Unix listener rows exceeds cap %d", len(rows.Listen), bpf.PlaneListenRowsMax)
	}
	seen := make(map[int]bool)
	for _, r := range rows.Listen {
		if r.Abstract {
			continue
		}
		if held == nil {
			return errors.New("plane fill: Unix listener parent descriptors are unavailable")
		}
		fd, ok := held(r.Path)
		if !ok {
			return fmt.Errorf("plane fill: no parent descriptor for Unix listener %s", r.Path)
		}
		if seen[fd] {
			return fmt.Errorf("plane fill: Unix listeners share parent descriptor %d", fd)
		}
		seen[fd] = true
		if r.Rule < 0 || r.Rule > int(bpf.PlaneRuleMax) || len(r.Name) == 0 || len(r.Name) > 107 {
			return fmt.Errorf("plane fill: invalid Unix listener %s", r.Path)
		}
		e := planeFillEntry{FD: fd, Path: r.Parent, What: bpf.PlaneFillListen, RuleIdx: uint16(r.Rule), Name: r.Name, Parent: r.Parent}
		if err := identify(&e, id); err != nil {
			return err
		}
		plan.Entries = append(plan.Entries, e)
	}
	sort.Slice(plan.Entries, func(i, j int) bool {
		if plan.Entries[i].What != plan.Entries[j].What {
			return plan.Entries[i].What < plan.Entries[j].What
		}
		return plan.Entries[i].FD < plan.Entries[j].FD
	})
	return nil
}

func abstractListenRows(req planeFillRequest) ([]bpf.PlaneListenKey, []bpf.PlaneListenRow, error) {
	if len(req.Rows.Listen) > bpf.PlaneListenRowsMax {
		return nil, nil, fmt.Errorf("plane fill: %d Unix listener rows exceeds cap %d", len(req.Rows.Listen), bpf.PlaneListenRowsMax)
	}
	var keys []bpf.PlaneListenKey
	var vals []bpf.PlaneListenRow
	seen := make(map[bpf.PlaneListenKey]bool)
	for _, r := range req.Rows.Listen {
		if !r.Abstract {
			continue
		}
		if req.Gen == 0 || r.Rule < 0 || r.Rule > int(bpf.PlaneRuleMax) || len(r.Name) == 0 || len(r.Name) > 107 {
			return nil, nil, fmt.Errorf("plane fill: invalid abstract Unix listener %q", r.Name)
		}
		key := bpf.PlaneListenKey{NameLen: uint32(len(r.Name)), Abstract: 1}
		copy(key.Name[:], r.Name)
		if seen[key] {
			return nil, nil, fmt.Errorf("plane fill: duplicate abstract Unix listener %q", r.Name)
		}
		seen[key] = true
		keys = append(keys, key)
		vals = append(vals, bpf.PlaneListenRow{Gen: req.Gen, RuleIdx: uint16(r.Rule)})
	}
	return keys, vals, nil
}

func (p *bpfPlane) putListenNames(req planeFillRequest) error {
	keys, vals, err := abstractListenRows(req)
	if err != nil || len(keys) == 0 {
		return err
	}
	inner, err := innerOf(p.listenRows, req.Slot, bpf.MapPlaneListenRows)
	if err != nil {
		return err
	}
	defer func() { _ = inner.Close() }()
	for i := range keys {
		err = inner.Put(keys[i], vals[i])
		if errors.Is(err, unix.E2BIG) {
			if _, _, cerr := p.filler.clearSlot(req.Slot, req.Gen); cerr != nil {
				return cerr
			}
			err = inner.Put(keys[i], vals[i])
		}
		if err != nil {
			return mapFull(bpf.MapPlaneListenRows, err)
		}
	}
	return nil
}
