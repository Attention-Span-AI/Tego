// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

// planeFillGenerated registers the two builds of bpf/decide_fill.bpf.c (planefill.go), apart from generated and
// planeGenerated so that no loop over those loads them. Never written after initialization.
var planeFillGenerated = map[Object]binding{
	ObjectPlaneFillRdonly: {load: loadPlanefillrd, raw: _PlanefillrdBytes},
	ObjectPlaneFillProbe:  {load: loadPlanefillpr, raw: _PlanefillprBytes},
}
