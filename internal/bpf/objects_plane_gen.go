// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

// planeGenerated registers the two builds of bpf/decide.bpf.c (plane.go), apart from generated so that no loop
// over the tier-2 objects loads them. Never written after initialization.
var planeGenerated = map[Object]binding{
	ObjectPlaneRdonly: {load: loadPlanerd, raw: _PlanerdBytes},
	ObjectPlaneProbe:  {load: loadPlanepr, raw: _PlaneprBytes},
}
