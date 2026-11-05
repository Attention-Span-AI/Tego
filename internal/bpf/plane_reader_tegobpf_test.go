// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import "testing"

// The probe objects are the 6.1 path. A cast accidentally added to an included header or peer hook must
// not silently turn them into the read-only objects and raise the documented floor (ADR 0024).
func TestPlaneProbeBuildHasNoKfuncCalls(t *testing.T) {
	for _, obj := range []Object{ObjectPlaneProbe, ObjectPlaneFillProbe, ObjectPlaneRdonly} {
		spec, err := Load(obj)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		for name, p := range spec.Programs {
			for _, ins := range p.Instructions {
				if !ins.IsKfuncCall() {
					continue
				}
				calls++
				if obj != ObjectPlaneRdonly {
					t.Errorf("%s/%s requires a kfunc: %v", obj, name, ins)
				}
			}
		}
		if obj == ObjectPlaneRdonly && calls == 0 {
			t.Fatal("the read-only control has no kfunc calls: the test inspects no casts")
		}
	}
}
