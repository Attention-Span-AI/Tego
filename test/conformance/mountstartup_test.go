// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"strings"
	"testing"
)

func TestBindMountStartupExpectations(t *testing.T) {
	want := map[string]bool{
		"mounts-bind": false, "mounts-bindsub": false,
		"mounts-bindfile": true, "mounts-bindhidden": true, "mounts-bindmove": true,
		"mounts-bindancestor": true, "mounts-bindask": true,
	}
	for _, fx := range Fixtures() {
		detached, ok := want[fx.Name]
		if !ok {
			continue
		}
		delete(want, fx.Name)
		if !fx.Model.ListenerRefuses || fx.Model.PlaneCannotHold != detached {
			t.Errorf("%s startup: listener refuses=%v, plane cannot hold=%v; want true, %v", fx.Name,
				fx.Model.ListenerRefuses, fx.Model.PlaneCannotHold, detached)
		}
		if fx.Name == "mounts-bindask" {
			if !strings.Contains(fx.Contract, "ask: [\"./pub/\"]") || !strings.Contains(fx.Contract, "timeout: 100ms") {
				t.Error("ask-parent fixture needs its real scope and a bounded Landlock timeout")
			}
			if len(fx.Cells) != 2 || fx.Cells[0].Op != OpRename || fx.Cells[1].Op != OpExchange {
				t.Error("ask-parent fixture needs rename and exchange cells, neither reached at root tiers")
			}
		}
	}
	for name := range want {
		t.Errorf("missing fixture %s", name)
	}
}
