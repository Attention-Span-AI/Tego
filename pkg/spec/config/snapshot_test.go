// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestMachineSnapshotPreservesPrivateFacts(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		m := Builtin()
		m.Home = "/selected/home"
		m.Layers = []string{"/selected/config.yaml"}
		m.layerBytes = map[Layer][]byte{LayerEnvFile: []byte("exact bytes")}
		m.layerIdentities[2] = layerIdentity{Target: m.Layers[0], Device: 3, Inode: 7}
		m.sources = []LayerSource{{Layer: LayerEnvFile, File: m.Layers[0], State: LayerPresent, SHA256: "known"}}
		if unknown {
			m.sources[0].State = LayerUnknown
		}
		m.baseline = Baseline{entries: []BaselineEntry{{Key: BaselineDenyRead, Value: "~/secret", Sources: []Provenance{{File: m.Layers[0], Line: 4, Layer: LayerEnvFile}}}}, unknown: unknown}
		raw, err := json.Marshal(m.Snapshot())
		if err != nil {
			t.Fatal(err)
		}
		var snapshot Snapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			t.Fatal(err)
		}
		got := snapshot.Restore()
		if !reflect.DeepEqual(m, got) {
			t.Fatalf("private machine context changed in transfer: unknown=%v\nwant=%+v\ngot=%+v", unknown, m, got)
		}
		if got.BaselineKnown() != m.BaselineKnown() {
			t.Fatal("unknown baseline became known")
		}
	}
}
