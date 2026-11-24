// SPDX-License-Identifier: Apache-2.0

package result

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAdvancedForeignProcessFolderPrivacy(t *testing.T) {
	s := advancedExample(t)
	foreign := s.Items[0].Process()
	if foreign.Cwd != nil {
		t.Fatal("published foreign process fixture records a working folder")
	}
	for _, mode := range []string{"short", "verbose", "json"} {
		t.Run(mode, func(t *testing.T) {
			var out, errs bytes.Buffer
			if err := Render(&out, &errs, s, mode == "json", mode == "verbose", nil); err != nil {
				t.Fatal(err)
			}
			if mode == "json" {
				decoded, err := Decode(out.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				if decoded.Items[0].Process().Cwd != nil {
					t.Fatal("JSON retained a foreign working folder")
				}
			} else if !strings.Contains(out.String(), "observed uid 1001; folder not recorded for other accounts") {
				t.Fatal("foreign row did not explain the omitted folder: " + out.String())
			}
		})
	}

	const canary = "/home/other/PRIVATE_WORKING_FOLDER_CANARY"
	foreign.Cwd = Path(canary)
	s.Items[0].Detail = Detail(foreign)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := Decode(b); !errors.Is(err, ErrInvalid) || decoded.Schema != "" || strings.Contains(err.Error(), canary) {
		t.Fatalf("foreign folder was accepted or echoed: %v", err)
	}
	if _, err := Encode(s); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign folder could be saved: %v", err)
	}
	// The same path remains valid for a process owned by the result recipient.
	foreign.UID = s.As.Recipient
	s.Items[0].Detail = Detail(foreign)
	if _, err := Encode(s); err != nil {
		t.Fatalf("recipient folder was refused: %v", err)
	}
}
