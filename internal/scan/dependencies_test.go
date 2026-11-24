// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestJSONDependencies(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		bad               bool
	}{
		{"tables", `{"dependencies":{"@openai/codex":"TOKEN","unknown-TOKEN":"https://TOKEN"},"devDependencies":{"@langchain/langgraph":"TOKEN"},"optionalDependencies":{"opencode-ai":"TOKEN"},"peerDependencies":{"@google/gemini-cli":"TOKEN"},"scripts":{"@openai/codex":"TOKEN"},"name":"TOKEN","author":"TOKEN"}`, "dep-codex,dep-opencode,dep-gemini,dep-langgraph-js", false},
		{"ignore subtrees", `{"scripts":{"dependencies":{"@openai/codex":"TOKEN"}},"nested":[1,true,null,{"x":"TOKEN"}]}`, "", false},
		{"escaped key", `{"dependencies":{"@openai/\u0063odex":"TOKEN"}}`, "dep-codex", false},
		{"duplicate", `{"dependencies":{"@openai/codex":"TOKEN","@openai/\u0063odex":"TOKEN"}}`, "", true},
		{"later syntax", `{"dependencies":{"@openai/codex":"TOKEN"},"x":`, "", true},
		{"nonstring", `{"dependencies":{"@openai/codex":{}}}`, "", true},
		{"bad table", `{"dependencies":[]}`, "", true},
		{"comments", `{"dependencies":{"@openai/codex":"TOKEN"}/*TOKEN*/}`, "", true},
		{"surrogate", `{"x":"\ud800"}`, "", true},
		{"utf8", "{\"x\":\"\xff\"}", "", true},
		{"trailing", `{} TOKEN`, "", true},
		{"depth", `{"x":` + strings.Repeat("[", 34) + `0` + strings.Repeat("]", 34) + `}`, "", true},
		{"string bound", `{"x":"` + strings.Repeat("x", 4097) + `"}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := parseJSONDependencies(t.Context(), strings.NewReader(tc.input))
			if (e != nil) != tc.bad {
				t.Fatalf("error %v", e)
			}
			if e != nil && len(got) != 0 {
				t.Fatal("salvaged prefix")
			}
			ids := []string{}
			for _, d := range got {
				ids = append(ids, d.ID)
			}
			if strings.Join(ids, ",") != tc.want {
				t.Fatalf("ids %v", ids)
			}
			b, _ := json.Marshal(got)
			if strings.Contains(string(b), "TOKEN") {
				t.Fatal("retained values")
			}
		})
	}
}
func TestRequirements(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		bad         bool
	}{
		{"# TOKEN\nLangGraph[extra]>=0.2, <1 ; python_version >= '3.10' and (sys_platform != \"win32\") # TOKEN\ncrewai==0.5\nunknown-TOKEN==TOKEN\n", "dep-langgraph,dep-crewai", false},
		{"crewai\nlanggraph\ncrewai\n", "dep-langgraph,dep-crewai", false},
		{"langgraph (>=0.2, <1)\n", "dep-langgraph", false},
		{"langgraph\n-r TOKEN.txt\n", "", true},
		{"--index-url https://TOKEN\n", "", true},
		{"langgraph @ https://TOKEN\n", "", true},
		{"https://TOKEN\n", "", true},
		{"-e TOKEN\n", "", true},
		{"langgraph==1 \\\n TOKEN\n", "", true},
		{"langgraph>=1 --hash=TOKEN\n", "", true},
		{"langgraph; TOKEN == 'TOKEN'\n", "", true},
		{"langgraph[\n", "", true},
		{"langgraph; python_version >= \"TOKEN\n", "", true},
		{"langgraph\n\xff\n", "", true},
	} {
		t.Run(tc.input[:min(12, len(tc.input))], func(t *testing.T) {
			got, e := parseRequirements(t.Context(), strings.NewReader(tc.input))
			if (e != nil) != tc.bad {
				t.Fatalf("error %v", e)
			}
			ids := []string{}
			for _, d := range got {
				ids = append(ids, d.ID)
			}
			if strings.Join(ids, ",") != tc.want {
				t.Fatalf("ids %v", ids)
			}
			b, _ := json.Marshal(got)
			if strings.Contains(string(b), "TOKEN") {
				t.Fatal("retained values")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := parseRequirements(ctx, strings.NewReader("langgraph")); e == nil {
		t.Fatal("cancel ignored")
	}
}
func FuzzScanJSONDependencies(f *testing.F) {
	for _, s := range []string{`{}`, `{"dependencies":{"@openai/codex":"SECRET"}}`, `{"x":"\ud800"}`, `{"dependencies":{"x":"TOKEN"},"x":`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, e := parseJSONDependencies(t.Context(), strings.NewReader(s))
		if e != nil && len(got) != 0 {
			t.Fatal("prefix retained")
		}
		if e == nil && !json.Valid([]byte(s)) {
			t.Fatal("accepted invalid JSON")
		}
	})
}
func FuzzScanRequirements(f *testing.F) {
	for _, s := range []string{"langgraph==0.2 # SECRET\n", "crewai[tools]>=1; python_version > '3.10'\n", "-r SECRET\n", "langgraph @ https://SECRET\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, e := parseRequirements(t.Context(), strings.NewReader(s))
		if e != nil && len(got) != 0 {
			t.Fatal("prefix retained")
		}
		for _, d := range got {
			if d.ID != "dep-langgraph" && d.ID != "dep-crewai" {
				t.Fatal("unknown dependency")
			}
		}
	})
}

func TestManifestBounds(t *testing.T) {
	jsonEntries := `{"dependencies":{`
	for i := 0; i < 129; i++ {
		if i > 0 {
			jsonEntries += ","
		}
		jsonEntries += fmt.Sprintf(`"unknown%d":"value"`, i)
	}
	jsonEntries += `}}`
	jsonTokens := `{"x":[` + strings.Repeat("0,", 4096) + `0]}`
	for _, input := range []string{jsonEntries, jsonTokens, strings.Repeat(" ", manifestBytes+1) + `{}`} {
		if _, e := parseJSONDependencies(t.Context(), strings.NewReader(input)); e == nil {
			t.Fatal("JSON bound ignored")
		}
	}
	reqEntries := strings.Repeat("unknown==1\n", 129)
	for _, input := range []string{reqEntries, strings.Repeat("#\n", 4097), "#" + strings.Repeat("x", 4096), strings.Repeat("# abcdefghijklmnopqrstuvwxyz\n", manifestBytes/25)} {
		if _, e := parseRequirements(t.Context(), strings.NewReader(input)); e == nil {
			t.Fatal("requirements bound ignored")
		}
	}
}
