// SPDX-License-Identifier: Apache-2.0

package mcptool

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecidePrecedence(t *testing.T) {
	r := Rules{Allow: []string{"read_file", "list_dir"}, Deny: []string{"delete_file"}, Ask: []string{"write_file"}}
	open := Rules{}
	for _, c := range []struct {
		name       string
		rules      Rules
		live, tool string
		want       Result
	}{
		{"deny", r, "", "delete_file", Result{Deny, "mcp[files].tools.deny[delete_file]"}},
		{"ask", r, "", "write_file", Result{Ask, "mcp[files].tools.ask[write_file]"}},
		{"allow listed", r, "", "read_file", Result{Allow, "mcp[files].tools.allow[read_file]"}},
		{"not on allow list", r, "", "exec", Result{Deny, "mcp[files].tools.allow"}},
		{"empty allow list denies all", Rules{Allow: []string{}}, "", "x", Result{Deny, "mcp[files].tools.allow"}},
		{"no rules", open, "", "x", Result{Allow, "mcp[files]"}},
		{"live loosens a deny", r, Allow, "delete_file", Result{Allow, "mcp[files].live[delete_file]"}},
		{"live tightens an allow", r, Deny, "read_file", Result{Deny, "mcp[files].live[read_file]"}},
		{"live ask on open server", open, Ask, "x", Result{Ask, "mcp[files].live[x]"}},
		{"unknown live ignored", r, "maybe", "read_file", Result{Allow, "mcp[files].tools.allow[read_file]"}},
		{"deny beats ask", Rules{Deny: []string{"t"}, Ask: []string{"t"}}, "", "t", Result{Deny, "mcp[files].tools.deny[t]"}},
		{"ask beats allow list", Rules{Allow: []string{"a"}, Ask: []string{"t"}}, "", "t", Result{Ask, "mcp[files].tools.ask[t]"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := Decide(c.rules, c.live, "files", c.tool); got != c.want {
				t.Fatalf("Decide = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestLoosens(t *testing.T) {
	for _, c := range []struct {
		from, to string
		want     bool
	}{
		{Deny, Ask, true}, {Deny, Allow, true}, {Ask, Allow, true},
		{Allow, Ask, false}, {Allow, Deny, false}, {Ask, Deny, false}, {Allow, Allow, false}, {Deny, Deny, false},
	} {
		if got := Loosens(c.from, c.to); got != c.want {
			t.Errorf("Loosens(%s, %s) = %v", c.from, c.to, got)
		}
	}
}

func TestFilterToolsList(t *testing.T) {
	denied := func(n string) bool { return n == "delete_file" }
	in := json.RawMessage(`{"tools":[{"name":"read_file","description":"r"},{"name":"delete_file"},{"name":"write_file"}],"nextCursor":"abc"}`)
	out, names, ok := FilterToolsList(in, denied)
	if !ok {
		t.Fatal("not ok")
	}
	if strings.Join(names, ",") != "read_file,delete_file,write_file" {
		t.Fatalf("names = %v", names)
	}
	var got struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
		NextCursor string `json:"nextCursor"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Tools) != 2 || got.Tools[0].Name != "read_file" || got.Tools[1].Name != "write_file" || got.NextCursor != "abc" {
		t.Fatalf("filtered = %s", out)
	}
	// Nothing denied: the bytes are untouched.
	if out, _, ok := FilterToolsList(in, func(string) bool { return false }); !ok || string(out) != string(in) {
		t.Fatalf("unfiltered = %s", out)
	}
	for _, bad := range []string{`not json`, `[]`, `{"tools":"x"}`, `{"tools":[{"name":1}]}`, `{"other":1}`, `null`} {
		out, _, ok := FilterToolsList(json.RawMessage(bad), denied)
		if ok || string(out) != bad {
			t.Errorf("malformed %s = %s, %v; want untouched and not ok", bad, out, ok)
		}
	}
}

func TestRefusalBytes(t *testing.T) {
	got := string(Refusal(json.RawMessage(`7`), "files", "delete_file", "mcp[files].tools.deny[delete_file]", ReasonDenied))
	want := `{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"Tego refused the MCP tool delete_file on files: the run's rules deny this tool","data":{"tego":{"rule":"mcp[files].tools.deny[delete_file]","reason":"mcp-tool-denied"}}}}`
	if got != want {
		t.Fatalf("Refusal =\n%s\nwant\n%s", got, want)
	}
	if s := string(Refusal(nil, "s", "t", "r", "ask-timeout")); !strings.Contains(s, `"id":null`) || !strings.Contains(s, "in time") {
		t.Fatalf("Refusal(nil id) = %s", s)
	}
	if s := string(Refusal(json.RawMessage(`"abc"`), "s", "t", "r", "ask-denied")); !strings.Contains(s, `"id":"abc"`) {
		t.Fatalf("string id = %s", s)
	}
}
