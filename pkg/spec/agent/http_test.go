// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

const httpContract = "version: 0\nname: http-policy\ncommand: [/bin/true]\ncapture: forwarder\nmodels:\n  - {provider: anthropic, host: API.Example.com., port: 8443}\nnet:\n  http:\n    - {host: api.example.com, allow: [/v1/messages], methods: [POST]}\n"

func TestHTTPContractScopeAndCompile(t *testing.T) {
	c, ds, err := LoadBytes("http.yaml", []byte(httpContract), nil)
	if err != nil {
		t.Fatalf("load: %v %v", err, ds)
	}
	rt, ds, err := Compile(c, &config.Machine{}, Offline(), WithMountInfo(""))
	if err != nil {
		t.Fatalf("compile: %v %v", err, ds)
	}
	if rt.HTTP == nil || !rt.HTTP.Covers("api.example.com:8443") {
		t.Fatal("canonical listener policy missing")
	}
	for _, bad := range []string{
		strings.Replace(httpContract, "capture: forwarder", "capture: auto", 1),
		strings.Replace(httpContract, "capture: forwarder", "capture: uprobe", 1),
		strings.Replace(httpContract, "capture: forwarder", "capture: off", 1),
		httpContract + "tier: observe\n",
		strings.Replace(httpContract, "host: api.example.com, allow", "host: other.example.com, allow", 1),
		strings.Replace(httpContract, "host: api.example.com, allow", "host: 'api.example.com:443', allow", 1),
		strings.Replace(httpContract, "host: api.example.com, allow", "host: 'https://api.example.com', allow", 1),
		strings.Replace(httpContract, "net:\n", "  - {provider: openai, host: api.example.com, port: 443}\nnet:\n", 1),
		strings.Replace(httpContract, "net:\n", "  - {provider: openai, host: other.example.com, port: 443}\nnet:\n", 1),
		strings.Replace(httpContract, "allow: [/v1/messages]", "allow: [/v1/%2fmessages]", 1),
		strings.Replace(httpContract, "methods: [POST]", "methods: [CONNECT]", 1),
	} {
		if _, ds, err := LoadBytes("bad.yaml", []byte(bad), nil); err == nil {
			t.Fatalf("unsupported HTTP contract loaded: %s %v", bad, ds)
		}
	}
	// Compile knows the machine ceiling; Load alone must not certify this run.
	for _, m := range []*config.Machine{
		{Capture: config.Ceiling[config.CaptureSetting]{Value: config.CaptureSetting{Capture: "off"}, Bounded: true}},
		{Tier: config.Ceiling[config.TierSetting]{Value: config.TierSetting{Tier: "observe"}, Bounded: true}},
	} {
		if _, _, err := Compile(c, m, Offline(), WithMountInfo("")); err == nil {
			t.Fatal("HTTP policy lowered below enforcement")
		}
	}
}

func TestHTTPCompileTestIsARequest(t *testing.T) {
	c, _, err := LoadBytes("http.yaml", []byte(httpContract), nil)
	if err != nil {
		t.Fatal(err)
	}
	rt, _, err := Compile(c, &config.Machine{}, Offline(), WithMountInfo(""))
	if err != nil {
		t.Fatal(err)
	}
	table, ds, err := LoadTestTableBytes("test.yaml", []byte("version: 0\ntests:\n  - {action: net.http, host_port: API.Example.com.:8443, method: POST, path: /v1/messages/count_tokens, expect: allow, rule: 'net.http[0]'}\n  - {action: net.http, host_port: api.example.com:8443, method: GET, path: /v1/messages, expect: refused}\n  - {action: net.http, host_port: api.example.com:8443, method: POST, path: /v1/messages-extra, expect: refused}\n"))
	if err != nil {
		t.Fatalf("table: %v %v", err, ds)
	}
	for _, row := range table.Rows {
		a := row.action("/unrelated", "")
		if !strings.HasPrefix(a.Path, "/v1/") {
			t.Fatalf("HTTP path treated as filesystem %q", a.Path)
		}
		if !row.matches(rt.Evaluate(a, backend.TierLandlock)) {
			t.Fatalf("HTTP request failed %+v", row)
		}
	}
}

func TestHTTPCompileTestNeverResolvesFilesystemPaths(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "actual")
	alias := filepath.Join(dir, "alias")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	a := Action{Kind: ActionNetHTTP, Host: "h", Port: 443, Method: "GET", Path: alias}
	got, paths := resolveAction(a, evalLanders)
	if got.Path != alias || paths.Path != "" {
		t.Fatalf("HTTP URL resolved through filesystem: %+v %+v", got, paths)
	}
}
