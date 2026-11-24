// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestCaptureCallerResolverSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"default", nil, nil},
		{"empty-localdomain", map[string]string{"LOCALDOMAIN": ""}, []string{"LOCALDOMAIN"}},
		{"localdomain", map[string]string{"LOCALDOMAIN": "private.example"}, []string{"LOCALDOMAIN"}},
		{"empty-options", map[string]string{"RES_OPTIONS": ""}, nil},
		{"options", map[string]string{"RES_OPTIONS": "attempts:1"}, []string{"RES_OPTIONS"}},
		{"aliases", map[string]string{"HOSTALIASES": "/private/aliases"}, []string{"HOSTALIASES"}},
		{"host-conf", map[string]string{"RESOLV_HOST_CONF": "/private/host.conf"}, []string{"RESOLV_HOST_CONF"}},
		{"empty-host-conf", map[string]string{"RESOLV_HOST_CONF": ""}, []string{"RESOLV_HOST_CONF"}},
		{"multi", map[string]string{"RESOLV_MULTI": "on"}, []string{"RESOLV_MULTI"}},
		{"reorder", map[string]string{"RESOLV_REORDER": "off"}, []string{"RESOLV_REORDER"}},
		{"add-trim", map[string]string{"RESOLV_ADD_TRIM_DOMAINS": ".private.example"}, []string{"RESOLV_ADD_TRIM_DOMAINS"}},
		{"override-trim", map[string]string{"RESOLV_OVERRIDE_TRIM_DOMAINS": ".private.example"}, []string{"RESOLV_OVERRIDE_TRIM_DOMAINS"}},
		{"go", map[string]string{"GODEBUG": "netdns=go+2"}, []string{"GODEBUG/netdns"}},
		{"cgo", map[string]string{"GODEBUG": "netdns=2+cgo"}, []string{"GODEBUG/netdns"}},
		{"debug-only", map[string]string{"GODEBUG": "netdns=2"}, nil},
		{"edns", map[string]string{"GODEBUG": "netedns0=0"}, []string{"GODEBUG/netedns0"}},
		{"default-edns", map[string]string{"GODEBUG": "netedns0=1"}, nil},
		{"mptcp", map[string]string{"GODEBUG": "multipathtcp=3"}, []string{"GODEBUG/multipathtcp"}},
		{"cleared", map[string]string{"GODEBUG": "netdns=cgo,netdns="}, nil},
		{"unrelated", map[string]string{"GODEBUG": "panicnil=1"}, nil},
		{"combined", map[string]string{"LOCALDOMAIN": "", "HOSTALIASES": "/private/aliases", "GODEBUG": "netdns=go,netedns0=0,multipathtcp=1"}, []string{"LOCALDOMAIN", "HOSTALIASES", "GODEBUG/netdns", "GODEBUG/netedns0", "GODEBUG/multipathtcp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range []string{"LOCALDOMAIN", "RES_OPTIONS", "HOSTALIASES", "RESOLV_HOST_CONF", "RESOLV_MULTI", "RESOLV_REORDER", "RESOLV_ADD_TRIM_DOMAINS", "RESOLV_OVERRIDE_TRIM_DOMAINS", "GODEBUG"} {
				t.Setenv(key, "")
				if err := os.Unsetenv(key); err != nil {
					t.Fatal(err)
				}
			}
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			data, err := json.Marshal(CaptureCaller())
			if err != nil {
				t.Fatal(err)
			}
			var got struct{ ResolverSettings []string }
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.ResolverSettings, tc.want) {
				t.Fatalf("captured selectors %q, want %q", got.ResolverSettings, tc.want)
			}
		})
	}
}
