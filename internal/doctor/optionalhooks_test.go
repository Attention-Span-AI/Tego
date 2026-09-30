// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// withUnixSupport drives the backend's BPF_CGROUP_UNIX_CONNECT probe, which D7 shares with it.
func withUnixSupport(t *testing.T, ok bool) {
	t.Helper()
	was := unixSupported
	unixSupported = func() (bool, error) { return ok, nil }
	t.Cleanup(func() { unixSupported = was })
}

// kernelSpecWith is a kernel BTF that declares the named functions.
func kernelSpecWith(t *testing.T, names ...string) *btf.Spec {
	t.Helper()
	var types []btf.Type
	for _, n := range names {
		types = append(types, &btf.Func{Name: n, Type: &btf.FuncProto{Return: (*btf.Void)(nil)}, Linkage: btf.StaticFunc})
	}
	spec, err := btf.LoadSpec(writeFakeBTF(t, types...))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// TestOptionalFexitIsAbsentByBTFNotVersion is the backend's rule (cgroup dropTraceWhereAbsent: the function is in
// the kernel's BTF). A 5.14 kernel that backports security_file_truncate is not Absent, so its program is
// tested as the backend loads it; a 6.17 kernel without the function is.
func TestOptionalFexitIsAbsentByBTFNotVersion(t *testing.T) {
	h := hookNamed(t, "fexit/security_file_truncate")
	backported := testHook(h, kernelSpecWith(t, "security_file_truncate"), nil, nil, Version{5, 14, 0})
	if backported.Absent || !backported.BTF {
		t.Errorf("a backporting 5.14 kernel = %+v, want the hook present and tested", backported)
	}
	missing := testHook(h, kernelSpecWith(t, "security_path_truncate"), nil, nil, Version{6, 17, 0})
	if !missing.Absent || missing.Loaded || !strings.Contains(missing.Detail, "runs without it") {
		t.Errorf("a 6.17 kernel without the function = %+v, want an absent row", missing)
	}
}

// TestUnixHooksAreAbsentByTheBackendsProbeNotVersion: a kernel below 6.7 that accepts the attach type is
// tested (its program is loaded there, where the backend loads it), and a 6.7+ kernel that refuses it is Absent
// (the backend drops the two programs and runs).
func TestUnixHooksAreAbsentByTheBackendsProbeNotVersion(t *testing.T) {
	h := hookNamed(t, "cgroup/connect_unix")
	withUnixSupport(t, true)
	if got := testHook(h, nil, nil, nil, Version{5, 14, 0}); got.Absent {
		t.Errorf("a backporting 5.14 kernel = %+v, want the hook tested", got)
	}
	withUnixSupport(t, false)
	if got := testHook(h, nil, nil, nil, Version{6, 17, 0}); !got.Absent || got.Loaded {
		t.Errorf("a 6.17 kernel refusing the attach type = %+v, want an absent row", got)
	}

	boom := errors.New("bpf: EPERM")
	was := unixSupported
	unixSupported = func() (bool, error) { return false, boom }
	t.Cleanup(func() { unixSupported = was })
	got := testHook(h, nil, nil, nil, Version{6, 17, 0})
	if got.Absent || !strings.Contains(got.Detail, "EPERM") {
		t.Errorf("a probe that could not run = %+v, want a failed row, not an absent one", got)
	}
}
