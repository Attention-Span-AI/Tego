// SPDX-License-Identifier: Apache-2.0

package identity

import "testing"

func TestPaths(t *testing.T) {
	run := RunID("r-0123abcd-0000000000000-abcdef")
	agent := AgentID("retriever")
	cases := []struct {
		name, got, want string
	}{
		{"RunDir", RunDir("/home/u/.tego/runs", run), "/home/u/.tego/runs/r-0123abcd-0000000000000-abcdef"},
		{"UserCgroupPath", UserCgroupPath("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service", agent, run),
			"/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/tego.slice/tego-retriever.slice/run-r-0123abcd-0000000000000-abcdef.scope"},
		{"SystemCgroupPath", SystemCgroupPath(agent, run),
			"/sys/fs/cgroup/tego.slice/tego-retriever.slice/run-r-0123abcd-0000000000000-abcdef.scope"},
		{"DockerParentSlice", DockerParentSlice(agent, run.Slug()), "tego-retriever-r0123abcd0000000000000abcdef.slice"},
		{"DockerParentCgroupfs", DockerParentCgroupfs(agent, run), "/sys/fs/cgroup/tego/retriever/r-0123abcd-0000000000000-abcdef"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}
