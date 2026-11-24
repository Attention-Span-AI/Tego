// SPDX-License-Identifier: Apache-2.0

package scan

import "strings"

// parseContainer selects only fixed cgroup components and full runtime ids.
// The cgroup is already validated by parseCgroup. A hint is never a daemon claim.
func parseContainer(b []byte) (string, string) {
	if len(b) > maxProcText {
		return "", ""
	}
	runtime, id := "", ""
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		components := strings.Split(strings.TrimPrefix(line, "0::"), "/")
		for i, c := range components {
			r, v := "", ""
			for _, p := range []struct{ prefix, runtime string }{{"docker-", "docker"}, {"libpod-", "podman"}, {"cri-containerd-", "containerd"}} {
				if strings.HasPrefix(c, p.prefix) && strings.HasSuffix(c, ".scope") {
					r, v = p.runtime, strings.TrimSuffix(strings.TrimPrefix(c, p.prefix), ".scope")
				}
			}
			if i > 0 && components[i-1] == "docker" {
				r, v = "docker", c
			}
			if len(v) != 64 || strings.Trim(v, "0123456789abcdef") != "" {
				continue
			}
			if id != "" && (id != v || runtime != r) {
				return "", ""
			}
			runtime, id = r, v
		}
	}
	return runtime, id
}
