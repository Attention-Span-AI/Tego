// SPDX-License-Identifier: Apache-2.0

package container

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestContainerGuideQuotesTheRefusalTheProductPrints: on Docker's defaults the cgroup mount is read-only and
// `tego run` refuses before it starts the agent. A guest run printed
// "no enforcement tier available on this machine [tier-unavailable] missing for landlock: cgroupv2: cgroup: no
// delegated cgroup v2 subtree for uid ...", not "runtime: cgroup: ...", which the guide had quoted. The guide
// (docs/site/containers.md) quotes the refusal's code; each fragment of the refusal it quotes must be one the code
// still holds, and the old quote must stay out.
func TestContainerGuideQuotesTheRefusalTheProductPrints(t *testing.T) {
	const page = "docs/site/containers.md"
	guide := readText(t, "../../"+page)
	if !strings.Contains(guide, "[tier-unavailable]") {
		t.Errorf("%s does not quote the refusal's code [tier-unavailable]", page)
	}
	for _, q := range []struct{ quote, file, holds string }{
		{"no enforcement tier available on this machine", "../../pkg/spec/backend/select.go", "no enforcement tier available on this machine"},
		{"[tier-unavailable]", "../../pkg/spec/backend/select.go", `"tier-unavailable"`},
		{"missing for landlock: cgroupv2:", "../../internal/doctor/report.go", "missing for %s: %s"},
		{"no delegated cgroup v2 subtree", "../../internal/runtime/cgroup/errors.go", "no delegated cgroup v2 subtree"},
		{"in a container there is no systemd to delegate a cgroup subtree: Tego needs what the example image's entrypoint and examples/container/compose.yaml give it",
			"../../internal/platform/whereami/whereami.go", "in a container there is no systemd to delegate a cgroup subtree: Tego needs "},
		{"/.dockerenv", "../../internal/platform/whereami/whereami.go", `"/.dockerenv"`},
		{"/run/.containerenv", "../../internal/platform/whereami/whereami.go", `"/run/.containerenv"`},
		{"tego-entrypoint: no delegated cgroup subtree:", "tego-entrypoint.sh", `say "no delegated cgroup subtree: $why"`},
		{"/sys/fs/cgroup is read-only and could not be remounted read-write", "tego-entrypoint.sh", "is read-only and could not be remounted read-write"},
	} {
		if src := readText(t, q.file); !strings.Contains(src, q.holds) {
			t.Errorf("the refusal prints %q but %s no longer holds %q", q.quote, q.file, q.holds)
		}
	}
	if strings.Contains(guide, "`tego run` refuses with `runtime: cgroup") {
		t.Error(page + " says `tego run` refuses with `runtime: cgroup: ...`, which Docker's defaults do not print")
	}
}

// TestContainerGuideOrderMatchesCompose: the quick start builds before it starts the dashboard (the dashboard service
// never pulls the local name), names the packages that give `docker compose`, and its two `events --verify` lines run
// as the image's own user: the published image's 10001, and the uid and gid a local build was given. The volumes the
// local line names are the ones compose.yaml makes under its project name.
func TestContainerGuideOrderMatchesCompose(t *testing.T) {
	guide := readText(t, "../../docs/site/containers.md")
	build, dash := strings.Index(guide, "docker compose build"), strings.Index(guide, "docker compose up -d control")
	if build < 0 || dash < 0 || build > dash {
		t.Errorf("the quick start must build (%d) before it starts the dashboard (%d)", build, dash)
	}
	for _, pkg := range []string{"docker-compose", "docker-compose-v2", "docker-buildx", "docker-compose-plugin", "docker.io"} {
		if !strings.Contains(guide, pkg) {
			t.Errorf("the guide does not name the package %s", pkg)
		}
	}
	flat := strings.Join(strings.Fields(guide), " ") // line breaks of the guide do not matter
	for _, want := range []string{`--user 10001:10001`, `--user "$TEGO_UID:$TEGO_GID"`, "tego:local tego events <run> --verify",
		"`tego version` inside it prints `tego=dev commit=none`"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the guide lacks %q", want)
		}
	}
	compose := readText(t, "compose.yaml")
	project := regexp.MustCompile(`(?m)^name: (\S+)$`).FindStringSubmatch(compose)
	if project == nil {
		t.Fatal("compose.yaml names no project")
	}
	for _, vol := range []string{"tego-state", "tego-ledger"} {
		if !regexp.MustCompile(`(?m)^  ` + vol + `:$`).MatchString(compose) {
			t.Errorf("compose.yaml has no volume %s", vol)
		}
		if name := project[1] + "_" + vol; !strings.Contains(guide, "-v "+name+":") {
			t.Errorf("the guide's local verify line does not mount %s", name)
		}
	}
}

// TestContainerGuideQuotesTheListHandIn: the guide's account of the handed-in security-module list quotes words
// the entrypoint and Tego print, names the setting and the file the image's config names, and each check it lists is one
// the reader still makes. Line breaks in the guide do not matter.
func TestContainerGuideQuotesTheListHandIn(t *testing.T) {
	guide := strings.Join(strings.Fields(readText(t, "../../docs/site/containers.md")), " ")
	for _, q := range []struct{ quote, file, holds string }{
		{"tego-entrypoint: no security-module list handed in:", "tego-entrypoint.sh", `say "no security-module list handed in: $LSM_LIST_WHY"`},
		{"held file opens read this list", "../../internal/doctor/lsm.go", "held file opens read this list"},
		{"whether `bpf` is active is unknown", "../../internal/doctor/lsm.go", "whether bpf is an active LSM is unknown"},
		{"`TEGO_LSM_LIST`", "tego-entrypoint.sh", "TEGO_LSM_LIST"},
		{"/run/tego-lsm/lsm-list", "config.yaml", "list_file: /run/tego-lsm/lsm-list"},
		{"/run/tego-lsm/lsm-list", "tego-entrypoint.sh", "/run/tego-lsm/lsm-list"},
		{"`CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER` or `CAP_SYS_ADMIN`", "../../internal/platform/lsmlist/lsmlist.go", `{0, "CAP_CHOWN"}, {1, "CAP_DAC_OVERRIDE"}, {3, "CAP_FOWNER"}, {21, "CAP_SYS_ADMIN"}`},
		{"the **boot id** of the running kernel", "../../internal/platform/lsmlist/lsmlist.go", "/proc/sys/kernel/random/boot_id"},
		{"bind the host's list into the container read-only", "../../internal/platform/lsmlist/lsmlist.go", `checkBind(p, f, "/lsm")`},
	} {
		if !strings.Contains(guide, q.quote) {
			t.Errorf("docs/site/containers.md no longer says %q", q.quote)
		}
		if src := readText(t, q.file); !strings.Contains(src, q.holds) {
			t.Errorf("the guide says %q but %s no longer holds %q", q.quote, q.file, q.holds)
		}
	}
}

// TestInstallContainerSectionVerifiesTheRecord: the container guide (docs/site/containers.md) has a step that
// reads and checks the run's record from a fresh container, with the user and the two volumes it needs.
func TestInstallContainerSectionVerifiesTheRecord(t *testing.T) {
	sec := readText(t, "../../docs/site/containers.md")
	for _, want := range []string{
		"--user 10001:10001", "-v tego-state:/home/tego/.tego", "-v tego-ledger:/var/lib/tego/runs", `tego events "$run" --verify`,
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("docs/site/containers.md lacks %q", want)
		}
	}
}

func readText(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
