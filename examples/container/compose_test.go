// SPDX-License-Identifier: Apache-2.0

package container

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The paths the image, the compose file, the machine config and the entrypoint must agree on.
const (
	stateDir  = "/home/tego/.tego"   // the run user's ~/.tego: the chain anchor, the own log
	ledgerDir = "/var/lib/tego/runs" // ledger_root
	workDir   = "/work"
)

// service is the part of a compose service these tests read.
type service struct {
	User            string   `yaml:"user"`
	Command         []string `yaml:"command"`
	Init            bool     `yaml:"init"`
	Cgroup          string   `yaml:"cgroup"`
	NetworkMode     string   `yaml:"network_mode"`
	Pid             string   `yaml:"pid"`
	CapDrop         []string `yaml:"cap_drop"`
	CapAdd          []string `yaml:"cap_add"`
	SecurityOpt     []string `yaml:"security_opt"`
	StopGracePeriod string   `yaml:"stop_grace_period"`
	Volumes         []string `yaml:"volumes"`
	Environment     map[string]string
}

func readCompose(t *testing.T) (services map[string]service, volumes map[string]any) {
	t.Helper()
	b, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]service `yaml:"services"`
		Volumes  map[string]any     `yaml:"volumes"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("compose.yaml: %v", err)
	}
	return doc.Services, doc.Volumes
}

// mounts maps each volume's target to its source and whether it is read-only.
func mounts(t *testing.T, s service) map[string]struct {
	src string
	ro  bool
} {
	t.Helper()
	m := map[string]struct {
		src string
		ro  bool
	}{}
	for _, v := range s.Volumes {
		parts := strings.Split(v, ":")
		if len(parts) < 2 || len(parts) > 3 {
			t.Fatalf("volume %q: want source:target[:ro]", v)
		}
		m[parts[1]] = struct {
			src string
			ro  bool
		}{parts[0], len(parts) == 3 && parts[2] == "ro"}
	}
	return m
}

// TestComposeAgentSettings holds the agent service to what the entrypoint and tego need in a container, and to
// nothing more: a private cgroup namespace (the entrypoint refuses the host's), exactly the capabilities the
// entrypoint uses or Docker's seccomp profile keys clone3 and pidfd_getfd on, no_new_privs, and the anchor and the
// ledger on two named volumes of their own.
func TestComposeAgentSettings(t *testing.T) {
	services, volumes := readCompose(t)
	a, ok := services["agent"]
	if !ok {
		t.Fatal("compose.yaml has no agent service")
	}
	if a.Cgroup != "private" {
		t.Errorf("agent cgroup: %q, want private", a.Cgroup)
	}
	if !a.Init {
		t.Error("agent init: false; docker-init should be PID 1, to reap and to pass SIGTERM on")
	}
	if !slices.Equal(a.CapDrop, []string{"ALL"}) {
		t.Errorf("agent cap_drop: %v, want [ALL]", a.CapDrop)
	}
	caps := slices.Sorted(slices.Values(a.CapAdd))
	if want := []string{"CHOWN", "SETGID", "SETPCAP", "SETUID", "SYS_ADMIN", "SYS_PTRACE"}; !slices.Equal(caps, want) {
		t.Errorf("agent cap_add: %v, want %v", caps, want)
	}
	if !slices.Contains(a.SecurityOpt, "no-new-privileges:true") {
		t.Errorf("agent security_opt %v lacks no-new-privileges:true", a.SecurityOpt)
	}
	if len(a.Command) < 2 || a.Command[0] != "tego" || a.Command[1] != "run" {
		t.Errorf("agent command %v, want tego run <contract>", a.Command)
	}
	// stop_grace (10 s by default) for the agent, then time for tego to write the run's end, as the systemd unit.
	if d, err := time.ParseDuration(a.StopGracePeriod); err != nil || d <= config.DefaultStopGrace {
		t.Errorf("agent stop_grace_period %q, want a duration above the default stop_grace %s", a.StopGracePeriod, config.DefaultStopGrace)
	}
	m := mounts(t, a)
	state, ledger, work := m[stateDir], m[ledgerDir], m[workDir]
	for target, v := range map[string]struct {
		src string
		ro  bool
	}{stateDir: state, ledgerDir: ledger, workDir: work} {
		if v.src == "" {
			t.Errorf("agent mounts nothing on %s", target)
			continue
		}
		if _, ok := volumes[v.src]; !ok {
			t.Errorf("agent's %s comes from %q, not a named volume of the file", target, v.src)
		}
		if v.ro {
			t.Errorf("agent mounts %s read-only; tego writes it", target)
		}
	}
	if state.src == ledger.src {
		t.Errorf("the anchor and the ledger share the volume %q; the anchor is what the ledger is checked against", state.src)
	}
	if work.src == state.src || work.src == ledger.src {
		t.Errorf("the agent's work volume %q holds tego's state too", work.src)
	}
}

// TestComposeControlSettings: the dashboard runs as the tego user (tego-control refuses root), on the host's
// loopback, in the host's cgroup namespace (it refuses changes it cannot place in the tree), with the anchor
// read-only and the agent's ledger volume.
func TestComposeControlSettings(t *testing.T) {
	services, _ := readCompose(t)
	c, ok := services["control"]
	if !ok {
		t.Fatal("compose.yaml has no control service")
	}
	if c.User == "" || strings.HasPrefix(c.User, "0:") || c.User == "0" || c.User == "root" {
		t.Errorf("control user %q: tego-control refuses root, and the entrypoint drops only for root", c.User)
	}
	if c.NetworkMode != "host" {
		t.Errorf("control network_mode %q, want host: the dashboard listens on loopback only", c.NetworkMode)
	}
	if c.Cgroup != "host" {
		t.Errorf("control cgroup %q, want host", c.Cgroup)
	}
	if !slices.Equal(c.CapDrop, []string{"ALL"}) || len(c.CapAdd) != 0 {
		t.Errorf("control caps: drop %v add %v, want drop [ALL] and none added", c.CapDrop, c.CapAdd)
	}
	if !slices.Equal(c.Command[:2], []string{"tego-control", "serve"}) {
		t.Fatalf("control command %v, want tego-control serve", c.Command)
	}
	addr := ""
	for i, a := range c.Command {
		if a == "--addr" && i+1 < len(c.Command) {
			addr = c.Command[i+1]
		}
	}
	if !regexp.MustCompile(`^\$\{TEGO_DASHBOARD_ADDR:-127\.0\.0\.1:[0-9]+\}$`).MatchString(addr) {
		t.Errorf("control --addr %q, want a loopback default", addr)
	}
	m := mounts(t, c)
	a := mounts(t, func() service { s, _ := readCompose(t); return s["agent"] }())
	if v := m[stateDir]; v.src != a[stateDir].src || !v.ro {
		t.Errorf("control's %s: %+v, want the agent's volume %q read-only", stateDir, v, a[stateDir].src)
	}
	if v := m[ledgerDir]; v.src != a[ledgerDir].src || v.ro {
		t.Errorf("control's %s: %+v, want the agent's volume %q read-write", ledgerDir, v, a[ledgerDir].src)
	}
}

// dockerfile reads the Dockerfile's instructions, continuation lines joined, comments dropped.
func dockerfile(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []string
	var cur strings.Builder
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || (line == "" && cur.Len() == 0) {
			continue
		}
		if s, ok := strings.CutSuffix(line, "\\"); ok {
			cur.WriteString(s + " ")
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestDockerfilePinsAndPaths: the base images are pinned by digest and the Go image is go.mod's toolchain (one Go
// everywhere, as precommit_test.sh holds the workflows to); the runtime's volumes are the compose file's targets; every
// file it copies from this directory exists; the entrypoint is the script these tests run.
func TestDockerfilePinsAndPaths(t *testing.T) {
	ins := dockerfile(t)
	gomod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	toolchain := regexp.MustCompile(`(?m)^toolchain go([0-9.]+)$`).FindSubmatch(gomod)
	if toolchain == nil {
		t.Fatal("go.mod has no toolchain line")
	}
	pinned := regexp.MustCompile(`^FROM ([a-z0-9./-]+):([A-Za-z0-9._-]+)@sha256:[0-9a-f]{64} AS ([a-z]+)$`)
	seen := map[string]string{} // stage -> image:tag
	var volume, entry string
	for _, in := range ins {
		if m := pinned.FindStringSubmatch(in); m != nil {
			seen[m[3]] = m[1] + ":" + m[2]
		} else if strings.HasPrefix(in, "FROM ") && in != "FROM scratch AS binaries" {
			t.Errorf("%s: want FROM <image>:<tag>@sha256:<digest> AS <stage>", in)
		}
		if v, ok := strings.CutPrefix(in, "VOLUME "); ok {
			volume = v
		}
		if v, ok := strings.CutPrefix(in, "ENTRYPOINT "); ok {
			entry = v
		}
		if v, ok := strings.CutPrefix(in, "COPY examples/container/"); ok {
			fields := strings.Fields("examples/container/" + v)
			for _, src := range fields[:len(fields)-1] {
				if _, err := os.Stat(strings.TrimPrefix(src, "examples/container/")); err != nil {
					t.Errorf("COPY %s: %v", src, err)
				}
			}
		}
	}
	if img := seen["build"]; !strings.HasPrefix(img, "golang:"+string(toolchain[1])+"-") {
		t.Errorf("build stage FROM %q, want golang at go.mod's toolchain %s", img, toolchain[1])
	}
	if seen["runtime"] == "" {
		t.Error("no pinned runtime stage")
	}
	if want := `["` + stateDir + `", "` + ledgerDir + `"]`; volume != want {
		t.Errorf("VOLUME %s, want %s", volume, want)
	}
	if entry != `["/usr/local/bin/tego-entrypoint"]` {
		t.Errorf("ENTRYPOINT %s", entry)
	}
}

// TestStatePathsAgree: the machine config's ledger_root is the ledger volume, and the entrypoint hands the state,
// ledger and work directories, and only those, to the tego user.
func TestStatePathsAgree(t *testing.T) {
	b, err := os.ReadFile("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["ledger_root"] != ledgerDir {
		t.Errorf("config.yaml ledger_root %v, want %s", cfg["ledger_root"], ledgerDir)
	}
	ep := readFile(t, entrypoint)
	got := regexp.MustCompile(`(?m)^\town_dir (\S+) "\$uid" "\$gid"$`).FindAllStringSubmatch(ep, -1)
	var dirs []string
	for _, m := range got {
		dirs = append(dirs, m[1])
	}
	if want := []string{`"$home/.tego"`, ledgerDir, workDir}; !slices.Equal(dirs, want) {
		t.Errorf("the entrypoint hands %v to the user, want %v", dirs, want)
	}
}
