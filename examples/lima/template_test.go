// SPDX-License-Identifier: Apache-2.0

package lima

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// template is the part of a Lima template this test reads.
type template struct {
	Images []struct {
		Location string `yaml:"location"`
		Arch     string `yaml:"arch"`
		Digest   string `yaml:"digest"`
	} `yaml:"images"`
	Provision []struct {
		Mode   string `yaml:"mode"`
		Script string `yaml:"script"`
	} `yaml:"provision"`
	PortForwards []struct {
		GuestPort int  `yaml:"guestPort"`
		Ignore    bool `yaml:"ignore"`
	} `yaml:"portForwards"`
}

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func load(t *testing.T) (string, template) {
	t.Helper()
	raw := read(t, "tego.yaml")
	var tpl template
	if err := yaml.Unmarshal([]byte(raw), &tpl); err != nil {
		t.Fatal(err)
	}
	return raw, tpl
}

// repo is the OWNER/NAME scripts/install.sh installs from, which the template's URLs must name.
func repo(t *testing.T) string {
	t.Helper()
	src := read(t, "../../scripts/install.sh")
	owner := regexp.MustCompile(`(?m)^repo_owner="([^"]+)"$`).FindStringSubmatch(src)
	name := regexp.MustCompile(`(?m)^repo_name="([^"]+)"$`).FindStringSubmatch(src)
	if owner == nil || name == nil {
		t.Fatal("scripts/install.sh has no repo_owner/repo_name line")
	}
	return owner[1] + "/" + name[1]
}

// TestImagesAreUbuntu2404ForBothMacArchitectures: Apple silicon boots the arm64 image, an Intel Mac the amd64 one,
// and each architecture has a pinned image first and the current release image after it.
func TestImagesAreUbuntu2404ForBothMacArchitectures(t *testing.T) {
	_, tpl := load(t)
	file := map[string]string{"aarch64": "ubuntu-24.04-server-cloudimg-arm64.img", "x86_64": "ubuntu-24.04-server-cloudimg-amd64.img"}
	digest := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	pinned, current := map[string]bool{}, map[string]bool{}
	for _, img := range tpl.Images {
		want, ok := file[img.Arch]
		if !ok {
			t.Errorf("image %s: arch %q, want aarch64 or x86_64", img.Location, img.Arch)
			continue
		}
		if !strings.HasPrefix(img.Location, "https://cloud-images.ubuntu.com/releases/noble/") || !strings.HasSuffix(img.Location, "/"+want) {
			t.Errorf("image %s for %s: want Ubuntu 24.04's %s", img.Location, img.Arch, want)
		}
		switch {
		case img.Digest != "":
			if !digest.MatchString(img.Digest) {
				t.Errorf("image %s: digest %q is not sha256:<64 hex>", img.Location, img.Digest)
			}
			if current[img.Arch] {
				t.Errorf("image %s: a pinned image after the current one is never used", img.Location)
			}
			pinned[img.Arch] = true
		case strings.Contains(img.Location, "/noble/release/"):
			current[img.Arch] = true
		default:
			t.Errorf("image %s: a dated image needs its digest", img.Location)
		}
	}
	for arch := range file {
		if !pinned[arch] || !current[arch] {
			t.Errorf("%s: pinned %v, current %v; want both", arch, pinned[arch], current[arch])
		}
	}
}

// TestProvisionRunsTheOneLineInstall: the VM installs tego as its default user with the Linux one-liner, from the
// latest release of the repository install.sh names, and every URL in the file is an asset of that release.
func TestProvisionRunsTheOneLineInstall(t *testing.T) {
	raw, tpl := load(t)
	oneLiner := fmt.Sprintf("curl -fsSL https://github.com/%s/releases/latest/download/install.sh | sh", repo(t))
	n := 0
	for _, p := range tpl.Provision {
		if strings.Contains(p.Script, "install.sh") {
			n++
			if p.Mode != "user" {
				t.Errorf("the install runs in mode %q; want user, so tego lands in the default user's ~/.local/bin", p.Mode)
			}
			if !strings.Contains(p.Script, "\n"+oneLiner+"\n") {
				t.Errorf("the install script does not run %q:\n%s", oneLiner, p.Script)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d provision steps run install.sh; want 1", n)
	}
	// Every download is a release asset of install.sh's repository, never a branch's file.
	if strings.Contains(raw, "raw.githubusercontent.com") {
		t.Error("the template fetches a file from a branch; take it from the release")
	}
	for _, url := range regexp.MustCompile(`https://github\.com/[^/\s]+/[^/\s]+/[^\s]*`).FindAllString(raw, -1) {
		if !strings.HasPrefix(url, "https://github.com/"+repo(t)+"/releases/latest/download/") {
			t.Errorf("%s is not an asset of %s's latest release", url, repo(t))
		}
	}
	start := fmt.Sprintf("limactl start --name=tego https://github.com/%s/releases/latest/download/tego.yaml", repo(t))
	if !strings.Contains(raw, start) {
		t.Errorf("the header does not give %q", start)
	}
}

// TestTheDashboardPortIsNotForwardedByTheGuestAgent: the dashboard serves only its own user's connections, and
// Lima's default forwarder connects as root in the VM, so its port is left to the SSH forward the message gives.
func TestTheDashboardPortIsNotForwardedByTheGuestAgent(t *testing.T) {
	raw, tpl := load(t)
	serve := read(t, "../../internal/control/cli/serve.go")
	if !strings.Contains(serve, `fs.String("addr", "127.0.0.1:8484",`) {
		t.Fatal("tego serve's default address is no longer 127.0.0.1:8484: change the template's port and this test")
	}
	ignored := false
	for _, pf := range tpl.PortForwards {
		ignored = ignored || (pf.GuestPort == 8484 && pf.Ignore)
	}
	if !ignored {
		t.Error("portForwards does not ignore guest port 8484")
	}
	if !strings.Contains(raw, "-L 8484:127.0.0.1:8484 lima-{{.Name}}") {
		t.Error("the message does not give the SSH forward of port 8484")
	}
}
