// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// pairsScript is the VM harness whose contracts TestPairsContractsCompile compiles.
const pairsScript = "../../test/vm/tier2-pairs.sh"

// pairsContractWriters is each contract's heredoc in pairsScript, and the line naming the file the self-deny run reads.
var pairsContractWriters = regexp.MustCompile(`(?ms)^cat >"\$w"/(?:agent|self)\.yaml <<EOF\n.*?^EOF$|^SELF_LINK=[^\n]*$`)

// TestPairsContractsCompile compiles the contracts test/vm/tier2-pairs.sh writes, as `tego run` compiles them with the
// launcher at TEGO, which `make vm-pairs` runs from /usr/local/bin. Nothing but a guest runs that script, so a compile
// rule that refuses one of its contracts (R10 over the launcher's directory did) would otherwise stop the variant with
// no gate seeing it. The self-deny contract's deny_read must stay nested in a write entry, which ADR 0021's proof
// needs: that half is asserted here, the plane's refusal in the guest.
func TestPairsContractsCompile(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("the contracts are bash heredocs: %v", err)
	}
	src, err := os.ReadFile(pairsScript)
	if err != nil {
		t.Fatal(err)
	}
	writers := pairsContractWriters.FindAllString(string(src), -1)
	if len(writers) != 3 {
		t.Fatalf("%s: found %d of the two contracts and the SELF_LINK line:\n%s", pairsScript, len(writers), strings.Join(writers, "\n"))
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	w := filepath.Join(dir, "w")
	install := filepath.Join(dir, "usr", "local", "bin")
	secretDir := filepath.Join(dir, "var", "lib", "tego-pairs")
	for _, d := range []string{w, install, secretDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tego, secret := filepath.Join(install, "tego-pie"), filepath.Join(secretDir, "secret")
	for _, f := range []string{tego, secret} {
		if err := os.WriteFile(f, []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := executable
	t.Cleanup(func() { executable = old })
	executable = func() (string, error) { return tego, nil }

	cmd := exec.Command(bash, "-c", strings.Join(writers, "\n")+"\nprintf %s \"$SELF_LINK\"\n")
	cmd.Env = append(os.Environ(), "w="+w, "TEGO="+tego, "SECRET="+secret)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("writing the contracts: %v: %s", err, stderr.String())
	}
	link := stdout.String()
	if err := os.Link(tego, link); err != nil {
		t.Fatalf("the self-deny run's link: %v", err)
	}

	// The link gives the launcher's file a second name, which compile cannot list, so a write entry on its filesystem
	// is refused unless only root may write the file and the agent is not root (ADR 0059, amendment 2026-11-11 (3)).
	// That is the guest's case: `make vm-pairs` runs a root-owned /usr/local/bin/tego under sudo, and the agent is the
	// sudo user. A test that is not root has a stand-in it owns, which its agent could rewrite through the link: there
	// both contracts are refused, and the guest's own run shows they compile.
	uid, _ := config.InvokingUID()
	exempt := os.Geteuid() == 0 && uid != 0
	for _, name := range []string{"agent.yaml", "self.yaml"} {
		code, _, errs := run(t, "compile", filepath.Join(w, name), "--offline")
		switch {
		case exempt && code != identity.ExitOK:
			t.Errorf("tego compile %s: exit %d:\n%s", name, code, errs)
		case !exempt && (code == identity.ExitOK || !strings.Contains(errs, "has 2 hard links, whose other names compile cannot list")):
			t.Errorf("tego compile %s with a launcher its agent could rewrite through a second link: exit %d:\n%s", name, code, errs)
		}
	}
	text, err := os.ReadFile(filepath.Join(w, "self.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(text, []byte(`write: ["`+filepath.Dir(link)+`/"]`)) || !bytes.Contains(text, []byte(`deny_read: ["`+link+`"]`)) {
		t.Errorf("self.yaml does not deny %s nested in a write entry, so Landlock would refuse it before the plane:\n%s", link, text)
	}
}
