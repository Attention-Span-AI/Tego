// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestExtraHostsRetryInField(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "python3")
	t.Chdir(f.Home)
	code, out, errs := runGuide(t, "4\npython3\n1\n3\n0\nhttps://bad.example\napi.github.com, pypi.org\n")
	if code != identity.ExitOK {
		t.Fatalf("invalid host aborted guide instead of retrying: %d %s %s", code, out, errs)
	}
	wantAll(t, "host retry", out, "write a host or host:port, not a URL", "Created agent tego-sample")
	wantAll(t, "saved hosts", savedRules(t, guideSample), "api.github.com:443", "pypi.org:443")
}
