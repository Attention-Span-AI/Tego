// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestProfileFor asserts docs/p0/enforce-landlock.md R2, E3, E25.
func TestProfileFor(t *testing.T) {
	base := accessFSv1
	cases := []struct {
		abi   int
		fs    accessFS
		net   netAccess
		scope scope
	}{
		{0, 0, 0, 0},
		{1, base, 0, 0},
		{2, base | accessRefer, 0, 0},
		{3, base | accessRefer | accessTruncate, 0, 0},
		{4, base | accessRefer | accessTruncate, accessNetBindTCP | accessNetConnectTCP, 0},
		{5, base | accessRefer | accessTruncate | accessIoctlDev, accessNetBindTCP | accessNetConnectTCP, 0},
		{6, base | accessRefer | accessTruncate | accessIoctlDev, accessNetBindTCP | accessNetConnectTCP, scopeSignal | scopeAbstractUnixSocket},
		{7, base | accessRefer | accessTruncate | accessIoctlDev, accessNetBindTCP | accessNetConnectTCP, scopeSignal | scopeAbstractUnixSocket},
		{8, base | accessRefer | accessTruncate | accessIoctlDev, accessNetBindTCP | accessNetConnectTCP, scopeSignal | scopeAbstractUnixSocket},
		{9, base | accessRefer | accessTruncate | accessIoctlDev | accessResolveUnix, accessNetBindTCP | accessNetConnectTCP, scopeSignal | scopeAbstractUnixSocket},
		{10, base | accessRefer | accessTruncate | accessIoctlDev | accessResolveUnix, accessNetBindTCP | accessNetConnectTCP | accessNetBindUDP | accessNetConnectSendUDP, scopeSignal | scopeAbstractUnixSocket},
		{11, base | accessRefer | accessTruncate | accessIoctlDev | accessResolveUnix, accessNetBindTCP | accessNetConnectTCP | accessNetBindUDP | accessNetConnectSendUDP, scopeSignal | scopeAbstractUnixSocket},
	}
	for _, tc := range cases {
		p := profileFor(tc.abi)
		if p.Version != tc.abi || p.FS != tc.fs || p.Net != tc.net || p.Scope != tc.scope {
			t.Errorf("profileFor(%d) = %+v, want fs=%#x net=%#x scope=%#x", tc.abi, p, tc.fs, tc.net, tc.scope)
		}
	}
	// E25: anything beyond the highest known row clamps to it.
	if got, want := profileFor(99), profileFor(maxKnownABI); got.FS != want.FS || got.Net != want.Net || got.Scope != want.Scope || got.Version != maxKnownABI {
		t.Errorf("profileFor(99) = %+v, want the ABI-%d row", got, maxKnownABI)
	}
}

func TestAccessBitsMatchTheCompiler(t *testing.T) {
	// The compiler's AccessSet and this package's accessFS mirror the same header bit for bit, so
	// the cast in writeMask is exact.
	pairs := []struct {
		a agent.AccessSet
		b accessFS
	}{
		{agent.AccessExecute, accessExecute}, {agent.AccessWriteFile, accessWriteFile}, {agent.AccessReadFile, accessReadFile},
		{agent.AccessReadDir, accessReadDir}, {agent.AccessRemoveDir, accessRemoveDir}, {agent.AccessRemoveFile, accessRemoveFile},
		{agent.AccessMakeChar, accessMakeChar}, {agent.AccessMakeDir, accessMakeDir}, {agent.AccessMakeReg, accessMakeReg},
		{agent.AccessMakeSock, accessMakeSock}, {agent.AccessMakeFifo, accessMakeFifo}, {agent.AccessMakeBlock, accessMakeBlock},
		{agent.AccessMakeSym, accessMakeSym}, {agent.AccessRefer, accessRefer}, {agent.AccessTruncate, accessTruncate},
		{agent.AccessIoctlDev, accessIoctlDev}, {agent.AccessResolveUnix, accessResolveUnix},
	}
	for _, p := range pairs {
		if accessFS(p.a) != p.b {
			t.Errorf("agent bit %#x != landlock bit %#x", p.a, p.b)
		}
	}
	if accessFS(agent.AccessWriteSet)&^profileFor(9).FS != 0 {
		t.Errorf("compiler write set %#x has bits ABI 9 does not handle", agent.AccessWriteSet)
	}
}

// TestMaskByABI asserts docs/p0/enforce-landlock.md R2, E3.
func TestMaskByABI(t *testing.T) {
	all := accessFS(agent.AccessAll)
	for abi := 1; abi <= maxKnownABI; abi++ {
		got := profileFor(abi).mask(all)
		want := accessFS(agent.AccessAll.ForABI(abi))
		if got != want {
			t.Errorf("ABI %d: mask(all) = %#x, compiler ForABI = %#x", abi, got, want)
		}
	}
}
