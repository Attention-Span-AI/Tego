// SPDX-License-Identifier: Apache-2.0

package record

import "testing"

func TestListenerOutcomeFieldsRemainAdditiveInV1(t *testing.T) {
	e := action(KindNet, "")
	e.Source, e.Authority, e.Rule, e.Verdict, e.Reason = SourceKernel, AuthorityRule, "net.listen[unix:@svc]", VerdictRefused, ReasonNetNotAllowed
	p := NetPayload{Op: "bind", Proto: "unix", Dst: "unix:@svc\x00tail", Mechanism: MechanismPlane, DecisionPlane: DecisionPlaneLSM, SyscallRet: -13, SyscallErrno: 13, VerdictFrom: "plane"}
	if err := e.SetPayload(p); err != nil {
		t.Fatal(err)
	}
	line, err := e.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	var got NetPayload
	if err := d.DecodePayload(&got); err != nil {
		t.Fatal(err)
	}
	if got.Dst != p.Dst || got.SyscallRet != p.SyscallRet || got.SyscallErrno != p.SyscallErrno || got.Mechanism != p.Mechanism || got.VerdictFrom != p.VerdictFrom || d.V != Version {
		t.Fatalf("outcome lost during codec roundtrip %+v", got)
	}
	legacy := perKind(t)[KindNet]
	line, err = legacy.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	d, err = Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	got = NetPayload{}
	if err := d.DecodePayload(&got); err != nil {
		t.Fatal(err)
	}
	if got.Op != "" || got.Mechanism != "" || got.VerdictFrom != "" || got.SyscallErrno != 0 || got.SyscallRet != 0 {
		t.Fatal("legacy socket record invented listener outcomes")
	}
}
