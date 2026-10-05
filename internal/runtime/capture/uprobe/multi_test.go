// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/cilium/ebpf"
)

func TestMultiPlanRetainsExactTLSOperationsAndReadPairs(t *testing.T) {
	bin := &binary{Offsets: map[string]uint64{SymWrite: 90, SymWriteEx: 80, SymWriteEx2: 70, SymRead: 50, SymReadEx: 30, SymFree: 10}}
	plan, err := planMulti(probesFor(bin))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.entry.Addresses, []uint64{10, 30, 50, 70, 90}) ||
		!slices.Equal(plan.entry.Cookies, []uint64{bpf.SSLCookieFree, bpf.SSLCookieReadEx, bpf.SSLCookieRead, bpf.SSLCookieWriteEx, bpf.SSLCookieWrite}) ||
		!slices.Equal(plan.returns.Addresses, []uint64{30, 50}) ||
		!slices.Equal(plan.returns.Cookies, []uint64{bpf.SSLCookieReadEx, bpf.SSLCookieRead}) || plan.entry.PID != 0 || plan.returns.PID != 0 {
		t.Fatalf("wrong multi dispatch: %+v", plan)
	}
	// The preferred _ex2 consumes the one write-ex cookie; _ex must not also
	// appear, even though the library exports both names.
	for _, offset := range plan.entry.Addresses {
		if offset == 80 {
			t.Fatal("both write-ex variants were selected")
		}
	}
}

func TestMultiPlanRejectsUnboundedUnknownOrUnpairedOperations(t *testing.T) {
	read := Probe{Program: bpf.ProgSSLRead, Symbol: SymRead, Offset: 10}
	ret := Probe{Program: bpf.ProgSSLReadReturn, Symbol: SymRead, Offset: 10, Return: true}
	for name, probes := range map[string][]Probe{
		"empty": nil, "oversize": make([]Probe, 8), "unpaired-entry": {read}, "unpaired-return": {ret},
		"duplicate":       {read, ret, read},
		"unknown-program": {{Program: "foreign", Symbol: SymRead, Offset: 10}, ret},
		"wrong-symbol":    {{Program: bpf.ProgSSLRead, Symbol: SymWrite, Offset: 10}, ret},
		"zero-offset":     {{Program: bpf.ProgSSLRead, Symbol: SymRead}, ret},
		"two-write-ex":    {read, ret, {Program: bpf.ProgSSLWriteEx, Symbol: SymWriteEx, Offset: 20}, {Program: bpf.ProgSSLWriteEx, Symbol: SymWriteEx2, Offset: 30}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := planMulti(probes); !errors.Is(err, ErrAttachFailed) {
				t.Fatalf("unsafe plan accepted: %+v err=%v", probes, err)
			}
		})
	}
	if _, err := planMulti([]Probe{{Program: bpf.ProgSSLWrite, Symbol: SymWrite, Offset: 1}}); !errors.Is(err, errNoMulti) {
		t.Fatalf("write-only library should retain single probes: %v", err)
	}
}

type pairCloser struct{ closed bool }

func (p *pairCloser) Close() error { p.closed = true; return nil }

func TestMultiPartialPairIsClosedBeforeFallback(t *testing.T) {
	for _, fail := range []string{"return", "entry", "none"} {
		t.Run(fail, func(t *testing.T) {
			ret, entry := &pairCloser{}, &pairCloser{}
			var order []string
			failure := errors.New("actual optional attachment refused")
			links, err := attachPair(func() (io.Closer, error) {
				order = append(order, "entry")
				if fail == "entry" {
					return nil, failure
				}
				return entry, nil
			}, func() (io.Closer, error) {
				order = append(order, "return")
				if fail == "return" {
					return nil, failure
				}
				return ret, nil
			})
			if fail == "return" && (!errors.Is(err, failure) || len(links) != 0 || !slices.Equal(order, []string{"return"})) ||
				fail == "entry" && (!errors.Is(err, failure) || len(links) != 0 || !ret.closed) ||
				fail == "none" && (err != nil || len(links) != 2 || links[0] != entry || links[1] != ret || ret.closed || entry.closed) {
				t.Fatalf("links=%v err=%v order=%v returnClosed=%v entryClosed=%v", links, err, order, ret.closed, entry.closed)
			}
		})
	}
}

func TestOptionalMultiProgramsDoNotEnterUnsupportedKernelSpec(t *testing.T) {
	programs := map[string]*ebpf.ProgramSpec{}
	for _, name := range bpf.SSLPrograms {
		programs[name] = &ebpf.ProgramSpec{Name: name}
	}
	spec := &ebpf.CollectionSpec{Programs: programs}
	selectSSLPrograms(spec, false)
	if len(spec.Programs) != len(bpf.SSLSinglePrograms) {
		t.Fatalf("required fallback changed: %+v", spec.Programs)
	}
	for _, name := range bpf.SSLSinglePrograms {
		if spec.Programs[name] == nil {
			t.Fatalf("required %s lost", name)
		}
	}
}

// A map a concurrent first run of the build pinned between this load's open and its pin fails the load with
// EEXIST. That is LoadCollection's retry to make, with the whole spec: dropping the dispatchers for it left the
// run without them for its life, and it then refused the multi pair the other run placed (capture-1).
func TestMultiProgramsSurviveAMapPinRace(t *testing.T) {
	programs := map[string]*ebpf.ProgramSpec{}
	for _, name := range bpf.SSLPrograms {
		programs[name] = &ebpf.ProgramSpec{Name: name}
	}
	spec := &ebpf.CollectionSpec{Programs: programs}
	var loads []int
	load := func(fail error) func(*ebpf.CollectionSpec) (*ebpf.Collection, error) {
		loads = nil
		return func(s *ebpf.CollectionSpec) (*ebpf.Collection, error) {
			loads = append(loads, len(s.Programs))
			if len(loads) == 1 {
				return nil, fail
			}
			return &ebpf.Collection{}, nil
		}
	}
	_, err := loadSSLCollection(spec, load(fmt.Errorf("pin map tego_ssl_reads: %w", os.ErrExist)))
	if !errors.Is(err, os.ErrExist) || !slices.Equal(loads, []int{len(bpf.SSLPrograms)}) {
		t.Fatalf("a pin race was not handed back for a retry of the whole spec: err %v, loads of %v programs", err, loads)
	}
	// Any other failure is the verifier's or the kernel's with the dispatchers, which the required programs
	// alone may still pass.
	_, err = loadSSLCollection(spec, load(errors.New("verifier: program too large")))
	if err != nil || !slices.Equal(loads, []int{len(bpf.SSLPrograms), len(bpf.SSLSinglePrograms)}) {
		t.Fatalf("a dispatcher load failure did not fall back to the required programs: err %v, loads of %v", err, loads)
	}
}
