// SPDX-License-Identifier: Apache-2.0

package grouptrust

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

var privateAccountData = [3]string{
	"person:x:1000:1000::/:/bin/sh\nbob:x:1001:2000::/:/bin/sh\n",
	"person:x:1000:person\nbob:x:2000:\n#    \n",
	"passwd: files\ngroup: files\n",
}

type accountInfo struct{ stat syscall.Stat_t }

func (f accountInfo) Name() string       { return "account" }
func (f accountInfo) Size() int64        { return f.stat.Size }
func (f accountInfo) Mode() os.FileMode  { return 0600 }
func (f accountInfo) ModTime() time.Time { return time.Unix(f.stat.Mtim.Sec, f.stat.Mtim.Nsec) }
func (f accountInfo) IsDir() bool        { return false }
func (f accountInfo) Sys() any           { s := f.stat; return &s }

func observation() (o accountObservation) {
	for i, s := range privateAccountData {
		o.data[i] = []byte(s)
		info := accountInfo{syscall.Stat_t{Dev: 1, Ino: uint64(i + 1), Size: int64(len(s)), Mtim: syscall.Timespec{Sec: 1}, Ctim: syscall.Timespec{Sec: 1}}}
		o.before[i], o.descriptor[i], o.path[i] = info, info, info
	}
	return o
}

func requireCollectionRefusal(t *testing.T, p Policy) {
	t.Helper()
	var mode *ModeError
	if err := p.Check(0664, 1000, 1000); !errors.As(err, &mode) || mode.Evidence != "accounts-unreadable" {
		t.Fatalf("changed account evidence must refuse accounts-unreadable: %v", err)
	}
}

func TestAccountCollectionObservations(t *testing.T) {
	cases := []struct {
		name   string
		change func(*[2]accountObservation)
		refuse bool
	}{
		{"unchanged", func(*[2]accountObservation) {}, false},
		{"mixed-membership-colliding-timestamps", func(o *[2]accountObservation) {
			// Before the group read, Bob's primary gid changes and the group
			// loses explicit bob in an equal-length edit (comment padding).
			// Bob continuously belongs to 1000, but pass 0 combines old passwd
			// with new group. All stat facts collide; pass 1 exposes new passwd.
			oldGroup := strings.Replace(privateAccountData[1], "person\nbob:x:2000:\n#    ", "person,bob\nbob:x:2000:\n#", 1)
			if len(oldGroup) != len(privateAccountData[1]) {
				t.Fatal("fixture edit changed length")
			}
			o[1].data[0] = []byte(strings.Replace(privateAccountData[0], "1001:2000", "1001:1000", 1))
		}, true},
		{"reviewer-literal-space-edit-colliding-timestamps", func(o *[2]accountObservation) {
			// The review's literal person,bob -> person,   edit is also
			// refused by byte comparison, before parsing its invalid member.
			for pass := range o {
				o[pass].data[1] = []byte("person:x:1000:person,   \nbob:x:2000:\n")
				f := o[pass].before[1].(accountInfo)
				f.stat.Size = int64(len(o[pass].data[1]))
				o[pass].before[1], o[pass].descriptor[1], o[pass].path[1] = f, f, f
			}
			o[1].data[0] = []byte(strings.Replace(privateAccountData[0], "1001:2000", "1001:1000", 1))
		}, true},
		{"in-place-after-first-pass", func(o *[2]accountObservation) {
			o[1].data[1] = []byte(strings.Replace(privateAccountData[1], "#    ", "#edit", 1))
		}, true},
		{"path-replaced-between-passes", func(o *[2]accountObservation) {
			f := o[1].before[1].(accountInfo)
			f.stat.Ino++
			o[1].before[1], o[1].descriptor[1], o[1].path[1] = f, f, f
		}, true},
		{"identical-bytes-changed-metadata", func(o *[2]accountObservation) {
			f := o[1].before[1].(accountInfo)
			f.stat.Ctim.Nsec++
			o[1].before[1], o[1].descriptor[1], o[1].path[1] = f, f, f
		}, true},
		{"changed-and-changed-back-accepted-stated-limit", func(*[2]accountObservation) {
			// A change and return to identical bytes between reads, with colliding
			// metadata, is invisible. Acceptance pins the stated limit, not a proof
			// that no intervening writes occurred.
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := [2]accountObservation{observation(), observation()}
			tc.change(&o)
			if tc.name == "mixed-membership-colliding-timestamps" {
				if err := accountPolicy(1000, o[0].data, nil).Check(0664, 1000, 1000); err != nil {
					t.Fatalf("mixed first pass must demonstrate unsafe acceptance alone: %v", err)
				}
				var mode *ModeError
				if err := accountPolicy(1000, o[1].data, nil).Check(0664, 1000, 1000); !errors.As(err, &mode) || mode.Evidence != "shared-primary" {
					t.Fatalf("second pass must expose Bob's primary membership: %v", err)
				}
			}
			reads := 0
			data, err := collectAccountReads(3, func(pass int, _ [3][]byte) (accountObservation, error) { reads++; return o[pass], nil })
			p := accountPolicy(1000, data, err)
			if tc.refuse {
				requireCollectionRefusal(t, p)
			} else if e := p.Check(0664, 1000, 1000); e != nil {
				t.Fatal(e)
			}
			if reads != 2 {
				t.Fatalf("got %d passes, want exactly two without retry", reads)
			}
		})
	}
}

func TestAccountCollectionPassValidation(t *testing.T) {
	for pass := 0; pass < 2; pass++ {
		for _, field := range []string{"descriptor", "path"} {
			t.Run(fmt.Sprintf("pass%d/%s", pass, field), func(t *testing.T) {
				data, err := collectAccountReads(3, func(n int, _ [3][]byte) (accountObservation, error) {
					o := observation()
					if n == pass {
						f := o.before[0].(accountInfo)
						f.stat.Ino++
						if field == "descriptor" {
							o.descriptor[0] = f
						} else {
							o.path[0] = f
						}
					}
					return o, nil
				})
				requireCollectionRefusal(t, accountPolicy(1000, data, err))
			})
		}
	}
}

func TestAccountCollectionReadFailure(t *testing.T) {
	for pass := 0; pass < 2; pass++ {
		data, err := collectAccountReads(3, func(n int, _ [3][]byte) (accountObservation, error) {
			if n == pass {
				return accountObservation{}, os.ErrPermission
			}
			return observation(), nil
		})
		requireCollectionRefusal(t, accountPolicy(1000, data, err))
	}
}

func TestAccountCollectionFilesystemSmoke(t *testing.T) {
	var paths [3]string
	for i, data := range privateAccountData {
		root := t.TempDir()
		if err := os.Chmod(root, 0755); err != nil {
			t.Fatal(err)
		}
		paths[i] = filepath.Join(root, fmt.Sprint(i))
		if err := os.WriteFile(paths[i], []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// This is a filesystem smoke fixture, with its owner modelling root.
	data, err := collectAccountFilesWith(paths, func(path string) (*config.SystemFile, error) {
		return config.OpenSystemFileAt(filepath.Dir(path), "/"+filepath.Base(path), os.Getuid())
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := accountPolicy(1000, data, nil).Check(0664, 1000, 1000); err != nil {
		t.Fatal(err)
	}
}

// fragmentedAccountReader models reads interleaved with root's equal-length
// writes inside one timestamp tick. Each region arrives from a different state.
type fragmentedAccountReader struct {
	chunks []string
	before func(int) string
	index  int
}

func (r *fragmentedAccountReader) Read(p []byte) (int, error) {
	if r.index == len(r.chunks) {
		return 0, io.EOF
	}
	if len(p) < len(r.chunks[r.index]) {
		return 0, io.ErrShortBuffer
	}
	chunk := r.before(r.index)
	n := copy(p, chunk)
	r.index++
	return n, nil
}

func TestAccountCollectionFragmentedReadsAcceptedStatedLimit(t *testing.T) {
	// Somebody belongs to 1000 in every whole-file state, no state repeats,
	// and the accepted a+b never existed. This acceptance pins the stated
	// root-editing limit; it is not evidence of a coherent snapshot.
	a := "person:x:1000:1000::/:/bin/sh\nbob:x:1001:2000:a:/:/bin/sh\n"
	b := "carol:x:1002:2000:b:/:/bin/sh\n"
	member := func(s, padding string) string {
		return strings.Replace(strings.Replace(s, ":2000:", ":1000:", 1), ":a:", ":"+padding+":", 1)
	}
	a1, a2, a3 := member(a, "1"), member(a, "2"), member(a, "3")
	b0 := strings.Replace(b, ":2000:b:", ":1000:0:", 1)
	b1 := strings.Replace(b0, ":0:", ":1:", 1)
	states := []string{a + b0, a1 + b0, a1 + b, a2 + b, a2 + b1, a + b1, a3 + b1, a3 + b}
	seen := map[string]bool{}
	for _, state := range states {
		if seen[state] || state == a+b {
			t.Fatal("whole-file fixture repeats or equals collected bytes")
		}
		seen[state] = true
		d := observation().data
		d[0] = []byte(state)
		var mode *ModeError
		if e := accountPolicy(1000, d, nil).Check(0664, 1000, 1000); !errors.As(e, &mode) || mode.Evidence != "shared-primary" {
			t.Fatalf("whole state lacks other membership: %v", e)
		}
	}
	var visited []int
	data, err := collectAccountReads(3, func(pass int, first [3][]byte) (accountObservation, error) {
		o := observation()
		r := &fragmentedAccountReader{chunks: []string{a, b}, before: func(region int) string {
			indices := [2][2]int{{0, 2}, {5, 7}}
			state := indices[pass][region]
			for len(visited) <= state {
				visited = append(visited, len(visited))
			}
			if region == 0 {
				return states[state][:len(a)]
			}
			return states[state][len(a):]
		}}
		var err error
		if pass == 0 {
			o.data[0], err = readAccountDescriptor(r)
		} else {
			err = compareAccountReader(r, first[0])
			o.data[0] = first[0]
		}
		f := o.before[0].(accountInfo)
		f.stat.Size = int64(len(a + b))
		o.before[0], o.descriptor[0], o.path[0] = f, f, f
		return o, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data[0], []byte(a+b)) || len(visited) != len(states) {
		t.Fatalf("fragmented reads not exercised: %q, %v", data[0], visited)
	}
	if e := accountPolicy(1000, data, err).Check(0664, 1000, 1000); e != nil {
		t.Fatal(e)
	}
}

type boundedComparisonReader struct {
	io.Reader
	largest int
}

func (r *boundedComparisonReader) Read(p []byte) (int, error) {
	if len(p) > r.largest {
		r.largest = len(p)
	}
	return r.Reader.Read(p)
}

func TestAccountSecondPassStreaming(t *testing.T) {
	first := bytes.Repeat([]byte{'x'}, accountFileLimit-1)
	for _, size := range []int{0, 4096, accountFileLimit - 2, accountFileLimit - 1, accountFileLimit, accountFileLimit + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			r := &boundedComparisonReader{Reader: io.LimitReader(&repeatingAccountReader{}, int64(size))}
			err := compareAccountReader(r, first)
			if (err == nil) != (size == len(first)) {
				t.Fatalf("length %d comparison: %v", size, err)
			}
			if r.largest > 4096 {
				t.Fatalf("second pass requested %d bytes, want fixed buffer <=4096", r.largest)
			}
			if size >= accountFileLimit && !errors.Is(err, errAccountLimit) {
				t.Fatalf("cap: %v", err)
			}
		})
	}
	for _, at := range []int{0, 4096, len(first) - 1} {
		changed := bytes.Clone(first)
		changed[at] = 'y'
		if err := compareAccountReader(bytes.NewReader(changed), first); err == nil {
			t.Fatalf("changed byte at %d accepted", at)
		}
	}
	if err := compareAccountReader(&errorAccountReader{}, nil); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("read error lost: %v", err)
	}
}

type repeatingAccountReader struct{}

func (*repeatingAccountReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

type errorAccountReader struct{}

func (*errorAccountReader) Read([]byte) (int, error) { return 0, os.ErrPermission }
