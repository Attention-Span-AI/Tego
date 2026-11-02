// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// FuzzAskMutationNames is E64's path-reader fuzzing for a held mutation (ADR 0047): whatever bytes the target laid out
// at a mutation's pathname, the reader (pathRaw, through the fake target's memory) and the split a held mutation pins
// (mutationLeaf) give a name the completion acts on that is one entry of the pinned directory, never "", "." or "..",
// never holding "/" or NUL, and that with the directory part spells the pathname the task passed; a trailing slash is
// held only for an op on a directory.
func FuzzAskMutationNames(f *testing.F) {
	for _, seed := range []string{"/a/b\x00", "a\x00", "a/\x00", "/\x00", "//x//\x00", "../x\x00", "x/..\x00", ".\x00", "a/./b/\x00", strings.Repeat("d/", 2100) + "x\x00", ""} {
		f.Add([]byte(seed), seed != "" && seed[0] == '/', false)
	}
	f.Fuzz(func(t *testing.T, data []byte, absolute, dirOnly bool) {
		fk := newFake()
		fk.links["/proc/42/cwd"] = "/work"
		fk.links["/proc/42/fd/9"] = "/dirfd"
		if len(data) > 0 {
			fk.put(0x1000, data)
		}
		l, _ := New(testListener(), testPolicy(nil, nil, nil), &testSink{}, Options{kernel: fk, Workers: 1})
		r := l.newReader(notifFor(connectNR(), 42, 0, 0, 0))
		dirfd := int32(atFDCWD)
		if !absolute {
			dirfd = 9
		}
		_, raw := r.pathRaw(dirfd, 0x1000)
		if r.failed || r.unreadPath != "" {
			return // a pathname not read whole is never held: askMutation leaves it to the kernel's own refusal
		}
		if len(raw) >= pathMax || strings.IndexByte(raw, 0) >= 0 {
			t.Fatalf("raw pathname of %d bytes, NUL at %d", len(raw), strings.IndexByte(raw, 0))
		}
		parent, leaf, err := mutationLeaf(raw, dirOnly)
		if err != nil {
			if !errors.Is(err, errMutationUnsupported) {
				t.Fatalf("mutationLeaf(%q): %v", trim(raw), err)
			}
			return
		}
		if leaf == "" || leaf == "." || leaf == ".." || strings.ContainsAny(leaf, "/\x00") || parent == "" {
			t.Fatalf("mutationLeaf(%q) = %q, %q", trim(raw), trim(parent), leaf)
		}
		if strings.HasSuffix(raw, "/") && !dirOnly {
			t.Fatalf("trailing slash held for an op on a non-directory: %q", trim(raw))
		}
		// The directory part and the name spell the pathname back: "d/x", a bare "x" in ".", or "/x" at the root.
		whole := strings.TrimRight(raw, "/")
		if whole != parent+"/"+leaf && (parent != "." || whole != leaf) && (parent != "/" || whole != "/"+leaf) {
			t.Fatalf("%q split into %q and %q", trim(raw), trim(parent), leaf)
		}
	})
}

// The mutations the kernel fails before its permission check are not asked (errKernelAnswers), and the forms no held
// completion makes keep today's path (errMutationUnsupported), whatever the names hold.
func TestAskMutationStateAnswersWhatTheKernelAnswersFirst(t *testing.T) {
	file := mutationEnd{present: true}
	dir := mutationEnd{present: true, leafDir: true}
	none := mutationEnd{}
	cases := []struct {
		name  string
		op    string
		flags int
		ends  []mutationEnd
		want  error
	}{
		{"unlink missing", record.FSUnlink, 0, []mutationEnd{none}, errKernelAnswers},
		{"unlink a directory", record.FSUnlink, 0, []mutationEnd{dir}, errKernelAnswers},
		{"rmdir a file", record.FSUnlink, unix.AT_REMOVEDIR, []mutationEnd{file}, errKernelAnswers},
		{"unlink a file", record.FSUnlink, 0, []mutationEnd{file}, nil},
		{"rmdir a directory", record.FSUnlink, unix.AT_REMOVEDIR, []mutationEnd{dir}, nil},
		{"mkdir over a name", record.FSMkdir, 0, []mutationEnd{file}, errKernelAnswers},
		{"mkdir", record.FSMkdir, 0, []mutationEnd{none}, nil},
		{"symlink over a name", record.FSSymlink, 0, []mutationEnd{dir}, errKernelAnswers},
		{"link a directory", record.FSLink, 0, []mutationEnd{dir, none}, errKernelAnswers},
		{"link onto a name", record.FSLink, 0, []mutationEnd{file, file}, errKernelAnswers},
		{"link from a descriptor", record.FSLink, unix.AT_EMPTY_PATH, []mutationEnd{file, none}, errMutationUnsupported},
		{"link", record.FSLink, 0, []mutationEnd{file, none}, nil},
		{"rename missing", record.FSRename, 0, []mutationEnd{none, none}, errKernelAnswers},
		{"rename noreplace onto a name", record.FSRename, unix.RENAME_NOREPLACE, []mutationEnd{file, file}, errKernelAnswers},
		{"exchange with nothing", record.FSRename, unix.RENAME_EXCHANGE, []mutationEnd{file, none}, errKernelAnswers},
		{"rename a directory onto a file", record.FSRename, 0, []mutationEnd{dir, file}, errKernelAnswers},
		{"whiteout", record.FSRename, unix.RENAME_WHITEOUT, []mutationEnd{file, none}, errMutationUnsupported},
		{"rename over a file", record.FSRename, 0, []mutationEnd{file, file}, nil},
		{"exchange", record.FSRename, unix.RENAME_EXCHANGE, []mutationEnd{dir, file}, nil},
		{"chmod", record.FSChmod, 0, []mutationEnd{file}, errMutationUnsupported},
	}
	for _, c := range cases {
		q := mutationQuery{op: c.op, args: mutationArgs{flags: c.flags}}
		if got := mutationState(q, c.ends); !errors.Is(got, c.want) || (c.want == nil) != (got == nil) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
