// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// The producer list (ADR 0023 A10 F1) is generated from the sources of golang.org/x/sys/unix, at the version
// go.mod requires, and of the toolchain's syscall: every exported function, in a file that builds for one of
// producerBuilds (linux, and darwin for the maze setup tool's macOS files, on amd64 and arm64), whose results
// include an int named fd or nfd. A result int named anything else that ends in
// fd (efd, pidfd, ...) cannot be classified by that rule and is listed in unclassified below by hand, as a
// producer or not; generation fails on one that is not, so a new x/sys function is never silently left out.
// The forbidden primitives (A4) are counted as what they are, not as producers.

// unclassified are the generated sources' functions with an fd-like int result that the name rule cannot
// classify: true is a producer, false is not.
var unclassified = map[string]bool{
	"Fsmount":  true, // fsmount(2) answers the mount's descriptor (fsfd)
	"Signalfd": true, // signalfd4(2) answers a new descriptor (newfd) when its first argument is -1
}

// unnamedProducers are producers whose int result has a name the rule cannot see: x/sys's OpenTree answers
// (r int, err error). Generation adds each one its sources declare, and fails when x/sys no longer declares
// one, so the hand list cannot go stale.
var unnamedProducers = []string{"OpenTree"}

// otherShapes are producers whose result does not fit sys.Own's (int, error): their owner forms are the sys
// helpers (Pipe2, Socketpair, Accept4). Any call of them outside the owner's files is a raw site. IoctlKCMClone
// answers its new KCM socket inside a struct and has no owner form, so every call is one.
var otherShapes = []string{"Accept", "Accept4", "Pipe", "Pipe2", "Socketpair", "IoctlKCMClone"}

// producerSources names the directories the list is generated from: x/sys/unix at go.mod's version, and the
// toolchain's syscall.
func producerSources(root string) (unixDir, syscallDir string, err error) {
	run := func(args ...string) (string, error) {
		cmd := exec.Command(goTool(), args...)
		cmd.Dir = root
		cmd.Env = goEnv(mainConfigs[0]) // GOFLAGS and go.work cleared, as every other go command fdcheck runs
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("go %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
		return strings.TrimSpace(string(out)), nil
	}
	mod, err := run("list", "-m", "-f", "{{.Dir}}", "golang.org/x/sys")
	if err != nil {
		return "", "", err
	}
	goroot, err := run("env", "GOROOT")
	if err != nil {
		return "", "", err
	}
	return filepath.Join(mod, "unix"), filepath.Join(goroot, "src", "syscall"), nil
}

// producerBuilds are the systems and architectures the list is generated for: those the project ships for,
// linux and (the maze setup tool) darwin, on amd64 and arm64. One list serves every build: a name only macOS
// declares is never called in a Linux file, which would not compile.
var producerBuilds = [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"}}

// GenerateProducers lists the producers of one package's sources in dir, for producerBuilds, and the names it
// declares.
func GenerateProducers(dir string) ([]string, map[string]bool, error) {
	found, declared := map[string]bool{}, map[string]bool{}
	var unknown, unknownIoctl []string
	for _, b := range producerBuilds {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = b[0], b[1], false
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil, nil, err
		}
		for _, e := range ents {
			n := e.Name()
			if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			if ok, err := ctx.MatchFile(dir, n); err != nil || !ok {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, n), nil, parser.SkipObjectResolution)
			if err != nil {
				return nil, nil, err
			}
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || !fn.Name.IsExported() {
					continue
				}
				name := fn.Name.Name
				if strings.HasPrefix(name, "Ioctl") && !ioctlReqWrappers[name] && !ioctlFixed[name] && !slices.Contains(otherShapes, name) {
					unknownIoctl = append(unknownIoctl, name)
				}
				if fn.Type.Results == nil {
					continue
				}
				declared[name] = true
				for _, r := range fn.Type.Results.List {
					if id, ok := r.Type.(*ast.Ident); !ok || id.Name != "int" {
						continue
					}
					for _, rn := range r.Names {
						switch l := strings.ToLower(rn.Name); {
						case l == "fd" || l == "nfd":
							found[name] = true
						case strings.HasSuffix(l, "fd"):
							if is, ok := unclassified[name]; !ok {
								unknown = append(unknown, name+" ("+rn.Name+")")
							} else if is {
								found[name] = true
							}
						}
					}
				}
			}
		}
	}
	if len(unknownIoctl) > 0 {
		sort.Strings(unknownIoctl)
		return nil, nil, fmt.Errorf("%s: cannot classify the ioctl wrappers %s: add each to tools/fdcheck/rules.go's ioctlReqWrappers or ioctlFixed, or to otherShapes when it answers a descriptor",
			dir, strings.Join(dedupe(unknownIoctl), ", "))
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, nil, fmt.Errorf("%s: cannot classify %s: add each to tools/fdcheck/producers.go's unclassified", dir,
			strings.Join(dedupe(unknown), ", "))
	}
	for _, n := range append(append([]string{}, otherShapes...), unnamedProducers...) {
		if declared[n] {
			found[n] = true
		}
	}
	var out []string
	for n := range found {
		if _, forbidden := forbiddenCall[n]; forbidden {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out, declared, nil
}

func dedupe(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// Producers is the checked-in list: the producers of x/sys/unix and of syscall.
type Producers struct {
	Unix, Syscall map[string]bool
}

// FormatProducers writes the list file.
func FormatProducers(unixList, syscallList []string) []byte {
	var b bytes.Buffer
	b.WriteString("# Generated by `go run ./tools/fdcheck -producers -w` from golang.org/x/sys/unix (go.mod's version) and the\n")
	b.WriteString("# toolchain's syscall, linux and darwin on amd64 and arm64: every exported function with an int result named\n")
	b.WriteString("# fd or nfd, the hand-classified ones and the other-shape producers (ADR 0023 A10 F1). Do not edit; regenerate.\n")
	for _, n := range unixList {
		fmt.Fprintf(&b, "unix %s\n", n)
	}
	for _, n := range syscallList {
		fmt.Fprintf(&b, "syscall %s\n", n)
	}
	return b.Bytes()
}

// ParseProducers reads the list file.
func ParseProducers(src []byte) (Producers, error) {
	p := Producers{Unix: map[string]bool{}, Syscall: map[string]bool{}}
	sc := bufio.NewScanner(bytes.NewReader(src))
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) != 2 {
			return p, fmt.Errorf("producers.txt:%d: want \"unix|syscall Name\", have %q", line, t)
		}
		switch f[0] {
		case "unix":
			p.Unix[f[1]] = true
		case "syscall":
			p.Syscall[f[1]] = true
		default:
			return p, fmt.Errorf("producers.txt:%d: unknown package %q", line, f[0])
		}
	}
	if len(p.Unix) == 0 || len(p.Syscall) == 0 {
		return p, fmt.Errorf("producers.txt lists no unix or no syscall producer")
	}
	return p, sc.Err()
}

// generatedProducers generates the list file's content from the module and toolchain sources.
func generatedProducers(root string) ([]byte, error) {
	ud, sd, err := producerSources(root)
	if err != nil {
		return nil, err
	}
	u, declared, err := GenerateProducers(ud)
	if err != nil {
		return nil, err
	}
	for _, n := range unnamedProducers {
		if !declared[n] {
			return nil, fmt.Errorf("%s no longer declares %s: drop it from tools/fdcheck/producers.go's unnamedProducers", ud, n)
		}
	}
	s, _, err := GenerateProducers(sd)
	if err != nil {
		return nil, err
	}
	return FormatProducers(u, s), nil
}
