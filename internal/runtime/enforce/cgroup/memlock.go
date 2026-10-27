// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/pin"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// bpfObjects reads what the kernel says of bpf objects: pinned, of the pin at a path; program and mapByID, of an
// object by its id. A set of functions so a test replaces the kernel (SweepOptions.objects).
type bpfObjects struct {
	pinned  func(path string) (bpfObject, error)
	program func(id ebpf.ProgramID) (bpfObject, error)
	mapByID func(id ebpf.MapID) (bpfObject, error)
}

// bpfObject is one object as bpfObjects read it: a map or a program, with its id, its memlock and whether its fdinfo
// reported one (reported: a "memlock:" line, which says 0 for an empty LPM trie on 6.x, is a 0 the kernel said; no
// line is a memlock left unsaid) and, for a program, the maps it uses; or a link, whose id is its program's.
type bpfObject struct {
	kind     objectKind
	id       uint32
	memlock  uint64
	reported bool
	maps     []ebpf.MapID
}

type objectKind uint8

const (
	objMap objectKind = iota + 1
	objProgram
	objLink
)

// kernelObjects opens each pin, or each id, to read its info; it needs root, as ListBuilds does.
var kernelObjects = &bpfObjects{
	pinned: func(path string) (bpfObject, error) {
		obj, err := pin.Load(path, nil) // read-write: a pinned link opens no other way (bpf_obj_get_user)
		if err != nil {
			return bpfObject{}, err
		}
		defer func() { _ = obj.Close() }()
		switch o := obj.(type) {
		case *ebpf.Map:
			return mapObject(o)
		case *ebpf.Program:
			return programObject(o)
		case link.Link:
			info, err := o.Info()
			if err != nil {
				return bpfObject{}, fmt.Errorf("cgroup: read the link pinned at %s: %w", path, err)
			}
			return bpfObject{kind: objLink, id: uint32(info.Program)}, nil
		}
		return bpfObject{}, fmt.Errorf("cgroup: %s pins an object of type %T", path, obj)
	},
	program: func(id ebpf.ProgramID) (bpfObject, error) {
		p, err := ebpf.NewProgramFromID(id)
		if err != nil {
			return bpfObject{}, err
		}
		defer func() { _ = p.Close() }()
		return programObject(p)
	},
	mapByID: func(id ebpf.MapID) (bpfObject, error) {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return bpfObject{}, err
		}
		defer func() { _ = m.Close() }()
		return mapObject(m)
	},
}

func mapObject(m *ebpf.Map) (bpfObject, error) {
	info, err := m.Info()
	if err != nil {
		return bpfObject{}, fmt.Errorf("cgroup: read a map's info: %w", err)
	}
	id, ok := info.ID()
	if !ok {
		return bpfObject{}, errors.New("cgroup: the kernel names no id for a map")
	}
	var n uint64
	var reported bool
	_ = ebpfbindings.MapFD(m, func(fd int) error {
		return readFdinfo(fd, func(r io.Reader) { n, reported = fdinfoMemlock(r) })
	})
	return bpfObject{kind: objMap, id: uint32(id), memlock: n, reported: reported}, nil
}

func programObject(p *ebpf.Program) (bpfObject, error) {
	info, err := p.Info()
	if err != nil {
		return bpfObject{}, fmt.Errorf("cgroup: read a program's info: %w", err)
	}
	id, ok := info.ID()
	if !ok {
		return bpfObject{}, errors.New("cgroup: the kernel names no id for a program")
	}
	var n uint64
	var reported bool
	_ = ebpfbindings.ProgramFD(p, func(fd int) error {
		return readFdinfo(fd, func(r io.Reader) { n, reported = fdinfoMemlock(r) })
	})
	maps, _ := info.MapIDs()
	return bpfObject{kind: objProgram, id: uint32(id), memlock: n, reported: reported, maps: maps}, nil
}

// fdinfoDir holds a descriptor's fdinfo, a file named by its number. mapObject and programObject read the memlock
// line there themselves: cilium's MapInfo.Memlock and ProgramInfo.Memlock say a memlock of 0 is none, so an empty
// LPM trie, whose fdinfo says "memlock:\t0", would count as unreported on every kernel.
const fdinfoDir = "/proc/self/fdinfo/"

// readFdinfo opens the fdinfo of the lent number fd, hands it to read and closes it, all before it returns, so that
// its caller runs it inside the lend (ADR 0023): procfs looks the number up in the descriptor table each time the
// fdinfo is read, not when it is opened, so an fdinfo read after the lend ends would describe whatever file holds the
// number then, or fail once it is free.
func readFdinfo(fd int, read func(io.Reader)) error {
	f, err := sys.Own(unix.Open(fdinfoDir+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0))
	if err != nil {
		return err
	}
	file, err := f.Release("fdinfo")
	if err != nil {
		_ = f.Close()
		return err
	}
	defer func() { _ = file.Close() }()
	read(file)
	return nil
}

// fdinfoMemlock reads the "memlock:" line of an fdinfo: its value, and false when there is no such line, it does not
// hold a number, or the fdinfo cannot be read.
func fdinfoMemlock(r io.Reader) (uint64, bool) {
	s := bufio.NewScanner(r)
	for s.Scan() {
		key, value, ok := strings.Cut(s.Text(), ":")
		if !ok || key != "memlock" {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// memlock sums the memlock of every object pinned under roots, of every program their links attach and of every map
// those programs use, each once by its id, and counts the objects it could not read or whose fdinfo has no memlock (a
// memlock of 0 the kernel reported is a 0). Pins are read first, so an object pinned under a root is never opened
// again by its id.
func (o *bpfObjects) memlock(roots []string) (total uint64, unreported int) {
	progs := map[ebpf.ProgramID]bool{}
	maps := map[ebpf.MapID]bool{}
	var linked []ebpf.ProgramID
	var used []ebpf.MapID
	add := func(obj bpfObject) {
		switch obj.kind {
		case objMap:
			if maps[ebpf.MapID(obj.id)] {
				return
			}
			maps[ebpf.MapID(obj.id)] = true
		case objProgram:
			if progs[ebpf.ProgramID(obj.id)] {
				return
			}
			progs[ebpf.ProgramID(obj.id)] = true
			used = append(used, obj.maps...)
		case objLink:
			if obj.id != 0 {
				linked = append(linked, ebpf.ProgramID(obj.id))
			}
			return
		default:
			return
		}
		if !obj.reported {
			unreported++
		}
		total += obj.memlock
	}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
			switch {
			case err != nil:
				unreported++ // a directory that cannot be read: what it pins is left out, and said to be
				return nil
			case e.IsDir():
				return nil
			}
			obj, err := o.pinned(path)
			if err != nil {
				unreported++
				return nil
			}
			add(obj)
			return nil
		})
	}
	for _, id := range linked {
		if progs[id] {
			continue
		}
		obj, err := o.program(id)
		if err != nil {
			unreported++
			continue
		}
		add(obj)
	}
	for _, id := range used {
		if maps[id] {
			continue
		}
		obj, err := o.mapByID(id)
		if err != nil {
			unreported++
			continue
		}
		add(obj)
	}
	return total, unreported
}
