// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

// generated wires the bpf2go output into this package's object registry. The file compiles only under the
// tegobpf tag; the bindings it names are committed (gen.go), so the tag needs no clang. Without the tag
// objects_stub.go supplies an empty registry and nothing here is referenced. The map is never written after
// initialization.
//
// The three architecture-neutral objects are registered here. The uprobe object is added by withArchObjects,
// which objects_ssl_gen.go defines for the architectures uprobessl is compiled for and objects_ssl_none.go
// defines as the identity everywhere else (gen.go says why the object is per architecture).
var generated = withArchObjects(map[Object]binding{
	ObjectCgroupNet:   {load: loadCgroupnet, raw: _CgroupnetBytes},
	ObjectCgroupTrack: {load: loadCgrouptrack, raw: _CgrouptrackBytes},
	ObjectTraceProc:   {load: loadTrace, raw: _TraceBytes},
})

// readerGenerated registers the rdonly build of each tier-2 object compiled once per reader (reader.go), keyed by
// the object it is a build of; generated holds the probe build under the same name. Never written after
// initialization.
var readerGenerated = map[Object]binding{
	ObjectTraceProc: {load: loadTracerd, raw: _TracerdBytes},
}
