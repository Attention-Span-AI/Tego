// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestCheckProtocolRetainsRawSourceBytes(t *testing.T) {
	data := bytes.Repeat([]byte{0, 255, 42}, (1<<20)/3)
	owner := 0
	req := checkRequest{Caller: &config.CallerContext{UID: 0, RuntimeDirs: []string{"/caller/runtime"}, PATH: "/caller/bin"}, Operation: "source", Data: data, DataPresent: true, Owner: &owner, OwnerPresent: true, MountInfoPresent: true,
		CompileContext: CompileContext{MountInfo: new(string)},
		ReadError:      packError(errors.Join(os.ErrNotExist, registry.ErrCatalogBound)), machine: config.Builtin()}
	encoded, err := encodeCheck(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > len(data)+(16<<10) {
		t.Fatalf("source bytes expanded from %d to %d bytes", len(data), len(encoded))
	}
	var got checkRequest
	if err := decodeCheck(encoded, &got); err != nil {
		t.Fatal(err)
	}
	got.restoreZeros()
	if got.Caller == nil || got.Caller.UID != 0 || got.Caller.PATH != "/caller/bin" || len(got.Caller.RuntimeDirs) != 1 || got.Caller.RuntimeDirs[0] != "/caller/runtime" {
		t.Fatal("caller facts lost in framing")
	}
	if !bytes.Equal(data, got.Data) || !got.DataPresent || got.Owner == nil || *got.Owner != 0 || got.machine != nil || got.CompileContext.MountInfo == nil || *got.CompileContext.MountInfo != "" {
		t.Fatal("source context did not survive private protocol")
	}
	if err := got.ReadError.error(); !errors.Is(err, os.ErrNotExist) || !errors.Is(err, registry.ErrCatalogBound) {
		t.Fatalf("typed source error did not survive private protocol: %v", err)
	}
}

func TestCheckProtocolRetainsEmptySource(t *testing.T) {
	m := config.Builtin()
	snapshot := m.Snapshot()
	compileContext, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "never-created.yaml")
	req := checkRequest{Caller: CallerContext(context.Background()), Operation: "source", Data: []byte{}, DataPresent: true, Context: compileContext,
		Entry: Entry{Path: path}, Places: registry.Places{Dir: filepath.Dir(path), UID: os.Getuid()}}
	encoded, err := encodeCheck(req)
	if err != nil {
		t.Fatal(err)
	}
	response, err := handleRequestContext(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	var reply checkReply
	if err := decodeCheck(response, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Entry.State != "invalid" {
		t.Fatalf("empty retained source was reopened: state %s", reply.Entry.State)
	}
}

func TestCheckProtocolRejectsInvalidMessages(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("not a private request")} {
		if _, err := handleRequestContext(context.Background(), data); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	encoded, err := encodeCheck(checkRequest{Caller: CallerContext(context.Background()), Operation: "unknown"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handleRequestContext(context.Background(), encoded); err == nil {
		t.Fatal("unknown operation accepted")
	}
}

func TestHelperRefusesMissingCallerContext(t *testing.T) {
	data, err := encodeCheck(checkRequest{Operation: "place", Path: "/"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = handleRequestContext(context.Background(), data)
	if err == nil || !strings.Contains(err.Error(), "missing caller context") {
		t.Fatalf("missing context was accepted: %v", err)
	}
}
