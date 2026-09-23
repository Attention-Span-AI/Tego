// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	bin "encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fakeRing replays a fixed list of records and then ends, so a Stop that joins the drain goroutine is
// proof that every record was processed.
type fakeRing struct {
	mu      sync.Mutex
	records [][]byte
	closed  bool
}

// ReadInto is RingReader's read; next is the record it copies.
func (r *fakeRing) ReadInto(rec *ringbuf.Record) error { return readInto(rec, r.next) }

// readInto hands out one record the way *ringbuf.Reader.ReadInto does: copied into rec's own array, which the
// next read overwrites. A drain that kept a record's bytes past its read would see them change here, as it
// would on a kernel ring, rather than keep a private copy the fake happened to give it.
func readInto(rec *ringbuf.Record, next func() (ringbuf.Record, error)) error {
	got, err := next()
	if err != nil {
		return err
	}
	rec.RawSample = append(rec.RawSample[:0], got.RawSample...)
	rec.Remaining = got.Remaining
	return nil
}

// next takes the next record off the fake's list, or reports the ring closed once it is empty.
func (r *fakeRing) next() (ringbuf.Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || len(r.records) == 0 {
		return ringbuf.Record{}, ringbuf.ErrClosed
	}
	next := r.records[0]
	r.records = r.records[1:]
	return ringbuf.Record{RawSample: next}, nil
}

func (r *fakeRing) SetDeadline(time.Time) {}

func (r *fakeRing) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

// fakeLost is a kernel lost counter under test control.
type fakeLost struct {
	mu    sync.Mutex
	value uint64
	err   error
}

func (l *fakeLost) Lost() (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.value, l.err
}

// fakeSink collects the events a source emits.
type fakeSink struct {
	mu  sync.Mutex
	evs []*record.Event
}

func (s *fakeSink) Emit(e *record.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evs = append(s.evs, e)
}

func (s *fakeSink) events() []*record.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*record.Event(nil), s.evs...)
}

// fakeLink is one attached probe under test control.
type fakeLink struct {
	closed bool
	mu     *sync.Mutex
}

func (l *fakeLink) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}

// fakeAttacher records every probe it was asked for and hands back closable links.
type fakeAttacher struct {
	mu     sync.Mutex
	probes []Probe
	paths  []string
	// files is the file each path named when its probe was placed, which is what the kernel attaches to.
	files []os.FileInfo
	links []*fakeLink
	err   error
}

func (a *fakeAttacher) Attach(path string, p Probe) (io.Closer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return nil, a.err
	}
	a.probes = append(a.probes, p)
	a.paths = append(a.paths, path)
	fi, _ := os.Stat(path)
	a.files = append(a.files, fi)
	l := &fakeLink{mu: &a.mu}
	a.links = append(a.links, l)
	return l, nil
}

// placedOn reports whether the nth probe was placed on the file path names.
func (a *fakeAttacher) placedOn(t *testing.T, n int, path string) bool {
	t.Helper()
	want, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.files[n] != nil && os.SameFile(a.files[n], want)
}

func (a *fakeAttacher) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.probes)
}

func (a *fakeAttacher) openLinks() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, l := range a.links {
		if !l.closed {
			n++
		}
	}
	return n
}

// chunkRecord builds one ring-buffer record the way bpf/uprobe_ssl.bpf.c writes it.
func chunkRecord(cgroup uint64, pid, tid uint32, ssl uint64, dir uint8, monoNS uint64, data []byte, trunc bool) []byte {
	return holeRecord(cgroup, pid, tid, ssl, dir, monoNS, data, trunc, 0)
}

// holeRecord is chunkRecord for a chunk the kernel says is followed by skipped bytes it did not emit: the last of a
// call over R6's 128 KiB, or one whose plaintext the probe could not read.
func holeRecord(cgroup uint64, pid, tid uint32, ssl uint64, dir uint8, monoNS uint64, data []byte, trunc bool,
	skipped uint64) []byte {
	b := make([]byte, bpf.SSLEventSize)
	o := bin.NativeEndian
	o.PutUint16(b[0:2], bpf.EventsVersion)
	o.PutUint16(b[2:4], uint16(bpf.KindSSLChunk))
	o.PutUint32(b[4:8], uint32(bpf.SSLEventSize))
	o.PutUint64(b[8:16], monoNS)
	o.PutUint64(b[16:24], cgroup)
	o.PutUint32(b[24:28], pid)
	o.PutUint32(b[28:32], tid)
	o.PutUint64(b[bpf.HeaderSize:bpf.HeaderSize+8], ssl)
	o.PutUint32(b[bpf.HeaderSize+8:bpf.HeaderSize+12], uint32(len(data)))
	b[bpf.HeaderSize+12] = dir
	if trunc {
		b[bpf.HeaderSize+13] = 1
	}
	skippedAt := unsafe.Offsetof(bpf.SSLMeta{}.Skipped)
	o.PutUint64(b[skippedAt:skippedAt+8], skipped)
	copy(b[unsafe.Offsetof(bpf.SSLEvent{}.Data):], data)
	return b
}

// newTestUprobe builds a source over a fake ring buffer and returns it with the sink it feeds.
func newTestUprobe(t *testing.T, records [][]byte, opts Options) (*Uprobe, *fakeSink) {
	t.Helper()
	opts.Reader = &fakeRing{records: records}
	u, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return u, &fakeSink{}
}

// runSource starts a source, waits for the drain to end and stops it.
func runSource(t *testing.T, u *Uprobe, sink *fakeSink, run source.RunRef) {
	t.Helper()
	if err := u.Start(context.Background(), run, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// The fake ring ends once its records are exhausted, so waiting for the drain goroutine is what
	// makes every record's effect observable before Stop closes anything.
	<-u.done
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// exchange is the plaintext of one request and its response.
const (
	exchangeRequest = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
		"Content-Type: application/json\r\nAuthorization: Bearer sk-secret-token\r\n" +
		"X-Api-Key: sk-ant-secret\r\nContent-Length: 17\r\n\r\n{\"model\":\"opus\"}\n"
	exchangeResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nRequest-Id: req_0123\r\n" +
		"Content-Length: 22\r\n\r\n{\"id\":\"msg_01\",\"x\":1}\n"
)

// TestDrainEmitsPair covers the whole path with no kernel: two chunk records become one ssl_request and
// one ssl_response, stamped from the records' own kernel header.
func TestDrainEmitsPair(t *testing.T) {
	records := [][]byte{
		chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false),
		chunkRecord(41, 100, 101, 0xabc, bpf.SSLRead, 9_000_000, []byte(exchangeResponse), false),
	}
	blobs := &fakeBlobs{}
	u, sink := newTestUprobe(t, records, Options{Blobs: blobs, Rules: &agent.RuleTable{Record: agent.RecordFull}})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "retriever", CgroupID: 41})

	evs := sink.events()
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d", len(evs))
	}
	if evs[0].Kind != record.KindSSLRequest || evs[1].Kind != record.KindSSLResponse {
		t.Fatalf("kinds = %s, %s", evs[0].Kind, evs[1].Kind)
	}
	for _, e := range evs {
		if e.Source != record.SourceSSL || e.Run != "r-1" || e.Agent != "retriever" {
			t.Errorf("common fields = %+v", e)
		}
		if e.PID != 100 || e.TID != 101 || e.Cgroup != 41 {
			t.Errorf("process fields = pid %d tid %d cgroup %d", e.PID, e.TID, e.Cgroup)
		}
		// The ledger writer owns seq, id and prev; everything else must already satisfy the
		// record's own rules before the event ever reaches the pipeline.
		if err := e.Validate(); err != nil {
			t.Errorf("%s event is not a valid record: %v", e.Kind, err)
		}
	}
	var req record.SSLRequestPayload
	if err := json.Unmarshal(evs[0].Payload, &req); err != nil {
		t.Fatalf("decode request payload: %v", err)
	}
	if req.Method != "POST" || req.Path != "/v1/messages" || req.Host != "api.anthropic.com" {
		t.Errorf("request payload = %+v", req)
	}
	if req.Size != 17 || req.Blob == "" {
		t.Errorf("body size %d blob %q", req.Size, req.Blob)
	}
	var resp record.SSLResponsePayload
	if err := json.Unmarshal(evs[1].Payload, &resp); err != nil {
		t.Fatalf("decode response payload: %v", err)
	}
	if resp.Status != 200 || resp.RequestID != "req_0123" {
		t.Errorf("response payload = %+v", resp)
	}
	if resp.LatencyMS != 8 {
		t.Errorf("latency = %d ms, want the 8 ms between the two records' kernel stamps", resp.LatencyMS)
	}
	if len(u.Gaps()) != 0 {
		t.Errorf("gaps = %v", u.Gaps())
	}
}

// TestCredentialsNeverReachAPayload is capture-derive.md I5: the header allow-list is what guarantees it, so the assertion
// is over the raw payload bytes rather than over a struct field.
func TestCredentialsNeverReachAPayload(t *testing.T) {
	records := [][]byte{
		chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false),
		chunkRecord(41, 100, 101, 0xabc, bpf.SSLRead, 9_000_000, []byte(exchangeResponse), false),
	}
	u, sink := newTestUprobe(t, records, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	for _, e := range sink.events() {
		for _, secret := range []string{"sk-secret-token", "sk-ant-secret", "Authorization", "X-Api-Key"} {
			if strings.Contains(string(e.Payload), secret) {
				t.Fatalf("%s payload carries %q: %s", e.Kind, secret, e.Payload)
			}
		}
	}
}

// fakeBlobs is a content-addressed store under test control.
type fakeBlobs struct {
	mu   sync.Mutex
	put  [][]byte
	err  error
	last string
}

func (b *fakeBlobs) PutStream(r io.Reader) (string, int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return "", 0, b.err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return "", 0, err
	}
	b.put = append(b.put, data)
	b.last = fmt.Sprintf("%064x", len(b.put))
	return b.last, int64(len(data)), nil
}

// TestBodiesOnlyUnderRecordFull covers `record: summary`, which stores no bodies, and a blob store that
// fails, which is a gap and never a failed call (§7).
func TestBodiesOnlyUnderRecordFull(t *testing.T) {
	mk := func(rules *agent.RuleTable, blobs BlobStore) []*record.Event {
		records := [][]byte{
			chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false),
			chunkRecord(41, 100, 101, 0xabc, bpf.SSLRead, 9_000_000, []byte(exchangeResponse), false),
		}
		u, sink := newTestUprobe(t, records, Options{Rules: rules, Blobs: blobs})
		runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
		return sink.events()
	}
	t.Run("summary stores nothing", func(t *testing.T) {
		blobs := &fakeBlobs{}
		evs := mk(&agent.RuleTable{Record: agent.RecordSummary}, blobs)
		if len(blobs.put) != 0 {
			t.Errorf("summary stored %d bodies", len(blobs.put))
		}
		var req record.SSLRequestPayload
		if err := json.Unmarshal(evs[0].Payload, &req); err != nil {
			t.Fatal(err)
		}
		if req.Blob != "" || req.Size != 17 {
			t.Errorf("summary payload = %+v; size is still recorded, the blob is not", req)
		}
	})
	t.Run("a failing store is a gap", func(t *testing.T) {
		blobs := &fakeBlobs{err: errors.New("disk full")}
		records := [][]byte{
			chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false),
		}
		u, sink := newTestUprobe(t, records, Options{Rules: &agent.RuleTable{Record: agent.RecordFull}, Blobs: blobs})
		runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
		if len(sink.events()) != 1 {
			t.Fatalf("the event is still emitted: %d", len(sink.events()))
		}
		if !hasGap(u.Gaps(), "malformed") {
			t.Errorf("gaps = %v", u.Gaps())
		}
	})
}

// TestOtherRunsChunksAreIgnored covers R9's userspace half: one host-wide ring buffer, several runs.
func TestOtherRunsChunksAreIgnored(t *testing.T) {
	records := [][]byte{
		chunkRecord(99, 200, 200, 0xdef, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false),
		chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 2_000_000, []byte(exchangeRequest), false),
	}
	u, sink := newTestUprobe(t, records, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	evs := sink.events()
	if len(evs) != 1 {
		t.Fatalf("want only this run's request, got %d events", len(evs))
	}
	if evs[0].Cgroup != 41 {
		t.Errorf("cgroup = %d", evs[0].Cgroup)
	}
}

// TestAdoptedDescendantCgroup covers a descendant cgroup the run materialized after Start.
func TestAdoptedDescendantCgroup(t *testing.T) {
	records := [][]byte{chunkRecord(77, 300, 300, 0x1, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false)}
	u, sink := newTestUprobe(t, records, Options{})
	u.Adopt(77)
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	evs := sink.events()
	if len(evs) != 1 {
		t.Fatalf("want the adopted descendant's request, got %d events", len(evs))
	}
	if evs[0].Cgroup != 77 {
		t.Errorf("event from cgroup %d", evs[0].Cgroup)
	}
}

// TestUndecodableRecordIsAGap covers a sample this build cannot read: one gap, and the drain keeps going.
func TestUndecodableRecordIsAGap(t *testing.T) {
	records := [][]byte{
		make([]byte, 12),
		chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false),
	}
	u, sink := newTestUprobe(t, records, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	if len(sink.events()) != 1 {
		t.Fatalf("the good record was dropped too: %d events", len(sink.events()))
	}
	if !hasGap(u.Gaps(), GapSizeCap) {
		t.Errorf("gaps = %v", u.Gaps())
	}
}

// TestTruncatedChunkMarksTheMessage covers R6 reaching the ledger: a call the kernel cut leaves the
// message it belongs to marked, so derive knows the JSON it sees is a prefix (edge case #8).
func TestTruncatedChunkMarksTheMessage(t *testing.T) {
	head := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 4\r\n\r\n"
	records := [][]byte{
		chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 1_000_000, []byte(head), true),
		chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 2_000_000, []byte("{\"a\""), false),
	}
	u, sink := newTestUprobe(t, records, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	if len(sink.events()) != 1 {
		t.Fatalf("want one request, got %d", len(sink.events()))
	}
}

// TestRingBufferDropGap covers I7: the kernel's own lost counter becomes a gap with a count, of the drops made
// while the run captured.
func TestRingBufferDropGap(t *testing.T) {
	lost := &fakeLost{}
	u, sink := newTestUprobe(t, nil, Options{Lost: lost})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	lost.mu.Lock()
	lost.value = 7
	lost.mu.Unlock()
	<-u.done
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	gaps := u.Gaps()
	if !hasGap(gaps, GapRingBufferDrop) {
		t.Fatalf("gaps = %v", gaps)
	}
	for _, g := range gaps {
		if g.Why == GapRingBufferDrop && g.Count != 7 {
			t.Errorf("count = %d, want 7", g.Count)
		}
	}
}

// TestStopFlushesHalfMessage covers edge case #28: a connection mid-request at Stop is a gap, not a
// silent half-message.
func TestStopFlushesHalfMessage(t *testing.T) {
	half := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 100\r\n\r\n{\"a\":1}"
	records := [][]byte{chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 1_000_000, []byte(half), false)}
	u, sink := newTestUprobe(t, records, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	if !hasGap(u.Gaps(), "malformed") {
		t.Fatalf("gaps = %v", u.Gaps())
	}
	if len(sink.events()) != 1 {
		t.Errorf("the bytes that did arrive were dropped: %d events", len(sink.events()))
	}
}

// TestStartTwiceAndStopTwice covers the lifecycle contract.
func TestStartTwiceAndStopTwice(t *testing.T) {
	u, sink := newTestUprobe(t, nil, Options{})
	run := source.RunRef{ID: "r-1", Agent: "a"}
	if err := u.Start(context.Background(), run, nil); err == nil {
		t.Error("Start with a nil sink must fail")
	}
	if err := u.Start(context.Background(), run, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := u.Start(context.Background(), run, sink); !errors.Is(err, ErrAlreadyStarted) {
		t.Errorf("second Start = %v", err)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	if u.Name() != Name {
		t.Errorf("Name = %q", u.Name())
	}
}

// TestStopWithoutStart covers a source the run never started.
func TestStopWithoutStart(t *testing.T) {
	u, _ := newTestUprobe(t, nil, Options{})
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestNewNeedsAReader covers the constructor's one precondition.
func TestNewNeedsAReader(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrNoReader) {
		t.Fatalf("New = %v, want ErrNoReader", err)
	}
}

// TestContextCancelStopsTheDrain covers §9's "every long-lived goroutine runs under the run's context".
func TestContextCancelStopsTheDrain(t *testing.T) {
	ring := &fakeRing{}
	u, err := New(Options{Reader: ring})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := u.Start(ctx, source.RunRef{ID: "r-1", Agent: "a"}, &fakeSink{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	cancel()
	done := make(chan error, 1)
	go func() { done <- u.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Stop after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return after the context was cancelled")
	}
}

// procTree builds a fake /proc for one process.
type procTree struct {
	root string
}

func newProcTree(t *testing.T) *procTree {
	t.Helper()
	return &procTree{root: t.TempDir()}
}

// process writes a pid's maps and exe. Every library path is relative to the process's own root, which is
// what R39's /proc/<pid>/root resolution has to find.
func (p *procTree) process(t *testing.T, pid int, exe string, libs []string) {
	t.Helper()
	dir := filepath.Join(p.root, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(dir, "root"), 0o755); err != nil {
		t.Fatal(err)
	}
	var maps strings.Builder
	for i, lib := range append([]string{exe}, libs...) {
		fmt.Fprintf(&maps, "7f0000%03d000-7f0000%03dfff r-xp 00000000 fd:01 %d %s\n", i, i, 1000+i, lib)
	}
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(maps.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
}

// inRoot writes a file inside a process's own mount namespace and returns the path the process sees.
func (p *procTree) inRoot(t *testing.T, pid int, name string, content []byte) string {
	t.Helper()
	full := filepath.Join(p.root, strconv.Itoa(pid), "root", name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return "/" + name
}

// TestDiscoverCandidates covers R4's order and R39's namespace resolution.
func TestDiscoverCandidates(t *testing.T) {
	tree := newProcTree(t)
	lib := tree.inRoot(t, 7, "usr/lib/x86_64-linux-gnu/libssl.so.3", []byte("not really an elf"))
	tree.process(t, 7, "/usr/bin/python3.12", []string{lib, "/usr/lib/libc.so.6"})
	d := &discoverer{fs: proc.NewAt(tree.root)}
	got, err := d.candidates(7)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no candidates")
	}
	if got[0].Name != lib {
		t.Errorf("first candidate = %q, want the libssl mapping", got[0].Name)
	}
	if !strings.Contains(got[0].Path, filepath.Join("7", "root")) {
		t.Errorf("libssl path %q does not go through /proc/<pid>/root (R39)", got[0].Path)
	}
	if _, err := os.Stat(got[0].Path); err != nil {
		t.Errorf("the resolved path does not exist: %v", err)
	}
	var sawExe bool
	for _, c := range got {
		if c.Name == "/usr/bin/python3.12" && strings.HasSuffix(c.Path, "/exe") {
			sawExe = true
		}
	}
	if !sawExe {
		t.Errorf("the static-link fallback is missing: %+v", got)
	}
}

// TestDiscoverNoCandidates covers a process whose maps cannot be read at all, which is R37's
// no-openssl bucket and, per capture-derive.md E31, also where a ptrace-denied read lands.
func TestDiscoverNoCandidates(t *testing.T) {
	tree := newProcTree(t)
	d := &discoverer{fs: proc.NewAt(tree.root)}
	if _, err := d.candidates(4242); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("error = %v, want ErrNoCandidate", err)
	}
}

// TestMaxScanBoundsDiscovery covers the bound on how many mappings are considered.
func TestMaxScanBoundsDiscovery(t *testing.T) {
	tree := newProcTree(t)
	var libs []string
	for i := 0; i < 100; i++ {
		libs = append(libs, fmt.Sprintf("/usr/lib/lib%03d.so", i))
	}
	tree.process(t, 8, "/nonexistent/agent", libs)
	d := &discoverer{fs: proc.NewAt(tree.root), maxScan: 4}
	got, err := d.candidates(8)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(got) > 5 { // the exe plus maxScan others
		t.Errorf("%d candidates past a scan bound of 4", len(got))
	}
}

// TestOnExecAttachesOnceAndDetaches covers I8 and I9 together: two processes sharing one libssl attach
// once, and the links close only when the last of them is gone (R7, R8, edge case #26).
func TestOnExecAttachesOnceAndDetaches(t *testing.T) {
	tree := newProcTree(t)
	so := writeELF(t, elfOptions{
		Dynamic: map[string]uint64{SymWrite: 0x1100, SymWriteEx2: 0x1140, SymRead: 0x1180, SymReadEx: 0x11c0},
		BuildID: []byte{1, 2, 3, 4},
	})
	soBytes, err := os.ReadFile(so)
	if err != nil {
		t.Fatal(err)
	}
	// Both processes map the same file: pid 12's mount namespace is pid 11's, which is what makes
	// the (device, inode) key one entry rather than two (R7, edge case #4).
	lib := tree.inRoot(t, 11, "usr/lib/libssl.so.3", soBytes)
	tree.process(t, 11, "/nonexistent/python3", []string{lib})
	tree.process(t, 12, "/nonexistent/python3", []string{lib})
	if err := os.RemoveAll(filepath.Join(tree.root, "12", "root")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(tree.root, "11", "root"), filepath.Join(tree.root, "12", "root")); err != nil {
		t.Fatal(err)
	}
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(11, 41, "")
	first := att.count()
	// Six probes: SSL_write, SSL_write_ex2, and an entry and a return for each read (R1-R3).
	if first != 6 {
		t.Fatalf("%d probes for one binary, want 6", first)
	}
	u.OnExec(12, 41, "")
	if att.count() != first {
		t.Errorf("a second process attached again: %d probes", att.count())
	}
	if u.cache.size() != 1 {
		t.Errorf("attach cache holds %d binaries", u.cache.size())
	}
	u.OnExit(11)
	if att.openLinks() != 6 {
		t.Errorf("links closed while a process still maps the binary (R8)")
	}
	u.OnExit(12)
	if att.openLinks() != 0 {
		t.Errorf("%d links still open after the last process exited (I9)", att.openLinks())
	}
	if len(u.Gaps()) != 0 {
		t.Errorf("gaps = %v", u.Gaps())
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestOnExecNoSymbolsGaps covers capture-derive.md E5 (a fresh exec of a stripped copy has no symbols) and R37's static-tls-no-symbols: a real binary with no OpenSSL in it.
func TestOnExecNoSymbolsGaps(t *testing.T) {
	tree := newProcTree(t)
	so := writeELF(t, elfOptions{Dynamic: map[string]uint64{"malloc": 0x1100}})
	b, err := os.ReadFile(so)
	if err != nil {
		t.Fatal(err)
	}
	lib := tree.inRoot(t, 21, "usr/lib/bun/libcrypto.so", b)
	tree.process(t, 21, "/nonexistent/bun", []string{lib})
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(21, 41, "")
	gaps := u.Gaps()
	if !hasGap(gaps, GapStaticTLSNoSymbols) {
		t.Fatalf("gaps = %v, want static-tls-no-symbols", gaps)
	}
	if named := gapBinary(gaps, GapStaticTLSNoSymbols); named == "" {
		t.Errorf("the gap does not name a binary: %v", gaps)
	}
	if att.count() != 0 {
		t.Errorf("attached %d probes to a binary with no symbols", att.count())
	}
	// One attempt per binary: a second exec of the same process must not re-read or re-attach.
	u.OnExec(21, 41, "")
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestOnExecNoLibraryGaps covers R4 finding nothing at all.
func TestOnExecNoLibraryGaps(t *testing.T) {
	tree := newProcTree(t)
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: &fakeAttacher{}})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(999, 41, "")
	if !hasGap(u.Gaps(), GapNoOpenSSL) {
		t.Fatalf("gaps = %v, want no-openssl", u.Gaps())
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestAttachFailureGapsAndDoesNotRetry covers §7's "one attempt per (dev, ino), no retry storm".
func TestAttachFailureGapsAndDoesNotRetry(t *testing.T) {
	tree := newProcTree(t)
	so := writeELF(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180}})
	b, err := os.ReadFile(so)
	if err != nil {
		t.Fatal(err)
	}
	lib := tree.inRoot(t, 31, "usr/lib/libssl.so.3", b)
	tree.process(t, 31, "/nonexistent/curl", []string{lib})
	att := &fakeAttacher{err: errors.New("perf_event_open: operation not permitted")}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(31, 41, "")
	if !hasGap(u.Gaps(), GapNoOpenSSL) {
		t.Fatalf("gaps = %v, want the generic no-openssl bucket (§7)", u.Gaps())
	}
	before := len(u.Gaps())
	u.OnExec(31, 41, "")
	if len(u.Gaps()) != before {
		t.Errorf("a second exec produced new gap reasons: %v", u.Gaps())
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestAttachBudget covers §4's 50 ms ceiling on discovery and attach together (capture-derive.md E1 (edge case #1)).
func TestAttachBudget(t *testing.T) {
	tree := newProcTree(t)
	so := writeELF(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1100}})
	b, err := os.ReadFile(so)
	if err != nil {
		t.Fatal(err)
	}
	lib := tree.inRoot(t, 41, "usr/lib/libssl.so.3", b)
	tree.process(t, 41, "/nonexistent/node", []string{lib})
	// Every reading is a second past the last, so any budget is already spent. The clock is shared
	// with the drain goroutine, so it is guarded.
	var clockMu sync.Mutex
	now := time.Unix(1700000000, 0)
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		now = now.Add(time.Second)
		return now
	}
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Now: clock})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(41, 41, "")
	if att.count() != 0 {
		t.Errorf("attached past the budget")
	}
	if !hasGap(u.Gaps(), GapSizeCap) {
		t.Errorf("gaps = %v, want size-cap for the spent budget", u.Gaps())
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestParseTraceparent covers the one header uprobe capture reads for identity.
func TestParseTraceparent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in           string
		trace, paren string
	}{
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			"4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"},
		{"", "", ""},
		{"garbage", "", ""},
		{"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "", ""},
		{"00-short-00f067aa0ba902b7-01", "", ""},
		{"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", "", ""},
		// The forwarder's rule (derive.ParseTraceparent): all-zero ids and a bad flags field are invalid.
		{"00-00000000000000000000000000000000-00f067aa0ba902b7-01", "", ""},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", "", ""},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz", "", ""},
	}
	for _, tc := range cases {
		trace, paren := parseTraceparent(tc.in)
		if trace != tc.trace || paren != tc.paren {
			t.Errorf("parseTraceparent(%q) = %q, %q; want %q, %q", tc.in, trace, paren, tc.trace, tc.paren)
		}
	}
}

// TestEndpointNamesTheDeclaredProvider covers the endpoint field: a declared models[] host becomes its
// provider, and anything else keeps its own name rather than claiming one.
func TestEndpointNamesTheDeclaredProvider(t *testing.T) {
	t.Parallel()
	u := &Uprobe{opts: Options{Rules: &agent.RuleTable{Contract: &agent.Contract{
		Models: []agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com", Port: 443}},
	}}}}
	if got := u.endpoint("api.anthropic.com"); got != "anthropic" {
		t.Errorf("endpoint = %q, want anthropic", got)
	}
	if got := u.endpoint("api.anthropic.com:443"); got != "anthropic" {
		t.Errorf("endpoint with a port = %q", got)
	}
	if got := u.endpoint("example.test"); got != "example.test" {
		t.Errorf("undeclared endpoint = %q", got)
	}
	bare := &Uprobe{opts: Options{}}
	if got := bare.endpoint("api.anthropic.com"); got != "api.anthropic.com" {
		t.Errorf("endpoint with no contract = %q", got)
	}
}

// TestProviderMatchesTheCanonicalHost: a Host header and a models[] host compare in one spelling
// (agent.CanonicalHost), so case, a port, an IPv6 literal's brackets and a trailing dot on either side still name the
// declared provider. The bracketed IPv6 authority kept its brackets and matched no entry.
func TestProviderMatchesTheCanonicalHost(t *testing.T) {
	t.Parallel()
	u := &Uprobe{opts: Options{Rules: &agent.RuleTable{Contract: &agent.Contract{
		Models: []agent.ModelEndpoint{
			{Provider: "anthropic", Host: "API.Anthropic.com.", Port: 443},
			{Provider: "local", Host: "[::1]", Port: 8080},
		},
	}}}}
	for host, want := range map[string]string{
		"api.anthropic.com":       "anthropic",
		"API.ANTHROPIC.COM:443":   "anthropic",
		"api.anthropic.com.:8443": "anthropic",
		"[::1]:8080":              "local",
		"::1":                     "local",
		"[::2]:8080":              "",
	} {
		if got := u.provider(host); got != want {
			t.Errorf("provider(%q) = %q, want %q", host, got, want)
		}
		wantEndpoint := want
		if want == "" {
			wantEndpoint = agent.CanonicalHost(host)
		}
		if got := u.endpoint(host); got != wantEndpoint {
			t.Errorf("endpoint(%q) = %q, want %q", host, got, wantEndpoint)
		}
	}
}

// BenchmarkHandle measures the budgeted drain path: one chunk record from bytes to reassembled message.
func BenchmarkHandle(b *testing.B) {
	rec := chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false)
	u, err := New(Options{Reader: &fakeRing{}})
	if err != nil {
		b.Fatal(err)
	}
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, &fakeSink{}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		u.handle(rec)
	}
	b.StopTimer()
	_ = u.Stop()
}

// hasGap reports whether a gap with the given reason is present.
func hasGap(gaps []source.Gap, why string) bool {
	for _, g := range gaps {
		if g.Why == why && g.Count > 0 {
			return true
		}
	}
	return false
}

// gapBinary returns the binary a gap named.
func gapBinary(gaps []source.Gap, why string) string {
	for _, g := range gaps {
		if g.Why == why {
			return g.Binary
		}
	}
	return ""
}
