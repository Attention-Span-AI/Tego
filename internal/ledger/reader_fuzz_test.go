// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The fuzz targets in this file cover the ledger's readers of bytes a tamperer controls: events.jsonl and
// the blobs directory are plain files anyone with the run's uid can rewrite (E16), and tamper evidence is
// the promise the record makes about them (ARCHITECTURE §16 asks a fuzz target of every such reader).

// canonicalHead matches the start R2 fixes for every canonical line: v, then seq, then the 64-hex id.
var canonicalHead = regexp.MustCompile(`^\{"v":1,"seq":([0-9]+),"id":"([0-9a-f]{64})"`)

// FuzzVerify feeds Reader.Verify and Reader.Iter an events.jsonl a tamperer wrote. The property is the tamper
// evidence itself, checked by a second implementation of R2, I3 and I4 over encoding/json rather than through
// record.Chain: when Verify reports no error, every line it counted re-hashes to its own id with the id
// zeroed, carries its position as seq and the previous line's id as prev, and names the run Verify reports;
// the head is the last line's id, an unterminated chunk with a lexically closed top-level value is checked in full,
// and only a chunk with no closed value can be exactly TornBytes long,
// an anchored run's head is the anchor's, and Iter yields exactly the lines Verify counted. A failure is
// ErrUnverified from Verify, since reading a regular file cannot fail, and ErrCorruptLedger from Iter.
//
// The seeds are a small ledger the real Writer closed and anchored, and the first lines of the committed
// fixture, which belong to another run. In the named mode the run directory is named after the Writer's run,
// so the anchor lookup and the run-mismatch check are reachable; otherwise it is a copy under another name.
func FuzzVerify(f *testing.F) {
	anchor := &memAnchor{}
	dir := filepath.Join(f.TempDir(), testRef.ID)
	w, err := Open(dir, testRef, WithClock(newStepClock(fixedStart, 5_000_000_000, time.Millisecond)), WithAnchor(anchor))
	if err != nil {
		f.Fatal(err)
	}
	if err := w.WriteRunStart(startPayload()); err != nil {
		f.Fatal(err)
	}
	for _, ev := range []*record.Event{fsEvent("/work/out/a", nil), gapEvent("channel-full")} {
		if err := w.Append(ev); err != nil {
			f.Fatal(err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndStopped}); err != nil {
		f.Fatal(err)
	}
	closed, err := os.ReadFile(filepath.Join(dir, EventsFile))
	if err != nil {
		f.Fatal(err)
	}
	head, ok, _ := anchor.Head(testRef.ID)
	if !ok {
		f.Fatal("the Writer's Close anchored nothing")
	}
	fixture, err := os.ReadFile(filepath.Join("..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl"))
	if err != nil {
		f.Fatal(err)
	}
	lines := bytes.SplitAfter(closed, []byte("\n"))
	live := bytes.Join(lines[:len(lines)-2], nil) // run_end and the empty remainder dropped: a live run
	const named, anchored = 1, 2
	f.Add(closed, uint8(named|anchored), head)
	f.Add(closed, uint8(named), "")
	f.Add(closed, uint8(0), "")
	f.Add(live, uint8(named|anchored), head)
	f.Add(append(bytes.Clone(live), lines[len(lines)-2][:40]...), uint8(named), "") // a torn tail (E6)
	f.Add(append(bytes.Clone(closed), `{"v":1`...), uint8(named|anchored), head)
	f.Add(bytes.Join(bytes.SplitAfter(fixture, []byte("\n"))[:3], nil), uint8(named), "")
	// A tamperer's two cheapest edits, which keep every line's own id valid: a line deleted, two swapped.
	f.Add(bytes.Join(append(slices.Clone(lines[:1]), lines[2:]...), nil), uint8(named|anchored), head)
	f.Add(bytes.Join([][]byte{lines[0], lines[2], lines[1], lines[3]}, nil), uint8(named|anchored), head)
	f.Add([]byte{}, uint8(named|anchored), head)
	// One directory of each name per fuzzing process, whose events.jsonl each input rewrites: a t.TempDir per
	// input made and removed a directory every time and slowed the fuzzer to a few inputs a minute.
	base := f.TempDir()
	for _, name := range []string{"copy", testRef.ID} {
		if err := os.Mkdir(filepath.Join(base, name), 0o700); err != nil {
			f.Fatal(err)
		}
	}
	f.Fuzz(func(t *testing.T, events []byte, mode uint8, anchorHead string) {
		name := "copy"
		if mode&named != 0 {
			name = testRef.ID
		}
		dir := filepath.Join(base, name)
		if err := os.WriteFile(filepath.Join(dir, EventsFile), events, 0o600); err != nil {
			t.Fatal(err)
		}
		var anchor ChainAnchor
		if mode&anchored != 0 {
			anchor = &memAnchor{heads: map[string]string{testRef.ID: anchorHead}}
		}
		r, err := OpenReader(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		rep, verr := r.Verify(context.Background(), anchor)
		var iterIDs []string
		var iterErr error
		for e, err := range r.Iter() {
			if err != nil {
				iterErr = err
				break
			}
			iterIDs = append(iterIDs, e.ID)
		}
		if iterErr != nil && !errors.Is(iterErr, ErrCorruptLedger) {
			t.Fatalf("Iter failed with %v, which is not ErrCorruptLedger", iterErr)
		}
		if verr != nil {
			if !errors.Is(verr, ErrUnverified) {
				t.Fatalf("Verify failed with %v, which is not ErrUnverified", verr)
			}
			return
		}
		ids := recheckChain(t, events, rep)
		if iterErr != nil {
			t.Fatalf("Verify passed and Iter failed: %v", iterErr)
		}
		if !slices.Equal(iterIDs, ids) {
			t.Fatalf("Iter yielded %d ids, Verify verified %d: %v vs %v", len(iterIDs), len(ids), iterIDs, ids)
		}
		switch {
		case rep.Anchored && anchorHead != rep.Head:
			t.Fatalf("anchored at %q, but the ledger's head is %q", anchorHead, rep.Head)
		case anchor != nil && rep.Run == testRef.ID && !rep.Anchored:
			t.Fatalf("the anchor holds a line for %s and Verify passed without consulting it", rep.Run)
		}
	})
}

// recheckChain is FuzzVerify's second implementation of the chain rules: it splits the bytes into the lines
// Verify should have counted and checks each one without record.Chain, returning their ids in order.
func recheckChain(t *testing.T, events []byte, rep VerifyReport) []string {
	t.Helper()
	var lines [][]byte
	for rest := events; len(rest) > 0; {
		i := bytes.IndexByte(rest, '\n')
		if i >= 0 {
			lines = append(lines, rest[:i])
			rest = rest[i+1:]
			continue
		}
		// Verify succeeded: a retained chunk with a lexically closed top-level value must decode,
		// including its suffix; otherwise only a chunk with no closed value may be torn (§4, E6).
		if _, err := record.Decode(rest); err == nil {
			lines = append(lines, rest)
		} else if rep.TornBytes != len(rest) {
			t.Fatalf("a torn tail of %d bytes reported as %d", len(rest), rep.TornBytes)
		}
		break
	}
	if uint64(len(lines)) != rep.Lines {
		t.Fatalf("Verify counted %d lines, the file holds %d", rep.Lines, len(lines))
	}
	ids := make([]string, len(lines))
	prev := ""
	for i, line := range lines {
		m := canonicalHead.FindSubmatchIndex(line)
		if m == nil {
			t.Fatalf("line %d verified but does not start the way R2 fixes: %.80q", i, line)
		}
		if seq, err := strconv.ParseUint(string(line[m[2]:m[3]]), 10, 64); err != nil || seq != uint64(i) {
			t.Fatalf("line %d verified with seq %s (I4)", i, line[m[2]:m[3]])
		}
		id := string(line[m[4]:m[5]])
		zeroed := bytes.Clone(line)
		copy(zeroed[m[4]:m[5]], record.ZeroID)
		if sum := sha256.Sum256(zeroed); hex.EncodeToString(sum[:]) != id {
			t.Fatalf("line %d verified but its bytes hash to %x, not its id %s (R2)", i, sum, id)
		}
		var fields struct {
			Prev *string `json:"prev"`
			Run  string  `json:"run"`
			Kind string  `json:"kind"`
		}
		if err := json.Unmarshal(line, &fields); err != nil {
			t.Fatalf("line %d verified but is not JSON: %v", i, err)
		}
		if p := fields.Prev; (p == nil && prev != "") || (p != nil && *p != prev) {
			t.Fatalf("line %d verified with prev %v, want %q (I3)", i, p, prev)
		}
		if fields.Run != rep.Run {
			t.Fatalf("line %d is run %q in a ledger verified as %q", i, fields.Run, rep.Run)
		}
		if i == 0 && rep.Started != (fields.Kind == string(record.KindRunStart)) {
			t.Fatalf("Started=%v with a first line of kind %q", rep.Started, fields.Kind)
		}
		ids[i], prev = id, id
	}
	if rep.Head != prev {
		t.Fatalf("head %q, want the last line's id %q", rep.Head, prev)
	}
	return ids
}

// fuzzBlobName is the name FuzzBody gives the i-th file of its blobs directory. The names are not the files'
// sha256, because a splice must be able to name another file and a fuzzer cannot write a digest; Body never
// checks a blob's bytes against its name (E16), so any 64-hex name reaches the same code.
func fuzzBlobName(i int) string { return fmt.Sprintf("%064x", i+1) }

// fuzzBlobFiles is how many files FuzzBody's input may describe; "#0" to "#7" in a file name them.
const fuzzBlobFiles = 8

// fuzzBlobs is a read-only blobs directory held in memory that counts what Body opens and reads, which
// is what R11's budgets bound.
type fuzzBlobs struct {
	files map[string][]byte
	opens int64
	read  int64
}

func (c *fuzzBlobs) Get(sha string) (io.ReadCloser, error) {
	c.opens++
	b, ok := c.files[sha]
	if !ok {
		return nil, fmt.Errorf("fuzz blob %s: %w", sha, os.ErrNotExist)
	}
	return io.NopCloser(&fuzzReadCounter{r: bytes.NewReader(b), n: &c.read}), nil
}

func (c *fuzzBlobs) Has(sha string) (bool, error) { _, ok := c.files[sha]; return ok, nil }

func (c *fuzzBlobs) Put([]byte) (string, error) { return "", errors.New("fuzz blobs are read-only") }

func (c *fuzzBlobs) PutStream(io.Reader) (string, int64, error) {
	return "", 0, errors.New("fuzz blobs are read-only")
}

// fuzzReadCounter adds every byte read through it to *n.
type fuzzReadCounter struct {
	r io.Reader
	n *int64
}

func (c *fuzzReadCounter) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	*c.n += int64(k)
	return k, err
}

// FuzzBody's mode bits, the third value of its input. The fuzzer sets any bit of the uint8, and an input
// committed under testdata/fuzz/FuzzBody means what its bits meant when it was committed, so a bit given a
// meaning later would change what every committed input with that bit set tests: the input for the unbounded
// blob read (below) had mode 'y', which sets bit 8, and ran as a hugeSize input once bit 8 was given that
// meaning, with no size bound left to check. TestFuzzBodyCorpusSetsOnlyKnownModes holds every committed input
// to fuzzBodyModes, so a new bit reinterprets none of them.
const (
	fuzzBodyBlob   = 1 // the event names file 0 as its whole body, not as a splice
	fuzzBodyHonest = 2 // body_sha256 is the plain expansion's sha256, so a rebuild can succeed
	fuzzBodyNoSize = 4 // with fuzzBodyBlob: the event is an ssl_response, which records no size
	fuzzBodyHuge   = 8 // the event records 2^63-1-size, held to 1 GiB
	fuzzBodyModes  = fuzzBodyBlob | fuzzBodyHonest | fuzzBodyNoSize | fuzzBodyHuge
)

// fuzzBodyHugeWork is the most work, in parts visited and bytes read or appended, a hugeSize splice input may
// take in FuzzBody. At 1 GiB R11 lets Body open 1.3 million files and read over 3 GiB for one body, which a
// fuzz worker cannot spend on one input, and the wrap hugeSize exists for is reached by a splice of a few files.
const fuzzBodyHugeWork = 1 << 24

// FuzzBody feeds Reader.Body a blobs directory a tamperer wrote. The input is up to eight files separated
// by NUL, in which "#k" stands for the k-th file's name; the event names file 0 as its frame (or, in one
// mode, as its whole-body blob) and records size. The properties are R11's:
//
//   - the work is bounded by size whatever the files hold: at most 5·size/4 KiB + 8 files opened, and at
//     most 3·size + 256 per file allowed + 64 KiB bytes of splices plus size bytes of raw blobs read (one
//     byte more each, the probe that finds a file too large);
//   - a refusal is ErrCorruptBlob, and a body is refused for its cost only past those budgets: in honest
//     mode, where body_sha256 is the plain expansion's, a body whose plain expansion opens and reads no more
//     than they allow is returned (plainExpand keeps R11's third budget, two parts per byte, itself);
//   - a body that is returned is at most size bytes, hashes to the event's body_sha256, and is what a
//     plain recursive expansion of the same files rebuilds.
//
// The seeds include the fan-out the R11 amendment of 2026-09-22 records (one splice naming, forty times,
// a splice padded with whitespace), whose reads the byte budget exists to stop.
//
// In blob mode (the event names one file as the whole body) the same properties take their one-file form:
// one file opened and at most size+1 bytes of it read, a file longer than size refused with ErrCorruptBlob,
// and any other file returned as it is. With noSize as well the event is an ssl_response, whose payload has
// no size field, and the bound is R11's 1 GiB, which no input here reaches, so the file comes back whole.
// Blob mode once checked only that the file came back, because Body read it whole whatever its size (E16).
// testdata/fuzz/FuzzBody/65691599bdbfde99 is the fuzzer's input for that unbounded read, a 64-byte file for a
// body of 19 bytes, with its mode rewritten from 'y' to '\x01' when bit 8 became hugeSize: blob mode alone,
// which is what 'y' selected when the fuzzer found it.
//
// In hugeSize mode, splice or blob, the event records a size within 2^16 of 2^63-1, which the forwarder
// writes for a client that declared such a Content-Length, and R11 holds it to 1 GiB, so the properties are
// those of a 1 GiB body. The size the fuzzer picks is otherwise at most 2^16, which never reached the wrap
// that a size of 2^63-1 caused, an empty body returned with no error, or the one a size near it caused in
// expand's budgets, which refused an honest splice. A hugeSize splice whose plain expansion takes more than
// fuzzBodyHugeWork is skipped: Body walks the same files, and budgets for 1 GiB would not stop it much sooner.
func FuzzBody(f *testing.F) {
	join := func(files ...string) []byte { return []byte(strings.Join(files, "\x00")) }
	f.Add(join(`{"v":1,"parts":[{"text":"{\"messages\":"},{"splice":"#1"},{"text":"}"}]}`,
		`{"v":1,"parts":[{"blob":"#2"},{"text":","},{"blob":"#3"}]}`,
		`[{"role":"user","content":"hi"}`, `{"role":"assistant","content":"hello"}]`), uint16(4096), uint8(fuzzBodyHonest))
	fanOut := `{"v":1,"parts":[` + strings.Repeat(`{"splice":"#1"},`, 39) + `{"splice":"#1"}]}`
	f.Add(join(fanOut, `{"v":1,"parts":[{"blob":"#2"}]}`+strings.Repeat(" ", 8<<10), ``), uint16(4096), uint8(fuzzBodyHonest))
	// The same fan-out padded past what the file budget alone keeps small: the byte budget is what stops it.
	f.Add(join(fanOut, `{"v":1,"parts":[{"blob":"#2"}]}`+strings.Repeat(" ", 32<<10), ``), uint16(1024), uint8(fuzzBodyHonest))
	f.Add(join(`{"v":1,"parts":[{"splice":"#0"}]}`), uint16(64), uint8(fuzzBodyHonest))
	f.Add(join(`{"v":1,"parts":[]}`), uint16(64), uint8(fuzzBodyHonest))
	f.Add(join(`{"v":1,"parts":[{"text":"a","blob":"#1"}]}`, `b`), uint16(64), uint8(fuzzBodyHonest))
	f.Add(join(`{"v":1,"parts":[{"blob":"#1"}]}`, strings.Repeat("x", 100)), uint16(64), uint8(fuzzBodyHonest))
	f.Add(join(`{"v":1,"parts":[{"text":"body"}]}`), uint16(64), uint8(0))
	f.Add(join(`the whole body`), uint16(14), uint8(fuzzBodyBlob))
	// A body's blob replaced by a longer file (E16): the event says 10 bytes, the file holds 100.
	f.Add(join(strings.Repeat("x", 100)), uint16(9), uint8(fuzzBodyBlob))
	f.Add(join(`the whole response`), uint16(0), uint8(fuzzBodyBlob|fuzzBodyNoSize))
	f.Add(join(`the whole body, declared as 2^63-1 bytes`), uint16(0), uint8(fuzzBodyBlob|fuzzBodyHuge))
	// An honest splice declared as 2^63-1 bytes, which fits R11's budgets for 1 GiB and so has to come back.
	f.Add(join(`{"v":1,"parts":[{"text":"{\"messages\":"},{"blob":"#1"},{"text":"}"}]}`, `[]`), uint16(0),
		uint8(fuzzBodyHonest|fuzzBodyHuge))
	f.Fuzz(func(t *testing.T, input []byte, size uint16, mode uint8) {
		limit, recorded := int64(size)+1, int64(size)+1
		if mode&fuzzBodyHuge != 0 {
			limit, recorded = 1<<30, math.MaxInt64-int64(size)
		}
		repo := &fuzzBlobs{files: map[string][]byte{}}
		for i, b := range bytes.SplitN(input, []byte{0}, fuzzBlobFiles) {
			for k := range fuzzBlobFiles {
				b = bytes.ReplaceAll(b, []byte("#"+strconv.Itoa(k)), []byte(fuzzBlobName(k)))
			}
			repo.files[fuzzBlobName(i)] = b
		}
		root := fuzzBlobName(0)
		payload := map[string]any{"size": recorded}
		kind := record.KindSSLRequest
		if mode&fuzzBodyBlob != 0 && mode&fuzzBodyNoSize != 0 {
			delete(payload, "size")
			kind = record.KindSSLResponse
		}
		var plain plainExpansion
		if mode&fuzzBodyBlob != 0 {
			// A blob is named by the sha256 of its bytes, which Body checks: the file is stored under that name.
			sum := sha256.Sum256(repo.files[root])
			name := hex.EncodeToString(sum[:])
			repo.files[name] = repo.files[root]
			root = name
			payload["blob"] = root
		} else {
			work := int64(math.MaxInt64)
			if mode&fuzzBodyHuge != 0 {
				work = fuzzBodyHugeWork
			}
			// Body walks the files in the order plainExpand does and stops no later, so what plainExpand
			// finishes within work, Body does too.
			if plain = plainExpand(repo.files, root, limit, work); plain.cut {
				t.Skipf("a %d-byte splice whose plain expansion takes more than %d", limit, work)
			}
			payload["frame"] = root
			sum := sha256.Sum256([]byte("not the body"))
			if mode&fuzzBodyHonest != 0 && plain.ok {
				sum = sha256.Sum256(plain.body)
			}
			payload["body_sha256"] = hex.EncodeToString(sum[:])
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		r := &Reader{blobs: repo}
		body, err := r.Body(&record.Event{Kind: kind, Payload: raw})
		if mode&fuzzBodyBlob != 0 {
			// R11's one-file bound, stated here rather than through maxSpliceBody for the reason the splice
			// bounds below give: the event's size, or 1 GiB for an event that records none.
			bound := limit
			if _, sized := payload["size"]; !sized {
				bound = 1 << 30
			}
			file := repo.files[root]
			if repo.opens != 1 {
				t.Fatalf("Body opened %d files for a body stored as one", repo.opens)
			}
			if repo.read > bound+1 {
				t.Fatalf("Body read %d bytes of a blob for a body of %d bytes; R11 allows %d", repo.read, bound, bound+1)
			}
			if int64(len(file)) > bound {
				if !errors.Is(err, ErrCorruptBlob) {
					t.Fatalf("Body of a %d-byte blob for a body of %d bytes = %d bytes, %v; want ErrCorruptBlob",
						len(file), bound, len(body), err)
				}
				return
			}
			if err != nil || !bytes.Equal(body, file) {
				t.Fatalf("Body of blob %s = %q, %v; want the file's bytes", root, body, err)
			}
			return
		}
		// R11's bounds as record-ledger.md states them, computed here rather than through spliceOpens and
		// spliceBytes, so that loosening those cannot loosen the check along with them.
		opens := 5*limit/(4<<10) + 8
		spliceRead := 3*limit + 256*opens + 64<<10
		if repo.opens > opens {
			t.Fatalf("Body opened %d files for a body of %d bytes; R11 allows %d", repo.opens, limit, opens)
		}
		if most := spliceRead + limit + 2; repo.read > most {
			t.Fatalf("Body read %d bytes for a body of %d bytes; R11 allows %d", repo.read, limit, most)
		}
		if err != nil {
			if !errors.Is(err, ErrCorruptBlob) {
				t.Fatalf("Body refused with %v, which is not ErrCorruptBlob", err)
			}
			// plainExpand makes every refusal expand makes but the two budgets above, the parts budget included,
			// so an honest body within those two is one Body rebuilds as plainExpand did, to body_sha256.
			if mode&fuzzBodyHonest != 0 && plain.ok && plain.opens <= opens && plain.spliceBytes <= spliceRead {
				t.Fatalf("Body refused an honest %d-byte body of %d files and %d bytes of splices, which R11 allows "+
					"for a body of %d bytes (%d files, %d bytes): %v", len(plain.body), plain.opens, plain.spliceBytes,
					limit, opens, spliceRead, err)
			}
			return
		}
		if int64(len(body)) > limit {
			t.Fatalf("Body returned %d bytes for an event of size %d", len(body), limit)
		}
		if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != payload["body_sha256"] {
			t.Fatalf("Body returned bytes that do not hash to body_sha256")
		}
		if !plain.ok || !bytes.Equal(body, plain.body) {
			t.Fatalf("Body rebuilt %q; a plain expansion of the same files gives %q (ok=%v)", body, plain.body, plain.ok)
		}
	})
}

// plainExpansion is what plainExpand rebuilt and what that cost, counted as R11 counts expand's work.
type plainExpansion struct {
	body []byte
	// ok reports that the files rebuild a body of at most the limit.
	ok bool
	// opens counts the files opened, splices and blobs together, and spliceBytes the bytes of the splices
	// among them: what R11's first two budgets bound.
	opens, spliceBytes int64
	// cut reports that the expansion passed the work it was allowed and stopped, so ok and body say nothing.
	cut bool
}

// plainExpand is FuzzBody's reference: the splice format of messages.go expanded by plain recursion, with
// none of expand's budgets except the part count and the size. It refuses what expand must refuse whatever
// its budgets allow: a name that is not a sha, a missing file, a splice that does not parse, is not version
// 1, has no parts or contains itself, a part that is not exactly one of text, blob and splice, and a result
// over limit. The recursion is at most fuzzBlobFiles deep, since a splice on its own path is refused. It
// stops, cut, once the parts it has visited and the bytes it has read or appended pass work.
func plainExpand(files map[string][]byte, root string, limit, work int64) plainExpansion {
	var (
		x       plainExpansion
		out     []byte
		visited int64
		spent   int64
		onPath  = map[string]bool{}
		walk    func(sha string) bool
	)
	spend := func(n int64) bool {
		if spent += n; spent > work {
			x.cut = true
		}
		return !x.cut
	}
	walk = func(sha string) bool {
		b, ok := files[sha]
		if !IsSHA(sha) || !ok || onPath[sha] {
			return false
		}
		x.opens++
		x.spliceBytes += int64(len(b))
		if !spend(int64(len(b))) {
			return false
		}
		var s splice
		if json.Unmarshal(b, &s) != nil || s.V != spliceVersion || len(s.Parts) == 0 {
			return false
		}
		onPath[sha] = true
		defer delete(onPath, sha)
		for _, p := range s.Parts {
			if visited++; visited > 2*limit || !spend(1) {
				return false
			}
			switch {
			case p.Splice != "" && p.Blob == "" && p.Text == "":
				if !walk(p.Splice) {
					return false
				}
			case p.Blob != "" && p.Splice == "" && p.Text == "":
				b, ok := files[p.Blob]
				if !IsSHA(p.Blob) || !ok {
					return false
				}
				x.opens++
				if !spend(int64(len(b))) {
					return false
				}
				out = append(out, b...)
			case p.Text != "" && p.Blob == "" && p.Splice == "":
				if !spend(int64(len(p.Text))) {
					return false
				}
				out = append(out, p.Text...)
			default:
				return false
			}
			if int64(len(out)) > limit {
				return false
			}
		}
		return true
	}
	if walk(root) && !x.cut {
		x.body, x.ok = out, true
	}
	return x
}

// TestFuzzBodyCorpusSetsOnlyKnownModes holds every input committed under testdata/fuzz/FuzzBody to the mode
// bits FuzzBody gives a meaning (fuzzBodyModes), so that a bit defined later cannot change what one tests. A
// fuzzer's new input for this target is committed with its other bits cleared, which FuzzBody ignores.
func TestFuzzBodyCorpusSetsOnlyKnownModes(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "fuzz", "FuzzBody", "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no committed FuzzBody input, so the unbounded blob read has no regression seed")
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 4 || lines[0] != "go test fuzz v1" {
			t.Fatalf("%s is not a FuzzBody input of three values: %q", path, lines)
		}
		mode, ok := parseFuzzByte(lines[3])
		if !ok {
			t.Fatalf("%s: the third value %q is not FuzzBody's mode as go test writes a uint8", path, lines[3])
		}
		if mode&^fuzzBodyModes != 0 {
			t.Errorf("%s sets mode bits %#x that FuzzBody gives no meaning; a bit defined later would change what it tests",
				path, mode&^fuzzBodyModes)
		}
	}
}

// parseFuzzByte reads a uint8 value of a go test fuzz v1 file, byte('\x01') as go test writes it or uint8(1).
func parseFuzzByte(v string) (uint64, bool) {
	inner, ok := strings.CutPrefix(v, "byte(")
	if !ok {
		if inner, ok = strings.CutPrefix(v, "uint8("); !ok {
			return 0, false
		}
	}
	if inner, ok = strings.CutSuffix(inner, ")"); !ok {
		return 0, false
	}
	if lit, quoted := strings.CutPrefix(inner, "'"); quoted {
		lit, closed := strings.CutSuffix(lit, "'")
		r, _, rest, err := strconv.UnquoteChar(lit, '\'')
		return uint64(r), closed && err == nil && rest == "" && r <= 0xff
	}
	n, err := strconv.ParseUint(inner, 0, 8)
	return n, err == nil
}
