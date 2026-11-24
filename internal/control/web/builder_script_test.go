// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// nodeHarnessHangGuard bounds a harness once it runs; it is far above what promise chaining needs.
const nodeHarnessHangGuard = 30 * time.Second

// nodeHarnessStarted is what runNodeHarness has node write on stderr as the harness's first act.
const nodeHarnessStarted = "node-harness-started\n"

// runNodeHarness runs the script harness in node with stdin as its input and returns what it wrote on stdout.
// How long node takes to start is the machine's, not the page script's, and under load it can be many seconds. So
// no clock runs until node itself says it is executing the harness; from then on the harness only chains
// in-memory promises, and nodeHarnessHangGuard is a hang guard for a script that never settles, not a pass/fail
// timer. A node that exits before it reports (it failed to start, or finished at once) fails or passes on its status.
func runNodeHarness(t *testing.T, node, harness string, stdin []byte) string {
	t.Helper()
	var stdout bytes.Buffer
	diag := &startedWriter{started: make(chan struct{})}
	cmd := exec.Command(node, "-e", "process.stderr.write('node-harness-started\\n');\n"+harness)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = &stdout, diag
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	finish := func(err error) string {
		if err != nil {
			t.Fatalf("node: %v\n%s%s", err, stdout.String(), diag.String())
		}
		return stdout.String()
	}
	select {
	case err := <-done:
		return finish(err)
	case <-diag.started:
	}
	guard := time.NewTimer(nodeHarnessHangGuard)
	defer guard.Stop()
	select {
	case err := <-done:
		return finish(err)
	case <-guard.C:
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("node: the harness started and never settled in %v\n%s%s", nodeHarnessHangGuard, stdout.String(), diag.String())
	}
	return ""
}

// A cancelled transport may already have delivered its response. Only the preview
// generation can decide whether those bytes still describe the person's draft.
func TestBuilderPreviewDiscardsResponsesAfterInput(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node to run the builder script in")
	}
	src, err := assets.ReadFile("static/builder.js")
	if err != nil {
		t.Fatal(err)
	}
	runNodeHarness(t, node, builderPreviewHarness, src)
}

const builderPreviewHarness = `
const assert=require('node:assert/strict'),vm=require('node:vm');
const source=require('node:fs').readFileSync(0,'utf8');
function deferred(){let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};}
(async()=>{
 for(const delayed of ['headers','body']){
  const handlers={},pending=[],button={disabled:false},say={textContent:''},draft={value:'initial-draft'};let replacements=0;
  const result={replaceWith(){replacements++;button.disabled=false;}};
  const form={dataset:{},action:'/rules/new',isConnected:true,
   addEventListener(k,f){handlers[k]=f;},querySelector(q){return q==='[name="current-view"]'?{value:'simple'}:q==='[name="draft"]'?draft:null;},
   querySelectorAll(){return [];},before(){}};
  const document={readyState:'complete',addEventListener(){},
   getElementById(id){return {'builder-edit':form,'builder-result':result,'builder-updates':say}[id]||null;},
   querySelector(){return null;},querySelectorAll(){return [button];}};
  const context=vm.createContext({document,window:{addEventListener(){}},AbortController,
   matchMedia(){return {matches:false};},URLSearchParams,FormData:class{*[Symbol.iterator](){yield ['draft',draft.value];}},
   DOMParser:class{parseFromString(text){return {getElementById(id){return id==='builder-result'?{}:id==='builder-edit'?{querySelector(){return {value:text.includes('current preview')?'rotated-draft':'stale-draft'};}}:null;}};}},
   fetch(url,options){const headers=deferred(),body=deferred();pending.push({headers,body,postedDraft:options.body.get('draft')});return headers.promise;}});
  vm.runInContext(source,context,{filename:'builder.js'});
  const preview=handlers.change();
  if(delayed==='body'){pending[0].headers.resolve({ok:true,text(){return pending[0].body.promise;}});await Promise.resolve();}
  handlers.input();assert.equal(button.disabled,true,'input must disable the earlier Save');
  pending[0].headers.resolve({ok:true,text(){return pending[0].body.promise;}});
  pending[0].body.resolve('<main>old preview</main>');await preview;
  assert.equal(replacements,0,delayed+': an older preview must never install an enabled Save');
  assert.equal(button.disabled,true,delayed+': the current unreviewed draft stays unsaveable');
  assert.equal(draft.value,'initial-draft','a stale preview must not rotate the current draft');
  const fresh=handlers.change();pending[1].headers.resolve({ok:true,text(){return pending[1].body.promise;}});
  pending[1].body.resolve('<main>current preview</main>');await fresh;
  assert.equal(replacements,1,'a response for the current generation still installs its preview');
  assert.equal(draft.value,'rotated-draft','the accepted preview refreshes the editor draft token');
  const next=handlers.change();assert.equal(pending[2].postedDraft,'rotated-draft','the next post uses the refreshed draft token');
  pending[2].headers.resolve({ok:true,text(){return pending[2].body.promise;}});
  pending[2].body.resolve('<main>current preview</main>');await next;
 }
})().catch(e=>{console.error(e);process.exitCode=1;});
`

// startedWriter collects node's diagnostics and closes started when the harness reports it is running.
type startedWriter struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	once    sync.Once
	started chan struct{}
}

func (w *startedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if bytes.Contains(w.buf.Bytes(), []byte(nodeHarnessStarted)) {
		w.once.Do(func() { close(w.started) })
	}
	return len(p), nil
}

func (w *startedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}
