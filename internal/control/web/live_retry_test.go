// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Run the served functions in node, as twin_test does, with deterministic fetches and timers.
func TestLiveRegionsRetryQuietRevision(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node to run static/live.js in")
	}
	src, err := assets.ReadFile("static/live.js")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "-e", liveRetryHarness)
	cmd.Stdin = strings.NewReader(string(src))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
}

const liveRetryHarness = `
const assert = require('node:assert/strict'), fs = require('node:fs');
const src = fs.readFileSync(0,'utf8');
const init = src.slice(src.indexOf('  var sig ='),src.indexOf('  function title('));
const state = src.slice(src.indexOf('  function onState('),src.indexOf('  function poll()'));
const refreshCode = src.slice(src.indexOf('  // refresh fetches'),src.indexOf('  // more puts'));
const d={sig:'old',rev:1};var out=false,feed=null,deferred=false,release=null;
var timers=[],fetches=0,fail=true,merges=0;
function title(){} function more(){} function ago(){} function gone(r){if(r.status===401)out=true;throw Error(r.status);}
function shown(){return ['asks:old'];} function selecting(){return false;} function kids(){merges++;}
function setTimeout(fn,ms){assert(ms>0 && ms<=30000);timers.push({fn,ms});return timers.length;}
function clearTimeout(){} const location={pathname:'/approvals',search:''};
const window={tegoLive:{}}; const body={};
const document={activeElement:body,dispatchEvent(){},querySelector(){return {dataset:{}};},createElement(){return {set innerHTML(v){},content:{querySelectorAll(){return [{dataset:{live:'asks',h:'new'},content:{}}];}}};}};
function CustomEvent(){} function fetch(){fetches++;const response={ok:true,text:()=>Promise.resolve('<template>')};if(deferred)return new Promise(r=>{release=()=>r(response);});return fail?Promise.reject(Error('once')):Promise.resolve(response);}
eval(init+'\n'+state+'\n'+refreshCode);
const flush=async()=>{for(let i=0;i<12;i++)await Promise.resolve();};
(async()=>{
 onState({sig:'pending',rev:2,pending:1});await flush();
 assert.equal(fetches,1);assert.equal(renderedRev,1,'a failed fetch rendered nothing');
 assert.equal(timers.length,1,'failed region fetch must schedule a retry without a ledger event');
 // The initial state on reconnect is identical. The timer must still recover the ask card.
 onState({sig:'pending',rev:2,pending:1});await flush();
 fail=false;last=0;timers.shift().fn();await flush();
 assert(merges>0,'pending ask was not rendered');assert.equal(renderedRev,2);assert.equal(renderedSig,'pending');
 // Persistent failure backs off to a ceiling, and success resets it.
 timers=[];fail=true;last=0;onState({sig:'next',rev:3,pending:1});await flush();
 for(let i=0;i<8;i++){assert.equal(timers.length,1);last=0;timers.shift().fn();await flush();}
 assert.equal(timers[0].ms,30000);fail=false;last=0;timers.shift().fn();await flush();assert.equal(regionBackoff,1000);
 // A state received during a fetch cannot be marked rendered by that older response.
 timers=[];last=0;deferred=true;onState({sig:'four',rev:4,pending:1});await flush();const first=release;
 onState({sig:'five',rev:5,pending:1});last=0;first();await flush();
 assert.equal(renderedRev,4,'the response rendered revision four, although five was received');
 const second=release;deferred=false;second();await flush();assert.equal(renderedRev,5);
})().catch(e=>{console.error(e);process.exitCode=1;});
`
