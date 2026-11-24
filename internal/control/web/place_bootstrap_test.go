// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"os/exec"
	"testing"
)

// TestPlaceBootstrapKeepsEarlyAskAnnouncements runs both served scripts with place.js deliberately delayed.
// The initial requests stay quiet, while a request arriving during that delay is announced once.
// Answered keys are retired, so the remembered set stays bounded by the requests still pending.
func TestPlaceBootstrapKeepsEarlyAskAnnouncements(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node to run the live and place scripts in")
	}
	sources := make(map[string]string)
	for _, name := range []string{"live", "place"} {
		src, err := assets.ReadFile("static/" + name + ".js")
		if err != nil {
			t.Fatal(err)
		}
		sources[name] = string(src)
	}
	input, err := json.Marshal(sources)
	if err != nil {
		t.Fatal(err)
	}
	runNodeHarness(t, node, placeBootstrapHarness, input)
}

const placeBootstrapHarness = `
const assert=require('node:assert/strict'),vm=require('node:vm');
const sources=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
for (const [initial,arrived,want] of [['old','old',0],['old','old early',1],['','early',1]]) {
 let keys=initial,spoken=0,loaded=[],timers=[],text='',navPresent=true,pendingState;
 // Observe the production pending map itself, without exposing a testing hook in either served script.
 const trackedObject=new Proxy(Object,{get(target,name,receiver){
  if(name==='create')return function(prototype,...rest){
   const value=Object.create(prototype,...rest);if(prototype===null)pendingState=value;return value;
  };
  return Reflect.get(target,name,receiver);
 }});
 const handlers={},windowHandlers={};
 const say={get textContent(){return text;},set textContent(v){text=v;if(v)spoken++;}};
 const nav={dataset:{get askKeys(){return keys;}}};
 const strip={scrollLeft:0,clientWidth:50,scrollWidth:180,classList:{toggle(){}},addEventListener(){},querySelector(){return {offsetLeft:100,offsetWidth:50};}};
 const body={dataset:{sig:'initial',rev:'1',title:'Tego'},setAttribute(){}};
 const document={body,hidden:false,head:{appendChild(s){loaded.push(s.src);}},
  querySelector(q){return q==='.nav[data-ask-keys]'&&navPresent?nav:null;},
  querySelectorAll(q){return q==='.tabs'?[strip]:[];},
  getElementById(id){return id==='ask-say'?say:null;},createElement(){return {};},
  addEventListener(k,f){(handlers[k]??=[]).push(f);},
  dispatchEvent(e){for(const f of handlers[e.type]||[])f(e);}};
 const window={scrollY:0,addEventListener(k,f){(windowHandlers[k]??=[]).push(f);}};
 class EventSource {constructor(){keys=arrived;document.dispatchEvent({type:'tego:merged'});}addEventListener(){}close(){}}
 window.EventSource=EventSource;
 const context=vm.createContext({window,document,EventSource,Object:trackedObject,CustomEvent:class{constructor(type){this.type=type;}},
  location:{pathname:'/runs',search:'',hash:''},history:{state:null,replaceState(){}},
  performance:{getEntriesByType(){return [];}},sessionStorage:{getItem(){return null;},removeItem(){}},
  setTimeout(fn){timers.push(fn);return timers.length;},setInterval(){return 1;},clearTimeout(){}});
 vm.runInContext(sources.live,context,{filename:'live.js'});
 assert.deepEqual(loaded,['/static/place.js','/static/guide.js'],'live.js must load the presentation and guide scripts');
 vm.runInContext(sources.place,context,{filename:'place.js'});
 function flush(){while(timers.length)timers.shift()();}
 function merged(){document.dispatchEvent({type:'tego:merged'});flush();}
 function retained(expected){
  assert.deepEqual(Object.keys(pendingState).sort(),[...new Set(expected.split(' ').filter(Boolean))].sort(),
   'remembered request keys must match the current pending set');
 }
 flush();assert.equal(spoken,want,'initial requests stay quiet and arrivals during bootstrap are announced');
 document.dispatchEvent({type:'tego:enter'});flush();
 assert.equal(spoken,want,'entering a view with the same initial or early requests stays quiet');
 document.dispatchEvent({type:'tego:merged'});flush();
 assert.equal(spoken,want,'the same request must not be announced twice');
 keys+=' later';document.dispatchEvent({type:'tego:merged'});flush();
 assert.equal(spoken,want+1,'a later request must still be announced');
 const base=keys;let expectedSpeech=want+1;
 retained(base);
 for(let i=0;i<100;i++){
  keys=base+' cycle-'+i;merged();expectedSpeech++;
  assert.equal(spoken,expectedSpeech,'each newly pending request is announced once');retained(keys);
  merged();assert.equal(spoken,expectedSpeech,'an unchanged pending request stays quiet');
  keys=base;merged();
  assert.equal(spoken,expectedSpeech,'an answer does not announce a new request');retained(base);
 }
 navPresent=false;merged();retained(base);
 navPresent=true;merged();
 assert.equal(spoken,expectedSpeech,'a temporarily absent navigation strip must not repeat pending requests');
 keys='';merged();retained('');
 keys=base.split(' ').filter(Boolean)[0];merged();expectedSpeech++;
 assert.equal(spoken,expectedSpeech,'a request that leaves the pending set and returns is announced on return');retained(keys);
 merged();assert.equal(spoken,expectedSpeech,'the returned request is announced only once');
 keys+=' entered';document.dispatchEvent({type:'tego:enter'});flush();expectedSpeech++;
 assert.equal(spoken,expectedSpeech,'a request first observed while entering a view must be announced');retained(keys);
 document.dispatchEvent({type:'tego:enter'});flush();
 assert.equal(spoken,expectedSpeech,'entering again with the same requests must stay quiet');
 merged();assert.equal(spoken,expectedSpeech,'the view arrival must not be announced again on the next live merge');
 strip.scrollLeft=0;window.tegoLive.after();
 assert.equal(strip.scrollLeft,84,'after a view merge the active tab must come back into view');
}
`
