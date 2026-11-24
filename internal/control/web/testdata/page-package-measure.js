// SPDX-License-Identifier: Apache-2.0
// Direct per-ancestor geometry; a sibling scroller cannot excuse another cut.
JSON.stringify((()=>{
 const masked=e=>{if(e.closest('.sr,.skip,#ask-banner-h'))return true;for(let a=e;a;a=a.parentElement){const r=a.getBoundingClientRect(),s=getComputedStyle(a);if(a.tagName==='THEAD'&&r.width<=2&&r.height<=2&&s.clipPath!=='none')return true;}return false;};
 const visible=e=>!masked(e)&&e.checkVisibility({visibilityProperty:true,contentVisibilityAuto:true})&&e.getClientRects().length&&!e.closest('svg,option')&&!e.closest('[popover]:not(:popover-open)');
 const all=[...document.querySelectorAll('body *')].filter(visible),desc=e=>e.tagName+'.'+e.className;
 const text=all.filter(e=>[...e.childNodes].some(n=>n.nodeType===3&&n.textContent.trim())||e.matches('input:not([type=hidden]):not([type=checkbox]):not([type=radio]),textarea,select'));
 const targets=all.filter(e=>e.matches('a[href],button,input:not([type=hidden]),select,textarea,summary'));
 const targetBox=e=>(e.matches('input[type=checkbox],input[type=radio]')&&e.closest('label')||e).getBoundingClientRect();
 const small=targets.filter(e=>{const r=targetBox(e);return r.width<43.9||r.height<43.9}).map(e=>({element:desc(e),w:targetBox(e).width,h:targetBox(e).height}));
 const sizes=[...new Set(text.map(e=>parseFloat(getComputedStyle(e).fontSize)))].sort((a,b)=>a-b);
 const smallText=text.filter(e=>parseFloat(getComputedStyle(e).fontSize)<13).map(desc),clips=[],contrast=[],pairs=[];
 const rgb=s=>(s.match(/[\d.]+/g)||[]).map(Number),blend=(a,b)=>{const x=a[3]??1;return a.slice(0,3).map((v,i)=>v*x+b[i]*(1-x))};
 const bg=e=>{let layers=[];for(let a=e;a;a=a.parentElement)layers.push(rgb(getComputedStyle(a).backgroundColor));let b=[255,255,255];for(const a of layers.reverse())if(a.length>=3)b=blend(a,b);return b};
 const lum=c=>c.map(x=>{x/=255;return x<=.04045?x/12.92:((x+.055)/1.055)**2.4}).reduce((s,x,i)=>s+x*[.2126,.7152,.0722][i],0);
 let minContrast=100;
 for(const e of text){
  if(e.matches('option'))continue;
  const s=getComputedStyle(e),ink=e.matches('input,textarea')&&!e.value&&e.placeholder?getComputedStyle(e,'::placeholder').color:s.color,f=blend(rgb(ink),bg(e)),a=lum(f),b=lum(bg(e)),ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);minContrast=Math.min(minContrast,ratio);pairs.push({fg:f,bg:bg(e),ratio});
  if(ratio<4.5)contrast.push({element:desc(e),ratio,text:e.textContent.trim().slice(0,60)});
  for(const n of e.childNodes){if(n.nodeType!==3||!n.textContent.trim())continue;const range=document.createRange();range.selectNodeContents(n);
   for(const r of range.getClientRects()){
    let ellipsis=false;
    for(let a=e;a;a=a.parentElement){const s=getComputedStyle(a),b=a.getBoundingClientRect();
     if(a.matches('.sp-d,.sp-b')&&getComputedStyle(a).textOverflow==='ellipsis'&&a.closest('#ask-banner')?.querySelector('.ab-act a[href*="ask="]')?.getAttribute('aria-label')?.includes(n.textContent.trim())){ellipsis=true;break;}
     if(a.matches('.phone-who')&&a.closest('a.phone-row[href]')||a.matches('.ab-summary')&&a.closest('#ask-banner')?.querySelector('a[href]')||a.matches('.ab-name,.ab-short-target')&&getComputedStyle(a).textOverflow==='ellipsis'&&a.closest('#ask-banner')?.querySelector('.ab-act a[href]')?.getAttribute('aria-label')?.includes(a.closest('.ab-summary')?.getAttribute('aria-label'))||a.matches('.ap-summary')&&a.closest('.ap-compact').querySelector('a[href*="ask="]')){ellipsis=true;break;}
     if((/hidden|clip/.test(s.overflowX)&&(r.left<b.left-1||r.right>b.right+1))||(/hidden|clip/.test(s.overflowY)&&(r.top<b.top-1||r.bottom>b.bottom+1))){clips.push({element:desc(e),ancestor:desc(a),text:n.textContent.trim().slice(0,70)});break;}
    }
    const td=e.closest('td');if(!ellipsis&&td){const b=td.getBoundingClientRect();if(r.left<b.left-1||r.right>b.right+1)clips.push({element:desc(e),ancestor:'cell bounds',text:n.textContent.trim().slice(0,70)});}
    if(!ellipsis&&(r.left< -1||r.right>innerWidth+1))clips.push({element:desc(e),ancestor:'viewport',text:n.textContent.trim().slice(0,70)});
   }
  }
 }
 return {scrollWidth:document.documentElement.scrollWidth,innerWidth,small,smallText,sizes,minText:Math.min(...sizes),minTargetWidth:Math.min(...targets.map(e=>targetBox(e).width)),minTargetHeight:Math.min(...targets.map(e=>targetBox(e).height)),clips,contrast,pairs,minContrast,decisionBottom:document.querySelector('.ap-detail .ask-d>form')?.getBoundingClientRect().bottom||0,targetBottom:document.querySelector('.ap-target')?.getBoundingClientRect().bottom||0};
})())
