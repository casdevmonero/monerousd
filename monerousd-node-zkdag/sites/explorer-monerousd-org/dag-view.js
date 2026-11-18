// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/* MoneroUSD live BlockDAG view — self-hosted (CSP script-src 'self' compliant).
   Injects an on-brand segmented toggle into the blocks card-header and a full-screen DAG overlay. */
(function(){
  var STYLE = ''
  + '.ev-seg{display:inline-flex;gap:2px;background:var(--bg-popover,#1c1c1c);border:1px solid var(--glass-border,rgba(255,255,255,.08));border-radius:9px;padding:3px;vertical-align:middle;flex:0 0 auto;}'
  + '.ev-seg button{cursor:pointer;border:0;background:transparent;color:var(--text-secondary,#b5b5b5);font:600 12px/1 inherit;letter-spacing:.2px;padding:7px 14px;border-radius:7px;display:inline-flex;align-items:center;gap:7px;transition:background .18s,color .18s,box-shadow .18s;white-space:nowrap;}'
  + '.ev-seg button:hover{color:var(--text-primary,#f7f7f7);}'
  + '.ev-seg button.on{background:var(--monero-orange,#FF6600);color:#0a0a0a;box-shadow:0 1px 7px rgba(255,102,0,.45);}'
  + '.ev-seg .dot{width:6px;height:6px;border-radius:50%;background:currentColor;opacity:.65;}'
  + '#ev-dagoverlay{position:fixed;inset:0;z-index:4000;display:none;background:#070605;animation:evfade .25s ease;}'
  + '#ev-dagoverlay iframe{width:100%;height:100%;border:0;display:block;}'
  + '@keyframes evfade{from{opacity:0}to{opacity:1}}'
  + '#ev-dagclose{position:fixed;top:18px;right:20px;z-index:4001;display:none;cursor:pointer;border:1px solid var(--glass-border,rgba(255,255,255,.14));background:rgba(17,17,17,.82);color:#f7f7f7;border-radius:999px;padding:9px 17px;font:600 12.5px/1 inherit;backdrop-filter:blur(10px);transition:border-color .18s;}'
  + '#ev-dagclose:hover{border-color:var(--monero-orange,#FF6600);color:#fff;}';

  function injectStyle(){ if(document.getElementById('ev-style'))return; var s=document.createElement('style'); s.id='ev-style'; s.textContent=STYLE; document.head.appendChild(s); }

  function buildOverlay(){
    if(document.getElementById('ev-dagoverlay'))return;
    var o=document.createElement('div'); o.id='ev-dagoverlay';
    var f=document.createElement('iframe'); f.title='Live BlockDAG'; f.setAttribute('data-src','dagview.html?embed=1');   /* relative: the app is served under its own prefix */ f.loading='lazy';
    /* ISOLATED REALM (hole scanner T1, 2026-10-28): the 3D view runs vendored three.js, so it runs in a sandboxed frame
       with an OPAQUE origin — no storage, no same-origin scripting of this page, and the wallet bridge refuses it by
       source (only the app's top frame may speak to the wallet). It fetches nothing: this page relays the public feed. */
    f.setAttribute('sandbox','allow-scripts');
    o.appendChild(f);
    window.addEventListener('message', function(ev){
      if(ev.source!==f.contentWindow) return;                      /* the realm we framed, nobody else */
      var d=ev.data; if(!d||d.t!=='dagview:feed') return;
      feed()
        .then(function(blocks){ f.contentWindow.postMessage({t:'dagview:blocks', id:d.id, blocks:blocks}, '*'); })
        .catch(function(e){ f.contentWindow.postMessage({t:'dagview:blocks', id:d.id, error:String(e&&e.message||e)}, '*'); });
    });
    var c=document.createElement('button'); c.id='ev-dagclose'; c.type='button'; c.textContent='✕  Close DAG view';
    c.addEventListener('click', function(){ showDag(false); });
    document.body.appendChild(o); document.body.appendChild(c);
  }
  /* The node's recent DAG, from wherever this page can read a node: the node's own app server (same origin), the
     wallet's node, then this machine's node (or the reader's override) — the same order every explorer read uses. */
  function blocksOf(j){ if(j && Array.isArray(j.blocks)) return j.blocks; throw new Error('the node served no DAG'); }
  function feed(){
    var tries=[
      function(){ return fetch('/api/explorer/dag-recent',{signal:AbortSignal.timeout(7000)}).then(function(r){ if(!r.ok) throw new Error('feed '+r.status); return r.json(); }).then(blocksOf); },
      function(){ var p=window.monerousd; if(!p||typeof p.nodeRpc!=='function') throw new Error('no wallet'); return p.nodeRpc('/dag_recent','').then(blocksOf); }
    ];
    var bases='http://127.0.0.1:27780';
    try{ bases=localStorage.getItem('daemon_rpcs_testnet')||bases; }catch(e){}
    bases.split(',').forEach(function(b){ b=b.trim().replace(/\/+$/,''); if(b) tries.push(function(){ return fetch(b+'/dag_recent',{signal:AbortSignal.timeout(7000)}).then(function(r){ if(!r.ok) throw new Error('feed '+r.status); return r.json(); }).then(blocksOf); }); });
    return tries.reduce(function(acc,t){ return acc.catch(function(){ return Promise.resolve().then(t); }); }, Promise.reject(new Error('start')));
  }
  function showDag(on){
    buildOverlay();
    var o=document.getElementById('ev-dagoverlay'), c=document.getElementById('ev-dagclose'), f=o.firstChild;
    if(on){ f.src=f.getAttribute('data-src')+'&_='+Date.now(); }   /* lazy-load the 3D scene on first open */
    o.style.display=on?'block':'none'; c.style.display=on?'block':'none';
    var segs=document.querySelectorAll('.ev-seg button');
    for(var i=0;i<segs.length;i++){ segs[i].classList.toggle('on',(segs[i].getAttribute('data-ev')==='dag')===on); }
  }
  function makeSeg(){
    var seg=document.createElement('span'); seg.className='ev-seg'; seg.setAttribute('role','tablist');
    var b=document.createElement('button'); b.type='button'; b.setAttribute('data-ev','block'); b.className='on';
    b.innerHTML='<span class="dot"></span>Blocks';
    var d=document.createElement('button'); d.type='button'; d.setAttribute('data-ev','dag');
    d.innerHTML='🌌 Live DAG';
    b.addEventListener('click',function(){ showDag(false); });
    d.addEventListener('click',function(){ showDag(true); });
    seg.appendChild(b); seg.appendChild(d); return seg;
  }
  function placeToggle(){
    var view=document.getElementById('view'); if(!view)return;
    if(view.querySelector('.ev-seg'))return;                /* already placed for this render */
    var headers=view.querySelectorAll('.card-header'), target=null;
    for(var i=0;i<headers.length;i++){ var h2=headers[i].querySelector('h2'); if(h2 && /block/i.test(h2.textContent||'')){ target=headers[i]; break; } }
    if(!target)return;                                      /* only on the home (a "Blocks" heading) */
    target.style.display='flex'; target.style.alignItems='center'; target.style.justifyContent='space-between'; target.style.gap='12px'; target.style.flexWrap='wrap';
    target.appendChild(makeSeg());
  }
  function boot(){
    injectStyle();
    var view=document.getElementById('view');
    if(view){ try{ new MutationObserver(function(){ placeToggle(); }).observe(view,{childList:true,subtree:true}); }catch(e){} }
    placeToggle();
    window.addEventListener('hashchange', function(){ showDag(false); setTimeout(placeToggle,60); });
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',boot); else boot();
})();
