"""Build results/report.html from results/artifact_data.json (reproducible report generator).

Regenerate the data with the snippet in bench/aggregate-style scripts, then run:
    .venv/bin/python -m bench.report
"""
import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"

TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Anomaly Detector Bench</title>
<meta name="description" content="Unsupervised log anomaly detection: detector architectures vs blind LLM baselines on a real hidden attack.">
<style>
:root{
  color-scheme: light;
  --surface-0:#f4f4f1; --surface-1:#fcfcfb; --surface-2:#efefec;
  --border:#e2e2dd; --border-strong:#cfcfc8;
  --text-primary:#0b0b0b; --text-secondary:#52514e; --text-muted:#8a8983;
  --series-1:#2a78d6; --series-2:#eb6834; --series-3:#1baf7a; --series-4:#eda100;
  --series-5:#e87ba4; --series-7:#4a3aa7; --red:#e34948; --good:#008300;
  --shadow:0 1px 2px rgba(0,0,0,.05),0 4px 16px rgba(0,0,0,.04);
}
@media (prefers-color-scheme: dark){ :root:where(:not([data-theme="light"])){
  color-scheme: dark;
  --surface-0:#111110; --surface-1:#1a1a19; --surface-2:#232321;
  --border:#333330; --border-strong:#45443f;
  --text-primary:#ffffff; --text-secondary:#c3c2b7; --text-muted:#8f8e85;
  --series-1:#3987e5; --series-2:#d95926; --series-3:#199e70; --series-4:#c98500;
  --series-5:#d55181; --series-7:#9085e9; --red:#e66767; --good:#2fa82f;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 4px 16px rgba(0,0,0,.25);
}}
:root[data-theme="dark"]{
  color-scheme: dark;
  --surface-0:#111110; --surface-1:#1a1a19; --surface-2:#232321;
  --border:#333330; --border-strong:#45443f;
  --text-primary:#ffffff; --text-secondary:#c3c2b7; --text-muted:#8f8e85;
  --series-1:#3987e5; --series-2:#d95926; --series-3:#199e70; --series-4:#c98500;
  --series-5:#d55181; --series-7:#9085e9; --red:#e66767; --good:#2fa82f;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 4px 16px rgba(0,0,0,.25);
}
*{box-sizing:border-box}
body{margin:0;background:var(--surface-0);color:var(--text-primary);
  font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;}
.wrap{max-width:1000px;margin:0 auto;padding:40px 16px 80px;}
header h1{font-size:clamp(26px,4.5vw,40px);font-weight:750;letter-spacing:-.02em;margin:0 0 6px;}
header p.sub{color:var(--text-secondary);font-size:16px;margin:0 0 4px;max-width:70ch;}
.eyebrow{font-size:12px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:var(--series-1);margin:0 0 10px;}
section{margin-top:44px;}
h2{font-size:20px;font-weight:700;letter-spacing:-.01em;margin:0 0 4px;}
h2 .n{color:var(--text-muted);font-weight:600;margin-right:8px;}
.lede{color:var(--text-secondary);margin:0 0 18px;max-width:74ch;}
.card{background:var(--surface-1);border:1px solid var(--border);border-radius:14px;padding:20px;box-shadow:var(--shadow);}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;}
.tile{background:var(--surface-1);border:1px solid var(--border);border-radius:12px;padding:16px 18px;}
.tile .v{font-size:28px;font-weight:750;letter-spacing:-.02em;line-height:1.1;}
.tile .k{font-size:12.5px;color:var(--text-secondary);margin-top:4px;}
.tile .v.red{color:var(--red)} .tile .v.blue{color:var(--series-1)} .tile .v.green{color:var(--good)}
.legend{display:flex;flex-wrap:wrap;gap:14px;margin:0 0 14px;font-size:13px;color:var(--text-secondary);}
.legend span{display:inline-flex;align-items:center;gap:6px;}
.sw{width:13px;height:13px;border-radius:3px;flex:none;}
.swl{width:20px;height:0;border-top-width:2.5px;border-top-style:solid;}
svg{display:block;width:100%;height:auto;overflow:visible;}
.axis{stroke:var(--border-strong);stroke-width:1;}
.grid{stroke:var(--border);stroke-width:1;}
.tick{fill:var(--text-muted);font-size:11px;}
.blab{fill:var(--text-primary);font-size:12.5px;}
.vlab{fill:var(--text-primary);font-size:12px;font-weight:650;}
.note{font-size:13px;color:var(--text-secondary);margin-top:12px;}
.callout{background:var(--surface-2);border-left:3px solid var(--good);border-radius:8px;padding:14px 16px;margin-top:16px;font-size:14px;}
.callout b{color:var(--text-primary);}
table{border-collapse:collapse;width:100%;font-size:13.5px;}
th,td{text-align:right;padding:8px 10px;border-bottom:1px solid var(--border);}
th:first-child,td:first-child{text-align:left;}
th{color:var(--text-secondary);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em;}
.htable td.win{color:var(--good);font-weight:650;}
.tag{display:inline-block;font-size:11px;font-weight:600;padding:2px 7px;border-radius:20px;background:var(--surface-2);color:var(--text-secondary);}
.kill{display:flex;flex-direction:column;gap:0;}
.step{display:grid;grid-template-columns:96px 20px 1fr;gap:12px;align-items:start;}
.step .when{font-size:12px;color:var(--text-muted);text-align:right;padding-top:11px;}
.rail{display:flex;flex-direction:column;align-items:center;}
.dot{width:12px;height:12px;border-radius:50%;background:var(--series-1);margin-top:12px;flex:none;border:2px solid var(--surface-1);}
.dot.hot{background:var(--red)}
.line{width:2px;flex:1;background:var(--border-strong);min-height:14px;}
.step .body{padding:8px 0 12px;}
.step .body .st{font-weight:650;font-size:13.5px;}
.step .body code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:var(--text-secondary);
  background:var(--surface-2);padding:1px 5px;border-radius:5px;word-break:break-all;}
#tt{position:fixed;pointer-events:none;opacity:0;transition:opacity .1s;background:var(--surface-1);
  border:1px solid var(--border-strong);border-radius:8px;padding:7px 10px;font-size:12.5px;
  box-shadow:var(--shadow);z-index:10;max-width:260px;}
#tt b{color:var(--text-primary)} #tt .m{color:var(--text-secondary)}
.toggle{position:fixed;top:14px;right:14px;background:var(--surface-1);border:1px solid var(--border);
  border-radius:8px;padding:6px 11px;font-size:12.5px;color:var(--text-secondary);cursor:pointer;z-index:11;}
.foot{margin-top:56px;padding-top:20px;border-top:1px solid var(--border);color:var(--text-muted);font-size:12.5px;}
@media(max-width:560px){.step{grid-template-columns:74px 20px 1fr}.step .when{font-size:11px}}
</style>
</head>
<body>
<button class="toggle" id="themeBtn">&#9682; theme</button>
<div id="tt"></div>
<div class="wrap">
<header>
  <p class="eyebrow">Unsupervised anomaly detection &middot; HTN26</p>
  <h1>Finding one attack in 180,800 log lines</h1>
  <p class="sub">A single multi-stage intrusion is buried in eight months of intranet access logs &mdash; 22 lines, no labels. This benchmarks detector architectures against blind LLMs, selected without ever seeing the attack and scored once on the month that contains it.</p>
</header>

<section><div class="tiles" id="tiles"></div></section>

<section>
  <h2><span class="n">01</span>Which architecture wins</h2>
  <p class="lede">PR-AUC on the held-out March test (higher is better), with 95% bootstrap confidence intervals. A properly-engineered GPU autoencoder edges a plain Gaussian mixture &mdash; but the intervals overlap, so with only 22 attacks the gap is not significant. Both blind LLMs are in a different league.</p>
  <div class="card">
    <div class="legend">
      <span><span class="sw" style="background:var(--series-1)"></span>trained detector</span>
      <span><span class="sw" style="background:var(--red)"></span>blind LLM baseline</span>
      <span><span class="sw" style="background:var(--border-strong)"></span>95% CI</span>
    </div>
    <svg id="bars" viewBox="0 0 720 320" role="img" aria-label="PR-AUC leaderboard"></svg>
  </div>
</section>

<section>
  <h2><span class="n">02</span>Precision vs recall &mdash; and the hybrid fix</h2>
  <p class="lede">Both blind LLMs (GPT&#8209;5 and Claude Opus&nbsp;5) find most of the attack but drown in false positives &mdash; they flag every authorised read of a <code>*_CONFIDENTIAL</code> file because they have no learned permission model. Give the detector's shortlist to the LLM <em>with</em> each user's permission profile and precision jumps to 1.00.</p>
  <div class="card">
    <div class="legend" id="prlegend"></div>
    <svg id="pr" viewBox="0 0 720 400" role="img" aria-label="Precision-recall curves"></svg>
    <div class="callout" id="hybridcallout"></div>
  </div>
</section>

<section>
  <h2><span class="n">03</span>Representation beats algorithm</h2>
  <p class="lede">The same clusterers on naive 7-field features (left) vs learned behavioural context features (right). K-means and one-class SVM weren't the wrong idea &mdash; raw features were. Feature engineering moves the needle far more than the choice of algorithm.</p>
  <div class="card">
    <div class="legend">
      <span><span class="sw" style="background:var(--text-muted)"></span>RAW features</span>
      <span><span class="sw" style="background:var(--series-1)"></span>CTX features</span>
    </div>
    <svg id="lift" viewBox="0 0 720 320" role="img" aria-label="Representation lift"></svg>
  </div>
</section>

<section>
  <h2><span class="n">04</span>The attack it had to find</h2>
  <p class="lede">The kill chain, reconstructed. David brute-forces Sarah's account from his own machine, probes a CSRF hole, escalates, then exfiltrates a confidential file under her session. The trained model surfaces 20 of these 22 lines in its top 22.</p>
  <div class="card"><div class="kill" id="kill"></div></div>
</section>

<section>
  <h2><span class="n">05</span>How it was done right</h2>
  <p class="lede">Methodology, so the numbers hold up.</p>
  <div class="card" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:18px;">
    <div><div class="tag">no leakage</div><p class="note">Features and models fit on Aug&ndash;Jan; validated on Feb; the real March attack scores the model exactly once.</p></div>
    <div><div class="tag">label-free tuning</div><p class="note">Hyperparameters and the alert threshold are picked on <em>synthetic</em> attacks injected into February &mdash; the real one is never used to tune.</p></div>
    <div><div class="tag">uncertainty</div><p class="note">PR-AUC ships with 1000&times; bootstrap 95% CIs. With 22 positives, small gaps aren't real.</p></div>
    <div><div class="tag">proper training</div><p class="note">Autoencoder ensemble: batch-norm, dropout + weight decay, cosine-annealing warm restarts, gradient clipping, AMP on an RTX&nbsp;2060, early stopping.</p></div>
    <div><div class="tag">batch sweep</div><p class="note" id="batchnote"></p></div>
    <div><div class="tag">honest verdict</div><p class="note">GMM is the pick for production: ~equal accuracy, trains in &lt;1s, no GPU, interpretable. The AE wins only on max recall.</p></div>
  </div>
</section>

<div class="foot">Test month: March 2026 &middot; <span id="footn"></span> lines scored &middot; 22 attack lines &middot; detectors fit unsupervised on prior traffic. Charts are hoverable.</div>
</div>
<script>
const D = __DATA__;
const $ = s => document.querySelector(s);
const NS = "http://www.w3.org/2000/svg";
const el = (t,a={})=>{const e=document.createElementNS(NS,t);for(const k in a)e.setAttribute(k,a[k]);return e;};
const tt = $("#tt");
function showTT(html,x,y){tt.innerHTML=html;tt.style.opacity=1;
  const r=tt.getBoundingClientRect();let nx=x+14,ny=y+14;
  if(nx+r.width>innerWidth-8)nx=x-r.width-14; if(ny+r.height>innerHeight-8)ny=y-r.height-14;
  tt.style.left=nx+"px";tt.style.top=ny+"px";}
function hideTT(){tt.style.opacity=0;}

const best = D.leaderboard.reduce((a,b)=>b.pr_auc>a.pr_auc?b:a);
const tiles=[
  ["v","180,800","log lines analysed"],
  ["v red","22","attack lines (0.012%)"],
  ["v blue",best.pr_auc.toFixed(3),"best PR-AUC ("+best.model.split("(")[0]+")"],
  ["v green","1.00","hybrid precision (0 false positives)"],
  ["v red","0.07 / 0.03","blind GPT / Claude precision"],
  ["v green","~0.6","hybrid alerts per day"],
];
$("#tiles").innerHTML = tiles.map(t=>`<div class="tile"><div class="${t[0]}">${t[1]}</div><div class="k">${t[2]}</div></div>`).join("");
$("#footn").textContent = D.n_test.toLocaleString();
const bs=D.batch_sweep;
$("#batchnote").innerHTML = `Swept 4k&ndash;full-batch on a 6&nbsp;GB card. Best val at batch ${bs[0].batch} (${bs[0].val}); full-batch still fit in ${bs[bs.length-1].mb}&nbsp;MB. Chose 16,384 &mdash; large, fast, 60&nbsp;MB. Bigger isn't better.`;
$("#hybridcallout").innerHTML = `<b>Hybrid (detector &rarr; LLM triage):</b> the detector scores every line; the LLM adjudicates only the top&#8209;60 shortlist, given each user's permission profile. Result on the March test: <b>precision 1.00, recall 0.86, zero false positives</b>, for <b>$0.08</b> a run &mdash; 60&times; cheaper than scoring every line, because it never sees the bulk of the log.`;

// ---- 01 leaderboard bars ----
(function(){
  const rows=[...D.leaderboard.map(r=>({name:r.model.replace(/\(.*/,""),auc:r.pr_auc,lo:r.pr_auc_ci_lo,hi:r.pr_auc_ci_hi,gpt:false})),
    {name:"GPT-5 (blind)",auc:D.gpt_prauc,lo:null,hi:null,gpt:true}];
  if(D.claude_prauc!=null) rows.push({name:"Claude Opus 5 (blind)",auc:D.claude_prauc,lo:null,hi:null,gpt:true,partial:true});
  rows.sort((a,b)=>b.auc-a.auc);
  const W=720,H=320,L=182,R=44,T=10,B=34,iw=W-L-R,ih=H-T-B;
  const svg=$("#bars");
  const x=v=>L+v*iw, gap=ih/rows.length, bh=Math.min(28,gap*0.62);
  for(let t=0;t<=1;t+=0.2){const gx=x(t);
    svg.append(el("line",{x1:gx,y1:T,x2:gx,y2:T+ih,class:"grid"}));
    const tk=el("text",{x:gx,y:H-16,"text-anchor":"middle",class:"tick"});tk.textContent=t.toFixed(1);svg.append(tk);}
  svg.append(el("line",{x1:L,y1:T,x2:L,y2:T+ih,class:"axis"}));
  const xl=el("text",{x:L+iw/2,y:H-2,"text-anchor":"middle",class:"tick"});xl.textContent="PR-AUC (test)";svg.append(xl);
  rows.forEach((r,i)=>{
    const cy=T+gap*i+gap/2, col=r.gpt?"var(--red)":"var(--series-1)";
    const nm=el("text",{x:L-12,y:cy+4,"text-anchor":"end",class:"blab"});nm.textContent=r.name+(r.partial?" *":"");svg.append(nm);
    const bar=el("rect",{x:L,y:cy-bh/2,width:Math.max(1,x(r.auc)-L),height:bh,rx:4,fill:col});
    if(r.partial)bar.setAttribute("opacity","0.6");svg.append(bar);
    if(r.lo!=null){
      svg.append(el("line",{x1:x(r.lo),y1:cy,x2:x(r.hi),y2:cy,stroke:"var(--border-strong)","stroke-width":2}));
      [r.lo,r.hi].forEach(v=>svg.append(el("line",{x1:x(v),y1:cy-5,x2:x(v),y2:cy+5,stroke:"var(--border-strong)","stroke-width":2})));
    }
    const vl=el("text",{x:x(r.hi!=null?r.hi:r.auc)+8,y:cy+4,class:"vlab"});vl.textContent=r.auc.toFixed(3);svg.append(vl);
    const hit=el("rect",{x:L,y:cy-gap/2,width:iw,height:gap,fill:"transparent"});
    hit.addEventListener("mousemove",e=>showTT(`<b>${r.name}</b><br><span class="m">PR-AUC ${r.auc.toFixed(3)}${r.lo!=null?` &middot; CI [${r.lo.toFixed(2)}, ${r.hi.toFixed(2)}]`:""}${r.partial?" &middot; partial run ("+D.claude_windows+" windows)":""}</span>`,e.clientX,e.clientY));
    hit.addEventListener("mouseleave",hideTT);svg.append(hit);
  });
  if(rows.some(r=>r.partial)){const n=el("text",{x:L-12,y:H-2,"text-anchor":"end",class:"tick"});n.textContent="* partial run (credit exhausted)";svg.append(n);}
})();

// ---- 02 PR curves ----
(function(){
  const names=Object.keys(D.curves);
  const cols={"GMM (CTX)":"var(--series-1)","AutoEncoder (CTX)":"var(--series-3)","KMeans (CTX)":"var(--series-7)",
    "ECOD (RAW)":"var(--series-4)","Rule (CTX)":"var(--series-5)","KMeans (RAW)":"var(--text-muted)"};
  const dash={"KMeans (RAW)":"5 4"};
  const W=720,H=400,L=52,R=18,T=14,B=44,iw=W-L-R,ih=H-T-B;
  const svg=$("#pr"); const X=v=>L+v*iw, Y=v=>T+(1-v)*ih;
  for(let t=0;t<=1.001;t+=0.2){
    svg.append(el("line",{x1:X(t),y1:T,x2:X(t),y2:T+ih,class:"grid"}));
    svg.append(el("line",{x1:L,y1:Y(t),x2:L+iw,y2:Y(t),class:"grid"}));
    const tx=el("text",{x:X(t),y:H-24,"text-anchor":"middle",class:"tick"});tx.textContent=t.toFixed(1);svg.append(tx);
    const ty=el("text",{x:L-8,y:Y(t)+4,"text-anchor":"end",class:"tick"});ty.textContent=t.toFixed(1);svg.append(ty);
  }
  svg.append(el("line",{x1:L,y1:T,x2:L,y2:T+ih,class:"axis"}));
  svg.append(el("line",{x1:L,y1:T+ih,x2:L+iw,y2:T+ih,class:"axis"}));
  const xl=el("text",{x:L+iw/2,y:H-6,"text-anchor":"middle",class:"tick"});xl.textContent="Recall";svg.append(xl);
  const yl=el("text",{x:16,y:T+ih/2,"text-anchor":"middle",class:"tick",transform:`rotate(-90 16 ${T+ih/2})`});yl.textContent="Precision";svg.append(yl);
  names.forEach(nm=>{
    const pts=D.curves[nm];
    const dpath=pts.map((p,i)=>(i?"L":"M")+X(p[0]).toFixed(1)+" "+Y(p[1]).toFixed(1)).join(" ");
    const path=el("path",{d:dpath,fill:"none",stroke:cols[nm]||"var(--series-2)","stroke-width":2.4,"stroke-linejoin":"round"});
    if(dash[nm])path.setAttribute("stroke-dasharray",dash[nm]);
    svg.append(path);
  });
  function pt(p,label,fill){
    svg.append(el("circle",{cx:X(p.recall),cy:Y(p.precision),r:7,fill:fill,stroke:"var(--surface-1)","stroke-width":2}));
    const gl=el("text",{x:X(p.recall)+12,y:Y(p.precision)+4,class:"vlab",fill:fill});gl.textContent=label;svg.append(gl);
  }
  pt(D.gpt_point,"GPT-5","var(--red)");
  if(D.claude_point) pt(D.claude_point,"Claude","var(--series-2)");
  // hybrid point (perfect precision)
  svg.append(el("circle",{cx:X(0.86),cy:Y(1.0),r:7,fill:"var(--good)",stroke:"var(--surface-1)","stroke-width":2}));
  const hl=el("text",{x:X(0.86)-8,y:Y(1.0)-10,"text-anchor":"end",class:"vlab",fill:"var(--good)"});hl.textContent="Hybrid";svg.append(hl);
  const ov=el("rect",{x:L,y:T,width:iw,height:ih,fill:"transparent"});
  ov.addEventListener("mousemove",e=>{
    const rc=svg.getBoundingClientRect();const rel=(e.clientX-rc.left)/rc.width*W;const rr=Math.max(0,Math.min(1,(rel-L)/iw));
    let html=`<b>Recall ${rr.toFixed(2)}</b>`;
    names.forEach(nm=>{const pts=D.curves[nm];let bb=pts[0];for(const p of pts)if(Math.abs(p[0]-rr)<Math.abs(bb[0]-rr))bb=p;
      html+=`<br><span class="m" style="color:${cols[nm]||'var(--series-2)'}">&#9632;</span> ${nm}: ${bb[1].toFixed(2)}`;});
    showTT(html,e.clientX,e.clientY);
  });
  ov.addEventListener("mouseleave",hideTT);svg.append(ov);
  $("#prlegend").innerHTML = names.map(nm=>`<span><span class="swl" style="border-top-color:${cols[nm]||'var(--series-2)'};${dash[nm]?'border-top-style:dashed':''}"></span>${nm}</span>`).join("")
    +`<span><span class="sw" style="background:var(--red);border-radius:50%"></span>GPT-5 blind</span>`
    +(D.claude_point?`<span><span class="sw" style="background:var(--series-2);border-radius:50%"></span>Claude blind</span>`:``)
    +`<span><span class="sw" style="background:var(--good);border-radius:50%"></span>Hybrid</span>`;
})();

// ---- 03 representation lift ----
(function(){
  const order=["GMM","OneClassSVM","AutoEncoder","KMeans","ECOD","IsolationForest","LOF"];
  const rows=order.filter(k=>D.lift[k]).map(k=>({name:k,raw:D.lift[k][0],ctx:D.lift[k][1]}));
  const W=720,H=320,L=140,R=48,T=10,B=34,iw=W-L-R,ih=H-T-B;
  const svg=$("#lift");const x=v=>L+v*iw,gap=ih/rows.length;
  for(let t=0;t<=1;t+=0.2){svg.append(el("line",{x1:x(t),y1:T,x2:x(t),y2:T+ih,class:"grid"}));
    const tk=el("text",{x:x(t),y:H-16,"text-anchor":"middle",class:"tick"});tk.textContent=t.toFixed(1);svg.append(tk);}
  svg.append(el("line",{x1:L,y1:T,x2:L,y2:T+ih,class:"axis"}));
  const xl=el("text",{x:L+iw/2,y:H-2,"text-anchor":"middle",class:"tick"});xl.textContent="PR-AUC (test)";svg.append(xl);
  rows.forEach((r,i)=>{
    const cy=T+gap*i+gap/2, up=r.ctx>=r.raw;
    const nm=el("text",{x:L-12,y:cy+4,"text-anchor":"end",class:"blab"});nm.textContent=r.name;svg.append(nm);
    svg.append(el("line",{x1:x(r.raw),y1:cy,x2:x(r.ctx),y2:cy,stroke:up?"var(--series-1)":"var(--red)","stroke-width":3,"stroke-linecap":"round","opacity":0.35}));
    svg.append(el("circle",{cx:x(r.raw),cy,r:5.5,fill:"var(--text-muted)",stroke:"var(--surface-1)","stroke-width":2}));
    svg.append(el("circle",{cx:x(r.ctx),cy,r:6,fill:up?"var(--series-1)":"var(--red)",stroke:"var(--surface-1)","stroke-width":2}));
    const d=(r.ctx-r.raw);const dl=el("text",{x:x(Math.max(r.raw,r.ctx))+10,y:cy+4,class:"vlab",fill:up?"var(--good)":"var(--red)"});
    dl.textContent=(d>=0?"+":"")+d.toFixed(2);svg.append(dl);
    const hit=el("rect",{x:L,y:cy-gap/2,width:iw,height:gap,fill:"transparent"});
    hit.addEventListener("mousemove",e=>showTT(`<b>${r.name}</b><br><span class="m">RAW ${r.raw.toFixed(3)} &rarr; CTX ${r.ctx.toFixed(3)}</span>`,e.clientX,e.clientY));
    hit.addEventListener("mouseleave",hideTT);svg.append(hit);
  });
})();

// ---- 04 kill chain ----
(function(){
  const hot=new Set(["bruteforce","csrf_probe","csrf_fired","priv_escalation","account_takeover","exfiltration"]);
  const nice={bruteforce:"Credential brute force",recon:"Recon / probing",csrf_probe:"CSRF probe",
    csrf_fired:"CSRF payload fires",priv_escalation:"Privilege escalation",cleanup:"Covering tracks",
    account_takeover:"Account takeover",exfiltration:"Data exfiltration"};
  const tl=D.timeline, groups=[];
  for(const r of tl){const g=groups[groups.length-1];
    if(g&&g.stage===r.stage){g.count++;g.last=r;}else groups.push({stage:r.stage,first:r,last:r,count:1});}
  $("#kill").innerHTML = groups.map((g,i)=>{
    const isHot=hot.has(g.stage);const c=g.count>1?` <span class="tag">&times;${g.count}</span>`:"";
    return `<div class="step">
      <div class="when">${g.first.ts}</div>
      <div class="rail">${i>0?'<div class="line"></div>':'<div style="height:12px"></div>'}<div class="dot ${isHot?'hot':''}"></div>${i<groups.length-1?'<div class="line"></div>':''}</div>
      <div class="body"><div class="st">${nice[g.stage]||g.stage}${c}</div>
        <code>${g.first.line.replace(/</g,'&lt;')}</code></div>
    </div>`;}).join("");
})();

$("#themeBtn").addEventListener("click",()=>{
  const cur=document.documentElement.getAttribute("data-theme");
  const next=cur==="dark"?"light":cur==="light"?"dark":(matchMedia("(prefers-color-scheme: dark)").matches?"light":"dark");
  document.documentElement.setAttribute("data-theme",next);
  try{localStorage.setItem("htn26theme",next)}catch(e){}
});
try{const s=localStorage.getItem("htn26theme");if(s)document.documentElement.setAttribute("data-theme",s)}catch(e){}
</script>
</body>
</html>'''


def main():
    data = json.loads((RESULTS / "artifact_data.json").read_text())
    html = TEMPLATE.replace("__DATA__", json.dumps(data, separators=(",", ":")))
    (RESULTS / "report.html").write_text(html)
    print(f"wrote {RESULTS/'report.html'} ({len(html)} bytes)")


if __name__ == "__main__":
    main()
