"""Build results/webapp.html: an interactive, client-side log-anomaly console.

Embeds the exported model (results/web/model.json) and a demo log sample
(results/web/demo_logs.txt), and a JS port of the CTX feature extraction + RuleNovelty
scorer that was validated to match the Python scorer exactly (see bench/export_web.py).

    .venv/bin/python -m bench.export_web && .venv/bin/python -m bench.webapp
"""
import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"

TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log Anomaly Console</title>
<meta name="description" content="Paste web-server logs and score each line for anomalies, in the browser, with reasons and a red/yellow/green triage.">
<style>
:root{
  color-scheme: light;
  --surface-0:#f4f4f1; --surface-1:#fcfcfb; --surface-2:#efefec; --surface-3:#e7e7e2;
  --border:#e2e2dd; --border-strong:#cfcfc8;
  --text-primary:#0b0b0b; --text-secondary:#52514e; --text-muted:#8a8983;
  --accent:#2a78d6;
  --red:#e34948; --red-bg:#fbe9e9; --yellow:#c98500; --yellow-bg:#fbf1dc; --green:#008300; --green-bg:#e6f3e6;
  --shadow:0 1px 2px rgba(0,0,0,.05),0 4px 16px rgba(0,0,0,.04);
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme: dark){ :root:where(:not([data-theme="light"])){
  color-scheme: dark;
  --surface-0:#111110; --surface-1:#1a1a19; --surface-2:#232321; --surface-3:#2c2c29;
  --border:#333330; --border-strong:#45443f;
  --text-primary:#ffffff; --text-secondary:#c3c2b7; --text-muted:#8f8e85;
  --accent:#3987e5;
  --red:#e66767; --red-bg:#3a1f1f; --yellow:#d9a13a; --yellow-bg:#332a15; --green:#3fb13f; --green-bg:#162a16;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 4px 16px rgba(0,0,0,.25);
}}
:root[data-theme="dark"]{
  color-scheme: dark;
  --surface-0:#111110; --surface-1:#1a1a19; --surface-2:#232321; --surface-3:#2c2c29;
  --border:#333330; --border-strong:#45443f;
  --text-primary:#ffffff; --text-secondary:#c3c2b7; --text-muted:#8f8e85;
  --accent:#3987e5;
  --red:#e66767; --red-bg:#3a1f1f; --yellow:#d9a13a; --yellow-bg:#332a15; --green:#3fb13f; --green-bg:#162a16;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 4px 16px rgba(0,0,0,.25);
}
*{box-sizing:border-box}
body{margin:0;background:var(--surface-0);color:var(--text-primary);
  font:14.5px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased;}
.wrap{max-width:1180px;margin:0 auto;padding:28px 16px 80px;}
header{display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:4px;}
h1{font-size:clamp(22px,3.4vw,30px);font-weight:750;letter-spacing:-.02em;margin:0;}
.sub{color:var(--text-secondary);margin:2px 0 22px;max-width:78ch;}
.toggle{background:var(--surface-1);border:1px solid var(--border);border-radius:8px;padding:6px 11px;font-size:12.5px;color:var(--text-secondary);cursor:pointer;}
.card{background:var(--surface-1);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:var(--shadow);margin-bottom:20px;}
.card h2{font-size:14px;font-weight:700;letter-spacing:.02em;text-transform:uppercase;color:var(--text-secondary);margin:0 0 14px;}
textarea{width:100%;min-height:96px;resize:vertical;background:var(--surface-2);border:1px solid var(--border);border-radius:10px;
  padding:11px 13px;font-family:var(--mono);font-size:12px;color:var(--text-primary);line-height:1.45;}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:12px;}
.row select{background:var(--surface-2);border:1px solid var(--border);border-radius:9px;padding:8px 10px;font-size:13px;color:var(--text-primary);}
button.btn{border:none;border-radius:9px;padding:9px 16px;font-size:13.5px;font-weight:600;cursor:pointer;background:var(--accent);color:#fff;}
button.btn.ghost{background:var(--surface-2);color:var(--text-primary);border:1px solid var(--border);}
button.btn:active{transform:translateY(1px);}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:12px;margin-bottom:20px;}
.tile{background:var(--surface-1);border:1px solid var(--border);border-radius:12px;padding:13px 15px;}
.tile .v{font-size:24px;font-weight:750;letter-spacing:-.02em;line-height:1.05;}
.tile .k{font-size:11.5px;color:var(--text-secondary);margin-top:3px;}
.tile.red .v{color:var(--red)} .tile.yellow .v{color:var(--yellow)} .tile.green .v{color:var(--green)}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:20px;}
@media(max-width:820px){.charts{grid-template-columns:1fr}}
svg{display:block;width:100%;height:auto;overflow:visible}
.grid{stroke:var(--border)} .axis{stroke:var(--border-strong)}
.tick{fill:var(--text-muted);font-size:10.5px}
.filters{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px;}
.filters input,.filters select{background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:7px 10px;font-size:13px;color:var(--text-primary);}
.filters input[type=search]{min-width:190px;flex:1;}
.chip{display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:20px;font-size:12.5px;font-weight:600;cursor:pointer;border:1px solid var(--border);background:var(--surface-2);color:var(--text-secondary);user-select:none;}
.chip.on.red{background:var(--red-bg);color:var(--red);border-color:var(--red)}
.chip.on.yellow{background:var(--yellow-bg);color:var(--yellow);border-color:var(--yellow)}
.chip.on.green{background:var(--green-bg);color:var(--green);border-color:var(--green)}
.chip .dot{width:9px;height:9px;border-radius:50%}
.chip.red .dot{background:var(--red)} .chip.yellow .dot{background:var(--yellow)} .chip.green .dot{background:var(--green)}
.chip:not(.on){opacity:.55}
table{border-collapse:collapse;width:100%;font-size:13px}
thead th{position:sticky;top:0;background:var(--surface-1);text-align:left;padding:9px 8px;border-bottom:2px solid var(--border);
  font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--text-secondary);cursor:pointer;white-space:nowrap;}
thead th.sorted::after{content:" \25be";color:var(--text-primary)}
thead th.asc.sorted::after{content:" \25b4"}
tbody td{padding:8px;border-bottom:1px solid var(--border);vertical-align:top}
tbody tr:hover{background:var(--surface-2)}
.tdot{width:10px;height:10px;border-radius:50%;display:inline-block}
.t-red .tdot{background:var(--red)} .t-yellow .tdot{background:var(--yellow)} .t-green .tdot{background:var(--green)}
.score-cell{display:flex;align-items:center;gap:8px;min-width:96px}
.bar{height:6px;border-radius:4px;background:var(--surface-3);flex:1;overflow:hidden;min-width:40px}
.bar > i{display:block;height:100%;border-radius:4px}
.t-red .bar>i{background:var(--red)} .t-yellow .bar>i{background:var(--yellow)} .t-green .bar>i{background:var(--green)}
.mono{font-family:var(--mono);font-size:11.5px;color:var(--text-secondary);word-break:break-all}
.reasons{display:flex;flex-wrap:wrap;gap:4px}
.rtag{font-size:10.5px;font-weight:600;padding:1px 6px;border-radius:5px;background:var(--surface-3);color:var(--text-secondary);white-space:nowrap}
.t-red .rtag{background:var(--red-bg);color:var(--red)}
.pager{display:flex;gap:10px;align-items:center;justify-content:space-between;margin-top:12px;color:var(--text-secondary);font-size:13px;flex-wrap:wrap}
.pager button{background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:6px 12px;cursor:pointer;color:var(--text-primary)}
.pager button:disabled{opacity:.4;cursor:default}
.empty{color:var(--text-muted);text-align:center;padding:30px}
#tt{position:fixed;pointer-events:none;opacity:0;transition:opacity .1s;background:var(--surface-1);border:1px solid var(--border-strong);border-radius:8px;padding:7px 10px;font-size:12px;box-shadow:var(--shadow);z-index:20;max-width:320px}
#tt .mono{color:var(--text-primary)}
.legend{display:flex;gap:14px;font-size:12px;color:var(--text-secondary);margin-bottom:8px;flex-wrap:wrap}
.legend span{display:inline-flex;align-items:center;gap:6px}
.sw{width:10px;height:10px;border-radius:50%}
.foot{margin-top:30px;color:var(--text-muted);font-size:12px;border-top:1px solid var(--border);padding-top:16px}
</style>
</head>
<body>
<div id="tt"></div>
<div class="wrap">
<header>
  <div>
    <h1>Log Anomaly Console</h1>
    <p class="sub">Paste web-server access logs (Apache common format). Each line is scored in your browser against a model trained on normal traffic, then triaged <b style="color:var(--red)">red</b> / <b style="color:var(--yellow)">yellow</b> / <b style="color:var(--green)">green</b> with the reasons that fired.</p>
  </div>
  <button class="toggle" id="themeBtn">&#9682; theme</button>
</header>

<div class="card">
  <h2>Logs</h2>
  <textarea id="input" spellcheck="false" placeholder="10.0.5.12 - sarah_j [15/Mar/2026:22:30:40 -0400] &quot;GET /finance/reports/q1.zip HTTP/1.1&quot; 200 8459200"></textarea>
  <div class="row">
    <button class="btn" id="scoreBtn">Score logs</button>
    <select id="model" title="Scoring model">
      <option value="rule">Rule &mdash; in-browser</option>
      <option value="gmm">GMM &mdash; server</option>
      <option value="ae">Deep AE &mdash; server</option>
    </select>
    <button class="btn ghost" id="demoBtn">Load demo (2,200 lines)</button>
    <button class="btn ghost" id="appendChk" title="Add to existing instead of replacing">append mode: off</button>
    <button class="btn ghost" id="clearBtn">Clear</button>
    <span id="parsemsg" style="color:var(--text-muted);font-size:12.5px"></span>
  </div>
</div>

<div class="tiles" id="tiles"></div>

<div class="charts">
  <div class="card"><h2>Anomaly score over time</h2>
    <div class="legend"><span><i class="sw" style="background:var(--red)"></i>anomaly</span><span><i class="sw" style="background:var(--yellow)"></i>suspicious</span><span><i class="sw" style="background:var(--green)"></i>normal</span></div>
    <svg id="scatter" viewBox="0 0 560 240" role="img" aria-label="Scores over time"></svg>
  </div>
  <div class="card"><h2>Flagged lines by user</h2>
    <svg id="userbars" viewBox="0 0 560 240" role="img" aria-label="Flagged by user"></svg>
  </div>
</div>

<div class="card">
  <h2>Scored lines</h2>
  <div class="filters">
    <input type="search" id="q" placeholder="Search path / text…">
    <select id="fuser"><option value="">All users</option></select>
    <select id="fip"><option value="">All IPs</option></select>
    <input type="date" id="dfrom" title="From date">
    <input type="date" id="dto" title="To date">
    <span class="chip red on" data-tier="red"><span class="dot"></span>anomaly</span>
    <span class="chip yellow on" data-tier="yellow"><span class="dot"></span>suspicious</span>
    <span class="chip green on" data-tier="green"><span class="dot"></span>normal</span>
  </div>
  <div style="overflow-x:auto">
  <table id="tbl">
    <thead><tr>
      <th data-sort="tier">Tier</th>
      <th data-sort="score" class="sorted">Score</th>
      <th data-sort="ts">Time</th>
      <th data-sort="user">User</th>
      <th data-sort="ip">IP</th>
      <th data-sort="request">Request</th>
      <th data-sort="status">Status</th>
      <th>Why</th>
    </tr></thead>
    <tbody id="tbody"></tbody>
  </table>
  </div>
  <div class="pager"><span id="count"></span><span><button id="prev">Prev</button> <span id="pageinfo"></span> <button id="next">Next</button></span></div>
</div>

<div class="foot">Scoring runs entirely in your browser (no data leaves the page) using the interpretable RuleNovelty model &mdash; validated to match the Python scorer exactly. The deep autoencoder and GMM stay in the Python CLI for maximum accuracy. Trained on Aug 2025&ndash;Feb 2026 normal traffic.</div>
</div>

<script>
const MODEL = __MODEL__;
const DEMO = __DEMO__;
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const NS="http://www.w3.org/2000/svg", el=(t,a={})=>{const e=document.createElementNS(NS,t);for(const k in a)e.setAttribute(k,a[k]);return e;};
const tt=$("#tt");
function showTT(h,x,y){tt.innerHTML=h;tt.style.opacity=1;const r=tt.getBoundingClientRect();let nx=x+14,ny=y+14;if(nx+r.width>innerWidth-8)nx=x-r.width-14;if(ny+r.height>innerHeight-8)ny=y-r.height-14;tt.style.left=nx+"px";tt.style.top=ny+"px";}
function hideTT(){tt.style.opacity=0;}
const MONTHS={Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11};
const SEP=MODEL.sep, MR=MODEL.max_rarity, W=MODEL.rule_weights, SENS=MODEL.sensitive_prefixes;
const RX=/^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) ([^"]+)" (\d{3}) (\S+)$/;

function template(path){
  const qi=path.indexOf("?");
  let base=qi<0?path:path.slice(0,qi);
  const query=qi<0?"":path.slice(qi+1);
  base=base.replace(/\d{3,}/g,"{n}");
  if(!query)return base;
  const keys=query.split("&").map(kv=>kv.split("=")[0]).sort();
  return base+"?"+keys.map(k=>k+"=").join("&");
}
function parseTs(s){ // "13/Mar/2026:23:10:19 -0400"
  const m=s.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/);
  if(!m)return null;
  const [,dd,mon,yyyy,HH,MM,SS,sg,oh,om]=m;
  const off=(sg==="-"?-1:1)*(+oh*60+ +om)*60000;
  const utc=Date.UTC(+yyyy,MONTHS[mon],+dd,+HH,+MM,+SS)-off;
  const day=`${yyyy}-${String(MONTHS[mon]+1).padStart(2,"0")}-${dd}`;
  return {epoch:Math.floor((utc)/1000), ms:utc, hour:+HH, day,
          disp:`${day} ${HH}:${MM}:${SS}`, tz:`${sg}${oh}${om}`};
}
function parseLine(line){
  const m=line.trim().match(RX); if(!m)return null;
  const [,ip,,user,ts,method,path,,status,bytes]=m;
  const t=parseTs(ts); if(!t)return null;
  const tmpl=template(path), key=method+" "+tmpl;
  return {raw:line.trim(),ip,user,ts,method,path,tmpl,key,status:+status,
    bytes:bytes==="-"?0:+bytes, epoch:t.epoch,ms:t.ms,hour:t.hour,day:t.day,disp:t.disp,tz:t.tz};
}
function rollingFails(rows){ // fails_60s per (ip,user) among 401s
  const w=MODEL.burst_windows.fails_60s, by={};
  rows.forEach((r,i)=>{ if(r.status===401){ (by[r.ip+SEP+r.user]??=[]).push(i); } });
  const fails=new Array(rows.length).fill(0);
  for(const k in by){ const idx=by[k].sort((a,b)=>rows[a].epoch-rows[b].epoch);
    const ts=idx.map(i=>rows[i].epoch); let lo=0;
    for(let j=0;j<idx.length;j++){ while(ts[j]-ts[lo]>w)lo++; fails[idx[j]]=j-lo+1; } }
  return fails;
}
function scoreAll(rows){
  rows.sort((a,b)=>a.epoch-b.epoch);
  const fails=rollingFails(rows);
  rows.forEach((r,i)=>{
    const f={
      ip_new_for_user: (r.user+SEP+r.ip) in MODEL.user_ip?0:1,
      user_ip_rarity: MODEL.user_ip[r.user+SEP+r.ip] ?? MR,
      user_key_rarity: MODEL.user_key[r.user+SEP+r.key] ?? MR,
      status_for_key_rarity: MODEL.status_for_key[r.key+SEP+r.status] ?? MR,
      unseen_key: r.key in MODEL.key_global?0:1,
      unseen_status_for_key: (r.key+SEP+r.status) in MODEL.status_for_key?0:1,
      is_auth_fail: r.status===401?1:0,
      user_resource_denied_rate: SENS.some(p=>r.tmpl.startsWith(p)) ? (MODEL.denied_rate[r.user+SEP+r.tmpl] ?? MODEL.global_denied) : 0,
      fails_60s: fails[i],
    };
    let s=0; for(const c in W) s+=W[c]*f[c];
    r.score=s;
    r.tier = s>=MODEL.tiers.red?"red":(s>=MODEL.tiers.yellow?"yellow":"green");
    r.reasons=reasons(r,f);
  });
  return rows;
}
function reasons(r,f){
  const out=[];
  if(f.ip_new_for_user) out.push("new-IP-for-user");
  if(f.unseen_key) out.push("never-seen-endpoint");
  if(f.unseen_status_for_key) out.push("unusual-status");
  if(f.fails_60s>=3) out.push(f.fails_60s+"-fails-in-60s");
  if(f.user_resource_denied_rate>0.5 && r.status<400) out.push("success-on-denied-resource");
  if(f.status_for_key_rarity>2) out.push("rare-status");
  if(f.user_ip_rarity>2 && !f.ip_new_for_user) out.push("rare-IP-for-user");
  return out.length?out:["nominal"];
}

// ---------- state ----------
let ROWS=[], PAGE=0, PER=50, SORT={key:"score",asc:false};
const tierOn={red:true,yellow:true,green:true};
let RISK={lo:0,den:1};
// models differ wildly in scale (rule ~1-19, GMM ~1e5, AE ~1e6), so normalise to 0-1 on a
// shifted log scale for the bars/plot while still showing the raw score.
function computeRisk(rows){
  const ss=rows.map(r=>r.score); const lo=Math.min(...ss), hi=Math.max(...ss);
  RISK.lo=lo; RISK.den=Math.log1p(Math.max(0,hi-lo))||1;
  rows.forEach(r=>r.risk=riskOf(r.score));
}
function riskOf(v){return Math.min(1,Math.max(0,Math.log1p(Math.max(0,v-RISK.lo))/RISK.den));}
function invRisk(f){return RISK.lo+Math.expm1(f*RISK.den);}
function fmtScore(s){
  const a=Math.abs(s);
  if(a>=1e5)return s.toExponential(1);
  if(a>=1000)return Math.round(s).toLocaleString();
  return s.toFixed(1);
}

async function scoreServer(rows, model){ // real Python models via the localhost backend
  try{
    rows.sort((a,b)=>a.epoch-b.epoch);
    const res=await fetch("/api/score",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({model, lines:rows.map(r=>r.raw)})});
    if(!res.ok)return null;
    const d=await res.json();
    if(!d.scores||d.scores.length!==rows.length)return null;
    rows.forEach((r,i)=>{r.score=d.scores[i];r.tier=d.tiers[i];
      r.reasons=(d.reasons[i]&&d.reasons[i].length)?d.reasons[i]:["nominal"];});
    return d;
  }catch(e){ return null; }
}
async function ingest(text, append){
  const lines=text.split(/\r?\n/).filter(l=>l.trim());
  let parsed=[],bad=0;
  for(const l of lines){const r=parseLine(l); if(r)parsed.push(r); else if(l.trim())bad++;}
  if(!parsed.length){$("#parsemsg").textContent=`no valid log lines found${bad?` (${bad} unparseable)`:""}.`;return;}
  ROWS = append ? ROWS.concat(parsed) : parsed;
  const want=$("#model").value; let used=want, srv=null;
  if(want==="rule"){ scoreAll(ROWS); }
  else {
    $("#parsemsg").textContent=`scoring ${ROWS.length} lines with ${want.toUpperCase()} on the server…`;
    srv=await scoreServer(ROWS,want);
    if(!srv){ scoreAll(ROWS); used="rule"; }
  }
  if(srv&&srv.tiers_at){ MODEL.tiers=srv.tiers_at; }
  computeRisk(ROWS);
  const note = used!==want ? ` — server unavailable, used in-browser rule (run: python -m bench.serve)` : "";
  $("#parsemsg").textContent=`scored ${parsed.length} line${parsed.length>1?"s":""} with ${used.toUpperCase()}${bad?`, skipped ${bad} unparseable`:""}${note}.`;
  PAGE=0; buildFilters(); render();
}
function buildFilters(){
  const users=[...new Set(ROWS.map(r=>r.user))].sort();
  const ips=[...new Set(ROWS.map(r=>r.ip))].sort();
  fill($("#fuser"),users,"All users"); fill($("#fip"),ips,"All IPs");
  const days=ROWS.map(r=>r.day).sort();
  if(days.length){$("#dfrom").min=$("#dto").min=days[0];$("#dfrom").max=$("#dto").max=days[days.length-1];}
}
function fill(sel,vals,all){const cur=sel.value;sel.innerHTML=`<option value="">${all}</option>`+vals.map(v=>`<option>${v}</option>`).join("");if(vals.includes(cur))sel.value=cur;}

function filtered(){
  const q=$("#q").value.trim().toLowerCase(), u=$("#fuser").value, ip=$("#fip").value;
  const df=$("#dfrom").value, dt=$("#dto").value;
  return ROWS.filter(r=>tierOn[r.tier]
    && (!u||r.user===u) && (!ip||r.ip===ip)
    && (!df||r.day>=df) && (!dt||r.day<=dt)
    && (!q||r.raw.toLowerCase().includes(q)));
}
function sortRows(rows){
  const {key,asc}=SORT, order={red:2,yellow:1,green:0};
  return rows.sort((a,b)=>{
    let x=a[key],y=b[key];
    if(key==="tier"){x=order[a.tier];y=order[b.tier];}
    if(key==="request"){x=a.method+a.path;y=b.method+b.path;}
    if(x<y)return asc?-1:1; if(x>y)return asc?1:-1; return b.score-a.score;
  });
}

function render(){
  const rows=sortRows(filtered());
  // tiles
  const c={red:0,yellow:0,green:0}; ROWS.forEach(r=>c[r.tier]++);
  const users=new Set(ROWS.map(r=>r.user)).size;
  const topUser=(()=>{const m={};ROWS.forEach(r=>{if(r.tier!=="green")m[r.user]=(m[r.user]||0)+1;});
    const e=Object.entries(m).sort((a,b)=>b[1]-a[1])[0];return e?`${e[0]} (${e[1]})`:"—";})();
  const days=[...new Set(ROWS.map(r=>r.day))].sort();
  $("#tiles").innerHTML=[
    ["",ROWS.length,"lines scored"],
    ["red",c.red,"anomalies"],
    ["yellow",c.yellow,"suspicious"],
    ["green",c.green,"normal"],
    ["",users,"users"],
    ["",topUser,"top flagged user"],
    ["",days.length?days.length:"—","days covered"],
  ].map(t=>`<div class="tile ${t[0]}"><div class="v">${t[1]}</div><div class="k">${t[2]}</div></div>`).join("");
  // table (paged)
  const total=rows.length, pages=Math.max(1,Math.ceil(total/PER));
  if(PAGE>=pages)PAGE=pages-1; if(PAGE<0)PAGE=0;
  const slice=rows.slice(PAGE*PER,PAGE*PER+PER);
  $("#tbody").innerHTML = slice.length? slice.map(r=>{
    const w=Math.max(3,Math.min(100,r.risk*100));
    const time=r.disp;
    return `<tr class="t-${r.tier}">
      <td><span class="tdot"></span></td>
      <td><div class="score-cell"><span>${fmtScore(r.score)}</span><span class="bar"><i style="width:${w}%"></i></span></div></td>
      <td class="mono" style="white-space:nowrap">${time}</td>
      <td style="white-space:nowrap">${r.user}</td><td class="mono" style="white-space:nowrap">${r.ip}</td>
      <td class="mono">${esc(r.method)} ${esc(r.path)}</td>
      <td>${r.status}</td>
      <td><div class="reasons">${r.reasons.map(x=>`<span class="rtag">${x}</span>`).join("")}</div></td>
    </tr>`;}).join("") : `<tr><td colspan="8" class="empty">No lines match the filters.</td></tr>`;
  $("#count").textContent=`${total} line${total!==1?"s":""} shown`;
  $("#pageinfo").textContent=`page ${PAGE+1} / ${pages}`;
  $("#prev").disabled=PAGE<=0; $("#next").disabled=PAGE>=pages-1;
  drawScatter(); drawUserBars();
}
function esc(s){return s.replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}

// ---------- charts ----------
function drawScatter(){
  const svg=$("#scatter"); svg.innerHTML="";
  const rows=filtered(); const W_=560,H=240,L=40,R=12,T=12,B=28,iw=W_-L-R,ih=H-T-B;
  if(!rows.length){return;}
  const t0=Math.min(...rows.map(r=>r.ms)), t1=Math.max(...rows.map(r=>r.ms))||t0+1;
  const X=t=>L+(t1===t0?0.5:(t-t0)/(t1-t0))*iw, Y=s=>T+ih-riskOf(s)*ih;
  [0,.25,.5,.75,1].forEach(f=>{const y=T+ih-f*ih;svg.append(el("line",{x1:L,y1:y,x2:L+iw,y2:y,class:"grid","stroke-width":1}));
    const tk=el("text",{x:L-6,y:y+3,"text-anchor":"end",class:"tick"});tk.textContent=fmtScore(invRisk(f));svg.append(tk);});
  // threshold lines
  [["red",MODEL.tiers.red],["yellow",MODEL.tiers.yellow]].forEach(([c,v])=>{
    svg.append(el("line",{x1:L,y1:Y(v),x2:L+iw,y2:Y(v),stroke:`var(--${c})`,"stroke-width":1,"stroke-dasharray":"4 3","opacity":.7}));});
  const col={red:"var(--red)",yellow:"var(--yellow)",green:"var(--green)"};
  const zo={green:0,yellow:1,red:2};
  rows.sort((a,b)=>zo[a.tier]-zo[b.tier]).forEach(r=>{
    const cx=X(r.ms),cy=Y(r.score);
    const c=el("circle",{cx,cy,r:r.tier==="green"?2.2:3.4,fill:col[r.tier],opacity:r.tier==="green"?.5:.95});
    c.addEventListener("mousemove",e=>showTT(`<b>${r.score.toFixed(1)}</b> · ${r.tier}<br><span class="mono">${esc(r.raw)}</span>`,e.clientX,e.clientY));
    c.addEventListener("mouseleave",hideTT); svg.append(c);
  });
  svg.append(el("line",{x1:L,y1:T,x2:L,y2:T+ih,class:"axis","stroke-width":1}));
  svg.append(el("line",{x1:L,y1:T+ih,x2:L+iw,y2:T+ih,class:"axis","stroke-width":1}));
  const lab=(t,x,anch)=>{const e=el("text",{x,y:H-8,"text-anchor":anch,class:"tick"});e.textContent=new Date(t).toISOString().slice(0,10);svg.append(e);};
  lab(t0,L,"start"); lab(t1,L+iw,"end");
}
function drawUserBars(){
  const svg=$("#userbars"); svg.innerHTML="";
  const rows=filtered(); const agg={};
  rows.forEach(r=>{(agg[r.user]??={red:0,yellow:0,green:0})[r.tier]++;});
  let users=Object.entries(agg).map(([u,c])=>({u,...c,flagged:c.red+c.yellow,total:c.red+c.yellow+c.green}))
    .sort((a,b)=>b.flagged-a.flagged||b.total-a.total).slice(0,8);
  if(!users.length)return;
  const W_=560,H=240,L=88,R=40,T=8,B=20,iw=W_-L-R,ih=H-T-B;
  users=users.filter(u=>u.flagged>0).slice(0,8);
  if(!users.length){const t=el("text",{x:W_/2,y:H/2,"text-anchor":"middle",class:"tick"});t.textContent="no flagged lines in view";svg.append(t);return;}
  const max=Math.max(...users.map(u=>u.flagged),1), x=v=>v/max*iw, gap=ih/users.length, bh=Math.min(22,gap*.6);
  users.forEach((u,i)=>{
    const cy=T+gap*i+gap/2;
    const nm=el("text",{x:L-10,y:cy+4,"text-anchor":"end",class:"tick",fill:"var(--text-primary)"});nm.textContent=u.u;svg.append(nm);
    let xx=L;
    [["red",u.red],["yellow",u.yellow]].forEach(([c,n])=>{ if(!n)return;
      const w=x(n); const rect=el("rect",{x:xx,y:cy-bh/2,width:Math.max(1,w-1),height:bh,rx:2,fill:`var(--${c})`});
      rect.addEventListener("mousemove",e=>showTT(`<b>${u.u}</b><br><span class="m">${n} ${c==="red"?"anomalies":"suspicious"} of ${u.total} lines</span>`,e.clientX,e.clientY));
      rect.addEventListener("mouseleave",hideTT); svg.append(rect); xx+=w; });
    const fl=el("text",{x:xx+6,y:cy+4,class:"tick",fill:"var(--text-primary)"});
    fl.textContent=`${u.flagged} of ${u.total}`;svg.append(fl);
  });
}

// ---------- wiring ----------
let APPEND=false;
$("#scoreBtn").onclick=()=>ingest($("#input").value,APPEND);
$("#demoBtn").onclick=()=>{$("#input").value=DEMO; ingest(DEMO,false);};
$("#model").onchange=()=>{ if(ROWS.length) ingest(ROWS.map(r=>r.raw).join("\n"),false); };
$("#clearBtn").onclick=()=>{$("#input").value="";ROWS=[];render();$("#parsemsg").textContent="";};
$("#appendChk").onclick=()=>{APPEND=!APPEND;$("#appendChk").textContent="append mode: "+(APPEND?"on":"off");};
["#q","#fuser","#fip","#dfrom","#dto"].forEach(s=>$(s).addEventListener("input",()=>{PAGE=0;render();}));
$$(".chip").forEach(ch=>ch.onclick=()=>{const t=ch.dataset.tier;tierOn[t]=!tierOn[t];ch.classList.toggle("on",tierOn[t]);PAGE=0;render();});
$$("thead th[data-sort]").forEach(th=>th.onclick=()=>{
  const k=th.dataset.sort; if(SORT.key===k)SORT.asc=!SORT.asc; else {SORT.key=k;SORT.asc=(k==="ts"||k==="user"||k==="ip");}
  $$("thead th").forEach(x=>x.classList.remove("sorted","asc"));
  th.classList.add("sorted"); if(SORT.asc)th.classList.add("asc"); render();});
$("#prev").onclick=()=>{PAGE--;render();}; $("#next").onclick=()=>{PAGE++;render();};
$("#themeBtn").onclick=()=>{const c=document.documentElement.getAttribute("data-theme");
  const n=c==="dark"?"light":c==="light"?"dark":(matchMedia("(prefers-color-scheme: dark)").matches?"light":"dark");
  document.documentElement.setAttribute("data-theme",n);try{localStorage.setItem("cons_theme",n)}catch(e){}render();};
try{const s=localStorage.getItem("cons_theme");if(s)document.documentElement.setAttribute("data-theme",s)}catch(e){}

MODEL.display_max=MODEL.tiers.red*1.5; // seed; ingest() recomputes from the data
ingest(DEMO,false); // start populated
</script>
</body>
</html>'''


def main():
    web = RESULTS / "web"
    model = json.loads((web / "model.json").read_text())
    demo = (web / "demo_logs.txt").read_text().strip()
    # grow display_max to the demo's real max so bars use the full range
    html = TEMPLATE.replace("__MODEL__", json.dumps(model, separators=(",", ":")))
    html = html.replace("__DEMO__", json.dumps(demo))
    (RESULTS / "webapp.html").write_text(html)
    print(f"wrote {RESULTS/'webapp.html'} ({len(html)/1024:.0f} KB, demo {demo.count(chr(10))+1} lines)")


if __name__ == "__main__":
    main()
