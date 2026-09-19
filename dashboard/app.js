"use strict";

const $ = (id) => document.getElementById(id);
const ICONS = {
  logs: '<path d="M5 5h14M5 12h10M5 19h14"/>',
  upload: '<path d="M12 16V3m-4 4 4-4 4 4M4 15v5a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-5"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  download: '<path d="M12 3v12m-4-4 4 4 4-4M4 15v5a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-5"/>',
  "arrow-down": '<path d="M12 4v16m-5-5 5 5 5-5"/>',
  x: '<path d="m6 6 12 12M6 18 18 6"/>',
};
const icon = (name) => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ""}</svg>`;
const escapeHTML = (value) => String(value).replace(/[&<>"']/g, (char) => ({"&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"}[char]));
const number = (value) => Number(value).toLocaleString("en-US");
const dateFormat = (timestamp, options) => new Intl.DateTimeFormat("en-US", {timeZone:"UTC", ...options}).format(new Date(timestamp));
const dayLabel = (time) => dateFormat(time, {month:"short", day:"numeric"});
const timeLabel = (time) => dateFormat(time, {hour:"2-digit", minute:"2-digit", second:"2-digit", hourCycle:"h23"});
const state = {
  ready:false, busy:false, reading:false, revision:0, inputMode:"file", file:null, models:[],
  run:null, source:"", synthetic:false, threshold:0.75, filter:"flagged", query:"", sourceFilter:"",
  descending:true, page:1, pageSize:12, rowsById:new Map(), flagged:[], minTime:0, maxTime:0,
};
const humanReason = (reason) => {
  const known = {
    "new-IP-for-user":"New IP for this user", "never-seen-endpoint":"Endpoint not seen in training",
    "unusual-status-for-endpoint":"Unusual status for endpoint", "success-on-usually-denied-resource":"Success on a usually denied resource",
    "rare-status":"Rare response status", "authentication-required":"Authentication required", "access-denied":"Access denied",
    "server-error":"Server error", "failed-login":"Failed login", "login-success-after-failures":"Successful login after repeated failures",
    "suspicious-request-content":"Suspicious request content", "administrative-write":"Administrative change request",
    "large-successful-response":"Response over 5 MiB", "bulk-or-sensitive-download":"Bulk or sensitive download path",
    "outside-07-to-20-hours":"Outside 07:00–20:00 (log timezone)",
  };
  return known[reason] || reason.replace(/-/g," ").replace(/60s/g,"60 seconds");
};
const isFlagged = (row) => row.score >= state.threshold;
const scoreChip = (row) => `<span class="score-chip ${row.tier ? `tier-${row.tier}` : ""} ${isFlagged(row) ? "flagged" : ""}">${(row.score * 100).toFixed(1)}</span>`;

async function api(path, options = {}) {
  let response;
  try { response = await fetch(path, options); }
  catch { throw new Error("The local server could not be reached. Start it with python3 -m bench.dashboard and try again."); }
  let body;
  try { body = await response.json(); }
  catch { throw new Error("The server returned an unreadable response. Please try again."); }
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status}).`);
  return body;
}
function showError(id, message = "") { $(id).textContent = message; $(id).hidden = !message; }
function toast(message) {
  $("toast").textContent = message; $("toast").hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { $("toast").hidden = true; }, 4000);
}
function syncControls() {
  const hasInput = state.inputMode === "file" ? Boolean(state.file) : Boolean($("log-input").value.trim());
  $("analyze-submit").disabled = !state.ready || state.busy || state.reading || !hasInput;
  $("analyze-submit").lastElementChild.textContent = state.busy ? "Analyzing…" : state.reading ? "Reading file…" : "Analyze logs";
  for (const id of ["load-sample","model-select","log-input","log-file","remove-file","tab-file","tab-paste"]) $(id).disabled = state.busy;
  $("load-sample").disabled = !state.ready || state.busy || state.reading;
  $("cancel-input").disabled = state.busy;
  $("progress-message").hidden = !state.busy && !state.reading;
  $("progress-message").textContent = state.reading ? "Reading your log file…" : state.busy ? "Analyzing requests. Large files and trained models can take a moment." : "";
  $("input-panel").setAttribute("aria-busy", String(state.busy || state.reading));
}
function switchInput(mode) {
  state.inputMode = mode;
  for (const option of ["file","paste"]) {
    $(option + "-input-panel").hidden = mode !== option;
    $("tab-" + option).classList.toggle("active", mode === option);
    $("tab-" + option).setAttribute("aria-pressed", String(mode === option));
  }
  showError("analyze-error"); syncControls();
}
function showInput() {
  $("input-panel").hidden = false; $("results-panel").hidden = true;
  $("cancel-input").hidden = !state.run;
}
function showResults() { $("input-panel").hidden = true; $("results-panel").hidden = false; }
function fileSize(bytes) { return bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`; }
function lineCount(logs) { return logs.split("\n").reduce((total, line) => total + (line.trim() ? 1 : 0), 0); }
function renderFile() {
  $("selected-file").hidden = !state.file; $("file-preview").hidden = !state.file;
  $("dropzone").hidden = Boolean(state.file);
  if (!state.file) return;
  $("file-name").textContent = state.file.name;
  $("file-info").textContent = `${fileSize(state.file.size)} · ${number(state.file.lines)} requests`;
  $("file-preview").textContent = state.file.logs.split(/\r?\n/, 3).join("\n") + (state.file.lines > 3 ? "\n…" : "");
}
async function readFile(file) {
  if (!file || state.busy) return;
  const revision = ++state.revision;
  state.reading = true; showError("analyze-error"); syncControls();
  try {
    const logs = new TextDecoder("utf-8", {fatal:true}).decode(await file.arrayBuffer());
    if (revision !== state.revision) return;
    if (logs.includes("\0")) throw new Error("This looks like a binary file. Choose a plain-text access log.");
    state.file = {logs, name:file.name, size:file.size, lines:lineCount(logs), synthetic:false};
    renderFile();
  } catch (error) {
    if (revision === state.revision) showError("analyze-error", error instanceof TypeError ? "This file is not UTF-8 text. Choose a UTF-8 .log or .txt file." : error.message);
  } finally { if (revision === state.revision) { state.reading = false; syncControls(); } }
}
function modelHelp() {
  const model = state.models.find((item) => item.id === $("model-select").value);
  $("model-help").textContent = model?.id === "rules" ? "Preview rules check request patterns and repeated login failures. They do not use a trained model or a learned user profile." : model ? "Uses your saved model, calibrated against its training baseline: 99.0 means more unusual than 99% of normal traffic. Scores measure how unusual a request is, not the probability of an attack." : "No model information available.";
}
function renderModels() {
  $("model-select").innerHTML = state.models.map((model) => `<option value="${escapeHTML(model.id)}" ${model.available ? "" : "disabled"}>${escapeHTML(model.id === "rules" ? "Preview rules" : model.name)}${model.available ? "" : " — unavailable"}</option>`).join("");
  $("model-select").value = state.models.find((model) => model.available && model.id !== "rules")?.id || "rules";
  $("model-setup").hidden = state.models.every((model) => model.available);
  modelHelp();
}
async function analyze(logs, model, source, synthetic = false) {
  if (state.busy || state.reading) return;
  if (!logs.trim()) { showError("analyze-error", "Add at least one log line to analyze."); return; }
  state.busy = true; syncControls(); showError("analyze-error");
  try {
    const run = await api("/api/predict", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({logs, model})});
    state.run = run; state.source = source; state.synthetic = synthetic;
    state.threshold = run.score_kind === "calibrated" ? (run.tiers?.yellow ?? 0.99)
      : run.score_kind === "percentile" ? 0.98 : 0.75;
    state.filter = "flagged"; state.page = 1; state.query = ""; state.sourceFilter = ""; state.descending = true;
    state.rowsById = new Map(); state.minTime = Infinity; state.maxTime = -Infinity;
    for (const row of run.rows) {
      row.time = new Date(row.timestamp).getTime(); row.signals = row.reasons.map(humanReason);
      state.rowsById.set(row.id, row); state.minTime = Math.min(state.minTime, row.time); state.maxTime = Math.max(state.maxTime, row.time);
    }
    $("threshold").value = String(state.threshold * 100); $("search").value = "";
    $("results-title").textContent = source;
    const duration = run.elapsed_ms < 1000 ? `${Math.max(1, Math.round(run.elapsed_ms))} ms` : `${(run.elapsed_ms / 1000).toFixed(1)} s`;
    $("run-description").textContent = `${dayLabel(state.minTime)}, ${dateFormat(state.minTime,{year:"numeric"})} – ${dayLabel(state.maxTime)}, ${dateFormat(state.maxTime,{year:"numeric"})} · ${run.model_name} · analyzed in ${duration}`;
    const sampleNotice = synthetic ? "Synthetic sample. " : "";
    $("run-notice").textContent = sampleNotice + (run.mode === "heuristic" ? "Preview rules only — these results are indicators for review. No trained model or historical user profile was used." : (run.notice || "Scored with your trained model. A high score does not confirm an attack."));
    $("score-explanation").textContent = run.score_kind === "calibrated" ? "Scores are calibrated against the training baseline, so they do not depend on what else you uploaded: 99.0 means more unusual than 99% of normal traffic. Amber marks the top 1%, red the top 0.1%. Explanation tags describe input features, not model attribution." : run.score_kind === "percentile" ? "Scores are batch percentiles. A cutoff of 98 reviews approximately the top 2% of this file (ties may change that). Explanation tags describe input features, not model attribution." : "Scores are fixed rule weights, not attack probabilities. The cutoff controls which requests appear in the review queue. A request below the cutoff may still deserve investigation.";
    showResults(); renderSummary(); renderTable();
    toast(`${number(run.rows.length)} requests analyzed.`);
  } catch (error) { showError("analyze-error", error.message); }
  finally { state.busy = false; syncControls(); }
}
function renderSummary() {
  if (!state.run) return;
  state.flagged = state.run.rows.filter(isFlagged);
  const sources = new Map();
  for (const row of state.flagged) {
    if (!sources.has(row.ip)) sources.set(row.ip, {ip:row.ip, count:0, users:new Set()});
    const source = sources.get(row.ip); source.count++; source.users.add(row.user);
  }
  $("stat-total").textContent = number(state.run.rows.length);
  $("stat-flagged").textContent = number(state.flagged.length);
  $("stat-rate").textContent = `${(state.flagged.length / state.run.rows.length * 100).toFixed(1)}% at cutoff ${Math.round(state.threshold * 100)}`;
  $("stat-sources").textContent = number(sources.size);
  $("flagged-count").textContent = number(state.flagged.length);
  document.querySelector(".context-grid").hidden = state.flagged.length === 0;
  const ordered = [...sources.values()].sort((a,b) => b.count - a.count);
  $("source-list").innerHTML = ordered.length ? ordered.slice(0,5).map((source) => `<button class="source-row ${state.sourceFilter === source.ip ? "active" : ""}" data-source="${escapeHTML(source.ip)}"><span class="source-summary"><strong>${escapeHTML(source.ip)}</strong><span>${escapeHTML([...source.users].map((user) => user === "-" ? "Anonymous" : user).slice(0,3).join(", "))}${source.users.size > 3 ? ` +${source.users.size - 3}` : ""}</span></span><span class="source-count">${number(source.count)} flagged</span></button>`).join("") + (ordered.length > 5 ? `<p class="context-note">Top 5 of ${number(ordered.length)} sources. Search the table for others.</p>` : "") : '<p class="context-note">No sources have requests above the current cutoff.</p>';
  renderActivity(); updateSourceFilter();
}
function renderActivity() {
  const day = 86400000, range = state.maxTime - state.minTime;
  const start = range >= day ? Math.floor(state.minTime / day) * day : state.minTime;
  const end = range >= day ? (Math.floor(state.maxTime / day) + 1) * day : Math.max(state.maxTime + 1000, start + 60000);
  const step = range >= day ? day * Math.max(1,Math.ceil((end-start)/day/32)) : (end-start)/8;
  const count = Math.ceil((end-start)/step);
  const bins = Array.from({length:count}, (_,i) => ({time:start+i*step, count:0}));
  for (const row of state.flagged) bins[Math.min(count-1, Math.floor((row.time-start)/step))].count++;
  const max = Math.max(4, Math.ceil(Math.max(...bins.map((bin) => bin.count)) / 4)*4);
  const svgWidth=Math.max(260,$("activity-chart").getBoundingClientRect().width || 700);
  const left=44, right=svgWidth-15, top=15, bottom=125, width=right-left, slot=width/count;
  let svg = `<svg viewBox="0 0 ${svgWidth} 165" role="img" aria-label="Flagged request count over the time range of this file">`;
  for (let i=0;i<=4;i++) {
    const y=bottom-i/4*(bottom-top);
    svg += `<line x1="${left}" x2="${right}" y1="${y}" y2="${y}" stroke="#e7eaf0"/><text x="${left-10}" y="${y+4}" text-anchor="end">${number(max*i/4)}</text>`;
  }
  bins.forEach((bin,i) => {
    const height=bin.count/max*(bottom-top), x=left+i*slot+slot*0.2;
    svg += `<rect x="${x}" y="${bottom-height}" width="${slot*0.6}" height="${height}" rx="2" fill="#b94a3e"><title>${escapeHTML(dayLabel(bin.time))} ${timeLabel(bin.time)} UTC: ${bin.count} flagged</title></rect>`;
  });
  const ticks=svgWidth<450?3:5;
  for (let i=0;i<ticks;i++) {
    const time=start+(end-start-1)*i/(ticks-1);
    svg += `<text x="${left+width*i/(ticks-1)}" y="155" text-anchor="${i===0?"start":i===ticks-1?"end":"middle"}">${escapeHTML(range>=day ? dayLabel(time) : range<3600000 ? timeLabel(time) : timeLabel(time).slice(0,5))}</text>`;
  }
  $("activity-chart").innerHTML = svg+'</svg>';
  $("chart-period").textContent = `${dayLabel(state.minTime)} – ${dayLabel(state.maxTime)}`;
}
function updateSourceFilter() {
  $("clear-source").hidden = !state.sourceFilter;
  $("active-source").hidden = !state.sourceFilter;
  $("active-source").textContent = state.sourceFilter ? `${state.sourceFilter} ×` : "";
}
function matchingRows() {
  if (!state.run) return [];
  const query=state.query.trim().toLowerCase(), base=state.filter === "flagged" ? state.flagged : state.run.rows;
  const rows=base.filter((row) => (!state.sourceFilter || row.ip === state.sourceFilter) && (!query || [row.ip,row.user,row.path,row.method,row.status,...row.signals].join(" ").toLowerCase().includes(query)));
  return state.descending ? rows : rows.sort((a,b) => a.score-b.score || a.id-b.id);
}
function renderTable() {
  const rows=matchingRows(), pages=Math.max(1,Math.ceil(rows.length/state.pageSize));
  state.page=Math.max(1,Math.min(state.page,pages));
  const start=(state.page-1)*state.pageSize, visible=rows.slice(start,start+state.pageSize);
  $("log-rows").innerHTML = visible.length ? visible.map((row) => `<tr data-row-id="${row.id}"><td>${scoreChip(row)}</td><td><div class="request-cell"><span class="method">${escapeHTML(row.method)}</span><span class="endpoint" title="${escapeHTML(row.path)}">${escapeHTML(row.path)}</span></div><div class="row-signals">${escapeHTML(row.signals.slice(0,2).join(" · ") || "No explanation tags")}${row.signals.length>2?` · +${row.signals.length-2}`:""}</div></td><td><span class="source-ip">${escapeHTML(row.ip)}</span><span class="source-user">${escapeHTML(row.user === "-" ? "Anonymous" : row.user)}</span></td><td><span class="http-status ${row.status>=400?"error":row.status>=300?"redirect":""}">${row.status}</span></td><td class="time-cell">${escapeHTML(dayLabel(row.time))}<span>${timeLabel(row.time)}</span></td><td><button class="text-button row-detail-button" data-inspect="${row.id}" aria-label="Inspect request on line ${row.id}">Details</button></td></tr>`).join("") : `<tr><td colspan="6" class="empty-table">${state.query || state.sourceFilter ? "No requests match these filters." : `No requests meet the ${Math.round(state.threshold*100)} / 100 review cutoff.`}<br><button class="text-button" id="show-all-empty">Show all requests</button></td></tr>`;
  $("table-caption").textContent = rows.length ? `${number(start+1)}–${number(Math.min(start+state.pageSize,rows.length))} of ${number(rows.length)} matching requests` : "0 matching requests";
  $("page-number").textContent = `${state.page} / ${pages}`;
  $("previous-page").disabled=state.page<=1; $("next-page").disabled=state.page>=pages;
  for (const filter of ["all","flagged"]) { $("filter-"+filter).classList.toggle("active",state.filter===filter); $("filter-"+filter).setAttribute("aria-pressed",String(state.filter===filter)); }
  $("sort-score").parentElement.setAttribute("aria-sort",state.descending?"descending":"ascending");
  $("sort-score").setAttribute("aria-label",`Score, ${state.descending?"highest":"lowest"} first. Reverse sort order`);
  $("sort-score").querySelector("svg").style.transform=state.descending?"":"rotate(180deg)";
  $("export-results").disabled=rows.length===0;
  $("export-results").title="Export all requests matching the current filters";
}
function inspectRow(id) {
  const row=state.rowsById.get(id); if (!row) return;
  const actorRows=state.run.rows.filter((item) => item.ip===row.ip && item.user===row.user).sort((a,b) => a.time-b.time || a.id-b.id);
  const index=actorRows.findIndex((item) => item.id===id), first=Math.max(0,index-5), related=actorRows.slice(first,Math.min(actorRows.length,first+11));
  $("detail-title").textContent=`${row.method} ${row.path}`;
  $("detail-line").textContent=`Original line ${number(row.id)} · ${state.source}`;
  const fields=[["Source",row.ip],["User",row.user==="-"?"Anonymous":row.user],["Time (UTC)",`${dayLabel(row.time)}, ${dateFormat(row.time,{year:"numeric"})} ${timeLabel(row.time)}`],["Response",`${row.status} · ${number(row.bytes)} bytes`]];
  $("detail-content").innerHTML=`<div class="detail-score">${scoreChip(row)}<div><strong>${isFlagged(row)?"Marked for review":"Below the review cutoff"}</strong><span>${state.run.score_kind==="calibrated"?"Calibrated vs training baseline":state.run.score_kind==="percentile"?"Batch percentile":"Rule score"} out of 100 · cutoff ${Math.round(state.threshold*100)}</span></div></div><dl class="detail-grid">${fields.map(([key,value])=>`<div><dt>${key}</dt><dd>${escapeHTML(value)}</dd></div>`).join("")}</dl><section class="detail-section"><h3>Signals</h3><ul class="signal-list">${row.signals.length?row.signals.map((signal)=>`<li>${escapeHTML(signal)}</li>`).join(""):"<li>No rule-based explanation tags for this request.</li>"}</ul>${state.run.mode==="trained"?'<p class="context-note">These tags describe input features; they are not an attribution of the model’s score.</p>':""}</section><section class="detail-section"><h3>Nearby requests from this IP and user</h3><p class="context-note">${number(first+1)}–${number(first+related.length)} of ${number(actorRows.length)} requests from this actor, in time order. Selected request highlighted.</p><div class="table-scroll"><table class="related-table"><thead><tr><th>Time (UTC)</th><th>Request</th><th>Status</th><th>Score</th></tr></thead><tbody>${related.map((item)=>`<tr class="${item.id===id?"current-row":""} ${isFlagged(item)?"flagged-row":""}"><td>${dayLabel(item.time)} ${timeLabel(item.time)}</td><td><button class="text-button" data-related="${item.id}">${escapeHTML(item.method)} ${escapeHTML(item.path)}</button></td><td>${item.status}</td><td>${(item.score*100).toFixed(1)}</td></tr>`).join("")}</tbody></table></div></section><section class="detail-section"><h3>Original log line</h3><pre class="raw-log">${escapeHTML(row.raw)}</pre></section>`;
  if (!$("detail-dialog").open) $("detail-dialog").showModal();
}
function exportCSV() {
  const rows=matchingRows(); if (!rows.length) return;
  const cell=(value)=>{ let text=String(value); if (/^[\s]*[=+@-]/.test(text)||/^[\t\r\n]/.test(text)) text="'"+text; return `"${text.replace(/"/g,'""')}"`; };
  const header=["source_line","timestamp","ip","user","method","path","status","bytes","score_0_to_100","flagged_for_review","review_cutoff","reasons","model","score_kind","synthetic_sample"];
  const lines=[header.map(cell).join(",")];
  for (const row of rows) lines.push([row.id,row.timestamp,row.ip,row.user,row.method,row.path,row.status,row.bytes,(row.score*100).toFixed(2),isFlagged(row),state.threshold*100,row.reasons.join("; "),state.run.model,state.run.score_kind,state.synthetic].map(cell).join(","));
  const url=URL.createObjectURL(new Blob(["\uFEFF",lines.join("\r\n")],{type:"text/csv;charset=utf-8;"}));
  const link=document.createElement("a"); link.href=url; link.download=`log-review-${state.run.model}-${new Date().toISOString().slice(0,10)}.csv`;
  document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
  toast(`Exported ${number(rows.length)} matching requests.`);
}

for (const element of document.querySelectorAll("[data-icon]")) element.innerHTML=icon(element.dataset.icon);
for (const mode of ["file","paste"]) $("tab-"+mode).addEventListener("click",()=>switchInput(mode));
$("new-analysis").addEventListener("click",showInput);
$("cancel-input").addEventListener("click",showResults);
$("model-select").addEventListener("change",modelHelp);
$("log-input").addEventListener("input",()=>{ $("paste-count").textContent=`${number(lineCount($("log-input").value))} requests`; syncControls(); });
$("log-file").addEventListener("change",async()=>{await readFile($("log-file").files[0]);$("log-file").value="";});
$("remove-file").addEventListener("click",()=>{state.revision++;state.reading=false;state.file=null;renderFile();syncControls();});
for (const type of ["dragenter","dragover"]) $("dropzone").addEventListener(type,(event)=>{event.preventDefault();$("dropzone").classList.add("dragging");});
for (const type of ["dragleave","drop"]) $("dropzone").addEventListener(type,(event)=>{event.preventDefault();$("dropzone").classList.remove("dragging");});
$("dropzone").addEventListener("drop",(event)=>{if(event.dataTransfer.files.length!==1)showError("analyze-error","Choose one log file at a time.");else readFile(event.dataTransfer.files[0]);});
$("analyze-form").addEventListener("submit",async(event)=>{
  event.preventDefault();if(state.busy||state.reading||!state.ready)return;
  const file=state.inputMode==="file"?state.file:null;
  const logs=state.inputMode==="file" ? (file?.logs || "") : $("log-input").value;
  await analyze(logs,$("model-select").value,file?.name||"Pasted logs",Boolean(file?.synthetic));
});
$("load-sample").addEventListener("click",async()=>{
  if(state.busy||state.reading)return;
  const revision=++state.revision;state.reading=true;syncControls();showError("analyze-error");
  try{
    const sample=await api("/api/sample");if(revision!==state.revision)return;
    state.file={logs:sample.logs,name:"Synthetic sample logs",size:new TextEncoder().encode(sample.logs).length,lines:lineCount(sample.logs),synthetic:true};
    state.reading=false;switchInput("file");renderFile();$("model-select").value="rules";modelHelp();
    await analyze(sample.logs,"rules",state.file.name,true);
  }catch(error){showError("analyze-error",error.message);}
  finally{if(revision===state.revision){state.reading=false;syncControls();}}
});
function updateThreshold(){
  const value=Number($("threshold").value);if(!Number.isFinite(value)||$("threshold").value===""){$("threshold").value=String(state.threshold*100);return;}
  state.threshold=Math.max(0,Math.min(100,Math.round(value)))/100;$("threshold").value=String(state.threshold*100);state.page=1;renderSummary();renderTable();
}
$("threshold").addEventListener("change",updateThreshold);
$("threshold").addEventListener("input",()=>{clearTimeout(state.thresholdTimer);if($("threshold").value!=="")state.thresholdTimer=setTimeout(updateThreshold,150);});
$("search").addEventListener("input",()=>{clearTimeout(state.searchTimer);state.query=$("search").value;state.page=1;state.searchTimer=setTimeout(renderTable,120);});
for(const filter of ["all","flagged"])$("filter-"+filter).addEventListener("click",()=>{state.filter=filter;state.page=1;renderTable();});
$("source-list").addEventListener("click",(event)=>{const target=event.target.closest("[data-source]");if(target){state.sourceFilter=target.dataset.source;state.filter="flagged";state.page=1;renderSummary();renderTable();}});
$("clear-source").addEventListener("click",()=>{state.sourceFilter="";state.page=1;renderSummary();renderTable();});
$("active-source").addEventListener("click",()=>{state.sourceFilter="";state.page=1;renderSummary();renderTable();});
$("sort-score").addEventListener("click",()=>{state.descending=!state.descending;state.page=1;renderTable();});
$("previous-page").addEventListener("click",()=>{state.page--;renderTable();});
$("next-page").addEventListener("click",()=>{state.page++;renderTable();});
$("export-results").addEventListener("click",exportCSV);
$("log-rows").addEventListener("click",(event)=>{
  if(event.target.closest("#show-all-empty")){state.filter="all";state.sourceFilter="";state.query="";$("search").value="";state.page=1;renderSummary();renderTable();return;}
  const row=event.target.closest("[data-row-id]");if(row)inspectRow(Number(row.dataset.rowId));
});
$("detail-content").addEventListener("click",(event)=>{const target=event.target.closest("[data-related]");if(target)inspectRow(Number(target.dataset.related));});
$("close-detail").addEventListener("click",()=>$("detail-dialog").close());
$("detail-dialog").addEventListener("click",(event)=>{if(event.target===$("detail-dialog")){const box=$("detail-dialog").getBoundingClientRect();if(event.clientX<box.left||event.clientX>box.right||event.clientY<box.top||event.clientY>box.bottom)$("detail-dialog").close();}});
window.addEventListener("resize",()=>{clearTimeout(state.resizeTimer);state.resizeTimer=setTimeout(()=>{if(state.run&&!$("results-panel").hidden)renderActivity();},100);});
(async()=>{
  try{const status=await api("/api/status");state.models=status.models;state.ready=true;renderModels();$("connection").textContent=state.models.some((model)=>model.available&&model.id!=="rules")?"Local server · trained models available":"Local server · preview rules only";syncControls();}
  catch(error){$("connection").textContent="Server unavailable";showError("page-error",error.message);}
})();
