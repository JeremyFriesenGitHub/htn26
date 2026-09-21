"use strict";

const $ = (id) => document.getElementById(id);
const Review = window.LogReview;
const ICONS = {
  logs: '<path d="M5 5h14M5 12h10M5 19h14"/>',
  upload: '<path d="M12 16V3m-4 4 4-4 4 4M4 15v5a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-5"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  report: '<path d="M6 3h9l4 4v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm9 0v5h4M8 12h8M8 16h8"/>',
  download: '<path d="M12 3v12m-4-4 4 4 4-4M4 15v5a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-5"/>',
  "arrow-down": '<path d="M12 4v16m-5-5 5 5 5-5"/>',
  x: '<path d="m6 6 12 12M6 18 18 6"/>',
};
const icon = (name) => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ""}</svg>`;
const escapeHTML = (value) => String(value).replace(/[&<>"']/g, (char) => ({"&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"}[char]));
const number = (value) => Number(value).toLocaleString("en-US");
const dateFormat = (timestamp, options) => new Intl.DateTimeFormat("en-US", options).format(new Date(timestamp));
const dayLabel = (time) => dateFormat(time, {month:"short", day:"numeric"});
const timeLabel = (time) => dateFormat(time, {hour:"2-digit", minute:"2-digit", second:"2-digit", hourCycle:"h23"});
const zoneLabel = (time) => new Intl.DateTimeFormat("en-US", {timeZoneName:"short"}).formatToParts(new Date(time)).find((part)=>part.type==="timeZoneName").value;
const Investigation = window.LogInvestigation;
const state = {
  ready:false,busy:false,reading:false,revision:0,inputMode:"file",file:null,models:[],
  run:null,source:"",synthetic:false,threshold:1,logs:"",rowsById:new Map(),
  runs:new Map(),activeModel:"",modelBusy:false,investigations:[],caseId:null,
  selection:null,edits:new Map(),dispositions:new Map(),eventNotes:new Map(),
  query:"",account:"",overviewPage:1,timelineLimit:40,earlierLimit:12,relatedLimit:12,includeContext:true,
  cacheKey:"",timeSliceLevel:10,timeSliceCustomized:false,sliceSpec:null,
};
const TIME_SLICE_TARGETS = [240,168,112,72,44,26,14,7,3,1];
const defaultCutoff = () => 1;
const isCandidate = (row) => Review.isCandidate(row,state.threshold);
const shortTime = (time) => `${dayLabel(time)} ${timeLabel(time)} ${zoneLabel(time)}`;
const accountName = (value) => value && value !== "-" ? value : "Anonymous";
const actionName = (row) => `${row.method} ${row.path}`;

const ANALYSIS_CACHE_DATABASE = "trace-analysis-cache";
const ANALYSIS_CACHE_STORE = "analyses";
const ANALYSIS_CACHE_VERSION = 1;
const ACTIVE_ANALYSIS_POINTER = "trace-active-analysis-v1";
function cacheRequest(request) {
  return new Promise((resolve,reject)=>{request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error||new Error("Browser storage failed."));});
}
function openAnalysisCache() {
  return new Promise((resolve,reject)=>{
    if(!window.indexedDB){reject(new Error("Browser analysis caching is unavailable."));return;}
    const request=indexedDB.open(ANALYSIS_CACHE_DATABASE,ANALYSIS_CACHE_VERSION);
    request.onupgradeneeded=()=>{
      const database=request.result;
      if(!database.objectStoreNames.contains(ANALYSIS_CACHE_STORE)){
        const store=database.createObjectStore(ANALYSIS_CACHE_STORE,{keyPath:"key"});
        store.createIndex("savedAt","savedAt");
      }
    };
    request.onsuccess=()=>resolve(request.result);
    request.onerror=()=>reject(request.error||new Error("Browser analysis caching is unavailable."));
  });
}
async function analysisCacheKey(logs,model) {
  if(!window.crypto?.subtle)return "";
  const digest=await window.crypto.subtle.digest("SHA-256",new TextEncoder().encode(logs));
  const hash=Array.from(new Uint8Array(digest),(byte)=>byte.toString(16).padStart(2,"0")).join("");
  return `v${ANALYSIS_CACHE_VERSION}:${model}:${hash}`;
}
async function packCachedAnalysis(value) {
  const json=JSON.stringify(value);
  if(typeof CompressionStream==="undefined")return {compressed:false,payload:json};
  const payload=await new Response(new Blob([json]).stream().pipeThrough(new CompressionStream("gzip"))).blob();
  return {compressed:true,payload};
}
async function unpackCachedAnalysis(record) {
  if(!record)return null;
  let text;
  if(record.compressed){
    if(typeof DecompressionStream==="undefined")return null;
    text=await new Response(record.payload.stream().pipeThrough(new DecompressionStream("gzip"))).text();
  }else text=typeof record.payload==="string"?record.payload:await record.payload.text();
  return {...record,...JSON.parse(text)};
}
async function pruneAnalysisCache(database,keep=4) {
  await new Promise((resolve,reject)=>{
    const transaction=database.transaction(ANALYSIS_CACHE_STORE,"readwrite"),store=transaction.objectStore(ANALYSIS_CACHE_STORE);
    const countRequest=store.count();
    countRequest.onsuccess=()=>{
      let remaining=Math.max(0,countRequest.result-keep);
      if(!remaining)return;
      const cursorRequest=store.index("savedAt").openKeyCursor();
      cursorRequest.onsuccess=()=>{
        const cursor=cursorRequest.result;
        if(!cursor||remaining<=0)return;
        store.delete(cursor.primaryKey);remaining--;cursor.continue();
      };
    };
    transaction.oncomplete=resolve;
    transaction.onerror=()=>reject(transaction.error||new Error("Could not prune the browser cache."));
    transaction.onabort=()=>reject(transaction.error||new Error("Could not prune the browser cache."));
  });
}
async function writeCachedAnalysis(key,model,logs,result) {
  if(!key)return;
  const packed=await packCachedAnalysis({logs,result});
  const database=await openAnalysisCache();
  try{
    await new Promise((resolve,reject)=>{
      const transaction=database.transaction(ANALYSIS_CACHE_STORE,"readwrite");
      transaction.objectStore(ANALYSIS_CACHE_STORE).put({key,model,savedAt:Date.now(),...packed});
      transaction.oncomplete=resolve;
      transaction.onerror=()=>reject(transaction.error||new Error("Could not cache this analysis."));
      transaction.onabort=()=>reject(transaction.error||new Error("Could not cache this analysis."));
    });
    await pruneAnalysisCache(database);
  }finally{database.close();}
}
async function readCachedAnalysis(key) {
  if(!key)return null;
  const database=await openAnalysisCache();
  try{
    const transaction=database.transaction(ANALYSIS_CACHE_STORE,"readonly");
    return await unpackCachedAnalysis(await cacheRequest(transaction.objectStore(ANALYSIS_CACHE_STORE).get(key)));
  }finally{database.close();}
}
function persistActiveAnalysis() {
  if(!state.run)return;
  try{
    if(!state.cacheKey){sessionStorage.removeItem(ACTIVE_ANALYSIS_POINTER);return;}
    sessionStorage.setItem(ACTIVE_ANALYSIS_POINTER,JSON.stringify({key:state.cacheKey,source:state.source,synthetic:state.synthetic,threshold:state.threshold,timeSliceLevel:state.timeSliceLevel,timeSliceCustomized:state.timeSliceCustomized}));
  }catch{}
}
function activeAnalysisPointer() {
  try{return JSON.parse(sessionStorage.getItem(ACTIVE_ANALYSIS_POINTER)||"null");}
  catch{return null;}
}

async function api(path, options = {}) {
  let response;
  try { response = await fetch(path, options); }
  catch { throw new Error("The analysis server could not be reached. Please try again."); }
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
function updateProgress(event) {
  state.progress = event;
  const names = {upload:"Sending logs",parse:"Parsing log lines",features:"Building request features",model:"Scoring requests",calibration:"Checking the training baseline",reasons:"Preparing explanations",results:"Preparing results",llm:"Reviewing shortlisted requests",display:"Building the review view",file:"Reading log file"};
  $("progress-stage").textContent = names[event.stage] || event.stage || "Processing";
  const known = Number.isFinite(event.completed) && Number.isFinite(event.total) && event.total > 0;
  const pct = known ? Math.min(100, event.completed / event.total * 100) : null;
  if (known) $("progress-bar").value = pct;
  else $("progress-bar").removeAttribute("value");
  $("progress-count").textContent = known ? `${number(event.completed)} / ${number(event.total)} · ${Math.floor(pct)}%` : "In progress";
  $("progress-message").textContent = event.message || "Processing on this server…";
  $("processing-progress").hidden = false;
}
async function predictStream(logs, model, report = updateProgress) {
  report({stage:"upload",message:"Sending logs to the analysis server."});
  await new Promise((resolve) => setTimeout(resolve, 0));
  let response;
  try { response = await fetch("/api/predict", {method:"POST",headers:{"Content-Type":"application/json","Accept":"application/x-ndjson"},body:JSON.stringify({logs,model})}); }
  catch { throw new Error("The analysis server could not be reached. Please try again."); }
  if (!response.headers.get("Content-Type")?.includes("application/x-ndjson")) {
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `Analysis failed (${response.status}).`);
    return body;
  }
  if (!response.body) throw new Error("The browser did not provide an analysis stream. Try again.");
  const reader = response.body.getReader(), decoder = new TextDecoder();
  let pieces = [], result;
  function consume(line) {
    if (!line.trim()) return;
    const event = JSON.parse(line);
    if (event.type === "error") throw new Error(event.error || "Analysis failed.");
    if (event.type === "progress") report(event);
    if (event.type === "result") result = event.result;
  }
  try {
    while (true) {
      const {done,value} = await reader.read();
      const text = done ? decoder.decode() : decoder.decode(value,{stream:true});
      const lines = text.split("\n");
      for (let i=0;i<lines.length;i++) {
        pieces.push(lines[i]);
        if (i<lines.length-1) { consume(pieces.join("")); pieces=[]; }
      }
      if (done) break;
    }
    if (pieces.length) consume(pieces.join(""));
  } catch (error) { await reader.cancel().catch(()=>{}); throw error; }
  finally { reader.releaseLock(); }
  if (!result) throw new Error("Analysis ended before results arrived. Please try again.");
  return result;
}
function syncControls() {
  const hasInput = state.inputMode === "file" ? Boolean(state.file) : Boolean($("log-input").value.trim());
  $("analyze-submit").disabled = !state.ready || state.busy || state.reading || !hasInput || !state.models.some((model)=>model.available&&model.id===$("model-select").value);
  $("analyze-submit").lastElementChild.textContent = state.busy ? "Analyzing…" : state.reading ? "Reading file…" : "Analyze logs";
  for (const id of ["load-sample","model-select","log-input","log-file","remove-file","tab-file","tab-paste","tab-session","session-file"]) $(id).disabled = state.busy;
  $("load-sample").disabled = !state.ready || state.busy || state.reading || !state.models.some((model)=>model.available&&model.id===$("model-select").value);
  $("model-select").disabled = state.busy || !state.ready || !state.models.some((model)=>model.available);
  $("session-file").disabled = state.busy || state.reading || state.modelBusy;
  $("session-load-status").hidden = !state.reading;
  if (state.reading) updateProgress({stage:"file",message:"Reading your file. There is no upload size limit."});
  $("processing-progress").hidden = !state.busy && !state.reading;
  $("input-panel").setAttribute("aria-busy", String(state.busy || state.reading));
}

function switchInput(mode) {
  state.inputMode = mode;
  for (const option of ["file","paste","session"]) {
    $(option + "-input-panel").hidden = mode !== option;
    $("tab-" + option).classList.toggle("active", mode === option);
    $("tab-" + option).setAttribute("aria-pressed", String(mode === option));
  }
  $("analyze-form").hidden = mode === "session";
  $("load-sample").hidden = mode === "session";
  showError("analyze-error"); syncControls();
}
const routes = {home:"/", investigations:"/investigations", analyze:"/analyze", models:"/models"};
if("scrollRestoration" in history)history.scrollRestoration="manual";
function routeTo(path, replace=false) {
  if(location.pathname + location.search !== path){
    history[replace?"replaceState":"pushState"]({},"",path);
    window.scrollTo(0,0);
  }
}
function setView(view) {
  for (const link of document.querySelectorAll(".primary-nav [data-view]")) {
    if (link.dataset.view === view) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  $("models-panel").hidden = view !== "models";
  $("home-panel").hidden = view !== "home";
  $("investigations-empty").hidden = view !== "investigations" || Boolean(state.run);
  document.title = `Trace · ${{home:"Home",analyze:"Analyze logs",investigations:"Investigations",models:"Models"}[view]}`;
}
function renderRoute() {
  const path = location.pathname.replace(/\/$/, "") || "/";
  if(path === "/") {
    setView("home"); $("input-panel").hidden=true; $("results-panel").hidden=true;
  } else if(path === "/analyze") {
    setView("analyze"); $("input-panel").hidden=false; $("results-panel").hidden=true;
    const mode=new URLSearchParams(location.search).get("input");
    switchInput(["file","paste","session"].includes(mode)?mode:"file");
  } else if(path === "/models") {
    setView("models"); $("input-panel").hidden=true; $("results-panel").hidden=true; renderModelCatalog();
  } else {
    setView("investigations"); $("input-panel").hidden=true; $("results-panel").hidden=!state.run;
    if(state.run) {
      const id=path.startsWith("/investigations/")?path.slice(16):null;
      const formerCandidate=/^investigation-(\d+)$/.exec(id||"");
      const item=id&&(caseById(id)||(formerCandidate&&state.investigations.find((entry)=>entry.candidateIds.includes(Number(formerCandidate[1])))));
      if(item){
        if(item.id!==id)routeTo(`/investigations/${encodeURIComponent(item.id)}`,true);
        openCase(item.id,false);
      }else {state.caseId=null;state.selection=null;renderOverview();}
    }
  }
}
function navigate(view) {
  if (state.busy || state.reading || state.modelBusy) { toast("Let the current analysis finish before switching views."); return; }
  if(cutoffTimer!==null)applyCutoff();
  routeTo(routes[view]||"/"); renderRoute();
}
window.addEventListener("popstate",()=>{if(cutoffTimer!==null)applyCutoff();renderRoute();window.scrollTo(0,0);});
const servedModelDescriptions = {
  gmm: "The Gaussian mixture model learns the distribution of standardized request features. The challenge configuration uses four components with diagonal covariance. Requests with combinations of features that are uncommon in the training data receive higher anomaly scores.",
  ae: "The deep autoencoder ensemble learns to reconstruct request features using seven neural networks. Each network is trained with regularization and early stopping. The model averages normalized reconstruction errors, assigning higher scores to requests whose features differ from the patterns learned during training.",
  hybrid: "This optional review combines GMM scoring with external LLM triage. GMM ranks the requests first, then shortlisted records and historical account context are sent to OpenAI. It uses the trained GMM and does not train a separate detector."
};
function renderModelCatalog() {
  const models = state.models.filter((model) => model.available);
  $("model-catalog").innerHTML = models.length ? models.map((model) => `<article class="panel model-card"><div class="model-card-heading"><h3>${escapeHTML(model.name)}</h3></div><p>${escapeHTML(servedModelDescriptions[model.id]||model.detail)}</p><button class="button secondary" data-use-model="${escapeHTML(model.id)}">Use this model →</button></article>`).join("") : "<p>No models are currently available.</p>";
}
for (const link of document.querySelectorAll("[data-view]")) link.addEventListener("click", (event) => {
  if(event.metaKey||event.ctrlKey||event.shiftKey||event.altKey)return;
  event.preventDefault();navigate(link.dataset.view);
});
$("model-catalog").addEventListener("click", (event) => {
  const button = event.target.closest("[data-use-model]");
  if (!button || button.disabled || state.busy || state.reading || state.modelBusy) return;
  navigate("analyze"); $("model-select").value = button.dataset.useModel; modelHelp(); $("model-select").focus();syncControls();
});
function showInput() { navigate("analyze"); }
function showResults() {
  routeTo(state.caseId?`/investigations/${encodeURIComponent(state.caseId).replace(/%3A/gi,":")}`:"/investigations");
  setView("investigations"); $("input-panel").hidden=true; $("results-panel").hidden=false;
  if(state.run) {if(state.caseId)renderWorkspace();else renderOverview();}
}
function updateCutoffLabel() {
  const value=Number($("investigation-cutoff").value);
  $("cutoff-value").textContent=`${Number(value.toFixed(3))}%`;
  $("investigation-cutoff").setAttribute("aria-valuetext",`${value} percentile`);
}
function caseLineRange(item) {
  let first=Infinity,last=-Infinity;
  for(const id of item.candidateIds){first=Math.min(first,id);last=Math.max(last,id);}
  if(first===Infinity)return "Investigation";
  return first===last?`Line ${first}`:`Lines ${first} to ${last}`;
}
function caseTimeRange(item) {
  const start=shortTime(item.start);
  if(item.start===item.end)return start;
  return dayLabel(item.start)===dayLabel(item.end)&&zoneLabel(item.start)===zoneLabel(item.end)
    ?`${dayLabel(item.start)} ${timeLabel(item.start)} – ${timeLabel(item.end)} ${zoneLabel(item.end)}`
    :`${start} – ${shortTime(item.end)}`;
}
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
    if(state.ready&&$("model-select").value)await loadCachedUpload(logs,$("model-select").value,file.name,false);
  } catch (error) {
    if (revision === state.revision) showError("analyze-error", error instanceof TypeError ? "This file is not UTF-8 text. Choose a UTF-8 .log or .txt file." : error.message);
  } finally { if (revision === state.revision) { state.reading = false; syncControls(); } }
}
function modelHelp() {
  const model = state.models.find((item) => item.id === $("model-select").value);
  if (model?.id === "hybrid") { $("model-help").textContent = "The GMM ranks every line on the analysis server, then only its top slice is sent to OpenAI for review with each user\u2019s normal-access profile. This is the only option that sends log data to an external AI service."; return; }
  $("model-help").textContent = model ? "Ranks requests using the saved model. Results show the raw anomaly score and its training-baseline percentile separately; neither is attack confidence." : "No model information available.";
}
function renderModels() {
  $("model-select").innerHTML = state.models.filter((model) => model.available).map((model) => `<option value="${escapeHTML(model.id)}">${escapeHTML(model.name)}</option>`).join("");
  $("model-select").value = state.models.find((model) => model.available && model.id === "gmm")?.id || state.models.find((model) => model.available)?.id || "";
  modelHelp(); renderModelCatalog();
}
async function prepareRun(run) {
  for (let i=0;i<run.rows.length;i++) {
    const row=run.rows[i];row.time=new Date(row.timestamp).getTime();row.signals=row.reasons||[];
    if(i%20000===0)await new Promise((resolve)=>setTimeout(resolve,0));
  }
  run.rowsById=new Map(run.rows.map((row)=>[row.id,row]));
  return run;
}
async function activateAnalysis(result,{logs,model,source,synthetic=false,threshold=defaultCutoff(),cacheKey=""}) {
  const run=await prepareRun(result);
  state.run=run;state.logs=logs;state.source=source;state.synthetic=synthetic;
  state.threshold=threshold;state.runs=new Map([[model,run]]);state.activeModel=model;state.cacheKey=cacheKey;
  state.rowsById=run.rowsById;state.caseId=null;state.selection=null;state.edits=new Map();
  state.dispositions=new Map();state.eventNotes=new Map();state.investigations=[];state.query="";state.account="";state.overviewPage=1;
  $("investigation-search").value="";$("investigation-cutoff").value=String(Number((state.threshold*100).toFixed(5)));
  updateCutoffLabel();
  $("run-notice").textContent=[run.warning||"",run.external?"Shortlisted requests were sent to OpenAI for review.":""].filter(Boolean).join(" ");
  $("run-notice").hidden=!$("run-notice").textContent;
  rebuildInvestigations();
}
async function loadCachedUpload(logs,model,source,synthetic=false) {
  let cacheKey,cached;
  try{
    updateProgress({stage:"file",message:"Checking this browser for an existing analysis."});
    cacheKey=await analysisCacheKey(logs,model);
    cached=await readCachedAnalysis(cacheKey);
  }catch{return false;}
  if(!cached?.result)return false;
  updateProgress({stage:"display",message:"Loading the saved analysis from this browser."});
  await activateAnalysis(cached.result,{logs,model,source,synthetic,cacheKey});
  showResults();persistActiveAnalysis();toast("Loaded cached model results.");
  return true;
}
async function analyze(logs,model,source,synthetic=false) {
  if(state.busy||state.reading||state.modelBusy)return;
  if(!logs.trim()){showError("analyze-error","Add at least one log line.");return;}
  state.busy=true;syncControls();showError("analyze-error");
  try {
    updateProgress({stage:"file",message:"Checking this browser for an existing analysis."});
    const cacheKey=await analysisCacheKey(logs,model);
    let cached=null;
    try{cached=await readCachedAnalysis(cacheKey);}catch{}
    let result=cached?.result,fromCache=Boolean(result),cacheReady=fromCache;
    if(!result){
      result=await predictStream(logs,model);
      updateProgress({stage:"display",message:"Saving these results in this browser."});
      if(cacheKey)try{await writeCachedAnalysis(cacheKey,model,logs,result);cacheReady=true;}catch{}
    }else updateProgress({stage:"display",message:"Loading the saved analysis from this browser."});
    await activateAnalysis(result,{logs,model,source,synthetic,cacheKey:cacheReady?cacheKey:""});
    showResults();persistActiveAnalysis();
    const investigationCount=state.investigations.length;
    toast(fromCache?"Loaded cached model results.":`${number(investigationCount)} candidate investigation${investigationCount===1?"":"s"} found.`);
  } catch(error){showError("analyze-error",error.message);}
  finally{state.busy=false;syncControls();}
}
async function restoreActiveAnalysis() {
  const pointer=activeAnalysisPointer();
  if(!pointer?.key)return false;
  let cached;
  try{cached=await readCachedAnalysis(pointer.key);}catch{return false;}
  if(!cached?.result||typeof cached.logs!=="string"||typeof cached.model!=="string")return false;
  const threshold=Number.isFinite(pointer.threshold)&&pointer.threshold>=0&&pointer.threshold<=1?pointer.threshold:defaultCutoff(cached.result);
  state.timeSliceCustomized=pointer.timeSliceCustomized===true;
  $("time-slice-size").value=String(state.timeSliceCustomized?Math.max(1,Math.min(TIME_SLICE_TARGETS.length,Number(pointer.timeSliceLevel)||10)):10);
  await activateAnalysis(cached.result,{logs:cached.logs,model:cached.model,source:String(pointer.source||"Cached analysis"),synthetic:Boolean(pointer.synthetic),threshold,cacheKey:pointer.key});
  if(!state.models.some((model)=>model.id===cached.model))state.models.push({id:cached.model,name:state.run.model_name||cached.model,available:false});
  return true;
}
function rebuildInvestigations(){
  const previous=state.investigations,previousEdits=new Map(state.edits),byCandidate=new Map(),previousById=new Map(previous.map((item)=>[item.id,item]));
  for(const item of previous)for(const id of item.candidateIds){if(!byCandidate.has(id))byCandidate.set(id,[]);byCandidate.get(id).push(item);}
  const level=Math.max(1,Math.min(TIME_SLICE_TARGETS.length,Number($("time-slice-size").value)||10));
  state.timeSliceLevel=level;
  state.sliceSpec=Investigation.timeSlices(state.run.rows,TIME_SLICE_TARGETS[level-1]);
  const inherited=new Set(),rebuilt=Investigation.buildInvestigations(state.run.rows,{isCandidate,slices:state.sliceSpec});
  for(const item of rebuilt){
    item.reviewCutoff=state.threshold;
    const ancestors=new Map();
    if(previousById.has(item.id))ancestors.set(item.id,previousById.get(item.id));
    for(const id of item.candidateIds)for(const old of byCandidate.get(id)||[])ancestors.set(old.id,old);
    if(!ancestors.size)continue;
    const present=new Set(item.rows.map((row)=>row.id)),episodes=[],notes=[],covered=new Set();let edited=false;
    for(const old of ancestors.values()){
      inherited.add(old.id);
      for(const row of old.rows){
        if(old.addedIds?.has(row.id)){
          if(!present.has(row.id)){item.rows.push(row);present.add(row.id);}
          if(!item.addedIds)item.addedIds=new Set();item.addedIds.add(row.id);
        }
        const status=disposition(row,old.id);if(status&&present.has(row.id))state.dispositions.set(dispositionKey(row,item.id),status);
      }
      const edit=previousEdits.get(old.id);if(!edit)continue;
      edited ||= Boolean(edit.edited);if(edit.note&&!notes.includes(edit.note))notes.push(edit.note);
      for(const episode of edit.episodes){
        const rows=episode.rows.filter((row)=>present.has(row.id)&&!covered.has(row.id));
        if(rows.length){rows.forEach((row)=>covered.add(row.id));episodes.push({...episode,rows,start:rows[0].time,end:rows[rows.length-1].time});}
      }
    }
    item.rows.sort((a,b)=>a.time-b.time||a.id-b.id);
    episodes.push(...Investigation.buildEpisodes(item.rows.filter((row)=>!covered.has(row.id)),item.candidateIds));
    episodes.sort((a,b)=>a.rows[0].time-b.rows[0].time);
    state.edits.set(item.id,{episodes,note:notes.join("\n\n"),edited});
  }
  // An annotated hypothesis remains accessible even if a new cutoff finds no overlap.
  for(const old of previous){
    const edit=state.edits.get(old.id),hasDecisions=old.rows.some((row)=>disposition(row,old.id)||state.eventNotes.has(row.id));
    if(!inherited.has(old.id)&&(edit?.edited||edit?.note||hasDecisions||old.addedIds?.size))rebuilt.push({...old,savedOnly:true});
  }
  state.investigations=rebuilt.sort((a,b)=>a.start-b.start);renderOverview();
}
function caseCutoff(item=caseById()){return item?.reviewCutoff??state.threshold;}
function caseById(id=state.caseId){return state.investigations.find((item)=>String(item.id)===String(id));}
function editsFor(item){
  if(!state.edits.has(item.id))state.edits.set(item.id,{episodes:item.episodes.map((episode)=>({...episode,rows:episode.rows.slice()})),note:""});
  return state.edits.get(item.id);
}
function candidateIds(item){return new Set(item.candidateIds);}
function dispositionKey(row,caseId=state.caseId){return `${caseId}:${row.id}`;}
function disposition(row,caseId=state.caseId){return state.dispositions.get(dispositionKey(row,caseId))||"";}
function caseRows(item){return item.rows;}
function episodeRows(episode){return episode.rows;}
function episodeLabel(episode){return episode.customLabel||episode.label||actionName(episode.rows[0]);}
function overviewMatches(){
  const query=state.query.trim().toLowerCase();
  return state.investigations.filter((item)=>(!query||[item.title||"",item.source||"",...item.sources,...item.rows.map((row)=>`${row.user} ${row.method} ${row.path} ${row.status}`)].join(" ").toLowerCase().includes(query)));
}
function renderOverviewActivity(matches=overviewMatches()){
  if(!state.run||!$("overview-timeline-chart"))return;
  const query=state.query.trim().toLowerCase(),ids=new Set(matches.flatMap((item)=>item.candidateIds));
  const chartRows=state.run.rows.filter((row)=>(!query||ids.has(row.id)));
  const slices=state.sliceSpec;
  const chart=window.LogCharts.renderActivity($("overview-timeline-chart"),{rows:chartRows,targetBars:slices?.count||TIME_SLICE_TARGETS[state.timeSliceLevel-1],domainStart:slices?.start,domainEnd:slices?.end,thresholdPreview:true,isFlagged:(row)=>ids.has(row.id),showAll:$("show-other-traffic").checked,onSelect:(group)=>{
    applyCutoff();
    const match=state.investigations.find((item)=>item.start<group.end&&item.end>=group.start);if(match)openCase(match.id);
  }});
  state.activityChart=chart;
  $("time-slice-value").textContent=chart.intervalLabel||"—";
}
function renderOverview(){
  if(!state.run)return;
  $("overview-panel").hidden=false;$("investigation-workspace").hidden=true;
  if($("overview-activity-title"))$("overview-activity-title").textContent=$("show-other-traffic").checked?"Requests around candidate investigations":"When candidate requests occurred";
  const matches=overviewMatches();
  const pages=Math.max(1,Math.ceil(matches.length/8));state.overviewPage=Math.min(state.overviewPage,pages);
  const shown=matches.slice((state.overviewPage-1)*8,state.overviewPage*8);
  $("overview-counts").textContent=`${number(matches.length)} candidate investigation${matches.length===1?"":"s"}`;
  $("investigation-list").innerHTML=shown.map((item)=>{
    return `<article class="investigation-card"><div class="investigation-card-heading"><div><h3>${escapeHTML(caseTimeRange(item))}</h3><p class="investigation-card-meta">${escapeHTML(caseLineRange(item))} · ${number(item.candidateIds.length)} candidate request${item.candidateIds.length===1?"":"s"}</p></div><button class="button primary" data-open-case="${escapeHTML(item.id)}">Open investigation</button></div></article>`;
  }).join("");
  $("overview-empty").hidden=matches.length>0;$("overview-empty").textContent=state.investigations.length?"No investigations match your search.":"No requests meet this cutoff. Lower it to broaden the investigation.";
  $("overview-page").textContent=`${state.overviewPage} / ${pages}`;$("overview-previous").disabled=state.overviewPage<=1;$("overview-next").disabled=state.overviewPage>=pages;
  renderOverviewActivity(matches);
}
function openCase(id, push=true){
  const item=caseById(id);if(!item)return;state.caseId=item.id;state.timelineLimit=40;state.earlierLimit=12;state.relatedLimit=12;
  $("baseline-content").closest("details").open=false;
  const episodes=editsFor(item).episodes;const first=episodes.find((episode)=>episode.rows.some(isCandidate))||episodes[0];
  const firstRequest=first?.rows.find(isCandidate)||first?.rows[0];
  state.selection=firstRequest?{type:"event",id:firstRequest.id}:null;
  if(push)routeTo(`/investigations/${encodeURIComponent(item.id).replace(/%3A/gi,":")}`);
  renderWorkspace();persistActiveAnalysis();$("investigation-title").focus({preventScroll:true});
}
function renderWorkspace(){
  const item=caseById();if(!item)return;
  $("overview-panel").hidden=true;$("investigation-workspace").hidden=false;
  $("investigation-title").textContent=caseLineRange(item);
  $("investigation-title").setAttribute("tabindex","-1");
  $("add-investigation-note").value=editsFor(item).note;
  renderTimeline();renderBaseline();renderEvidence();
}
function timelineRows(){
  const item=caseById();if(!item)return[];
  return editsFor(item).episodes.flatMap(episodeRows).sort((a,b)=>a.time-b.time||a.id-b.id);
}
function highlightedRequest(row){return Review.isCandidate(row,caseCutoff())||disposition(row)==="important";}
function renderTimeline(){
  const rows=timelineRows();
  const selectedIndex=rows.findIndex((row)=>row.id===state.selection?.id);
  if(selectedIndex>=state.timelineLimit)state.timelineLimit=selectedIndex+1;
  $("timeline-list").innerHTML=rows.slice(0,state.timelineLimit).map((row)=>`<button class="event-row ${highlightedRequest(row)?"candidate":"context"} ${disposition(row)}" data-select-event="${row.id}"><span class="event-time">${dayLabel(row.time)}<br>${timeLabel(row.time)} ${zoneLabel(row.time)}</span><span class="event-request">${escapeHTML(actionName(row))}<small>${escapeHTML(row.ip)} · line ${row.id}${disposition(row)?` · ${escapeHTML(disposition(row))}`:""}</small><code class="event-raw">${escapeHTML(row.raw)}</code></span><span class="event-result">${row.status}</span></button>`).join("")||'<p class="empty-state">No requests.</p>';
  if(rows.length>state.timelineLimit)$("timeline-list").insertAdjacentHTML("beforeend",`<button class="button secondary" data-more-requests>Show ${number(Math.min(40,rows.length-state.timelineLimit))} more requests</button>`);
}
function selectEvent(id){
  if(!state.rowsById.has(id))return;
  if(state.selection?.id!==id){state.earlierLimit=12;state.relatedLimit=12;$("baseline-content").closest("details").open=false;}
  state.selection={type:"event",id};
  renderTimeline();renderBaseline();renderEvidence();
  revealSelection();
}
function revealSelection(){
  if(window.matchMedia("(max-width: 850px)").matches){$("evidence-workspace").scrollIntoView({block:"start"});$("evidence-heading").setAttribute("tabindex","-1");$("evidence-heading").focus({preventScroll:true});}
  else if(state.selection?.type==="event")$("timeline-list").querySelector(`[data-select-event="${state.selection.id}"]`)?.scrollIntoView({block:"nearest"});
}
function selectedRows(){
  if(state.selection?.type!=="event")return[];
  return[state.rowsById.get(state.selection.id)].filter(Boolean);
}
function evidenceFields(fields){return `<dl class="evidence-fields">${fields.map(([label,value])=>`<div><dt>${escapeHTML(label)}</dt><dd>${escapeHTML(value)}</dd></div>`).join("")}</dl>`;}
function flaggedReasons(row){
  const run=state.runs.get(state.activeModel)||state.run,scored=run?.rowsById.get(row.id)||row;
  const reasons=[...new Set(scored.reasons||scored.signals||[])].filter((reason)=>reason&&reason!=="failed-login"&&!/^\d+-(?:prior-)?failed-logins-in-60s$/.test(String(reason)));
  if(!reasons.length)return "";
  const label=(reason)=>window.LogModelLens.signalLabel?.(reason)||String(reason).replace(/-/g," ").replace(/^./,(letter)=>letter.toUpperCase());
  return `<section class="request-reasons"><h4>Why it was flagged</h4><ul>${reasons.map((reason)=>`<li>${escapeHTML(label(reason))}</li>`).join("")}</ul></section>`;
}
function relatedButtons(rows){return rows.map((row)=>`<button class="event-row ${highlightedRequest(row)?"candidate":"context"}" data-select-event="${row.id}"><span class="event-time">${shortTime(row.time)}</span><span class="event-request">${escapeHTML(actionName(row))}<small>${escapeHTML(accountName(row.user))} · ${escapeHTML(row.ip)}</small></span><span class="event-result">${row.status}</span></button>`).join("");}
function earlierFor(row){
  return state.run.rows.filter((entry)=>entry.ip===row.ip&&entry.user===row.user&&(entry.time<row.time||(entry.time===row.time&&entry.id<row.id)));
}
function endpoint(row){return String(row.path||"").split("?",1)[0];}
function relatedEarlierFor(row, earlier){
  const target=endpoint(row),cutoff=caseCutoff();
  return earlier.filter((entry)=>endpoint(entry)===target||Review.isCandidate(entry,cutoff));
}
function relatedHistory(row){return relatedEarlierFor(row,earlierFor(row)).sort((a,b)=>b.time-a.time||b.id-a.id);}
function renderEvidence(){
  const item=caseById(),rows=selectedRows();if(!item)return;
  $("evidence-heading").textContent=rows[0]?actionName(rows[0]):"Select a request";
  if(!rows.length){$("evidence-content").innerHTML='<p class="empty-state">Select a request to inspect its fields and history.</p>';renderModelEvidence();return;}
  {
    const row=rows[0],dispositionValue=disposition(row);
    const history=relatedHistory(row);
    const historySection=history.length?`<details class="evidence-section"><summary>Earlier related activity (${number(history.length)})</summary><div class="related-events">${relatedButtons(history.slice(0,state.relatedLimit))}</div>${history.length>state.relatedLimit?`<button class="text-button show-more" data-more-related>Show ${number(Math.min(20,history.length-state.relatedLimit))} more requests</button>`:""}</details>`:"";
    $("evidence-content").innerHTML=`${flaggedReasons(row)}${evidenceFields([["Account",accountName(row.user)],["Source IP",row.ip],["Time",shortTime(row.time)],["HTTP status",row.status]])}<div class="evidence-actions"><label>Disposition<select id="event-disposition"><option value="">Unreviewed</option><option value="important">Important</option><option value="benign">Benign</option></select></label></div><label class="evidence-note">Request note<textarea id="event-note" rows="2" placeholder="Add your interpretation. This note will be added to the report.">${escapeHTML(state.eventNotes.get(row.id)||"")}</textarea></label>${historySection}`;
    $("event-disposition").value=dispositionValue;
  }
  renderModelEvidence();
}
function renderModelEvidence(){
  const rows=selectedRows(),run=state.runs.get(state.activeModel)||state.run;
  const selected=rows.map((row)=>run.rowsById.get(row.id)).filter(Boolean);
  const host=$("model-evidence-content");
  window.LogModelLens.render(host,{run,selectedRows:selected,allRows:run.rows,cutoff:run===state.run?caseCutoff():defaultCutoff(run),onSelectEvent:selectEvent});
  host.closest(".model-workspace").hidden=!host.childNodes.length&&!$("model-run-status").textContent;
}
function renderBaseline(){
  const item=caseById();if(!item)return;
  const row=selectedRows()[0];
  const earlier=row?earlierFor(row).sort((a,b)=>b.time-a.time||b.id-a.id):[];
  const panel=$("baseline-content").closest("details");
  panel.hidden=!earlier.length||relatedEarlierFor(row,earlier).length===earlier.length;
  panel.querySelector("summary").textContent=`Earlier requests (${number(earlier.length)})`;
  if(panel.hidden){
    $("baseline-content").replaceChildren();
    return;
  }
  $("baseline-content").innerHTML=`<div class="related-events">${relatedButtons(earlier.slice(0,state.earlierLimit))}</div>${earlier.length>state.earlierLimit?`<button class="text-button show-more" data-more-earlier>Show ${number(Math.min(20,earlier.length-state.earlierLimit))} more requests</button>`:""}`;
}
function saveFile(name,body,type){
  const url=URL.createObjectURL(new Blob([body],{type})),link=document.createElement("a");
  link.href=url;link.download=name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
// Portable v1: canonical records once, detector overlays, and analyst reconstruction by record ID.
function sessionSnapshot(){
  const record=(row)=>{const {time,signals,...saved}=row;return saved;};
  const episode=(item)=>{const {rows,...saved}=item;return {...saved,rowIds:rows.map((row)=>row.id)};};
  const runs=[...state.runs.values()].map((run)=>{
    const {rows,rowsById,...metadata}=run;
    return {...metadata,rows:rows.map((row)=>{
      const original=state.rowsById.get(row.id),overlay={id:row.id};
      for(const [key,value] of Object.entries(record(row)))if(key!=="id"&&(!original||JSON.stringify(value)!==JSON.stringify(original[key])))overlay[key]=value;
      return overlay;
    })};
  });
  return {schema:"log-order-investigation",version:1,saved_at:new Date().toISOString(),source:state.source,synthetic:state.synthetic,
    base_model:state.run.model,active_model:state.activeModel,threshold:state.threshold,time_slice_level:state.timeSliceLevel,rows:state.run.rows.map(record),runs,
    investigations:state.investigations.map((item)=>{const {rows,episodes,addedIds,...saved}=item;return {...saved,rowIds:rows.map((row)=>row.id),episodes:episodes.map(episode),addedIds:[...(addedIds||[])]};}),
    edits:[...state.edits].map(([id,value])=>[id,{...value,episodes:value.episodes.map(episode)}]),
    dispositions:[...state.dispositions],eventNotes:[...state.eventNotes],caseId:state.caseId,selection:state.selection,
    query:state.query,account:state.account,includeContext:state.includeContext};
}
async function restoreSession(saved){
  if(saved?.schema!=="log-order-investigation"||saved.version!==1||!Array.isArray(saved.rows)||!saved.rows.length||!Array.isArray(saved.runs)||!saved.runs.length)throw new Error("Choose a Trace investigation save (version 1).");
  const ids=new Set();
  for(const row of saved.rows){
    if(!Number.isSafeInteger(row.id)||ids.has(row.id)||!Number.isFinite(Date.parse(row.timestamp))||typeof row.raw!=="string"||!Number.isFinite(row.status))throw new Error("The saved investigation contains invalid or duplicate records.");
    ids.add(row.id);
  }
  const canonical=new Map(saved.rows.map((row)=>[row.id,row])),runs=new Map();
  for(const entry of saved.runs){
    if(typeof entry.model!=="string"||runs.has(entry.model)||!Array.isArray(entry.rows)||entry.rows.length!==saved.rows.length)throw new Error("A saved model has missing or duplicate records.");
    const seen=new Set();
    const rows=entry.rows.map((overlay)=>{
      if(!canonical.has(overlay.id)||seen.has(overlay.id))throw new Error("A model result does not match the saved records.");seen.add(overlay.id);
      const row={...canonical.get(overlay.id),...overlay};
      for(const field of ["raw","timestamp","user","ip","method","path","status","bytes"])if(row[field]!==canonical.get(row.id)[field])throw new Error("A model result changes the original evidence.");
      if(!Number.isFinite(row.score)||row.score<0||row.score>1)throw new Error("A model result has an invalid score.");
      return row;
    });
    runs.set(entry.model,await prepareRun({...entry,rows}));
  }
  const run=runs.get(saved.base_model);if(!run)throw new Error("The base detector is missing from this save.");
  const safeId=(id)=>typeof id==="string"&&/^[a-zA-Z0-9_:.-]+$/.test(id);
  const rowRefs=(rowIds)=>{if(!Array.isArray(rowIds)||rowIds.some((id)=>!run.rowsById.has(id)))throw new Error("The timeline refers to missing records.");return rowIds.map((id)=>run.rowsById.get(id));};
  const episode=(item)=>{if(!safeId(item.id))throw new Error("Invalid episode identifier.");const rows=rowRefs(item.rowIds);if(!rows.length)throw new Error("An episode has no records.");return {...item,rows,start:rows[0].time,end:rows[rows.length-1].time};};
  const threshold=Number.isFinite(saved.threshold)&&saved.threshold>=0&&saved.threshold<=1?saved.threshold:defaultCutoff(run);
  const timeSliceLevel=Math.max(1,Math.min(TIME_SLICE_TARGETS.length,Number(saved.time_slice_level)||10));
  const sliceSpec=Investigation.timeSlices(run.rows,TIME_SLICE_TARGETS[timeSliceLevel-1]);
  const investigations=saved.investigations? saved.investigations.map((item)=>{
    if(!safeId(item.id)||!Number.isFinite(item.start)||!Number.isFinite(item.end)||!Array.isArray(item.sources))throw new Error("Invalid investigation metadata.");
    rowRefs(item.candidateIds);return {...item,rows:rowRefs(item.rowIds),episodes:item.episodes.map(episode),addedIds:new Set(item.addedIds||[])};
  }):Investigation.buildInvestigations(run.rows,{isCandidate:(row)=>Review.isCandidate(row,threshold),slices:sliceSpec}).map((item)=>({...item,reviewCutoff:threshold}));
  const edits=new Map((saved.edits||[]).map(([id,value])=>[id,{...value,episodes:value.episodes.map(episode)}]));
  const dispositions=new Map(saved.dispositions||[]),eventNotes=new Map(saved.eventNotes||[]);
  if([...dispositions.values()].some((value)=>!["important","benign","promoted","excluded"].includes(value)))throw new Error("Invalid analyst disposition.");
  for(const [key,value] of dispositions){if(value==="excluded")dispositions.delete(key);else if(value==="promoted")dispositions.set(key,"important");}
  const selectedCase=investigations.find((item)=>item.id===saved.caseId);
  const selection=saved.selection;
  const validSelection=selectedCase&&selection?.type==="event"&&run.rowsById.has(selection.id);
  const fallbackSelection=selectedCase?.rows.find((row)=>selectedCase.candidateIds.includes(row.id))||selectedCase?.rows[0];
  state.revision++;state.run=run;state.runs=runs;state.rowsById=run.rowsById;state.logs=run.rows.map((row)=>row.raw).join("\n");state.cacheKey="";
  try{sessionStorage.removeItem(ACTIVE_ANALYSIS_POINTER);}catch{}
  state.source=String(saved.source||"Saved investigation");state.synthetic=Boolean(saved.synthetic);state.threshold=threshold;
  state.activeModel=runs.has(saved.active_model)?saved.active_model:saved.base_model;state.investigations=investigations;state.edits=edits;state.dispositions=dispositions;state.eventNotes=eventNotes;state.timeSliceLevel=timeSliceLevel;state.timeSliceCustomized=true;state.sliceSpec=sliceSpec;
  state.caseId=investigations.some((item)=>item.id===saved.caseId)?saved.caseId:null;state.selection=validSelection?selection:fallbackSelection?{type:"event",id:fallbackSelection.id}:null;
  state.query=String(saved.query||"");state.account="";state.includeContext=true;state.overviewPage=1;state.timelineLimit=40;state.earlierLimit=12;state.relatedLimit=12;
  for(const [id,cached] of runs)if(!state.models.some((model)=>model.id===id))state.models.push({id,name:cached.model_name||id,available:false});
  $("investigation-search").value=state.query;$("investigation-cutoff").value=String(Number((threshold*100).toFixed(5)));$("time-slice-size").value=String(timeSliceLevel);
  updateCutoffLabel();
  $("run-notice").textContent="";$("run-notice").hidden=true;
  $("baseline-content").closest("details").open=false;
  showResults();toast("Investigation restored, including model results and notes.");
}
window.LogSession={snapshot:sessionSnapshot,restore:restoreSession};
function reportParagraphs(text){
  return String(text||"").trim().split(/\n\s*\n/).filter(Boolean).map((paragraph)=>`<p>${escapeHTML(paragraph).replace(/\n/g,"<br>")}</p>`).join("");
}
function reportLineReferences(rows){
  const ids=[...new Set(rows.map((row)=>row.id))].sort((a,b)=>a-b),ranges=[];
  for(let index=0;index<ids.length;){let end=index;while(end+1<ids.length&&ids[end+1]===ids[end]+1)end++;ranges.push(index===end?String(ids[index]):`${ids[index]}–${ids[end]}`);index=end+1;}
  return ranges.join(", ");
}
function reportHTML(){
  const item=caseById(),edits=editsFor(item),rows=caseRows(item),candidateCount=rows.filter((row)=>Review.isCandidate(row,caseCutoff(item))).length;
  const sources=[...new Set(rows.map((row)=>row.ip))];
  if(!sources.length&&item.source)sources.push(item.source);
  const codeList=(values)=>values.map((value)=>`<code>${escapeHTML(value)}</code>`).join(", ");
  const defaultAssessment=`<p>This investigation covers ${number(rows.length)} request${rows.length===1?"":"s"} between <code>${escapeHTML(shortTime(rows[0]?.time??item.start))}</code> and <code>${escapeHTML(shortTime(rows[rows.length-1]?.time??item.end))}</code>. ${number(candidateCount)} request${candidateCount===1?"":"s"} met the selected review cutoff.</p><p>The observed requests came from ${codeList(sources)}. The numbered sections below preserve the HTTP methods, endpoints, response codes, and original log records for analyst review.</p>`;
  const assessment=defaultAssessment+(edits.note.trim()?reportParagraphs(edits.note):"");
  const sections=[];
  let sectionNumber=0;
  for(const episode of edits.episodes){
    const kept=episodeRows(episode);if(!kept.length)continue;sectionNumber++;
    const episodeSources=[...new Set(kept.map((row)=>row.ip))];
    const statuses=new Map();for(const row of kept)statuses.set(row.status,(statuses.get(row.status)||0)+1);
    let observed;
    if(kept.length===1){
      const row=kept[0];
      observed=`<p>At <code>${escapeHTML(shortTime(row.time))}</code>, <code>${escapeHTML(row.ip)}</code> issued <code>${escapeHTML(actionName(row))}</code>. The server returned <code>HTTP ${row.status}</code> with ${number(row.bytes)} response bytes.</p>`;
    }else{
      const results=[...statuses].map(([status,count])=>`<code>HTTP ${status}</code> for ${number(count)} request${count===1?"":"s"}`).join(", ");
      observed=`<p>Between <code>${escapeHTML(shortTime(kept[0].time))}</code> and <code>${escapeHTML(shortTime(kept[kept.length-1].time))}</code>, ${codeList(episodeSources)} issued ${number(kept.length)} requests. The recorded responses were ${results}.</p>`;
    }
    const notes=kept.filter((row)=>state.eventNotes.get(row.id)).map((row)=>reportParagraphs(state.eventNotes.get(row.id))).join("");
    sections.push(`<h2>${sectionNumber}. ${escapeHTML(episodeLabel(episode))}</h2>${observed}${notes}<small>Original request${kept.length===1?"":"s"} · line${kept.length===1?"":"s"} ${reportLineReferences(kept)}</small><pre>${kept.map((row)=>escapeHTML(row.raw)).join("\n")}</pre>`);
  }
  const firstByActor=new Map();
  for(const row of rows.filter((entry)=>Review.isCandidate(entry,caseCutoff(item)))){
    const key=JSON.stringify([row.ip,row.user]);
    const first=firstByActor.get(key);
    if(!first||row.time<first.time||(row.time===first.time&&row.id<first.id))firstByActor.set(key,row);
  }
  const earlier=[...new Map([...firstByActor.values()].flatMap((row)=>earlierFor(row)).map((row)=>[row.id,row])).values()].sort((a,b)=>a.time-b.time||a.id-b.id);
  const earlierShown=[...new Map([...earlier.slice(-12),...earlier.filter((row)=>state.eventNotes.get(row.id))].map((row)=>[row.id,row])).values()].sort((a,b)=>a.time-b.time||a.id-b.id);
  const earlierNotes=earlierShown.filter((row)=>state.eventNotes.get(row.id)).map((row)=>reportParagraphs(state.eventNotes.get(row.id))).join("");
  const earlierSection=earlier.length?`<h2>Earlier requests</h2><p>The uploaded logs contain ${number(earlier.length)} earlier request${earlier.length===1?"":"s"} from the same account and source IP combinations as the candidate requests. These records provide comparison context for the requests above.</p>${earlierNotes}<small>Earlier request${earlierShown.length===1?"":"s"} · line${earlierShown.length===1?"":"s"} ${reportLineReferences(earlierShown)}</small><pre>${earlierShown.map((row)=>escapeHTML(row.raw)).join("\n")}</pre>`:"";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Incident report</title><style>
body{margin:0;background:#fafaf8;color:#232823;font:17px/1.7 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.report-actions{position:sticky;top:0;z-index:2;display:flex;justify-content:flex-end;max-width:960px;margin:auto;padding:16px 28px}.report-actions button{padding:9px 14px;border:1px solid #8d9491;background:#fff;color:#232823;font:600 14px system-ui,sans-serif;cursor:pointer}main{max-width:960px;margin:auto;padding:28px 28px 56px}h2{font-size:25px;line-height:1.3;margin-top:48px;padding-top:22px;border-top:1px solid #ccd0c8}main>h2:first-child{border-top:0;margin-top:0;padding-top:0}p{max-width:880px}pre{font:12px/1.65 ui-monospace,SFMono-Regular,Menlo,monospace;background:#eeefe9;padding:16px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}small{display:block;margin-top:20px;color:#66705f}code{overflow-wrap:anywhere;font:.9em ui-monospace,SFMono-Regular,Menlo,monospace;background:#eeefe9;padding:2px 5px;border-radius:2px}@media print{.report-actions{display:none}main{padding:0}body{font-size:11px}h2{break-after:avoid}pre{break-inside:avoid}}
</style></head><body><div class="report-actions"><button id="print-report" type="button">Print to PDF</button></div><main><h2>Executive assessment</h2>${assessment}${sections.join("")}${earlierSection}</main></body></html>`;
}
function openReport(){
  const reportWindow=window.open("","_blank");
  if(!reportWindow){toast("Allow pop-ups to view the report.");return;}
  reportWindow.document.open();reportWindow.document.write(reportHTML());reportWindow.document.close();
  reportWindow.document.getElementById("print-report")?.addEventListener("click",()=>reportWindow.print());
  reportWindow.opener=null;
}
function addImportantRequestToTimeline(row){
  const item=caseById();
  if(item.rows.some((entry)=>entry.id===row.id))return false;
  if(!item.addedIds)item.addedIds=new Set();
  item.addedIds.add(row.id);
  item.rows.push(row);item.rows.sort((a,b)=>a.time-b.time||a.id-b.id);
  const edits=editsFor(item);
  edits.edited=true;
  edits.episodes.push({id:`important-${row.id}`,label:actionName(row),rows:[row],start:row.time,end:row.time});
  edits.episodes.sort((a,b)=>a.rows[0].time-b.rows[0].time);
  return true;
}
for(const element of document.querySelectorAll("[data-icon]"))element.innerHTML=icon(element.dataset.icon);
for(const mode of ["file","paste","session"])$("tab-"+mode).addEventListener("click",()=>{routeTo(`/analyze?input=${mode}`);switchInput(mode);});
$("model-select").addEventListener("change",()=>{modelHelp();syncControls();});
$("log-input").addEventListener("input",()=>{$("paste-count").textContent=`${number(lineCount($("log-input").value))} requests`;syncControls();});
$("log-file").addEventListener("change",async()=>{await readFile($("log-file").files[0]);$("log-file").value="";});
$("remove-file").addEventListener("click",()=>{state.revision++;state.reading=false;state.file=null;renderFile();syncControls();});
for(const type of ["dragenter","dragover"])$("dropzone").addEventListener(type,(event)=>{event.preventDefault();$("dropzone").classList.add("dragging");});
for(const type of ["dragleave","drop"])$("dropzone").addEventListener(type,(event)=>{event.preventDefault();$("dropzone").classList.remove("dragging");});
$("dropzone").addEventListener("drop",(event)=>{if(event.dataTransfer.files.length!==1)showError("analyze-error","Choose one log file at a time.");else readFile(event.dataTransfer.files[0]);});
$("analyze-form").addEventListener("submit",async(event)=>{
  event.preventDefault();if(state.busy||state.reading||!state.ready)return;
  const file=state.inputMode==="file"?state.file:null,logs=state.inputMode==="file"?(file?.logs||""):$("log-input").value;
  await analyze(logs,$("model-select").value,file?.name||"Pasted logs",Boolean(file?.synthetic));
});
$("load-sample").addEventListener("click",async()=>{
  if(state.busy||state.reading)return;
  const revision=++state.revision;state.reading=true;syncControls();showError("analyze-error");
  try{
    const sample=await api("/api/sample");if(revision!==state.revision)return;
    state.file={logs:sample.logs,name:"example.txt",size:new TextEncoder().encode(sample.logs).length,lines:lineCount(sample.logs),synthetic:true};
    state.reading=false;switchInput("file");renderFile();modelHelp();await analyze(sample.logs,$("model-select").value,state.file.name,true);
  }catch(error){showError("analyze-error",error.message);}
  finally{if(revision===state.revision){state.reading=false;syncControls();}}
});
$("investigation-search").addEventListener("input",()=>{clearTimeout(state.searchTimer);state.query=$("investigation-search").value;state.overviewPage=1;state.searchTimer=setTimeout(renderOverview,180);});
let cutoffFrame = null, cutoffTimer = null;
function applyCutoff() {
  const pending=cutoffTimer!==null||cutoffFrame!==null;
  clearTimeout(cutoffTimer);cutoffTimer=null;
  if(cutoffFrame!==null){cancelAnimationFrame(cutoffFrame);cutoffFrame=null;}
  const value=Number($("investigation-cutoff").value);
  if(!state.run||!Number.isFinite(value))return;
  const threshold=Math.max(0,Math.min(100,value))/100;
  if(threshold===state.threshold){if(pending)renderOverview();return;}
  state.threshold=threshold;state.caseId=null;state.overviewPage=1;
  rebuildInvestigations();persistActiveAnalysis();
}
$("investigation-cutoff").addEventListener("input",()=>{
  updateCutoffLabel();
  if(cutoffFrame===null)cutoffFrame=requestAnimationFrame(()=>{
    cutoffFrame=null;
    state.activityChart?.updateThreshold(Number($("investigation-cutoff").value)/100);
  });
  clearTimeout(cutoffTimer);
  cutoffTimer=setTimeout(applyCutoff,250);
});
$("investigation-cutoff").addEventListener("change",()=>{updateCutoffLabel();applyCutoff();});
$("investigation-list").addEventListener("click",(event)=>{const target=event.target.closest("[data-open-case]");if(target)openCase(target.dataset.openCase);});
$("overview-previous").addEventListener("click",()=>{state.overviewPage--;renderOverview();});
$("overview-next").addEventListener("click",()=>{state.overviewPage++;renderOverview();});
$("show-other-traffic").addEventListener("change",renderOverview);
let timeSliceTimer=null;
function applyTimeSlice(){
  clearTimeout(timeSliceTimer);timeSliceTimer=null;
  if(!state.run)return;
  const level=Math.max(1,Math.min(TIME_SLICE_TARGETS.length,Number($("time-slice-size").value)||10));
  if(level===state.timeSliceLevel)return;
  state.caseId=null;state.overviewPage=1;
  rebuildInvestigations();persistActiveAnalysis();
}
$("time-slice-size").addEventListener("input",()=>{
  state.timeSliceCustomized=true;
  clearTimeout(timeSliceTimer);
  timeSliceTimer=setTimeout(applyTimeSlice,120);
});
$("time-slice-size").addEventListener("change",()=>{state.timeSliceCustomized=true;applyTimeSlice();});
$("back-investigations").addEventListener("click",()=>navigate("investigations"));
$("add-investigation-note").addEventListener("input",()=>{editsFor(caseById()).note=$("add-investigation-note").value;$("investigation-notes").textContent="Note kept in this session and included in the report.";});
$("investigation-workspace").addEventListener("click",(event)=>{
  const selected=event.target.closest("[data-select-event]");if(selected){selectEvent(Number(selected.dataset.selectEvent));return;}
  if(event.target.closest("[data-more-earlier]")){state.earlierLimit+=20;renderBaseline();return;}
  if(event.target.closest("[data-more-related]")){
    state.relatedLimit+=20;
    const history=relatedHistory(selectedRows()[0]),details=$("evidence-content").querySelector(".evidence-section");
    details.querySelector(".related-events").innerHTML=relatedButtons(history.slice(0,state.relatedLimit));
    const more=details.querySelector("[data-more-related]");
    if(history.length>state.relatedLimit)more.textContent=`Show ${number(Math.min(20,history.length-state.relatedLimit))} more requests`;
    else more.remove();
    return;
  }
  if(event.target.closest("[data-more-requests]")){state.timelineLimit+=40;renderTimeline();return;}
});
$("evidence-workspace").addEventListener("change",(event)=>{
  if(event.target.id!=="event-disposition"||state.selection?.type!=="event")return;
  const row=state.rowsById.get(state.selection.id),value=event.target.value;
  if(value)state.dispositions.set(dispositionKey(row),value);else state.dispositions.delete(dispositionKey(row));
  const added=value==="important"&&addImportantRequestToTimeline(row);
  renderWorkspace();
  if(added){revealSelection();toast("Request added to the timeline.");}
});
$("evidence-workspace").addEventListener("input",(event)=>{if(event.target.id==="event-note"&&state.selection?.type==="event")state.eventNotes.set(state.selection.id,event.target.value);});
$("save-session").addEventListener("click",async()=>{
  if(!state.run||state.modelBusy||state.busy||$("save-session").disabled)return;
  if(cutoffTimer!==null)applyCutoff();
  const button=$("save-session");button.disabled=true;button.textContent="Saving investigation…";
  try{
    const json=JSON.stringify(sessionSnapshot());
    if(typeof CompressionStream!=="undefined"){
      const compressed=await new Response(new Blob([json]).stream().pipeThrough(new CompressionStream("gzip"))).blob();
      saveFile("trace-investigation.json.gz",compressed,"application/gzip");
    }else saveFile("trace-investigation.json",json,"application/json;charset=utf-8");
    toast("Saved all model results, timeline edits, and original records.");
  }catch(error){showError("page-error",`Could not save investigation: ${error.message}`);}
  finally{button.disabled=false;button.innerHTML=icon("upload")+"<span>Save investigation data</span>";}
});
$("session-file").addEventListener("change",async()=>{
  const file=$("session-file").files[0];$("session-file").value="";if(!file||state.busy||state.modelBusy||state.reading)return;
  state.reading=true;syncControls();showError("page-error");
  try{
    let text;
    if(/\.gz$/i.test(file.name)){
      if(typeof DecompressionStream==="undefined")throw new Error("This browser cannot open gzip saves. Unzip the file and open its JSON, or use a current browser.");
      text=await new Response(file.stream().pipeThrough(new DecompressionStream("gzip"))).text();
    }else text=await file.text();
    await restoreSession(JSON.parse(text));
  }catch(error){showError("page-error",`Could not open saved investigation: ${error.message}`);}
  finally{state.reading=false;syncControls();}
});
$("view-report").addEventListener("click",openReport);
window.addEventListener("resize",()=>{clearTimeout(state.resizeTimer);state.resizeTimer=setTimeout(()=>{if(state.run&&!$("results-panel").hidden){if(state.caseId)renderModelEvidence();else renderOverview();}},150);});
$("time-slice-size").value="10";
renderRoute();
(async()=>{
  try{
    const status=await api("/api/status");state.models=status.models.filter((model)=>model.id!=="rules"&&model.available);state.ready=true;
  }catch(error){showError("analyze-error",error.message);}
  try{await restoreActiveAnalysis();}catch{}
  for(const [id,run] of state.runs)if(!state.models.some((model)=>model.id===id))state.models.push({id,name:run.model_name||id,available:false});
  renderModels();renderRoute();syncControls();
})();
