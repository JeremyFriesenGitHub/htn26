"use strict";

const $ = (id) => document.getElementById(id);
const Review = window.LogReview;
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
const Investigation = window.LogInvestigation;
const state = {
  ready:false,busy:false,reading:false,revision:0,inputMode:"file",file:null,models:[],
  run:null,source:"",synthetic:false,threshold:0.75,logs:"",rowsById:new Map(),
  runs:new Map(),activeModel:"",modelBusy:false,investigations:[],caseId:null,
  selection:null,edits:new Map(),dispositions:new Map(),eventNotes:new Map(),
  query:"",account:"",overviewPage:1,episodeLimit:12,eventLimits:new Map(),includeContext:true,
};
const defaultCutoff = (run) => run.review_threshold ?? (run.score_kind === "heuristic" ? .75 : run.detector_score_kind === "calibrated" || run.score_kind === "calibrated" ? .999 : .98);
const isCandidate = (row) => Review.isCandidate(row,state.threshold);
const shortTime = (time) => `${dayLabel(time)} ${timeLabel(time)} UTC`;
const accountName = (value) => value && value !== "-" ? value : "Anonymous";
const actionName = (row) => `${row.method} ${row.path}`;
const scoreKindFor = (run,row) => run.score_kind === "triaged" ? (Number.isFinite(row.baseline_percentile)?"calibrated":"percentile") : run.score_kind;

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
  for (const id of ["load-sample","model-select","log-input","log-file","remove-file","tab-file","tab-paste"]) $(id).disabled = state.busy;
  $("load-sample").disabled = !state.ready || state.busy || state.reading || !state.models.some((model)=>model.available&&model.id===$("model-select").value);
  $("cancel-input").disabled = state.busy;
  if (state.reading) updateProgress({stage:"file",message:"Reading your file. There is no upload size limit."});
  $("processing-progress").hidden = !state.busy && !state.reading;
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
function setView(view) {
  for (const button of document.querySelectorAll("[data-view]")) {
    if (button.dataset.view === view) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  $("models-panel").hidden = view !== "models";
  $("investigations-empty").hidden = view !== "investigations" || Boolean(state.run);
  document.title = `Trace · ${{analyze:"Analyze logs",investigations:"Investigations",models:"Models"}[view]}`;
}
function navigate(view) {
  if (state.busy || state.reading || state.modelBusy) { toast("Let the current analysis finish before switching views."); return; }
  if (view === "analyze") showInput();
  else if (view === "investigations") {
    setView(view);
    $("input-panel").hidden = true;
    $("results-panel").hidden = !state.run;
    if (state.run) { state.caseId = null; state.selection = null; renderOverview(); }
  } else {
    setView("models");
    $("input-panel").hidden = true;
    $("results-panel").hidden = true;
    renderModelCatalog();
  }
}
function renderModelCatalog() {
  const models = state.models.filter((model) => model.available);
  $("model-catalog").innerHTML = models.length ? models.map((model) => `<article class="panel model-card"><div class="model-card-heading"><h3>${escapeHTML(model.name)}</h3></div><p>${escapeHTML(model.detail)}</p><button class="button secondary" data-use-model="${escapeHTML(model.id)}">Use this model →</button></article>`).join("") : "<p>No models are currently available.</p>";
}
for (const button of document.querySelectorAll("[data-view]")) button.addEventListener("click", () => navigate(button.dataset.view));
$("trace-home").addEventListener("click", () => navigate("analyze"));
$("empty-analyze").addEventListener("click", () => navigate("analyze"));
$("model-catalog").addEventListener("click", (event) => {
  const button = event.target.closest("[data-use-model]");
  if (!button || button.disabled || state.busy || state.reading || state.modelBusy) return;
  navigate("analyze"); $("model-select").value = button.dataset.useModel; modelHelp(); $("model-select").focus();
});
function showInput() {
  setView("analyze");
  $("input-panel").hidden = false; $("results-panel").hidden = true;
  $("cancel-input").hidden = !state.run;
}
function showResults() { setView("investigations"); $("input-panel").hidden = true; $("results-panel").hidden = false; if(state.run) { if(state.caseId)renderWorkspace(); else renderOverview(); } }
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
  const privacy = $("privacy-note");
  if (privacy) privacy.textContent = model?.id === "hybrid"
    ? "LLM triage sends the detector's top matches to OpenAI. Other requests stay on the analysis server."
    : "Processed on the analysis server. No external AI calls.";
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
async function analyze(logs,model,source,synthetic=false) {
  if(state.busy||state.reading||state.modelBusy)return;
  if(!logs.trim()){showError("analyze-error","Add at least one log line.");return;}
  state.busy=true;syncControls();showError("analyze-error");
  try {
    const run=await prepareRun(await predictStream(logs,model));
    state.run=run;state.logs=logs;state.source=source;state.synthetic=synthetic;
    state.threshold=defaultCutoff(run);state.runs=new Map([[model,run]]);state.activeModel=model;
    state.rowsById=run.rowsById;state.caseId=null;state.selection=null;state.edits=new Map();
    state.dispositions=new Map();state.eventNotes=new Map();state.investigations=[];state.query="";state.account="";state.overviewPage=1;
    $("investigation-search").value="";$("investigation-cutoff").value=String(Number((state.threshold*100).toFixed(5)));
    $("investigation-cutoff-label").textContent=run.mode==="heuristic"?"Rule score cutoff":"Percentile cutoff";
    $("investigation-account").innerHTML='<option value="">All accounts</option>'+Review.accountCounts(run.rows).map(([account])=>`<option value="${escapeHTML(account)}">${escapeHTML(accountName(account))}</option>`).join("");
    $("results-title").textContent="Investigations found";
    $("run-description").textContent=`${source} · ${number(run.rows.length)} requests · ${run.model_name}`;
    $("run-notice").textContent=[run.warning||"",run.external?"Shortlisted requests were sent to OpenAI for review.":""].filter(Boolean).join(" ");
    $("run-notice").hidden=!$("run-notice").textContent;
    rebuildInvestigations();showResults();toast(`${number(state.investigations.length)} candidate investigations found.`);
  } catch(error){showError("analyze-error",error.message);}
  finally{state.busy=false;syncControls();}
}
function rebuildInvestigations(){
  const previous=state.investigations,previousEdits=new Map(state.edits),byCandidate=new Map(),previousById=new Map(previous.map((item)=>[item.id,item]));
  for(const item of previous)for(const id of item.candidateIds){if(!byCandidate.has(id))byCandidate.set(id,[]);byCandidate.get(id).push(item);}
  const inherited=new Set(),rebuilt=Investigation.buildInvestigations(state.run.rows,{isCandidate});
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
function caseRows(item){return item.rows.filter((row)=>disposition(row)!=="excluded");}
function episodeRows(episode){return episode.rows.filter((row)=>disposition(row)!=="excluded");}
function episodeLabel(episode){return episode.customLabel||episode.label||actionName(episode.rows[0]);}
function caseProgression(item){
  const ids=candidateIds(item),rows=item.rows.filter((row)=>ids.has(row.id));
  const transitions=[];
  for(const row of rows){const name=actionName(row);if(transitions[transitions.length-1]!==name)transitions.push(name);}
  return transitions.length>3?[transitions[0],transitions[1],"…",transitions[transitions.length-1]]:transitions;
}
function renderOverview(){
  if(!state.run)return;
  $("overview-panel").hidden=false;$("investigation-workspace").hidden=true;
  const query=state.query.trim().toLowerCase();
  if($("overview-activity-title"))$("overview-activity-title").textContent=$("show-other-traffic").checked?"Requests around candidate investigations":"When candidate requests occurred";
  const matches=state.investigations.filter((item)=>(!state.account||(item.grouping?.manual?caseRows(item).some((row)=>row.user===state.account):item.account===state.account))&&(!query||[item.title||"",item.account,...item.sources,...item.rows.map((row)=>`${row.method} ${row.path} ${row.status}`)].join(" ").toLowerCase().includes(query)));
  const pages=Math.max(1,Math.ceil(matches.length/8));state.overviewPage=Math.min(state.overviewPage,pages);
  const shown=matches.slice((state.overviewPage-1)*8,state.overviewPage*8);
  $("overview-counts").textContent=`${number(matches.length)} candidate investigations · ${number(matches.reduce((sum,item)=>sum+item.candidateIds.length,0))} detector candidates · ${matches.some((item)=>item.grouping?.manual)?"includes analyst reconstructions":"grouped by account and time"}`;
  $("investigation-list").innerHTML=shown.map((item)=>`<article class="investigation-card"><div class="investigation-card-heading"><div><h3>${escapeHTML(item.title||accountName(item.account))}</h3><p class="investigation-card-meta">${shortTime(item.start)} – ${shortTime(item.end)}</p></div><button class="button primary" data-open-case="${escapeHTML(item.id)}">Open investigation</button></div><p class="investigation-card-meta">${number(item.candidateIds.length)} candidate requests · ${number(item.sources.length)} source IP${item.sources.length===1?"":"s"} · ${escapeHTML(item.sources.slice(0,3).join(", "))}${item.sources.length>3?" …":""}</p><p class="investigation-progression">${caseProgression(item).map(escapeHTML).join(' <span aria-hidden="true">→</span> ')}</p><p class="investigation-models">${item.savedOnly?"Saved analyst reconstruction at its original cutoff. ":""}${item.grouping?.manual?"Analyst reconstruction; detector scores are supporting evidence.":`Detected by ${escapeHTML(state.run.model_name)}.`} ${number(item.rows.length-item.candidateIds.length)} ${item.grouping?.manual?"additional evidence records":"nearby requests available as context"}.</p></article>`).join("");
  $("overview-empty").hidden=matches.length>0;$("overview-empty").textContent=state.investigations.length?"No investigations match this account or search. Clear those filters to see the other investigations.":"No requests meet this cutoff. Lower it to broaden the investigation.";
  $("overview-page").textContent=`${state.overviewPage} / ${pages}`;$("overview-previous").disabled=state.overviewPage<=1;$("overview-next").disabled=state.overviewPage>=pages;
  if($("overview-timeline-chart")){
    const ids=new Set(matches.flatMap((item)=>item.candidateIds));
    const chartRows=state.run.rows.filter((row)=>(!state.account||row.user===state.account)&&(!query||ids.has(row.id)));
    const chart=window.LogCharts.renderActivity($("overview-timeline-chart"),{rows:chartRows,isFlagged:(row)=>ids.has(row.id),showAll:$("show-other-traffic").checked,onSelect:(group)=>{
      const match=matches.find((item)=>item.start<group.end&&item.end>=group.start);if(match)openCase(match.id);
    }});
    $("overview-chart-caption").textContent=chart.caption.replace("view its requests","open a matching investigation");
  }
}
function openCase(id){
  const item=caseById(id);if(!item)return;state.caseId=item.id;state.episodeLimit=12;state.eventLimits=new Map();
  const episodes=editsFor(item).episodes;const first=episodes.find((episode)=>episode.rows.some(isCandidate))||episodes[0];
  state.selection=first?{type:"episode",id:first.id}:null;
  renderWorkspace();$("investigation-title").focus({preventScroll:true});$("investigation-workspace").scrollIntoView({block:"start"});
}
function renderWorkspace(){
  const item=caseById();if(!item)return;
  $("overview-panel").hidden=true;$("investigation-workspace").hidden=false;
  const retained=caseRows(item),ids=candidateIds(item),candidates=retained.filter((row)=>ids.has(row.id)),candidateSources=new Set(candidates.map((row)=>row.ip));
  $("investigation-title").textContent=item.title||`${item.savedOnly?"Saved investigation":"Investigation"}: ${accountName(item.account)}`;
  $("investigation-title").setAttribute("tabindex","-1");
  const observedSources=[...new Set(retained.map((row)=>row.ip))],observedAccounts=[...new Set(retained.map((row)=>accountName(row.user)))];
  $("investigation-meta").textContent=`${item.grouping?.manual?"Reconstruction window":"Candidate window"}: ${shortTime(item.start)} – ${shortTime(item.end)} · Evidence sources: ${observedSources.join(", ")}`;
  const first=candidates[0],last=candidates[candidates.length-1];
  const candidateAccounts=[...new Set(candidates.map((row)=>accountName(row.user)))];
  const candidateSubject=item.grouping?.manual?`${candidateAccounts.join(", ")||"This reconstruction"} ${candidateAccounts.length>1?"have":"has"}`:`${accountName(item.account)} has`;
  $("investigation-summary").innerHTML=`<span class="evidence-kind">Observed</span><p>${escapeHTML(candidateSubject)} ${number(candidates.length)} retained candidate requests associated with ${number(candidateSources.size)} source IP${candidateSources.size===1?"":"s"}. ${first?`The candidate sequence starts with <button class="text-button" data-select-event="${first.id}">${escapeHTML(actionName(first))}</button> (HTTP ${first.status})${last!==first?` and ends with <button class="text-button" data-select-event="${last.id}">${escapeHTML(actionName(last))}</button> (HTTP ${last.status})`:""}.`:"All candidate requests have been removed from this reconstruction."}</p><p class="field-hint">Evidence participants: ${escapeHTML(observedAccounts.join(", "))}. ${item.addedIds?.size?`${item.addedIds.size} history records explicitly added by the analyst. `:""}${escapeHTML(state.run.model_name)} supplied the candidate set. ${item.grouping?.manual?"The analyst linked these records; the proposed relationship is not an independently confirmed incident.":"Grouping proposes a relationship; it does not confirm an incident."}</p>`;
  if(item.summary?.narrative)$("investigation-summary").insertAdjacentHTML("beforeend",`<p><span class="evidence-kind">Analyst reconstruction</span> ${escapeHTML(item.summary.narrative)}</p>`);
  $("grouping-note").textContent=item.grouping?.manual?String(item.grouping.note||"Manually reconstructed by the analyst from linked evidence."):"Authenticated requests are linked by account, including source changes. Anonymous requests are linked by IP. A gap over 30 minutes between candidates starts another investigation. Context includes the same actor’s requests up to 5 minutes before and after. Episode boundaries follow request method, target, and time proximity—not inferred attack stages.";
  $("add-investigation-note").value=editsFor(item).note;$("include-context").checked=state.includeContext;
  $("restore-events").disabled=!item.rows.some((row)=>disposition(row)==="excluded");
  renderEpisodes();renderBaseline();renderEvidence();
  const comparison=state.baseline;
  $("investigation-summary").insertAdjacentHTML("beforeend",`<p class="field-hint"><span class="evidence-kind">Upload comparison</span> ${comparison.earlier.length?`${number(comparison.newSources.length)} source IPs and ${number(comparison.newPaths.length)} targets in the candidate window were absent from ${number(comparison.earlier.length)} earlier requests for this actor.`:"No earlier requests for this actor are available in this upload; usual behavior cannot be established here."} <button class="text-button" data-open-baseline>Inspect comparison and evidence</button></p>`);
}
function visibleEpisodes(){
  const item=caseById();if(!item)return[];const ids=candidateIds(item);
  return editsFor(item).episodes.filter((episode)=>episodeRows(episode).some((row)=>state.includeContext||ids.has(row.id)||["important","promoted"].includes(disposition(row))));
}
function renderEpisodes(){
  const item=caseById(),ids=candidateIds(item),episodes=visibleEpisodes();
  const selectedEpisode=state.selection?.type==="episode"?state.selection.id:episodes.find((episode)=>episode.rows.some((row)=>row.id===state.selection?.id))?.id;
  const selectedIndex=episodes.findIndex((episode)=>episode.id===selectedEpisode);if(selectedIndex>=state.episodeLimit)state.episodeLimit=selectedIndex+1;
  $("episode-list").innerHTML=episodes.slice(0,state.episodeLimit).map((episode,index)=>{
    const rows=episodeRows(episode).filter((row)=>state.includeContext||ids.has(row.id)||["important","promoted"].includes(disposition(row)));
    const limit=state.eventLimits.get(episode.id)||30,shown=rows.slice(0,limit),count=rows.filter((row)=>ids.has(row.id)).length;
    const statuses=[...new Set(rows.map((row)=>row.status))];
    return `<details class="episode ${episode.id===selectedEpisode?"selected":""}" data-episode="${escapeHTML(episode.id)}" ${episode.id===selectedEpisode?"open":""}><summary class="episode-summary"><span class="episode-time">${shortTime(rows[0].time)}${rows.length>1?` – ${shortTime(rows[rows.length-1].time)}`:""}</span><span class="episode-title">${escapeHTML(episodeLabel(episode))}</span><span class="episode-meta">${number(rows.length)} requests · ${number(count)} candidates · HTTP ${statuses.join(", ")}${episode.customLabel?" · Analyst label":""}</span></summary><div class="episode-actions"><button class="text-button" data-select-episode="${escapeHTML(episode.id)}">Model evidence for episode</button><button class="text-button" data-rename-episode="${escapeHTML(episode.id)}">Rename</button><button class="text-button" data-merge-episode="${escapeHTML(episode.id)}" ${index>=episodes.length-1?"disabled":""}>Merge with next</button></div><div class="event-list">${shown.map((row)=>`<button class="event-row ${ids.has(row.id)?"candidate":"context"} ${disposition(row)} ${state.selection?.type==="event"&&state.selection.id===row.id?"selected":""}" data-select-event="${row.id}" aria-pressed="${state.selection?.type==="event"&&state.selection.id===row.id}"><span class="event-time">${timeLabel(row.time)}</span><span class="event-request">${escapeHTML(actionName(row))}<small>${escapeHTML(row.ip)} · line ${row.id}${disposition(row)?` · Analyst: ${escapeHTML(disposition(row))}`:ids.has(row.id)?" · Candidate":" · Context"}</small></span><span class="event-result">${row.status}</span></button>`).join("")}</div>${rows.length>shown.length?`<button class="text-button show-more" data-more-events="${escapeHTML(episode.id)}">Show ${Math.min(30,rows.length-shown.length)} more requests (${number(rows.length)} total)</button>`:""}</details>`;
  }).join("")||'<p class="empty-state">No retained events in this view. Include context or restore removed events.</p>';
  if(episodes.length>state.episodeLimit)$("episode-list").insertAdjacentHTML("beforeend",`<button class="button secondary" data-more-episodes>Show more episodes (${number(episodes.length)} total)</button>`);
}
function selectEvent(id){
  if(!state.rowsById.has(id))return;
  state.selection={type:"event",id};
  const episode=editsFor(caseById()).episodes.find((item)=>item.rows.some((row)=>row.id===id));
  if(episode){const index=episode.rows.findIndex((row)=>row.id===id);state.eventLimits.set(episode.id,Math.max(30,index+1));}
  renderEpisodes();renderEvidence();
  revealSelection();
}
function revealSelection(){
  $("evidence-workspace").scrollTop=0;
  if(window.matchMedia("(max-width: 850px)").matches){$("evidence-workspace").scrollIntoView({block:"start"});$("evidence-heading").setAttribute("tabindex","-1");$("evidence-heading").focus({preventScroll:true});}
  else if(state.selection?.type==="event")$("episode-list").querySelector(`[data-select-event="${state.selection.id}"]`)?.scrollIntoView({block:"nearest"});
}
function selectedRows(){
  if(!state.selection)return[];
  if(state.selection.type==="event")return[state.rowsById.get(state.selection.id)].filter(Boolean);
  const episode=editsFor(caseById()).episodes.find((item)=>item.id===state.selection.id);
  return episode?episodeRows(episode):[];
}
function evidenceFields(fields){return `<dl class="evidence-fields">${fields.map(([label,value])=>`<div><dt>${escapeHTML(label)}</dt><dd>${escapeHTML(value)}</dd></div>`).join("")}</dl>`;}
function relatedButtons(rows){return rows.map((row)=>`<button class="event-row context" data-select-event="${row.id}"><span class="event-time">${shortTime(row.time)}</span><span class="event-request">${escapeHTML(actionName(row))}<small>${escapeHTML(accountName(row.user))} · ${escapeHTML(row.ip)}</small></span><span class="event-result">${row.status}</span></button>`).join("");}
function renderEvidence(){
  const item=caseById(),rows=selectedRows();if(!item)return;
  $("evidence-heading").textContent=state.selection?.type==="event"?`${item.rows.some((row)=>row.id===state.selection.id)?"Event":"Outside investigation · history"} · line ${state.selection.id}`:"Episode evidence";
  if(!rows.length){$("evidence-content").innerHTML='<p class="empty-state">Select an episode or event in the timeline.</p>';renderModelEvidence();return;}
  if(state.selection.type==="event"){
    const row=rows[0],ids=candidateIds(item),dispositionValue=disposition(row),inCase=item.rows.some((entry)=>entry.id===row.id),analystAdded=Boolean(item.addedIds?.has(row.id));
    const sameActor=state.run.rows.filter((entry)=>entry.user===row.user&&(row.user!=="-"||entry.ip===row.ip)).sort((a,b)=>a.time-b.time||a.id-b.id);
    const index=sameActor.findIndex((entry)=>entry.id===row.id),nearby=sameActor.slice(Math.max(0,index-3),index+4).filter((entry)=>entry.id!==row.id);
    const episode=editsFor(item).episodes.find((entry)=>entry.rows.some((entryRow)=>entryRow.id===row.id));
    const splitAllowed=episode&&episode.rows.findIndex((entry)=>entry.id===row.id)>0;
    $("evidence-content").innerHTML=`<span class="evidence-kind">Observed fields</span>${evidenceFields([["Account",accountName(row.user)],["Source IP",row.ip],["Target",actionName(row)],["Time",shortTime(row.time)],["HTTP result",row.status],["Response bytes",number(row.bytes)]])}<details class="evidence-section"><summary>Why this event is included</summary><p>${ids.has(row.id)?`Its ${escapeHTML(state.run.model_name)} result met the ${Number((caseCutoff(item)*100).toFixed(5))}${state.run.mode==="heuristic"?" / 100 rule-score":" percentile"} review cutoff.`:analystAdded?"The analyst explicitly added this history record to the reconstruction.":inCase?"It is nearby traffic for the same actor, provided as context.":"This record is outside the investigation. It was opened from observed history; promote it explicitly to include it in the reconstruction."} ${dispositionValue?`Analyst disposition: ${escapeHTML(dispositionValue)}.`:""} This relationship does not establish causation.</p></details><div class="evidence-actions"><label>Analyst disposition<select id="event-disposition"><option value="">Unreviewed</option><option value="important">Important</option><option value="benign">Benign</option><option value="promoted">Promote to timeline</option><option value="excluded" ${inCase?"":"disabled"}>Remove from reconstruction</option></select></label><button class="text-button" data-split-event="${row.id}" ${splitAllowed?"":"disabled"}>Start new episode here</button></div><label class="evidence-note">Event note <span class="analyst-label">Analyst interpretation</span><textarea id="event-note" rows="2" placeholder="Record your interpretation and supporting evidence.">${escapeHTML(state.eventNotes.get(row.id)||"")}</textarea></label><details class="evidence-section" open><summary>Surrounding account activity (${nearby.length} requests)</summary><div class="related-events">${relatedButtons(nearby)||'<p>No surrounding requests in this upload.</p>'}</div></details><details class="evidence-section"><summary>Source and target history in this upload</summary><p>Earlier requests sharing this source or exact target; these are observations, not a learned baseline.</p><div class="related-events">${relatedButtons(state.run.rows.filter((entry)=>entry.time<row.time&&(entry.ip===row.ip||entry.path===row.path)).sort((a,b)=>b.time-a.time).slice(0,8))||'<p>No earlier matching requests.</p>'}</div></details><details class="evidence-section"><summary>Original log record</summary><pre class="raw-log">${escapeHTML(row.raw)}</pre></details>`;
    $("event-disposition").value=dispositionValue;
  }else{
    const episode=editsFor(item).episodes.find((entry)=>entry.id===state.selection.id);
    const counts=new Map();for(const row of rows)counts.set(row.status,(counts.get(row.status)||0)+1);
    $("evidence-content").innerHTML=`<span class="evidence-kind">Observed episode</span><h4>${escapeHTML(episodeLabel(episode))}</h4>${evidenceFields([["Time",`${shortTime(rows[0].time)} – ${shortTime(rows[rows.length-1].time)}`],["Requests",number(rows.length)],["Sources",[...new Set(rows.map((row)=>row.ip))].join(", ")],["HTTP results",[...counts].map(([status,count])=>`${status}: ${count}`).join(" · ")]])}<p class="field-hint">${episode.customLabel?"The episode title was supplied by the analyst.":"This episode groups nearby requests to the same target. Its title is the observed method and path."}</p><p class="field-hint">Select a request for its parsed fields, neighboring traffic, and original log.</p>`;
  }
  renderModelEvidence();
}
function renderModelEvidence(){
  const rows=selectedRows(),run=state.runs.get(state.activeModel);
  $("evidence-model").innerHTML=state.models.filter((model)=>model.available||state.runs.has(model.id)).map((model)=>`<option value="${escapeHTML(model.id)}" ${model.available||state.runs.has(model.id)?"":"disabled"}>${escapeHTML(model.name)}${state.runs.has(model.id)?" · analyzed":model.available?" · not run":" · unavailable"}</option>`).join("");
  $("evidence-model").value=state.activeModel;$("evidence-model").disabled=state.modelBusy;
  if(run){
    const selected=rows.map((row)=>run.rowsById.get(row.id)).filter(Boolean);
    window.LogModelLens.render($("model-evidence-content"),{run,selectedRows:selected,allRows:run.rows,cutoff:run===state.run?caseCutoff():defaultCutoff(run),onSelectEvent:selectEvent});
  }else{
    const model=state.models.find((entry)=>entry.id===state.activeModel);
    $("model-evidence-content").innerHTML=`<p>This detector has not analyzed this upload. Your investigation and selection stay in place.</p>${model?.external||model?.id==="hybrid"?'<p class="field-hint">This option sends shortlisted logs and account profiles to OpenAI.</p>':""}<button id="run-evidence-model" class="button primary" ${state.modelBusy?"disabled":""}>${state.modelBusy?"Analyzing…":"Analyze this upload with "+escapeHTML(model?.name||state.activeModel)}</button>`;
  }
    $("model-comparison").innerHTML=`<h4>Detector perspectives</h4><p class="field-hint">Same selected ${rows.length===1?"event":"events"}; separate cutoffs. Agreement is not independent confirmation.</p><div class="model-comparison-list">${state.models.filter((model)=>model.available||state.runs.has(model.id)).map((model)=>{
    const scoredRun=state.runs.get(model.id),matched=scoredRun?rows.map((row)=>scoredRun.rowsById.get(row.id)).filter(Boolean):[];
    const cutoff=scoredRun===state.run?caseCutoff():scoredRun?defaultCutoff(scoredRun):null;
    const flagged=matched.filter((row)=>Review.isCandidate(row,cutoff)).length;
    return `<button class="model-comparison-row" data-lens="${escapeHTML(model.id)}" ${model.available||scoredRun?"":"disabled"} aria-pressed="${state.activeModel===model.id}"><span>${escapeHTML(model.name)}</span><span>${!scoredRun?(model.available?"Not run":"Unavailable"):!matched.length?"No selected events":`${flagged} / ${matched.length} above cutoff`}</span></button>`;
  }).join("")}</div>`;
}
async function runEvidenceModel(){
  if(state.modelBusy||!state.run)return;
  const model=state.activeModel,revision=state.revision,originalRun=state.run;
  state.modelBusy=true;$("new-analysis").disabled=true;renderModelEvidence();
  try{
    const run=await prepareRun(await predictStream(state.logs,model,(progress)=>{
      $("model-run-status").textContent=`${progress.message||progress.stage||"Processing"}${Number.isFinite(progress.completed)&&progress.total?` · ${number(progress.completed)} / ${number(progress.total)}`:""}`;
    }));
    if(revision!==state.revision||state.run!==originalRun)return;
    if(run.rows.length!==originalRun.rows.length||run.rows.some((row)=>originalRun.rowsById.get(row.id)?.raw!==row.raw))throw new Error("The detector returned records that do not match this upload. Its results were not attached.");
    state.runs.set(model,run);$("model-run-status").textContent=`${run.model_name} complete. Selection and reconstruction preserved.`;
  }catch(error){$("model-run-status").textContent=error.message;}
  finally{state.modelBusy=false;$("new-analysis").disabled=false;renderModelEvidence();}
}
function renderBaseline(){
  const item=caseById();if(!item)return;
  const sameActor=(row)=>row.user===item.account&&(item.account!=="-"||item.sources.includes(row.ip));
  const earlier=state.run.rows.filter((row)=>sameActor(row)&&row.time<item.start);
  const during=state.run.rows.filter((row)=>sameActor(row)&&row.time>=item.start&&row.time<=item.end);
  let priorStart=Infinity;for(const row of earlier)priorStart=Math.min(priorStart,row.time);
  const earlierSources=new Set(earlier.map((row)=>row.ip)),earlierPaths=new Set(earlier.map((row)=>row.path));
  const caseSources=[...new Set(during.map((row)=>row.ip))],casePaths=[...new Set(during.map((row)=>row.path))];
  const beforeMinutes=earlier.length?(item.start-priorStart)/60000:0,caseMinutes=(item.end-item.start)/60000;
  const priorRate=beforeMinutes>0?earlier.length/beforeMinutes:null,caseRate=caseMinutes>0?during.length/caseMinutes:null;
  state.baseline={earlier,during,priorStart,beforeMinutes,caseMinutes,priorRate,caseRate,newSources:caseSources.filter((ip)=>!earlierSources.has(ip)),newPaths:casePaths.filter((path)=>!earlierPaths.has(path))};
  const priorWindow=earlier.length?`${shortTime(priorStart)} to ${shortTime(item.start)} (end exclusive)`:"No earlier account traffic in this upload";
  $("baseline-content").innerHTML=`<span class="evidence-kind">Statistical comparison · this upload only</span><p class="field-hint">Earlier traffic is observed history, not verified normal behavior or the model’s training baseline.</p><div class="table-scroll"><table class="baseline-table"><thead><tr><th>Observation</th><th>Earlier in upload</th><th>Investigation window</th></tr></thead><tbody><tr><th>Window (UTC)</th><td>${priorWindow}</td><td>${shortTime(item.start)} to ${shortTime(item.end)}</td></tr><tr><th>Requests</th><td>${number(earlier.length)}</td><td>${number(during.length)}</td></tr><tr><th>Requests / minute</th><td>${priorRate===null?"Not enough time coverage":priorRate.toFixed(2)}${beforeMinutes?` over ${beforeMinutes.toFixed(2)} min`:""}</td><td>${caseRate===null?"Single timestamp; rate unavailable":caseRate.toFixed(2)}${caseMinutes?` over ${caseMinutes.toFixed(2)} min`:""}</td></tr><tr><th>Source IPs</th><td>${escapeHTML([...earlierSources].slice(0,6).join(", ")||"Not observed")}${earlierSources.size>6?` +${earlierSources.size-6}`:""}</td><td>${escapeHTML(caseSources.slice(0,6).join(", "))}${caseSources.length>6?` +${caseSources.length-6}`:""}${earlier.length?` · ${state.baseline.newSources.length} absent from earlier traffic`:""}</td></tr><tr><th>Distinct targets</th><td>${number(earlierPaths.size)}</td><td>${number(casePaths.length)}${earlier.length?` · ${state.baseline.newPaths.length} absent from earlier traffic`:""}</td></tr></tbody></table></div><details class="evidence-section"><summary>Supporting earlier requests (${number(earlier.length)})</summary><p class="field-hint">${earlier.length>20?"20 most recent shown; the report includes the full earlier comparison record IDs.":""}</p><div class="related-events">${relatedButtons(earlier.slice().sort((a,b)=>b.time-a.time).slice(0,20))||'<p>No earlier records. No claim about usual behavior can be made from this upload.</p>'}</div></details>`;
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
    base_model:state.run.model,active_model:state.activeModel,threshold:state.threshold,rows:state.run.rows.map(record),runs,
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
  const investigations=saved.investigations? saved.investigations.map((item)=>{
    if(!safeId(item.id)||!Number.isFinite(item.start)||!Number.isFinite(item.end)||!Array.isArray(item.sources))throw new Error("Invalid investigation metadata.");
    rowRefs(item.candidateIds);return {...item,rows:rowRefs(item.rowIds),episodes:item.episodes.map(episode),addedIds:new Set(item.addedIds||[])};
  }):Investigation.buildInvestigations(run.rows,{isCandidate:(row)=>Review.isCandidate(row,threshold)}).map((item)=>({...item,reviewCutoff:threshold}));
  const edits=new Map((saved.edits||[]).map(([id,value])=>[id,{...value,episodes:value.episodes.map(episode)}]));
  const dispositions=new Map(saved.dispositions||[]),eventNotes=new Map(saved.eventNotes||[]);
  if([...dispositions.values()].some((value)=>!["important","benign","promoted","excluded"].includes(value)))throw new Error("Invalid analyst disposition.");
  const selectedCase=investigations.find((item)=>item.id===saved.caseId);
  const selection=saved.selection;
  const selectedEpisodes=selectedCase?(edits.get(selectedCase.id)?.episodes||selectedCase.episodes):[];
  const validSelection=selectedCase&&selection&&(selection.type==="event"?run.rowsById.has(selection.id):selection.type==="episode"&&selectedEpisodes.some((item)=>item.id===selection.id));
  state.revision++;state.run=run;state.runs=runs;state.rowsById=run.rowsById;state.logs=run.rows.map((row)=>row.raw).join("\n");
  state.source=String(saved.source||"Saved investigation");state.synthetic=Boolean(saved.synthetic);state.threshold=threshold;
  state.activeModel=runs.has(saved.active_model)?saved.active_model:saved.base_model;state.investigations=investigations;state.edits=edits;state.dispositions=dispositions;state.eventNotes=eventNotes;
  state.caseId=investigations.some((item)=>item.id===saved.caseId)?saved.caseId:null;state.selection=validSelection?selection:selectedEpisodes.length?{type:"episode",id:selectedEpisodes[0].id}:null;
  state.query=String(saved.query||"");state.account=String(saved.account||"");state.includeContext=saved.includeContext!==false;state.overviewPage=1;state.episodeLimit=12;state.eventLimits=new Map();
  for(const [id,cached] of runs)if(!state.models.some((model)=>model.id===id))state.models.push({id,name:cached.model_name||id,available:false});
  $("investigation-search").value=state.query;$("investigation-cutoff").value=String(Number((threshold*100).toFixed(5)));
  $("investigation-cutoff-label").textContent=run.mode==="heuristic"?"Rule score cutoff":"Percentile cutoff";
  $("investigation-account").innerHTML='<option value="">All accounts</option>'+Review.accountCounts(run.rows).map(([account])=>`<option value="${escapeHTML(account)}">${escapeHTML(accountName(account))}</option>`).join("");$("investigation-account").value=state.account;
  $("results-title").textContent="Saved investigations";$("run-description").textContent=`${state.source} · ${number(run.rows.length)} requests · ${runs.size} saved detector results`;
  $("run-notice").textContent="Loaded saved results and analyst notes. No detectors were run.";$("run-notice").hidden=false;
  showResults();toast("Investigation restored, including model results and notes.");
}
window.LogSession={snapshot:sessionSnapshot,restore:restoreSession};
function exportReport(){
  const item=caseById(),edits=editsFor(item),rows=caseRows(item),baseline=state.baseline;
  const literal=(value)=>String(value).replace(/[\\`*_{}\[\]<>#|]/g,"\\$&");
  const lines = [
    "# Investigation report",
    `Source: ${literal(state.source)}${state.synthetic ? " (synthetic sample)" : ""}`,
    "",
    "This reconstruction is an investigative hypothesis. Original model scores and log records are preserved separately from analyst interpretation.",
    "",
    "## Who",
    `- Candidate account: ${literal(accountName(item.account))}`,
    `- Accounts in retained evidence: ${[...new Set(rows.map((row) => accountName(row.user)))].map(literal).join(", ")}`,
    `- Sources in retained evidence: ${[...new Set(rows.map((row) => row.ip))].map(literal).join(", ")}`,
    "",
    "## What",
    `${rows.length} retained requests; ${rows.filter((row) => Review.isCandidate(row, caseCutoff(item))).length} meet the ${literal(state.run.model_name)} cutoff. Targets and HTTP responses below are observed records, not inferred application outcomes.`,
    "",
    "## When",
    `Original candidate window: ${shortTime(item.start)} to ${shortTime(item.end)}`,
    `Retained evidence span: ${rows.length ? `${shortTime(rows[0].time)} to ${shortTime(rows[rows.length - 1].time)}` : "No retained events"}`,
    "",
    "## How: reconstructed episodes",
  ];
  for(const episode of edits.episodes){
    const kept=episodeRows(episode);if(!kept.length)continue;
    lines.push("",`### ${literal(episodeLabel(episode))}${episode.customLabel?" (analyst title)":""}`,`${shortTime(kept[0].time)} to ${shortTime(kept[kept.length-1].time)} · ${kept.length} requests`);
    for(const row of kept)lines.push(`- Line ${row.id}: ${shortTime(row.time)} · ${literal(actionName(row))} · HTTP ${row.status} · ${literal(row.ip)}${disposition(row)?` · analyst: ${literal(disposition(row))}`:""}${state.eventNotes.get(row.id)?` — Note: ${literal(state.eventNotes.get(row.id))}`:""}`);
  }
  lines.push("","## Earlier-upload comparison","Earlier traffic is not verified normal behavior. All windows and supporting row IDs are given to make comparisons inspectable.",`- Earlier: ${baseline.earlier.length} requests${baseline.earlier.length?` from ${shortTime(baseline.priorStart)} until ${shortTime(item.start)} (exclusive)`:"; no earlier history available"}`,`- Investigation: ${baseline.during.length} requests from ${shortTime(item.start)} through ${shortTime(item.end)}`,`- Observed rates: ${baseline.priorRate===null?"unavailable":baseline.priorRate.toFixed(4)} earlier, ${baseline.caseRate===null?"unavailable":baseline.caseRate.toFixed(4)} investigation requests/minute. Different window lengths can affect this comparison.`,`- Earlier evidence line IDs: ${baseline.earlier.map((row)=>row.id).join(", ")||"none"}`,"","## Model evidence","Detector agreement is not independent confirmation. Models without a run on this upload are not compared.");
  for(const run of state.runs.values()){
    const description=window.LogModelLens.describeModel(run),cutoff=run===state.run?caseCutoff():defaultCutoff(run);
    lines.push("",`### ${literal(run.model_name)}`,literal(description.meaning),`Cutoff: ${cutoff*100} / 100 (${run.detector_score_kind||run.score_kind}).`);
    for(const baseRow of rows){const row=run.rowsById.get(baseRow.id);if(!row)continue;lines.push(`- Line ${row.id}: ${literal(description.scoreLabel)} ${Number.isFinite(row.raw_score)?row.raw_score:row.score*100}; ${literal(Review.percentileLabel(row,scoreKindFor(run,row)))}; ${Review.isCandidate(row,cutoff)?"meets":"below"} cutoff${row.triage?`; LLM interpretation: ${literal(row.triage)} — ${literal(row.triage_reason||"")}`:""}`);}
  }
  lines.push("","## Analyst interpretation",literal(edits.note||"No investigation note supplied."),"","## Exclusions",item.rows.filter((row)=>disposition(row)==="excluded").map((row)=>`Line ${row.id}${state.eventNotes.get(row.id)?`: ${literal(state.eventNotes.get(row.id))}`:""}`).join("\n")||"No excluded events.","","## Supporting raw evidence");
  for(const row of item.rows){let fenceSize=3;for(const match of row.raw.matchAll(/`+/g))fenceSize=Math.max(fenceSize,match[0].length+1);const fence="`".repeat(fenceSize);lines.push("",`Line ${row.id}${disposition(row)==="excluded"?" (excluded by analyst)":""}`,fence+"text",row.raw,fence);}
  saveFile(`investigation-${item.id}.md`,lines.join("\n"),"text/markdown;charset=utf-8");toast("Investigation report exported.");
}
function exportRawCSV(){
  const item=caseById(),episodes=editsFor(item).episodes,episodeByRow=new Map();for(const episode of episodes)for(const row of episode.rows)episodeByRow.set(row.id,episodeLabel(episode));
  const cell=(value)=>{let text=String(value??"");if(/^[\s]*[=+@-]/.test(text))text="'"+text;return '"'+text.replace(/"/g,'""')+'"';};
  const lines=[["source_line","timestamp","account","source_ip","method","path","status","response_bytes","episode","analyst_disposition","analyst_note","base_model","base_raw_score","base_rank_or_rule_score","base_cutoff","original_log"]];
  for(const row of item.rows)lines.push([row.id,row.timestamp,row.user,row.ip,row.method,row.path,row.status,row.bytes,episodeByRow.get(row.id),disposition(row),state.eventNotes.get(row.id),state.run.model,row.raw_score??"",row.score,caseCutoff(item),row.raw]);
  saveFile(`investigation-${item.id}-records.csv`,"\uFEFF"+lines.map((line)=>line.map(cell).join(",")).join("\r\n"),"text/csv;charset=utf-8");toast("Investigation records exported, including analyst exclusions.");
}
function renameEpisode(id,button){
  const episode=editsFor(caseById()).episodes.find((entry)=>String(entry.id)===String(id));if(!episode)return;
  const form=document.createElement("form");form.className="episode-rename";
  const label=document.createElement("label");label.textContent="Analyst episode title";
  const input=document.createElement("input");input.type="text";input.value=episodeLabel(episode);input.maxLength=180;label.append(input);
  const save=document.createElement("button");save.className="button secondary";save.textContent="Save title";save.type="submit";
  const cancel=document.createElement("button");cancel.className="text-button";cancel.textContent="Cancel";cancel.type="button";cancel.addEventListener("click",()=>renderEpisodes());
  form.append(label,save,cancel);button.closest(".episode-actions").replaceWith(form);input.focus();input.select();
  form.addEventListener("submit",(event)=>{event.preventDefault();episode.customLabel=input.value.trim()||undefined;editsFor(caseById()).edited=true;renderWorkspace();});
}
function mergeEpisode(id){
  const edits=editsFor(caseById()),visible=visibleEpisodes(),index=visible.findIndex((entry)=>String(entry.id)===String(id));
  if(index<0||index>=visible.length-1)return;
  const first=visible[index],second=visible[index+1],all=edits.episodes;
  const merging=all.slice(all.indexOf(first),all.indexOf(second)+1);
  const mergedRows=merging.flatMap((episode)=>episode.rows).sort((a,b)=>a.time-b.time||a.id-b.id);
  const merged={...first,rows:mergedRows,customLabel:first.customLabel||`${actionName(mergedRows[0])} → ${actionName(mergedRows[mergedRows.length-1])}`,start:mergedRows[0].time,end:mergedRows[mergedRows.length-1].time};
  edits.edited=true;edits.episodes=all.flatMap((episode)=>episode===first?[merged]:merging.includes(episode)?[]:[episode]);state.selection={type:"episode",id:merged.id};renderWorkspace();
}
function splitAtEvent(id){
  const edits=editsFor(caseById()),episode=edits.episodes.find((entry)=>entry.rows.some((row)=>row.id===id));if(!episode)return;
  const index=episode.rows.findIndex((row)=>row.id===id);if(index<=0)return;
  const make=(rows,suffix)=>({...episode,id:`${episode.id}-${suffix}-${id}`,rows,label:actionName(rows[0]),customLabel:undefined,start:rows[0].time,end:rows[rows.length-1].time});
  const first=make(episode.rows.slice(0,index),"a"),second=make(episode.rows.slice(index),"b");
  edits.edited=true;edits.episodes=edits.episodes.flatMap((entry)=>entry===episode?[first,second]:[entry]);state.selection={type:"event",id};renderWorkspace();
}
function promoteExternalContext(row){
  const item=caseById();if(item.rows.some((entry)=>entry.id===row.id))return;
  if(!item.addedIds)item.addedIds=new Set();item.addedIds.add(row.id);
  item.rows.push(row);item.rows.sort((a,b)=>a.time-b.time||a.id-b.id);
  const episode={id:`promoted-${row.id}`,label:actionName(row),rows:[row],start:row.time,end:row.time};
  editsFor(item).episodes.push(episode);editsFor(item).episodes.sort((a,b)=>a.rows[0].time-b.rows[0].time);
}
for(const element of document.querySelectorAll("[data-icon]"))element.innerHTML=icon(element.dataset.icon);
for(const mode of ["file","paste"])$("tab-"+mode).addEventListener("click",()=>switchInput(mode));
$("new-analysis").addEventListener("click",()=>{if(!state.modelBusy)showInput();});
$("cancel-input").addEventListener("click",showResults);
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
$("investigation-account").addEventListener("change",()=>{state.account=$("investigation-account").value;state.overviewPage=1;renderOverview();});
$("investigation-cutoff").addEventListener("change",()=>{
  const value=Number($("investigation-cutoff").value);if(!Number.isFinite(value)||$("investigation-cutoff").value===""){$("investigation-cutoff").value=String(state.threshold*100);return;}
  state.threshold=Math.max(0,Math.min(100,value))/100;$("investigation-cutoff").value=String(state.threshold*100);state.caseId=null;state.overviewPage=1;rebuildInvestigations();
});
$("investigation-list").addEventListener("click",(event)=>{const target=event.target.closest("[data-open-case]");if(target)openCase(target.dataset.openCase);});
$("overview-previous").addEventListener("click",()=>{state.overviewPage--;renderOverview();});
$("overview-next").addEventListener("click",()=>{state.overviewPage++;renderOverview();});
$("show-other-traffic").addEventListener("change",renderOverview);
$("back-investigations").addEventListener("click",()=>{state.caseId=null;state.selection=null;renderOverview();$("results-title").scrollIntoView({block:"start"});});
$("include-context").addEventListener("change",()=>{state.includeContext=$("include-context").checked;renderEpisodes();});
$("restore-events").addEventListener("click",()=>{for(const row of caseById().rows)if(disposition(row)==="excluded")state.dispositions.delete(dispositionKey(row));renderWorkspace();});
$("add-investigation-note").addEventListener("input",()=>{editsFor(caseById()).note=$("add-investigation-note").value;$("investigation-notes").textContent="Note kept in this session and included in the report.";});
$("investigation-workspace").addEventListener("click",(event)=>{
  if(event.target.closest("[data-open-baseline]")){const panel=$("baseline-content").closest("details");panel.open=true;panel.scrollIntoView({block:"start"});return;}
  const selected=event.target.closest("[data-select-event]");if(selected){selectEvent(Number(selected.dataset.selectEvent));return;}
  const episode=event.target.closest("[data-select-episode]");if(episode){const found=editsFor(caseById()).episodes.find((entry)=>String(entry.id)===episode.dataset.selectEpisode);state.selection={type:"episode",id:found.id};renderEpisodes();renderEvidence();revealSelection();return;}
  const rename=event.target.closest("[data-rename-episode]");if(rename){renameEpisode(rename.dataset.renameEpisode,rename);return;}
  const merge=event.target.closest("[data-merge-episode]");if(merge){mergeEpisode(merge.dataset.mergeEpisode);return;}
  const split=event.target.closest("[data-split-event]");if(split){splitAtEvent(Number(split.dataset.splitEvent));return;}
  const more=event.target.closest("[data-more-events]");if(more){const id=more.dataset.moreEvents;state.eventLimits.set(id,(state.eventLimits.get(id)||30)+30);renderEpisodes();const node=Array.from($("episode-list").querySelectorAll("[data-episode]")).find((entry)=>entry.dataset.episode===id);if(node)node.open=true;return;}
  if(event.target.closest("[data-more-episodes]")){state.episodeLimit+=12;renderEpisodes();return;}
  const lens=event.target.closest("[data-lens]");if(lens&&!state.modelBusy){state.activeModel=lens.dataset.lens;$("model-run-status").textContent="";renderModelEvidence();return;}
  if(event.target.closest("#run-evidence-model"))runEvidenceModel();
});
$("evidence-workspace").addEventListener("change",(event)=>{
  if(event.target.id!=="event-disposition"||state.selection?.type!=="event")return;
  const row=state.rowsById.get(state.selection.id),value=event.target.value;
  if(value)state.dispositions.set(dispositionKey(row),value);else state.dispositions.delete(dispositionKey(row));
  if(["promoted","important"].includes(value))promoteExternalContext(row);
  renderWorkspace();
});
$("evidence-workspace").addEventListener("input",(event)=>{if(event.target.id==="event-note"&&state.selection?.type==="event")state.eventNotes.set(state.selection.id,event.target.value);});
$("evidence-model").addEventListener("change",()=>{state.activeModel=$("evidence-model").value;$("model-run-status").textContent="";renderModelEvidence();});
$("save-session").addEventListener("click",async()=>{
  if(!state.run||state.modelBusy||state.busy||$("save-session").disabled)return;
  const button=$("save-session");button.disabled=true;button.textContent="Saving investigation…";
  try{
    const json=JSON.stringify(sessionSnapshot());
    if(typeof CompressionStream!=="undefined"){
      const compressed=await new Response(new Blob([json]).stream().pipeThrough(new CompressionStream("gzip"))).blob();
      saveFile("trace-investigation.json.gz",compressed,"application/gzip");
    }else saveFile("trace-investigation.json",json,"application/json;charset=utf-8");
    toast("Saved all model results, timeline edits, and original records.");
  }catch(error){showError("page-error",`Could not save investigation: ${error.message}`);}
  finally{button.disabled=false;button.textContent="Save investigation data";}
});
$("load-session").addEventListener("click",()=>{if(!state.busy&&!state.modelBusy&&!state.reading)$("session-file").click();});
$("session-file").addEventListener("change",async()=>{
  const file=$("session-file").files[0];$("session-file").value="";if(!file||state.busy||state.modelBusy||state.reading)return;
  state.reading=true;syncControls();$("load-session").disabled=true;showError("page-error");
  try{
    let text;
    if(/\.gz$/i.test(file.name)){
      if(typeof DecompressionStream==="undefined")throw new Error("This browser cannot open gzip saves. Unzip the file and open its JSON, or use a current browser.");
      text=await new Response(file.stream().pipeThrough(new DecompressionStream("gzip"))).text();
    }else text=await file.text();
    await restoreSession(JSON.parse(text));
  }catch(error){showError("page-error",`Could not open saved investigation: ${error.message}`);}
  finally{state.reading=false;$("load-session").disabled=false;syncControls();}
});
$("export-investigation").addEventListener("click",exportReport);
$("export-investigation-csv").addEventListener("click",exportRawCSV);
window.addEventListener("resize",()=>{clearTimeout(state.resizeTimer);state.resizeTimer=setTimeout(()=>{if(state.run&&!$("results-panel").hidden){if(state.caseId)renderModelEvidence();else renderOverview();}},150);});
(async()=>{
  try{const status=await api("/api/status");state.models=status.models.filter((model)=>model.id!=="rules"&&model.available);for(const [id,run] of state.runs)if(!state.models.some((model)=>model.id===id))state.models.push({id,name:run.model_name||id,available:false});state.ready=true;renderModels();$("connection").textContent=state.models.some((model)=>model.available&&model.id!=="rules")?"Models online":"No models available";syncControls();}
  catch(error){$("connection").textContent="Server unavailable";showError("page-error",error.message);}
})();
