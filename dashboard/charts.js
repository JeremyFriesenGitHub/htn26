/* Log charts: plotted values and tooltip counts always come from the scoped rows. */
(function (root) {
  "use strict";
  const HOUR = 3600000, DAY = 24 * HOUR, SVG_NS = "http://www.w3.org/2000/svg";
  const number = (value) => Number(value).toLocaleString("en-US");
  const score = (value) => Number.isFinite(value) ? (value * 100).toFixed(2) : "—";
  const shortNumber = (value) => {
    if (!Number.isFinite(value)) return "—";
    if (value === 0) return "0";
    const magnitude = Math.abs(value);
    return magnitude >= 100000 || magnitude < 0.001 ? value.toExponential(2) : Number(value.toPrecision(4)).toLocaleString("en-US", {maximumFractionDigits: 6});
  };
  const timeOf = (row) => typeof row.time === "number" ? row.time : new Date(row.time ?? row.timestamp).getTime();
  const utc = (value) => new Date(value).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
  const dateTick = (value, timeOnly) => new Intl.DateTimeFormat("en-US", {
    timeZone: "UTC", ...(timeOnly ? {hour: "2-digit", minute: "2-digit", hourCycle: "h23"} : {month: "short", day: "numeric"}),
  }).format(new Date(value));
  const defaultFlagged = (row, options) => typeof options.isFlagged === "function" ? options.isFlagged(row) : row.score >= (options.threshold ?? .75);
  function extents(rows) {
    let minTime = Infinity, maxTime = -Infinity, minValue = Infinity, maxValue = -Infinity;
    let minNonzero = Infinity, maxAbs = 0, allRaw = rows.length > 0, valid = 0;
    for (const row of rows) if (!Number.isFinite(row.raw_score)) allRaw = false;
    for (const row of rows) {
      const time = timeOf(row), value = allRaw ? row.raw_score : row.score * 100;
      if (!Number.isFinite(time) || !Number.isFinite(value)) continue;
      valid++;
      minTime = Math.min(minTime, time); maxTime = Math.max(maxTime, time);
      minValue = Math.min(minValue, value); maxValue = Math.max(maxValue, value);
      const abs = Math.abs(value); maxAbs = Math.max(maxAbs, abs);
      if (abs > 0) minNonzero = Math.min(minNonzero, abs);
    }
    return {minTime, maxTime, minValue, maxValue, minNonzero, maxAbs, allRaw, valid};
  }
  function newGroup() {
    return {count: 0, flagged: 0, minTime: Infinity, maxTime: -Infinity, minScore: Infinity, maxScore: -Infinity,
      minRaw: Infinity, maxRaw: -Infinity, rawCount: 0, users: new Set(), ips: new Set(), anonymous: 0, examples: []};
  }
  function addRow(group, row, flagged) {
    const time = timeOf(row);
    group.count++; if (flagged) group.flagged++;
    group.minTime = Math.min(group.minTime, time); group.maxTime = Math.max(group.maxTime, time);
    if (row.score < group.minScore) { group.minScore = row.score; group.minScoreRow = row; }
    if (row.score > group.maxScore) { group.maxScore = row.score; group.maxScoreRow = row; }
    if (Number.isFinite(row.raw_score)) {
      group.minRaw = Math.min(group.minRaw, row.raw_score); group.maxRaw = Math.max(group.maxRaw, row.raw_score); group.rawCount++;
    }
    if (row.user && row.user !== "-") group.users.add(row.user); else group.anonymous++;
    if (row.ip) group.ips.add(row.ip);
    if (group.examples.length < 3) { group.examples.push(row); if (flagged) group.hasFlaggedExample = true; }
    // Keep a flagged example visible when a mixed cell begins with ordinary traffic.
    else if (flagged && !group.hasFlaggedExample) { group.examples[2] = row; group.hasFlaggedExample = true; }
  }
  function aggregateScatter(rows, options = {}) {
    const limits = extents(rows), width = Math.max(1, options.width || 640), height = Math.max(1, options.height || 240);
    if (!limits.valid) return {groups: [], ...limits};
    const symlog = limits.allRaw && (limits.maxAbs / limits.minNonzero >= 100 || !Number.isFinite(limits.maxValue - limits.minValue));
    const constant = symlog ? Math.max(Number.MIN_VALUE, limits.maxAbs / 1000) : 1;
    const transform = symlog ? (value) => Math.sign(value) * Math.log1p(Math.abs(value) / constant) : (value) => value;
    const inverse = symlog ? (value) => Math.sign(value) * Math.expm1(Math.abs(value)) * constant : (value) => value;
    let yMin = limits.allRaw ? transform(limits.minValue) : 0;
    let yMax = limits.allRaw ? transform(limits.maxValue) : 100;
    if (yMin === yMax) { const padding = Math.max(Math.abs(yMin) * .1, 1); yMin -= padding; yMax += padding; }
    else if (limits.allRaw) { const padding = (yMax - yMin) * .06; yMin -= padding; yMax += padding; }
    let xMin = limits.minTime, xMax = limits.maxTime;
    if (xMin === xMax) { xMin -= 30000; xMax += 30000; }
    const cellSize = 14, groups = new Map();
    for (const row of rows) {
      const time = timeOf(row), value = limits.allRaw ? row.raw_score : row.score * 100;
      if (!Number.isFinite(time) || !Number.isFinite(value)) continue;
      const x = (time - xMin) / (xMax - xMin) * width;
      const y = height - (transform(value) - yMin) / (yMax - yMin) * height;
      const key = `${Math.floor(x / cellSize)},${Math.floor(y / cellSize)}`;
      let group = groups.get(key);
      if (!group) { group = {...newGroup(), sumX: 0, sumY: 0}; groups.set(key, group); }
      const flagged = defaultFlagged(row, options);
      addRow(group, row, flagged); group.sumX += x; group.sumY += y;
    }
    for (const group of groups.values()) { group.x = group.sumX / group.count; group.y = group.sumY / group.count; }
    return {groups: Array.from(groups.values()).sort((a, b) => a.x - b.x || a.y - b.y), ...limits, xMin, xMax, yMin, yMax, transform, inverse, symlog, constant};
  }
  function aggregateActivity(rows, options = {}) {
    let minTime = Infinity, maxTime = -Infinity;
    for (const row of rows) { const time = timeOf(row); if (Number.isFinite(time)) { minTime = Math.min(minTime, time); maxTime = Math.max(maxTime, time); } }
    if (!Number.isFinite(minTime)) return {buckets: [], unit: HOUR, step: HOUR};
    const unit = maxTime - minTime <= 2 * DAY ? HOUR : DAY;
    const maxBars = Math.max(4, Math.min(72, Math.floor((options.width || 640) / 14)));
    let multiplier = Math.max(1, Math.ceil((maxTime - minTime + 1) / unit / maxBars));
    let step = unit * multiplier, start = Math.floor(minTime / step) * step;
    while (Math.floor((maxTime - start) / step) + 1 > maxBars) { multiplier++; step = unit * multiplier; start = Math.floor(minTime / step) * step; }
    const count = Math.floor((maxTime - start) / step) + 1;
    const buckets = Array.from({length: count}, (_, index) => ({...newGroup(), start: start + index * step, end: start + (index + 1) * step}));
    for (const row of rows) {
      const time = timeOf(row); if (!Number.isFinite(time)) continue;
      addRow(buckets[Math.min(count - 1, Math.floor((time - start) / step))], row, defaultFlagged(row, options));
    }
    return {buckets, unit, step, multiplier, minTime, maxTime, start, end: start + count * step};
  }

  const instances = new WeakMap();
  let serial = 0;
  function destroy(host) {
    const previous = instances.get(host);
    if (previous) { previous.abort.abort(); previous.tooltip.remove(); instances.delete(host); }
    host.replaceChildren();
  }
  function element(tag, className, text) {
    const node = document.createElement(tag); if (className) node.className = className; if (text != null) node.textContent = text; return node;
  }
  function svgElement(tag, attributes = {}) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
    return node;
  }
  function svgText(svg, x, y, text, anchor = "start", className = "log-chart-label") {
    const node = svgElement("text", {x, y, "text-anchor": anchor, class: className}); node.textContent = text; svg.append(node); return node;
  }
  function measuredWidth(host) {
    const css = root.getComputedStyle(host);
    return Math.max(220, Math.floor(host.getBoundingClientRect().width - parseFloat(css.paddingLeft || 0) - parseFloat(css.paddingRight || 0)) || 640);
  }
  function setup(host, options, type) {
    destroy(host);
    const abort = new AbortController(), id = `log-chart-tooltip-${++serial}`;
    const tooltip = element("div", "log-chart-tooltip"); tooltip.id = id; tooltip.setAttribute("role", "tooltip"); tooltip.hidden = true;
    const body = element("div", "log-chart-tooltip-body"), actions = element("div", "log-chart-tooltip-actions");
    const close = element("button", "button secondary", "Close"), inspect = element("button", "button primary", "Inspect request");
    close.type = inspect.type = "button"; actions.append(inspect, close); tooltip.append(body, actions); host.append(tooltip);
    const state = {abort, tooltip, body, actions, inspect, close, options, type, pinned: false, target: null, active: null};
    instances.set(host, state);
    const on = (target, event, fn) => target.addEventListener(event, fn, {signal: abort.signal});
    function hide(restoreFocus = false) {
      const target = state.target;
      if (target) target.removeAttribute("aria-describedby");
      tooltip.hidden = true; state.pinned = false; state.target = null; state.active = null;
      if (restoreFocus && target?.isConnected) target.focus({preventScroll: true});
    }
    state.hide = hide;
    on(close, "click", () => hide(true));
    on(inspect, "click", () => {
      const group = state.active; hide(); if (!group) return;
      if (type !== "scatter" && options.onSelect) options.onSelect(group);
      else if (group.count === 1 && options.onInspect) options.onInspect(group.examples[0].id);
    });
    on(document, "pointerdown", (event) => { if (state.pinned && !tooltip.contains(event.target) && !host.contains(event.target)) hide(); });
    on(document, "keydown", (event) => { if (event.key === "Escape" && !tooltip.hidden) { event.preventDefault(); hide(tooltip.contains(document.activeElement)); } });
    on(root, "resize", () => hide());
    document.addEventListener("scroll", (event) => { if (!tooltip.contains(event.target)) hide(); }, {capture: true, signal: abort.signal});
    return state;
  }
  function pair(parent, label, value) {
    const term = element("dt", "", label), description = element("dd", "", value); parent.append(term, description);
  }
  function fillTooltip(state, group) {
    const {body, options} = state; body.replaceChildren();
    const scatter = state.type === "scatter", single = scatter && group.count === 1;
    const title = scatter ? (single ? `${group.examples[0].method} ${group.examples[0].path}` : `${number(group.count)} requests`) : `${number(group.flagged)} review candidate${group.flagged === 1 ? "" : "s"}`;
    body.append(element("strong", "log-chart-tooltip-title", title));
    const details = element("dl", "log-chart-tooltip-values");
    if (!scatter) {
      pair(details, "When", `${dateTick(group.start, false)} ${dateTick(group.start, true)} – ${dateTick(group.end, false)} ${dateTick(group.end, true)} UTC`);
      if (state.type === "timeline") pair(details, "Who", `${group.account === "-" ? "Anonymous" : group.account} · ${group.source}`);
      else if (options.showAll) pair(details, "Other requests", number(group.count - group.flagged));
    } else {
      pair(details, "When", group.minTime === group.maxTime ? utc(group.minTime) : `${utc(group.minTime)} – ${utc(group.maxTime)}`);
      if (single) pair(details, "Who", `${group.examples[0].user === "-" ? "Anonymous" : group.examples[0].user} · ${group.examples[0].ip}`);
      else pair(details, "Candidates", `${number(group.flagged)} of ${number(group.count)}`);
      const low = group.rawCount ? shortNumber(group.minRaw) : score(group.minScore);
      const high = group.rawCount ? shortNumber(group.maxRaw) : score(group.maxScore);
      pair(details, group.rawCount ? "Anomaly score" : "Review score / 100", low === high ? low : `${low} – ${high}`);
    }
    body.append(details);
    state.inspect.textContent = scatter ? "Inspect request" : "View requests";
    state.inspect.hidden = scatter ? !(single && options.onInspect) : !(options.onSelect && (state.type === "timeline" || options.showAll ? group.count : group.flagged));
  }
  function positionTooltip(state, point) {
    const viewportWidth = root.innerWidth, viewportHeight = root.innerHeight;
    const bounds = state.tooltip.getBoundingClientRect(), margin = 10;
    let x = point.x + 14, y = point.y + 14;
    if (x + bounds.width > viewportWidth - margin) x = point.x - bounds.width - 14;
    if (y + bounds.height > viewportHeight - margin) y = point.y - bounds.height - 14;
    state.tooltip.style.left = `${Math.max(margin, Math.min(x, viewportWidth - bounds.width - margin))}px`;
    state.tooltip.style.top = `${Math.max(margin, Math.min(y, viewportHeight - bounds.height - margin))}px`;
  }
  function bindMarks(state, svg, groups) {
    const {signal} = state.abort;
    const markOf = (event) => event.target.closest?.("[data-chart-mark]");
    const pointOf = (event, target) => {
      if (event.clientX || event.clientY) return {x: event.clientX, y: event.clientY};
      const bounds = target.getBoundingClientRect(); return {x: bounds.left + bounds.width / 2, y: bounds.top + bounds.height / 2};
    };
    function show(target, event, pinned = false) {
      const group = groups[Number(target.dataset.chartMark)]; if (!group) return;
      if (state.target !== target || state.tooltip.hidden) {
        state.target?.removeAttribute("aria-describedby"); state.active = group; state.target = target; fillTooltip(state, group);
      }
      state.pinned = pinned; state.actions.hidden = !pinned;
      state.tooltip.hidden = false; state.tooltip.classList.toggle("pinned", pinned);
      state.tooltip.setAttribute("role", pinned ? "dialog" : "tooltip");
      if (pinned) state.tooltip.setAttribute("aria-label", "Chart details"); else state.tooltip.removeAttribute("aria-label");
      target.setAttribute("aria-describedby", state.tooltip.id);
      positionTooltip(state, pointOf(event, target));
    }
    svg.addEventListener("pointermove", (event) => { if (state.pinned || event.pointerType === "touch") return; const mark = markOf(event); if (mark) show(mark, event); else state.hide(); }, {signal});
    svg.addEventListener("pointerleave", () => { if (!state.pinned) state.hide(); }, {signal});
    svg.addEventListener("focusin", (event) => { const mark = markOf(event); if (mark && !state.pinned) show(mark, event); }, {signal});
    svg.addEventListener("focusout", (event) => { if (!state.pinned && !svg.contains(event.relatedTarget)) state.hide(); }, {signal});
    svg.addEventListener("click", (event) => { const mark = markOf(event); if (mark) { for (const node of svg.querySelectorAll("[data-chart-mark]")) node.setAttribute("tabindex", node === mark ? "0" : "-1"); show(mark, event, true); } else state.hide(); }, {signal});
    svg.addEventListener("keydown", (event) => {
      const mark = markOf(event); if (!mark) return;
      if (["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) {
        event.preventDefault(); const marks = Array.from(svg.querySelectorAll("[data-chart-mark]")), current = marks.indexOf(mark);
        const next = event.key === "Home" ? 0 : event.key === "End" ? marks.length - 1 : Math.max(0, Math.min(marks.length - 1, current + (["ArrowLeft", "ArrowUp"].includes(event.key) ? -1 : 1)));
        state.hide(); mark.setAttribute("tabindex", "-1"); marks[next].setAttribute("tabindex", "0"); marks[next].focus({preventScroll: true}); return;
      }
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); show(mark, event, true); (state.inspect.hidden ? state.close : state.inspect).focus({preventScroll: true}); }
    }, {signal});
  }
  function legend(host, type) {
    const node = element("div", "log-chart-legend");
    for (const [className, label] of [["total", "Below cutoff"], ["flagged", type === "activity" ? "Review candidates" : "Contains review candidates"]]) {
      const item = element("span"); item.append(element("i", `log-chart-swatch ${className}`), document.createTextNode(label)); node.append(item);
    }
    host.append(node);
  }
  function empty(host) { host.append(element("p", "chart-empty", "No requests match the current filters.")); }
  function renderScatter(host, options = {}) {
    const state = setup(host, options, "scatter"), rows = options.rows || [], width = measuredWidth(host), height = 304;
    const left = width < 400 ? 57 : 72, right = 14, top = 35, bottom = 44, plotWidth = width - left - right, plotHeight = height - top - bottom;
    const data = aggregateScatter(rows, {...options, width: plotWidth, height: plotHeight});
    if (!data.groups.length) { empty(host); return {caption: "No requests match the current filters.", axisLabel: "Review score"}; }
    const axisLabel = data.allRaw ? `Model score${data.symlog ? " (symlog scale)" : ""}` : "Review score / 100";
    const svg = svgElement("svg", {viewBox: `0 0 ${width} ${height}`, class: "log-chart-svg log-scatter-svg", role: "group", "aria-label": `Requests by time and ${axisLabel}. Focus a point, then use arrow keys to move between groups. Activate for request details.`});
    svgText(svg, left, 17, axisLabel);
    for (let index = 0; index <= 4; index++) {
      const y = top + plotHeight * (1 - index / 4), value = data.inverse(data.yMin + (data.yMax - data.yMin) * index / 4);
      svg.append(svgElement("line", {x1: left, x2: width - right, y1: y, y2: y, class: "log-chart-grid"}));
      svgText(svg, left - 9, y + 4, shortNumber(value), "end");
    }
    const tickCount = width < 450 ? 2 : 4;
    for (let index = 0; index <= tickCount; index++) {
      const time = data.xMin + (data.xMax - data.xMin) * index / tickCount;
      svgText(svg, left + plotWidth * index / tickCount, height - 21, dateTick(time, data.xMax - data.xMin < DAY), index === 0 ? "start" : index === tickCount ? "end" : "middle");
    }
    svgText(svg, width - right, height - 3, "Time (UTC)", "end");
    if (!data.allRaw && Number.isFinite(options.threshold)) {
      const y = top + plotHeight * (1 - options.threshold);
      svg.append(svgElement("line", {x1: left, x2: width - right, y1: y, y2: y, class: "log-chart-cutoff"}));
    }
    data.groups.forEach((group, index) => {
      const label = `${number(group.count)} request${group.count === 1 ? "" : "s"}, ${number(group.flagged)} review candidates, ${utc(group.minTime)}. ${group.count === 1 ? "Activate for request details." : "Activate for grouped request details."}`;
      const mark = svgElement("g", {transform: `translate(${left + group.x} ${top + group.y})`, class: "log-chart-mark", tabindex: index === 0 ? "0" : "-1", role: "button", "data-chart-mark": index, "aria-label": label});
      mark.append(svgElement("circle", {r: Math.min(7, 3.5 + Math.log2(group.count + 1) * .55), class: `log-chart-point ${group.flagged ? "flagged" : ""}`}));
      mark.append(svgElement("circle", {r: 9, class: "log-chart-point-hit", "aria-hidden": "true"}));
      svg.append(mark);
    });
    host.append(svg); legend(host, "scatter"); bindMarks(state, svg, data.groups);
    const omitted = rows.length - data.valid;
    return {axisLabel, caption: `${number(data.valid)} requests across ${number(data.groups.length)} plotted ${data.groups.length === 1 ? "group" : "groups"}. Nearby points are combined; larger dots represent more requests. ${data.allRaw ? "Vertical position uses the actual model score" + (data.symlog ? " on a symmetric logarithmic scale" : "") + "." : "Vertical position uses the review score; the dashed line is the review cutoff."}${omitted ? ` ${number(omitted)} requests lacked a valid time or score.` : ""} Hover, focus, or tap a dot for details.`};
  }
  function renderActivity(host, options = {}) {
    const state = setup(host, options, "activity"), width = measuredWidth(host), height = 232;
    const left = 50, right = 13, top = 26, bottom = 43, plotWidth = width - left - right, plotHeight = height - top - bottom;
    const data = aggregateActivity(options.rows || [], {...options, width: plotWidth});
    if (!data.buckets.length) { empty(host); return {caption: "No requests match the current filters.", axisLabel: "Requests"}; }
    let highest = 1; for (const bucket of data.buckets) highest = Math.max(highest, options.showAll ? bucket.count : bucket.flagged);
    const rough = highest / 4, magnitude = Math.pow(10, Math.floor(Math.log10(rough))), tickStep = Math.max(1, Math.ceil(rough / magnitude) * magnitude), max = tickStep * 4;
    const svg = svgElement("svg", {viewBox: `0 0 ${width} ${height}`, class: "log-chart-svg log-activity-svg", role: "group", "aria-label": "Request counts over time. Focus the chart and use arrow keys to move between time buckets. Activate for exact counts."});
    svgText(svg, left, 15, options.showAll ? "Requests" : "Candidates");
    for (let index = 0; index <= 4; index++) {
      const y = top + plotHeight * (1 - index / 4);
      svg.append(svgElement("line", {x1: left, x2: width - right, y1: y, y2: y, class: "log-chart-grid"}));
      svgText(svg, left - 8, y + 4, shortNumber(max * index / 4), "end");
    }
    const slot = plotWidth / data.buckets.length;
    data.buckets.forEach((bucket, index) => {
      const x = left + slot * index, barWidth = Math.max(2, Math.min(slot * .68, 44)), barX = x + (slot - barWidth) / 2;
      const totalHeight = (options.showAll ? bucket.count : bucket.flagged) / max * plotHeight, flaggedHeight = bucket.flagged / max * plotHeight;
      const belowHeight = options.showAll ? (bucket.count - bucket.flagged) / max * plotHeight : 0;
      svg.append(svgElement("rect", {x: barX, y: top + plotHeight - belowHeight, width: barWidth, height: belowHeight, class: "log-chart-bar total"}));
      svg.append(svgElement("rect", {x: barX, y: top + plotHeight - totalHeight, width: barWidth, height: flaggedHeight, class: "log-chart-bar flagged"}));
      svg.append(svgElement("rect", {x, y: top, width: slot, height: plotHeight, tabindex: index === 0 ? "0" : "-1", role: "button", class: "log-chart-bucket-hit", "data-chart-mark": index, "aria-label": `${utc(bucket.start)} to ${utc(bucket.end)}: ${number(bucket.count)} requests, ${number(bucket.flagged)} review candidates, ${number(bucket.users.size)} accounts. Activate for details.`}));
    });
    const ticks = width < 450 ? 2 : 4;
    for (let index = 0; index <= ticks; index++) {
      const time = data.start + (data.end - data.start) * index / ticks;
      svgText(svg, left + plotWidth * index / ticks, height - 20, dateTick(time, data.end - data.start <= DAY), index === 0 ? "start" : index === ticks ? "end" : "middle");
    }
    svgText(svg, width - right, height - 3, "Time (UTC)", "end");
    host.append(svg); if (options.showAll) legend(host, "activity"); bindMarks(state, svg, data.buckets);
    const interval = `${data.multiplier === 1 ? "" : data.multiplier + "-"}${data.unit === DAY ? "day" : "hour"}`;
    return {axisLabel: "Requests", caption: `${options.showAll ? "All requests" : "Review candidates"} per ${interval}. Select a bar to view its requests.${!data.buckets.some((bucket) => bucket.flagged) ? " No candidates at this cutoff." : ""}`};
  }
  function renderTimeline(host, options = {}) {
    const state = setup(host, options, "timeline"), rows = options.rows || [];
    const width = measuredWidth(host), left = width < 500 ? 140 : 210, right = 14;
    const plotWidth = Math.max(60, width - left - right);
    const bins = aggregateActivity(rows, {width: plotWidth, isFlagged: options.isFlagged});
    const actors = new Map();
    for (const row of rows) {
      if (!defaultFlagged(row, options) || !Number.isFinite(timeOf(row))) continue;
      const key = JSON.stringify([row.user, row.ip]);
      if (!actors.has(key)) actors.set(key, {account: row.user, source: row.ip, count: 0});
      actors.get(key).count++;
    }
    const ranked = [...actors.values()].sort((a, b) => b.count - a.count || a.account.localeCompare(b.account) || a.source.localeCompare(b.source));
    const visible = ranked.slice(0, 8), groups = new Map();
    if (!visible.length) {
      host.append(element("p", "chart-empty", "No candidates for the current filters and cutoff."));
      return {caption: "Lower the cutoff or clear filters to broaden the review."};
    }
    const lanes = new Map(visible.map((actor, index) => [JSON.stringify([actor.account, actor.source]), index]));
    for (const row of rows) {
      if (!defaultFlagged(row, options) || !Number.isFinite(timeOf(row))) continue;
      const lane = lanes.get(JSON.stringify([row.user, row.ip])); if (lane === undefined) continue;
      const bucket = Math.floor((timeOf(row) - bins.start) / bins.step), key = `${lane}:${bucket}`;
      if (!groups.has(key)) groups.set(key, {...newGroup(), lane, bucket, account: row.user, source: row.ip, start: bins.start + bucket * bins.step, end: bins.start + (bucket + 1) * bins.step});
      addRow(groups.get(key), row, true);
    }
    const top = 12, rowHeight = 48, bottom = 40, height = top + visible.length * rowHeight + bottom;
    const slot = plotWidth / bins.buckets.length;
    const svg = svgElement("svg", {viewBox: `0 0 ${width} ${height}`, class: "log-chart-svg", role: "group", "aria-label": "Candidate requests by account and source IP over time. Use arrow keys between cells, then activate to view requests."});
    function clipped(value, max) { return value.length > max ? value.slice(0, max - 1) + "…" : value; }
    visible.forEach((actor, lane) => {
      const y = top + lane * rowHeight;
      const label = svgText(svg, 0, y + 19, clipped(actor.account === "-" ? "Anonymous" : actor.account, width < 500 ? 17 : 26));
      const title = svgElement("title"); title.textContent = `${actor.account} · ${actor.source} · ${number(actor.count)} candidates`; label.append(title);
      svgText(svg, 0, y + 35, clipped(actor.source, width < 500 ? 20 : 30), "start", "log-chart-label timeline-ip");
      svg.append(svgElement("line", {x1: left, x2: width - right, y1: y + rowHeight, y2: y + rowHeight, class: "log-chart-grid"}));
    });
    const ordered = [...groups.values()].sort((a, b) => a.lane - b.lane || a.bucket - b.bucket);
    ordered.forEach((group, index) => {
      const x = left + group.bucket * slot, y = top + group.lane * rowHeight;
      const mark = svgElement("g", {class: "log-chart-mark", tabindex: index === 0 ? 0 : -1, role: "button", "data-chart-mark": index, "aria-label": `${group.account === "-" ? "Anonymous" : group.account}, ${group.source}, ${number(group.count)} candidates, ${utc(group.start)} to ${utc(group.end)}. Activate to view requests.`});
      mark.append(svgElement("rect", {x: x + 1, y: y + 8, width: Math.max(2, slot - 2), height: 32, class: "timeline-cell"}));
      if (slot >= 30) svgText(mark, x + slot / 2, y + 29, number(group.count), "middle", "timeline-count");
      svg.append(mark);
    });
    const ticks = plotWidth < 350 ? 2 : 4;
    for (let index = 0; index <= ticks; index++) {
      const time = bins.start + (bins.end - bins.start) * index / ticks;
      svgText(svg, left + plotWidth * index / ticks, height - 19, dateTick(time, bins.end - bins.start <= DAY), index === 0 ? "start" : index === ticks ? "end" : "middle");
    }
    svgText(svg, width - right, height - 2, "Time (UTC)", "end");
    host.append(svg); bindMarks(state, svg, ordered);
    return {caption: `${visible.length < ranked.length ? `Top ${visible.length} of ${number(ranked.length)} account / IP pairs by candidate count. ` : ""}Select a cell to review that account’s requests in that period. Blank periods have no candidates.`};
  }
  const api = {renderScatter, renderActivity, renderTimeline, destroy, aggregateScatter, aggregateActivity};
  root.LogCharts = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
