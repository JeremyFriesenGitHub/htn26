(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.LogModelLens = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const SVG_NS = "http://www.w3.org/2000/svg";
  const MODEL_INFO = {
    rules: {
      name: "Request rules", scoreLabel: "Rule score", unit: " / 100",
      meaning: "Higher scores mean more weighted request indicators fired.",
      method: "A fixed set of request rules adds weighted indicators, starting at 4 and capped at 99.",
      unavailable: "There is no learned baseline for this model.",
    },
    gmm: {
      name: "Gaussian mixture", scoreLabel: "Negative log density", unit: "",
      meaning: "Higher scores mean lower density in the model’s learned behavior distribution.",
      method: "The Gaussian mixture scores standardized request features. The native score is negative log density; it may be negative, and its scale is specific to this model.",
      unavailable: "Cluster memberships and feature contributions are not available in these results.",
    },
    ae: {
      name: "Autoencoder", scoreLabel: "Weighted reconstruction error", unit: "",
      meaning: "Higher scores mean the model had more difficulty reconstructing this request’s features.",
      method: "Squared reconstruction errors are divided by each feature’s average training error, averaged across features, then averaged across the saved autoencoder ensemble.",
      unavailable: "Feature-level reconstruction errors are not available in these results.",
    },
    hybrid: {
      name: "GMM + LLM review", scoreLabel: "GMM negative log density", unit: "",
      meaning: "The GMM measures unusual behavior; the LLM reviews a shortlist separately.",
      method: "Detector scores are unchanged GMM negative log densities. The LLM’s flagged or cleared decisions are separate interpretations, not a second independent detector or a probability of attack.",
      unavailable: "Cluster memberships and feature contributions are not available in these results.",
    },
  };

  function describeModel(run = {}) {
    return {...(MODEL_INFO[run.model] || {
      name: run.model_name || run.model || "Detector", scoreLabel: "Native anomaly score", unit: "",
      meaning: "This panel shows the scores supplied by this detector.",
      method: "Compare scores within this model. Native scores from different detectors do not share a common scale.",
      unavailable: "No additional model explanation was supplied.",
    }), model: run.model};
  }

  function el(doc, tag, className, text) {
    const node = doc.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function svgEl(doc, tag, attributes = {}, text) {
    const node = doc.createElementNS(SVG_NS, tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
    if (text != null) node.textContent = text;
    return node;
  }

  function exact(value) {
    return Number.isFinite(value) ? String(value) : "Not supplied";
  }

  function ruleScore(row) {
    return Number.isFinite(row.score) ? Number((row.score * 100).toFixed(6)) : NaN;
  }

  function tick(value) {
    if (!Number.isFinite(value)) return "—";
    if ((Math.abs(value) > 0 && Math.abs(value) < 0.001) || Math.abs(value) >= 10000) return value.toExponential(1);
    return Number(value.toPrecision(4)).toLocaleString("en-US", {maximumFractionDigits: 6});
  }

  function percentile(value) {
    if (!Number.isFinite(value)) return "Not supplied";
    if (value === 1) return "100";
    const number = value * 100;
    const label = Number(number.toFixed(number >= 99.99 ? 6 : number >= 99 ? 4 : 2));
    return number < 100 && label >= 100 ? "99.999999+" : String(label);
  }

  function extent(rows, getValue) {
    let min = Infinity, max = -Infinity, count = 0;
    for (const row of rows) {
      const value = getValue(row);
      if (!Number.isFinite(value)) continue;
      min = Math.min(min, value); max = Math.max(max, value); count++;
    }
    return {min, max, count};
  }

  function rangeText(range, format = exact, unit = "") {
    if (!range.count) return "Not supplied";
    return (range.min === range.max ? format(range.min) : `${format(range.min)} – ${format(range.max)}`) + unit;
  }

  function metric(doc, list, label, value, note) {
    const item = el(doc, "div", "lens-metric");
    item.append(el(doc, "dt", "", label), el(doc, "dd", "", value));
    if (note) item.append(el(doc, "dd", "lens-metric-note", note));
    list.append(item);
  }

  function verdict(rows, cutoff, run) {
    let scored = 0, candidates = 0;
    for (const row of rows) if (Number.isFinite(row.score)) {
      scored++; if (row.score >= cutoff) candidates++;
    }
    const kind = run.detector_score_kind || run.score_kind;
    const label = run.model === "rules" ? `rule score ${percentile(cutoff)}` : `${percentile(cutoff)} ${kind === "calibrated" ? "training" : "upload"} percentile`;
    if (!scored) return {text: "Not scored by this model", candidates, scored};
    if (!Number.isFinite(cutoff)) return {text: `${scored.toLocaleString()} scored · no cutoff supplied`, candidates, scored};
    if (rows.length === 1) return {text: `${candidates ? "Meets review cutoff" : "Below review cutoff"} · ${label}`, candidates, scored};
    return {
      text: `${candidates.toLocaleString()} of ${scored.toLocaleString()} scored events meet cutoff · ${label}` +
        (scored < rows.length ? ` · ${(rows.length - scored).toLocaleString()} not scored` : ""),
      candidates, scored,
    };
  }

  function renderPlot(doc, host, rows, selected, info, cutoff, onSelectEvent) {
    const getValue = info.model === "rules" ? ruleScore : (row) => row.raw_score;
    const limits = extent(rows, getValue);
    if (!limits.count) return;

    const width = 560, left = 34, right = 544, bottom = 122, countBins = 28;
    let smallest = Infinity;
    for (const row of rows) {
      const value = getValue(row);
      if (Number.isFinite(value) && value !== 0) smallest = Math.min(smallest, Math.abs(value));
    }
    const largest = Math.max(Math.abs(limits.min), Math.abs(limits.max));
    const logScale = info.model !== "rules" && Number.isFinite(smallest) && largest / smallest > 100;
    const scaleBase = logScale ? Math.max(Number.MIN_VALUE, largest / 1000) : 1;
    const transform = logScale ? (value) => Math.sign(value) * Math.log1p(Math.abs(value) / scaleBase) : (value) => value;
    const inverse = logScale ? (value) => Math.sign(value) * Math.expm1(Math.abs(value)) * scaleBase : (value) => value;
    let low = info.model === "rules" ? 0 : transform(limits.min), high = info.model === "rules" ? 100 : transform(limits.max);
    if (low === high) { const pad = Math.max(Math.abs(low) * 0.03, 1); low -= pad; high += pad; }
    const x = (value) => left + (transform(value) - low) / (high - low) * (right - left);
    const bins = Array.from({length: countBins}, () => 0);
    for (const row of rows) {
      const value = getValue(row);
      if (!Number.isFinite(value)) continue;
      bins[Math.max(0, Math.min(countBins - 1, Math.floor((transform(value) - low) / (high - low) * countBins)))]++;
    }
    let maxCount = 1;
    for (const count of bins) maxCount = Math.max(maxCount, count);
    const figure = el(doc, "figure", "lens-plot");
    const chart = svgEl(doc, "svg", {viewBox: `0 0 ${width} 164`, role: "group", "aria-label": `${info.scoreLabel} distribution for this upload; selected events marked by dots`});
    chart.append(svgEl(doc, "text", {x: left, y: 13, class: "lens-axis"}, "Selected events"));
    chart.append(svgEl(doc, "text", {x: left, y: 60, class: "lens-axis"}, `${maxCount.toLocaleString()} requests`));
    const barWidth = (right - left) / countBins;
    bins.forEach((count, index) => {
      if (!count) return;
      const height = count / maxCount * 54;
      const bar = svgEl(doc, "rect", {x: left + index * barWidth + 1, y: bottom - height, width: barWidth - 2, height, class: "lens-bin", fill: "#c9c8c3"});
      bar.append(svgEl(doc, "title", {}, `${count.toLocaleString()} requests`)); chart.append(bar);
    });
    const chosen = selected.filter((row) => Number.isFinite(getValue(row)));
    const markerLimit = 60, markerCount = Math.min(chosen.length, markerLimit), markerNodes = [];
    for (let index = 0; index < markerCount; index++) {
      const row = chosen[markerCount === chosen.length ? index : Math.round(index * (chosen.length - 1) / (markerCount - 1))];
      const value = getValue(row), position = x(value), y = 29 + (index % 3) * 10;
      const actionable = typeof onSelectEvent === "function";
      const candidate = Number.isFinite(row.score) && Number.isFinite(cutoff) && row.score >= cutoff;
      const label = `Line ${row.id}: ${info.scoreLabel} ${exact(value)}${info.unit}`;
      const marker = svgEl(doc, "g", {class: `lens-marker${candidate ? " is-candidate" : ""}`, "aria-label": label, ...(actionable ? {role: "button", tabindex: index === 0 ? "0" : "-1"} : {})});
      markerNodes.push(marker);
      marker.append(svgEl(doc, "title", {}, label));
      marker.append(svgEl(doc, "line", {x1: position, y1: y + 4, x2: position, y2: bottom, stroke: candidate ? "#a9342e" : "#414440", "stroke-opacity": "0.24"}));
      marker.append(svgEl(doc, "circle", {cx: position, cy: y, r: 4, fill: candidate ? "#a9342e" : "#414440", stroke: "#fff", "stroke-width": "1"}));
      if (actionable) {
        marker.addEventListener("click", () => onSelectEvent(row.id));
        marker.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelectEvent(row.id); }
          let next;
          if (event.key === "ArrowRight" || event.key === "ArrowDown") next = Math.min(markerCount - 1, index + 1);
          if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = Math.max(0, index - 1);
          if (event.key === "Home") next = 0;
          if (event.key === "End") next = markerCount - 1;
          if (next != null) {
            event.preventDefault();
            markerNodes.forEach((node, position) => node.setAttribute("tabindex", position === next ? "0" : "-1"));
            markerNodes[next].focus();
          }
        });
      }
      chart.append(marker);
    }
    chart.append(svgEl(doc, "line", {x1: left, y1: bottom, x2: right, y2: bottom, stroke: "#b8bbb5"}));
    for (const [fraction, anchor] of [[0, "start"], [0.5, "middle"], [1, "end"]]) {
      chart.append(svgEl(doc, "text", {x: left + fraction * (right - left), y: 141, "text-anchor": anchor, class: "lens-axis"}, tick(inverse(low + fraction * (high - low)))));
    }
    chart.append(svgEl(doc, "text", {x: (left + right) / 2, y: 159, "text-anchor": "middle", class: "lens-axis"}, `${info.scoreLabel}${logScale ? " · symmetric log scale" : ""}`));
    figure.append(chart);
    let caption = `Gray bars: ${limits.count.toLocaleString()} scored requests in this upload. Dots: selected events; red meets the review cutoff.`;
    if (chosen.length > markerLimit) caption += ` Showing ${markerLimit} of ${chosen.length.toLocaleString()} selected events.`;
    figure.append(el(doc, "figcaption", "lens-note", caption)); host.append(figure);
  }

  function renderTriage(doc, host, selected) {
    const section = el(doc, "section", "lens-triage");
    section.append(el(doc, "h4", "", "LLM review"));
    if (selected.length === 1) {
      const row = selected[0], outcome = row.triage === "flagged" ? "Flagged for review" : row.triage === "cleared" ? "Cleared by the reviewer" : "Not reviewed";
      section.append(el(doc, "p", "", outcome));
      if (row.triage_reason && row.triage !== "unreviewed") {
        const details = el(doc, "details", "lens-detail");
        details.append(el(doc, "summary", "", "Reviewer’s interpretation"), el(doc, "p", "", String(row.triage_reason)));
        section.append(details);
      }
    } else {
      let flagged = 0, cleared = 0, unreviewed = 0;
      for (const row of selected) {
        if (row.triage === "flagged") flagged++;
        else if (row.triage === "cleared") cleared++;
        else unreviewed++;
      }
      section.append(el(doc, "p", "", `${flagged.toLocaleString()} flagged · ${cleared.toLocaleString()} cleared · ${unreviewed.toLocaleString()} not reviewed`));
    }
    host.append(section);
  }

  function renderSuppliedEvidence(doc, host, selected) {
    // Optional structured outputs are displayed verbatim, never inferred from a score.
    const supplied = selected.filter((row) => row.model_evidence != null || row.feature_values != null);
    if (!supplied.length) return false;
    const details = el(doc, "details", "lens-detail");
    details.append(el(doc, "summary", "", "Additional model outputs"));
    for (const row of supplied.slice(0, 4)) {
      details.append(el(doc, "h4", "", `Line ${row.id}`));
      const content = JSON.stringify({model_evidence: row.model_evidence, feature_values: row.feature_values}, null, 2);
      details.append(el(doc, "pre", "lens-supplied", content.length > 12000 ? content.slice(0, 12000) + "\n… output truncated" : content));
    }
    if (supplied.length > 4) details.append(el(doc, "p", "lens-note", "Select an individual event to inspect its complete model output."));
    host.append(details); return true;
  }

  function render(host, options = {}) {
    if (!host) return;
    const doc = host.ownerDocument;
    host.replaceChildren();
    const run = options.run;
    if (!run) {
      host.append(el(doc, "p", "lens-empty", "Run a model on this upload to inspect its evidence."));
      return;
    }
    const info = describeModel(run), selected = options.selectedRows || [], rows = options.allRows || run.rows || [];
    const cutoff = Number.isFinite(options.cutoff) ? options.cutoff : run.review_threshold;
    const lens = el(doc, "section", "model-lens");
    const heading = el(doc, "div", "lens-heading");
    heading.append(el(doc, "h3", "", info.name), el(doc, "p", "", info.meaning)); lens.append(heading);
    if (!selected.length) {
      lens.append(el(doc, "p", "lens-empty", "No events from this selection were scored by this model."));
      host.append(lens); return;
    }

    const result = verdict(selected, cutoff, run);
    lens.append(el(doc, "p", `lens-verdict${result.candidates ? " has-candidates" : ""}`, result.text));
    const metrics = el(doc, "dl", "lens-metrics");
    const native = extent(selected, run.model === "rules" ? ruleScore : (row) => row.raw_score);
    metric(doc, metrics, info.scoreLabel, rangeText(native, exact, info.unit), selected.length > 1 && native.count ? "Selected event range" : null);
    if (run.model !== "rules") {
      const baseline = extent(selected, (row) => row.baseline_percentile);
      const batch = extent(selected, (row) => row.batch_percentile);
      let above = 0;
      for (const row of selected) if (row.above_baseline === true) above++;
      metric(doc, metrics, "Training percentile", rangeText(baseline, percentile), above ? `${above === 1 && selected.length === 1 ? "Score exceeds" : `${above.toLocaleString()} scores exceed`} the observed training range` : null);
      if (batch.count) metric(doc, metrics, "Upload percentile", rangeText(batch, percentile));
    }
    lens.append(metrics);
    renderPlot(doc, lens, rows, selected, info, cutoff, options.onSelectEvent);
    if (run.model === "hybrid" || run.score_kind === "triaged") renderTriage(doc, lens, selected);
    const hasAdditional = renderSuppliedEvidence(doc, lens, selected);
    const details = el(doc, "details", "lens-detail");
    details.append(el(doc, "summary", "", "How to read this model"));
    details.append(el(doc, "p", "", info.method));
    details.append(el(doc, "p", "lens-note", "Scores and percentiles describe unusual behavior, not the probability of an attack. A review cutoff is an analyst filter, not a confirmed incident verdict."));
    if (!hasAdditional) details.append(el(doc, "p", "lens-note", info.unavailable));
    lens.append(details); host.append(lens);
  }

  return {describeModel, render};
});
