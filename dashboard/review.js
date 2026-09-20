(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.LogReview = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  function isCandidate(row, cutoff) {
    return Number.isFinite(row.score) && row.score >= cutoff;
  }

  function scopeRows(rows, filters = {}) {
    const query = String(filters.query || "").trim().toLowerCase();
    return rows.filter((row) =>
      (!filters.user || row.user === filters.user) &&
      (!filters.source || row.ip === filters.source) &&
      (filters.timeStart == null || row.time >= filters.timeStart) &&
      (filters.timeEnd == null || row.time < filters.timeEnd) &&
      (!query || [row.ip, row.user, row.path, row.method, row.status, ...(row.signals || row.reasons || [])]
        .join(" ").toLowerCase().includes(query)));
  }

  function sortRows(rows, descending = true) {
    const direction = descending ? -1 : 1;
    return rows.slice().sort((a, b) => {
      const aValue = Number.isFinite(a.raw_score) ? a.raw_score : a.score;
      const bValue = Number.isFinite(b.raw_score) ? b.raw_score : b.score;
      return direction * (aValue - bValue) || a.id - b.id;
    });
  }

  function numericScore(value) {
    if (!Number.isFinite(value)) return "—";
    if ((Math.abs(value) > 0 && Math.abs(value) < 0.001) || Math.abs(value) >= 100000) return value.toExponential(3);
    return value.toLocaleString("en-US", {minimumFractionDigits: 2, maximumFractionDigits: 6});
  }

  function priorityRows(rows, limit, descending = true) {
    const ranked = sortRows(rows, true);
    return sortRows(limit > 0 ? ranked.slice(0, limit) : ranked, descending);
  }

  function percentileLabel(row, kind) {
    if (!Number.isFinite(row.score)) return "Unavailable";
    const value = Math.max(0, Math.min(1, row.score)) * 100;
    if (kind === "heuristic") return numericScore(value) + " / 100";
    if (row.above_baseline || row.beyond_baseline || row.percentile_censored || (kind !== "percentile" && row.score >= 1)) {
      return "Above baseline range";
    }
    // Preserve distinctions in the tail instead of rounding 99.999 to 100.00.
    const digits = value >= 99.99 ? 5 : value >= 99 ? 3 : 2;
    let formatted = value.toFixed(digits);
    if (value < 100 && Number(formatted) >= 100) formatted = "99.99999+";
    return formatted + (kind === "percentile" ? " batch percentile" : " baseline percentile");
  }

  function scoreLabel(row, kind) {
    return Number.isFinite(row.raw_score) ? numericScore(row.raw_score)
      : kind === "heuristic" ? numericScore(row.score * 100) : percentileLabel(row, kind);
  }

  function accountCounts(rows) {
    const counts = new Map();
    for (const row of rows) counts.set(row.user, (counts.get(row.user) || 0) + 1);
    return [...counts].sort(([a], [b]) => a.localeCompare(b));
  }

  // Group evidence by actor and elapsed time, without assigning incident labels.
  function eventSequences(rows) {
    const ordered = rows.slice().sort((a, b) => a.time - b.time || a.id - b.id);
    const active = new Map(), sequences = [];
    for (const row of ordered) {
      const key = JSON.stringify([row.user, row.ip]);
      let sequence = active.get(key);
      if (!sequence || row.time - sequence.end > 30 * 60 * 1000) {
        sequence = {id: row.id, account: row.user, source: row.ip, start: row.time, end: row.time, rows: [], reasons: new Set()};
        sequences.push(sequence); active.set(key, sequence);
      }
      sequence.rows.push(row); sequence.end = row.time;
      for (const reason of row.reasons || []) sequence.reasons.add(reason);
    }
    return sequences;
  }

  return {isCandidate, scopeRows, sortRows, priorityRows, eventSequences, numericScore, percentileLabel, scoreLabel, accountCounts};
});
