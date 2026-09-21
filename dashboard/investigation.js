(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.LogInvestigation = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const MINUTE = 60 * 1000;

  function timeOf(row) {
    return Number.isFinite(row.time) ? row.time : Date.parse(row.timestamp);
  }

  function orderedRows(rows) {
    return rows.slice().sort((a, b) => timeOf(a) - timeOf(b) ||
      (Number.isFinite(a.id) && Number.isFinite(b.id) ? a.id - b.id : String(a.id).localeCompare(String(b.id))));
  }

  function facts(rows) {
    const sources = new Set(), targets = new Set(), methods = new Set(), statuses = new Map();
    for (const row of rows) {
      sources.add(row.ip);
      targets.add(row.path);
      methods.add(row.method);
      statuses.set(row.status, (statuses.get(row.status) || 0) + 1);
    }
    return {
      requestCount: rows.length,
      sources: [...sources],
      targets: [...targets],
      methods: [...methods],
      statuses: [...statuses].map(([status, count]) => ({status, count})),
    };
  }

  // Episodes describe adjacent observations, without assigning attack or login outcomes.
  function buildEpisodes(rows, candidateIds = []) {
    const candidates = candidateIds instanceof Set ? candidateIds : new Set(candidateIds);
    const episodes = [];
    let episode;
    for (const row of orderedRows(rows)) {
      const time = timeOf(row);
      if (!Number.isFinite(time)) continue;
      if (!episode || episode.method !== row.method || episode.path !== row.path || time - episode.end > 5 * MINUTE) {
        episode = {
          id: `episode-${row.id}`,
          label: `${row.method || "—"} ${row.path || "—"}`,
          method: row.method,
          path: row.path,
          start: time,
          end: time,
          rows: [],
          candidateIds: [],
        };
        episodes.push(episode);
      }
      episode.rows.push(row);
      episode.end = time;
      if (candidates.has(row.id)) episode.candidateIds.push(row.id);
    }
    for (const item of episodes) {
      item.candidateCount = item.candidateIds.length;
      item.contextCount = item.rows.length - item.candidateCount;
      item.summary = facts(item.rows);
    }
    return episodes;
  }

  function lowerBound(rows, time) {
    let low = 0, high = rows.length;
    while (low < high) {
      const middle = low + Math.floor((high - low) / 2);
      if (timeOf(rows[middle]) < time) low = middle + 1;
      else high = middle;
    }
    return low;
  }

  function timeSlices(rows, targetBars = 1) {
    let start = Infinity, latest = -Infinity;
    for (const row of rows) {
      const time = timeOf(row);
      if (!Number.isFinite(time)) continue;
      start = Math.min(start, time);
      latest = Math.max(latest, time);
    }
    if (!Number.isFinite(start)) return null;
    const count = latest === start ? 1 : Math.max(1, Math.min(240, Math.round(Number(targetBars) || 1)));
    const step = Math.max(1, latest - start + 1) / count;
    return {start, end: start + count * step, count, step};
  }

  function buildInvestigations(rows, options = {}) {
    const isCandidate = typeof options.isCandidate === "function" ? options.isCandidate : () => false;
    const contextMs = 5 * MINUTE;
    const ordered = orderedRows(rows);
    const slices = options.slices || timeSlices(ordered, options.targetBars);
    if (!slices) return [];
    const bySource = new Map(), byAccount = new Map(), groups = new Map();
    const add = (index, key, row) => {
      if (!key || key === "-") return;
      if (!index.has(key)) index.set(key, []);
      index.get(key).push(row);
    };

    for (const row of ordered) {
      const time = timeOf(row);
      if (!Number.isFinite(time)) continue;
      add(bySource, row.ip, row);
      add(byAccount, row.user, row);
      if (!isCandidate(row)) continue;
      const index = Math.min(slices.count - 1, Math.max(0, Math.floor((time - slices.start) / slices.step)));
      if (!groups.has(index)) groups.set(index, []);
      groups.get(index).push(row);
    }

    const investigations = [];
    for (const [index, candidates] of groups) {
      const relatedById = new Map(candidates.map((row) => [row.id, row]));
      for (const candidate of candidates) {
        const contextStart = timeOf(candidate) - contextMs, contextEnd = timeOf(candidate) + contextMs;
        for (const [records, key] of [[bySource, candidate.ip], [byAccount, candidate.user]]) {
          const indexed = records.get(key) || [];
          for (let position = lowerBound(indexed, contextStart); position < indexed.length; position++) {
            const row = indexed[position];
            if (timeOf(row) > contextEnd) break;
            if (!isCandidate(row)) relatedById.set(row.id, row);
          }
        }
      }
      const related = orderedRows([...relatedById.values()]);
      const candidateIds = candidates.map((row) => row.id);
      const summary = facts(candidates);
      investigations.push({
        id: `investigation-${candidates[0].id}`,
        source: candidates[0].ip,
        sources: summary.sources,
        start: timeOf(candidates[0]),
        end: timeOf(candidates[candidates.length - 1]),
        rows: related,
        candidateIds,
        episodes: buildEpisodes(related, candidateIds),
        summary: {...summary, candidateCount: candidateIds.length, contextCount: related.length - candidateIds.length},
        contextStart: related.length ? timeOf(related[0]) : timeOf(candidates[0]),
        contextEnd: related.length ? timeOf(related[related.length - 1]) : timeOf(candidates[candidates.length - 1]),
        grouping: {contextMs, linkedBy: "time slice", sliceStart: slices.start + index * slices.step, sliceEnd: slices.start + (index + 1) * slices.step},
      });
    }
    return investigations.sort((a, b) => a.start - b.start || a.id.localeCompare(b.id));
  }

  return {buildInvestigations, buildEpisodes, timeSlices};
});
