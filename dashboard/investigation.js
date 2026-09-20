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

  function accountOf(row) {
    return row.user == null || row.user === "" || row.user === "-" ? "-" : String(row.user);
  }

  function actorKey(row) {
    const account = accountOf(row);
    return JSON.stringify(account === "-" ? ["source", row.ip] : ["account", account]);
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

  function buildInvestigations(rows, options = {}) {
    const isCandidate = typeof options.isCandidate === "function" ? options.isCandidate : () => false;
    const gapMs = Number.isFinite(options.gapMs) && options.gapMs >= 0 ? options.gapMs : 30 * MINUTE;
    const contextMs = 5 * MINUTE;
    const actors = new Map();

    // Keep references to the original records so every visible event remains traceable.
    for (const row of orderedRows(rows)) {
      if (!Number.isFinite(timeOf(row))) continue;
      const key = actorKey(row);
      let actor = actors.get(key);
      if (!actor) {
        actor = {rows: [], groups: []};
        actors.set(key, actor);
      }
      actor.rows.push(row);
      if (!isCandidate(row)) continue;
      let group = actor.groups[actor.groups.length - 1];
      if (!group || timeOf(row) - group.end > gapMs) {
        group = {id: `investigation-${row.id}`, account: accountOf(row), start: timeOf(row), end: timeOf(row), candidates: []};
        actor.groups.push(group);
      }
      group.candidates.push(row);
      group.end = timeOf(row);
    }

    const investigations = [];
    for (const actor of actors.values()) {
      for (const group of actor.groups) {
        const contextStart = group.start - contextMs, contextEnd = group.end + contextMs;
        const related = [];
        for (let index = lowerBound(actor.rows, contextStart); index < actor.rows.length; index++) {
          const row = actor.rows[index];
          if (timeOf(row) > contextEnd) break;
          related.push(row);
        }
        const candidateIds = group.candidates.map((row) => row.id);
        const summary = facts(group.candidates);
        investigations.push({
          id: group.id,
          account: group.account,
          source: summary.sources[0] || "",
          sources: summary.sources,
          start: group.start,
          end: group.end,
          rows: related,
          candidateIds,
          episodes: buildEpisodes(related, candidateIds),
          summary: {...summary, candidateCount: candidateIds.length, contextCount: related.length - candidateIds.length},
          contextStart: related.length ? timeOf(related[0]) : group.start,
          contextEnd: related.length ? timeOf(related[related.length - 1]) : group.end,
          grouping: {gapMs, contextMs, linkedBy: group.account === "-" ? "source IP" : "account"},
        });
      }
    }
    return investigations.sort((a, b) => a.start - b.start || a.id.localeCompare(b.id));
  }

  return {buildInvestigations, buildEpisodes};
});
