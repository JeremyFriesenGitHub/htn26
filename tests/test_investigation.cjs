const test = require("node:test");
const assert = require("node:assert/strict");
const {buildInvestigations, timeSlices} = require("../dashboard/investigation.js");
const {aggregateActivity} = require("../dashboard/charts.js");

const origin = Date.parse("2026-09-15T10:00:00Z");
const request = (id, minute, user, ip, candidate = true) => ({
  id, time: origin + minute * 60_000, user, ip, method: "GET", path: "/dashboard",
  status: 200, candidate,
});

test("time slices determine which candidates become one investigation", () => {
  const rows = [
    request(1, 0, "alice", "10.0.0.1"),
    request(2, 2, "charlie", "10.0.0.1", false),
    request(3, 4, "bob", "10.0.0.1"),
    request(4, 5, "alice", "10.0.0.2"),
    request(5, 40, "bob", "10.0.0.1"),
    request(6, 6, "erin", "10.0.0.3"),
  ];
  const isCandidate = (row) => row.candidate;
  const groups = buildInvestigations(rows, {isCandidate, targetBars: 2});
  assert.deepEqual(groups.map((group) => group.candidateIds), [
    [1, 3, 4, 6],
    [5],
  ]);
  assert.deepEqual(groups[0].rows.map((row) => row.id), [1, 2, 3, 4, 6]);
  assert.deepEqual(groups[0].sources, ["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
  assert.equal(groups[0].grouping.linkedBy, "time slice");
  assert.deepEqual(buildInvestigations(rows, {isCandidate, targetBars: 1}).map((group) => group.candidateIds), [[1, 3, 4, 6, 5]]);
  assert.equal(buildInvestigations(rows, {isCandidate, targetBars: 240}).length, 5);

  const slices = timeSlices(rows, 2);
  const filteredChart = aggregateActivity([rows[0]], {targetBars: slices.count, domainStart: slices.start, domainEnd: slices.end});
  assert.equal(filteredChart.buckets.length, 2);
  assert.deepEqual(filteredChart.buckets.map((bucket) => bucket.count), [1, 0]);
});
