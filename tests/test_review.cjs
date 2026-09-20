const test = require("node:test");
const assert = require("node:assert/strict");
const {
  isCandidate,
  scopeRows,
  sortRows,
  priorityRows,
  percentileLabel,
  scoreLabel,
  accountCounts,
} = require("../dashboard/review.js");

const request = (id, fields = {}) => ({
  id,
  user: "alice",
  ip: "10.0.0.1",
  path: "/reports",
  method: "GET",
  status: 200,
  score: 0.98,
  ...fields,
});

test("account selection is exact, including accounts with similar names", () => {
  const rows = [
    request(1),
    request(2, { user: "alice-admin" }),
    request(3, { user: "alice2" }),
    request(4, { user: "bob", path: "/users/alice" }),
  ];
  assert.deepEqual(scopeRows(rows, { user: "alice" }).map(row => row.id), [1]);
});

test("account, source address, and search apply together", () => {
  const rows = [
    request(1, { signals: ["failed-login-burst"] }),
    request(2, { user: "alice-admin", signals: ["failed-login-burst"] }),
    request(3, { ip: "10.0.0.2", signals: ["failed-login-burst"] }),
    request(4, { signals: ["new-IP-for-user"] }),
  ];
  assert.deepEqual(scopeRows(rows, {
    user: "alice",
    source: "10.0.0.1",
    query: "  FAILED-LOGIN  ",
  }).map(row => row.id), [1]);
  assert.equal(scopeRows(rows, { user: "alice", source: "10.0.0.9" }).length, 0);
});

test("anonymous accounts can be selected and clearing filters restores all requests", () => {
  const rows = [request(1), request(2, { user: "-" }), request(3, { user: "bob" })];
  assert.deepEqual(scopeRows(rows, { user: "-" }).map(row => row.id), [2]);
  assert.deepEqual(scopeRows(rows, { user: "", source: "", query: "" }), rows);
  assert.deepEqual(scopeRows(rows), rows);
});

test("the review cutoff includes sub-100 scores and is independent of stale severity colors", () => {
  const rows = [
    request(1, { score: 0.94, tier: "red" }),
    request(2, { score: 0.95, tier: "green" }),
    request(3, { score: 0.975, tier: "green" }),
    request(4, { score: 1, tier: "red" }),
  ];
  assert.deepEqual(rows.filter(row => isCandidate(row, 0.95)).map(row => row.id), [2, 3, 4]);
  assert.deepEqual(rows.filter(row => isCandidate(row, 0.97)).map(row => row.id), [3, 4]);
  assert.equal(isCandidate(request(5, { score: NaN, tier: "red" }), 0.95), false);
  assert.equal(isCandidate(request(6, { score: Infinity, tier: "red" }), 0.95), false);
});

test("requests beyond the baseline remain distinguishable and are not called 100% confident", () => {
  const rows = [
    request(1, { score: 1, raw_score: 3.12, above_baseline: true }),
    request(2, { score: 1, raw_score: 9.81, above_baseline: true }),
    request(3, { score: 1, raw_score: 6.45, above_baseline: true }),
  ];
  assert.deepEqual(sortRows(rows).map(row => row.id), [2, 3, 1]);
  assert.equal(new Set(rows.map(row => scoreLabel(row, "baseline"))).size, 3);
  for (const row of rows) {
    assert.equal(percentileLabel(row, "baseline"), "Above baseline range");
    assert.doesNotMatch(scoreLabel(row, "baseline"), /100|confidence/i);
  }
});

test("extreme tail percentiles below 100 are never displayed as 100", () => {
  for (const score of [0.99999, 0.999999999999]) {
    for (const kind of ["baseline", "percentile"]) {
      const label = percentileLabel(request(1, { score }), kind);
      assert.ok(Number.parseFloat(label) < 100, label);
      assert.match(label, /percentile$/);
      assert.doesNotMatch(label, /confidence/i);
    }
  }
  assert.equal(percentileLabel(request(1, { score: NaN }), "baseline"), "Unavailable");
});

test("close raw scores remain visually distinguishable when their percentiles saturate", () => {
  const lower = request(1, { score: 1, raw_score: 3.1234, above_baseline: true });
  const higher = request(2, { score: 1, raw_score: 3.12345, above_baseline: true });
  assert.notEqual(scoreLabel(lower, "baseline"), scoreLabel(higher, "baseline"));
  assert.deepEqual(sortRows([lower, higher]).map(row => row.id), [2, 1]);
});

test("sorting a top-100 review queue ascending preserves the 100 highest-priority requests", () => {
  const rows = Object.freeze(Array.from({ length: 150 }, (_, index) => Object.freeze(request(index, {
    score: 1,
    raw_score: index + 1,
    above_baseline: true,
  }))));
  const descending = priorityRows(rows, 100, true);
  const ascending = priorityRows(rows, 100, false);
  assert.equal(ascending.length, 100);
  assert.deepEqual(ascending.map(row => row.id), Array.from({ length: 100 }, (_, index) => index + 50));
  assert.deepEqual(descending.map(row => row.id), ascending.map(row => row.id).reverse());
  assert.deepEqual(rows.map(row => row.id), Array.from({ length: 150 }, (_, index) => index));
  assert.equal(priorityRows(rows, 0).length, 150);
  assert.equal(priorityRows(rows.slice(0, 8), 100).length, 8);
});

test("sorting the review table in either direction preserves its original population order", () => {
  const rows = Object.freeze([
    Object.freeze(request(1, { score: 0.97 })),
    Object.freeze(request(2, { score: 0.99 })),
    Object.freeze(request(3, { score: 0.95 })),
  ]);
  assert.deepEqual(sortRows(rows).map(row => row.id), [2, 1, 3]);
  assert.deepEqual(sortRows(rows, false).map(row => row.id), [3, 1, 2]);
  assert.deepEqual(rows.map(row => row.id), [1, 2, 3]);
});

test("the account filter contains every account, including those outside the top eight", () => {
  const rows = Array.from({ length: 20 }, (_, index) => request(index, { user: `account-${index}` }));
  rows.push(request(20, { user: "account-19" }), request(21, { user: "-" }));
  const counts = new Map(accountCounts(rows));
  assert.equal(counts.size, 21);
  for (let index = 0; index < 19; index++) assert.equal(counts.get(`account-${index}`), 1);
  assert.equal(counts.get("account-19"), 2);
  assert.equal(counts.get("-"), 1);
});

test("a 180,800-request upload can be scoped without truncating its account population", () => {
  const rows = Array.from({ length: 180800 }, (_, index) => request(index, {
    user: `account-${index % 16}`,
    ip: `10.0.0.${Math.floor(index / 16) % 4}`,
  }));
  const filtered = scopeRows(rows, { user: "account-7", source: "10.0.0.2", query: "reports" });
  assert.equal(filtered.length, 2825);
  assert.ok(filtered.every(row => row.user === "account-7" && row.ip === "10.0.0.2"));
  assert.equal(accountCounts(rows).length, 16);
  assert.equal(new Map(accountCounts(rows)).get("account-15"), 11300);
  assert.equal(scopeRows(rows, {}).length, 180800);
});
