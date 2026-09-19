"""Hybrid detector + LLM-triage layer (the recommended production design).

Pipeline:
  1. A trained detector (GMM by default) scores every line - cheap, runs on all traffic.
  2. Take the detector's top-K candidates (K ~ a few days of alerts, not the whole log).
  3. For each candidate, build a compact dossier: the line, a short window of the same
     actor's recent activity, and - crucially - the PERMISSION CONTEXT the raw LLM lacked
     (which IPs this user normally uses, which resources they normally access/are denied).
  4. The LLM adjudicates only that shortlist: real incident or benign? severity + reason.
  5. Final score = detector rank for everyone, promoted above the pack for lines the LLM
     confirms and demoted for lines it clears. Precision jumps because the LLM now knows
     what "authorised" looks like; cost stays tiny because it only sees the shortlist.

This turns the earlier finding (raw GPT flagged every authorised *_CONFIDENTIAL read) into
a fix: give the model the baseline it was missing.

    .venv/bin/python -m bench.hybrid --model gmm --topk 60 --llm gpt-5
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import rankdata

from . import data, labels, features, metrics
from . import llm_baseline as L

RESULTS = Path(__file__).resolve().parent.parent / "results"

SYSTEM = """You are a security analyst triaging alerts from an anomaly detector on corporate
intranet access logs. Each alert comes with the log line, the user's recent activity, and a
PROFILE describing what is normal for that user (their usual source IPs and which resources
they normally access or are denied). Authorised access to sensitive/confidential files IS
NORMAL when it matches the user's profile - do not flag it. Flag an alert as a real incident
only when it genuinely deviates: acting from an IP that isn't theirs, brute-force login
bursts, succeeding on a resource they are normally denied, injection/CSRF-style requests, or
out-of-character admin/privilege actions. Judge each alert with its profile in mind."""

SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "is_incident": {"type": "boolean"},
                    "severity": {"type": "number"},
                    "reason": {"type": "string"},
                },
                "required": ["id", "is_incident", "severity", "reason"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["verdicts"],
    "additionalProperties": False,
}


def build_profiles(train: pd.DataFrame) -> dict:
    prof = {}
    for u, g in train.groupby("user"):
        ips = g.ip.value_counts().index.tolist()[:3]
        allowed = sorted(g[(g.status == 200) & g.tmpl.str.startswith(
            ("/finance", "/hr", "/it", "/eng", "/exec", "/sales", "/marketing"))].tmpl.unique())
        denied = sorted(g[g.status == 403].tmpl.unique())
        prof[u] = {"usual_ips": ips, "normally_accesses": allowed[:8], "normally_denied": denied[:8]}
    return prof


def dossier(cand_rows, test_sorted, profiles):
    """Compact text block: each candidate line + that user's recent 5 events + profile."""
    lines = []
    for i, (_, r) in enumerate(cand_rows.iterrows(), start=1):
        recent = test_sorted[(test_sorted.user == r.user) & (test_sorted.ts <= r.ts)].tail(6)
        ctx = "\n".join("      " + data.to_line(x) for _, x in recent.iterrows())
        p = profiles.get(r.user, {})
        lines.append(
            f'ALERT {i}:\n    line: {data.to_line(r)}\n'
            f'    user profile: usual_ips={p.get("usual_ips")}, '
            f'normally_accesses={p.get("normally_accesses")}, '
            f'normally_denied={p.get("normally_denied")}\n'
            f'    {r.user} recent activity:\n{ctx}')
    return "\n\n".join(lines)


def run(model="gmm", topk=60, llm_model="gpt-5"):
    df = labels.attach(data.load())
    train = df[df.ts < data.VAL_END]
    test = df[df.ts >= data.VAL_END].sort_values("ts").reset_index(drop=True)
    y = test.label.values
    n_days = (test.ts.max() - test.ts.min()).days + 1

    # 1-2. detector scores everything; take top-K candidates
    from . import predict
    enc = predict.load_encoder()
    det = predict._load_ae() if model == "ae" else predict._load_gmm()
    Xte = enc.transform(test)
    det_score = np.asarray(det.score(Xte.values), float)
    det_pct = rankdata(det_score) / len(det_score)
    cand_idx = np.argsort(-det_score)[:topk]
    cands = test.iloc[cand_idx].copy()
    print(f"detector={model}: {len(test)} lines -> top {topk} candidates "
          f"({int(cands.label.sum())}/{int(y.sum())} true attacks in shortlist)")

    # 3-4. LLM adjudicates the shortlist with permission context
    profiles = build_profiles(train)
    prov = L.OpenAIProvider(llm_model) if llm_model.startswith(("gpt", "o3", "o4")) \
        else L.AnthropicProvider(llm_model)
    prompt = ("Triage these detector alerts. Use each alert's profile and recent activity.\n\n"
              + dossier(cands, test, profiles)
              + "\n\nReturn a verdict for every alert id as JSON.")
    # the providers read module-level SYSTEM/SCHEMA from llm_baseline - point them at ours
    L.SYSTEM, L.SCHEMA = SYSTEM, SCHEMA
    L.MAX_OUT, L.REASONING_EFFORT = 16000, "low"
    t = time.time()
    parsed, in_tok, out_tok = prov.classify(prompt)
    verdicts = {v["id"]: v for v in parsed.get("verdicts", [])}
    print(f"LLM adjudicated {len(verdicts)} alerts in {time.time()-t:.0f}s "
          f"({in_tok} in / {out_tok} out tokens)")

    # 5. combine: base = detector percentile; confirmed candidates promoted, cleared demoted
    final = det_pct.copy()
    llm_conf = {}
    for i, gi in enumerate(cand_idx, start=1):
        v = verdicts.get(i)
        if v is None:
            continue
        sev = float(v["severity"])
        if v["is_incident"]:
            final[gi] = 1.0 + sev          # promoted above all non-candidates
        else:
            final[gi] = det_pct[gi] * 0.05  # cleared -> demoted
        llm_conf[int(test.iloc[gi].src_line)] = v

    res = metrics.evaluate(final, y, n_days)
    # operating point: alert on everything the LLM confirmed
    confirmed_mask = np.array([final[i] > 1.0 for i in range(len(test))])
    tp = int(((confirmed_mask) & (y == 1)).sum()); fp = int(((confirmed_mask) & (y == 0)).sum())
    fn = int(((~confirmed_mask) & (y == 1)).sum())
    pin, pout = L.PRICING.get(llm_model, (0, 0))
    res.update(model=f"Hybrid({model}+{llm_model})", view="hybrid",
               confirmed=int(confirmed_mask.sum()), tp=tp, fp=fp, fn=fn,
               precision=round(tp / max(tp + fp, 1), 4), recall=round(tp / max(tp + fn, 1), 4),
               f1=round(2 * tp / max(2 * tp + fp + fn, 1), 4),
               input_tokens=in_tok, output_tokens=out_tok,
               est_cost_usd=round(in_tok / 1e6 * pin + out_tok / 1e6 * pout, 4),
               alerts_per_day=round(confirmed_mask.sum() / n_days, 2))
    RESULTS.mkdir(exist_ok=True)
    pd.DataFrame([res]).to_csv(RESULTS / f"hybrid_{model}_{llm_model}.csv", index=False)
    # dump adjudications
    rec = []
    for _, r in cands.iterrows():
        v = llm_conf.get(int(r.src_line), {})
        rec.append({"src_line": int(r.src_line), "label": int(r.label),
                    "llm_incident": v.get("is_incident"), "severity": v.get("severity"),
                    "reason": v.get("reason", ""), "line": data.to_line(r)})
    pd.DataFrame(rec).to_csv(RESULTS / f"hybrid_verdicts_{model}_{llm_model}.csv", index=False)

    print(json.dumps({k: res[k] for k in ["model", "pr_auc", "roc_auc", "recall@50",
          "confirmed", "tp", "fp", "fn", "precision", "recall", "f1",
          "input_tokens", "output_tokens", "est_cost_usd", "alerts_per_day"]},
          indent=2, default=str))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["gmm", "ae"], default="gmm")
    ap.add_argument("--topk", type=int, default=60)
    ap.add_argument("--llm", default="gpt-5")
    args = ap.parse_args()
    run(model=args.model, topk=args.topk, llm_model=args.llm)


if __name__ == "__main__":
    main()
