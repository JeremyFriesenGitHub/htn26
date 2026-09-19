"""Blind LLM anomaly-detection baseline over the March test window (Claude and/or GPT).

Same protocol for every provider so the comparison is fair:
  * The model sees only raw log lines, in chronological windows of WINDOW lines with
    OVERLAP lines of carry-over so cross-line attacks (bursts, IP/user mismatch) stay
    visible. No counts, no rarity tables, no hint about which lines are anomalous.
  * One fixed system prompt defines "anomalous" identically for every window/provider.
  * Structured JSON output returns flagged src_line numbers + severity + reason.
  * Flags are unioned across windows and scored with bench.metrics, exactly like any
    detector's per-line score (severity -> score; unflagged lines -> 0).

Windows are sent concurrently (threads) to keep wall-clock down. Requires the relevant
API key(s) in the environment.

    .venv/bin/python -m bench.llm_baseline --provider anthropic --model claude-opus-5
    .venv/bin/python -m bench.llm_baseline --provider openai   --model gpt-5
    .venv/bin/python -m bench.llm_baseline --provider both
"""
from __future__ import annotations

import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import numpy as np
import pandas as pd

from . import data, labels, metrics

RESULTS = Path(__file__).resolve().parent.parent / "results"
WINDOW = 120
OVERLAP = 20
MAX_WORKERS = 8
MAX_OUT = 12000            # generous so reasoning models don't truncate the JSON
REASONING_EFFORT = "low"   # triage over 120 lines doesn't need deep reasoning; keeps cost sane

# per-1M-token USD (input, output), for the est_cost column only
PRICING = {
    "claude-opus-5": (5.0, 25.0), "claude-sonnet-5": (2.0, 10.0), "claude-haiku-4-5": (1.0, 5.0),
    "gpt-5": (1.25, 10.0), "gpt-5-mini": (0.25, 2.0), "gpt-4o": (2.5, 10.0), "gpt-4o-mini": (0.15, 0.6),
}

SYSTEM = """You are a security analyst reviewing web-server access logs from a corporate intranet.
Each line is Apache common log format: IP - user [timestamp] "METHOD path HTTP/1.1" status bytes.
Normal traffic: employees browsing dashboards, a forum, static assets, and department files
they are authorised for; occasional 403s, isolated failed logins, and some off-hours/weekend
activity are all NORMAL background noise.

Flag a line as anomalous ONLY if it shows a genuine security concern, such as:
- a user authenticating or acting from an IP that is not theirs (account/session hijack)
- rapid repeated failed logins (brute force)
- a user successfully accessing a confidential resource they are normally denied
- requests with injection/CSRF-looking parameters or endpoints that don't belong to normal use
- a privilege-escalation or admin action that is out of character

Do NOT flag ordinary denials, single failed logins, or normal off-hours browsing.
Return ONLY the lines that are genuinely suspicious. Be precise, not trigger-happy."""

SCHEMA = {
    "type": "object",
    "properties": {
        "anomalies": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "src_line": {"type": "integer"},
                    "severity": {"type": "number", "description": "0.0-1.0 confidence it is a real threat"},
                    "reason": {"type": "string"},
                },
                "required": ["src_line", "severity", "reason"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["anomalies"],
    "additionalProperties": False,
}

USER_TMPL = ("Review these log lines. Column 1 (before the tab) is the line id to "
             "reference in your answer - copy it exactly.\n\n{body}\n\n"
             "Return the anomalous lines as JSON, using the column-1 line ids.")


def render_window(rows: pd.DataFrame):
    """Render a window with small LOCAL ids (1..N) and return the id->src_line map.

    LLMs reliably truncate/mangle large shared-prefix line numbers (e.g. 168311 -> 311),
    so we reference lines by a compact per-window index and translate back ourselves.
    """
    id_map, lines = {}, []
    for local, (_, r) in enumerate(rows.iterrows(), start=1):
        id_map[local] = int(r["src_line"])
        lines.append(f'{local}\t{data.to_line(r)}')
    return "\n".join(lines), id_map


def make_windows(test: pd.DataFrame):
    test = test.sort_values("ts").reset_index(drop=True)
    out, i = [], 0
    while i < len(test):
        out.append(test.iloc[max(0, i - OVERLAP): i + WINDOW])
        i += WINDOW
    return out


# ----------------------------------------------------------------- providers

class AnthropicProvider:
    def __init__(self, model):
        import anthropic
        self.model = model
        self.client = anthropic.Anthropic()

    def classify(self, prompt):
        msg = self.client.messages.create(
            model=self.model, max_tokens=MAX_OUT,
            system=[{"type": "text", "text": SYSTEM, "cache_control": {"type": "ephemeral"}}],
            output_config={"format": {"type": "json_schema", "schema": SCHEMA},
                           "effort": REASONING_EFFORT} if REASONING_EFFORT else
                          {"format": {"type": "json_schema", "schema": SCHEMA}},
            messages=[{"role": "user", "content": prompt}],
        )
        if msg.stop_reason == "max_tokens":
            raise RuntimeError("output truncated (stop_reason=max_tokens); raise MAX_OUT")
        text = next((b.text for b in msg.content if b.type == "text"), "{}")
        cache_rd = getattr(msg.usage, "cache_read_input_tokens", 0) or 0
        return json.loads(text), msg.usage.input_tokens + cache_rd, msg.usage.output_tokens


class OpenAIProvider:
    def __init__(self, model):
        import openai
        self.model = model
        self.client = openai.OpenAI()

    def classify(self, prompt):
        kw = dict(
            model=self.model,
            messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
            response_format={"type": "json_schema",
                             "json_schema": {"name": "anomalies", "strict": True, "schema": SCHEMA}},
        )
        if REASONING_EFFORT and self.model.startswith(("gpt-5", "o3", "o4")):
            kw["reasoning_effort"] = REASONING_EFFORT
        try:
            r = self.client.chat.completions.create(max_completion_tokens=MAX_OUT, **kw)
        except Exception as e:
            if "max_completion_tokens" in str(e) and "nsupported" in str(e):
                kw.pop("reasoning_effort", None)
                r = self.client.chat.completions.create(max_tokens=MAX_OUT, **kw)
            else:
                raise
        choice = r.choices[0]
        text = choice.message.content or "{}"
        if choice.finish_reason == "length":  # truncated before it could emit JSON
            raise RuntimeError("output truncated (finish_reason=length); raise MAX_OUT")
        u = r.usage
        return json.loads(text), u.prompt_tokens, u.completion_tokens


def make_provider(provider, model):
    return AnthropicProvider(model) if provider == "anthropic" else OpenAIProvider(model)


# ----------------------------------------------------------------- run + score

def run(provider_name, model, windows):
    prov = make_provider(provider_name, model)
    rendered = [render_window(w) for w in windows]  # (text, id_map) per window
    prompts = [USER_TMPL.format(body=body) for body, _ in rendered]
    id_maps = [m for _, m in rendered]
    flags, in_tok, out_tok, errors, bad_ids = {}, 0, 0, 0, 0
    t0 = time.time()

    def work(j):
        return j, prov.classify(prompts[j])

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = [ex.submit(work, j) for j in range(len(prompts))]
        done = 0
        for fut in as_completed(futs):
            done += 1
            try:
                j, (parsed, it, ot) = fut.result()
            except Exception as e:
                errors += 1
                if errors <= 3:
                    print(f"    window error: {type(e).__name__}: {str(e)[:120]}")
                continue
            in_tok += it; out_tok += ot
            for a in parsed.get("anomalies", []):
                sl = id_maps[j].get(int(a["src_line"]))  # local id -> real src_line
                if sl is None:
                    bad_ids += 1
                    continue
                flags[sl] = max(flags.get(sl, 0.0), float(a.get("severity", 1.0)))
            if done % 40 == 0:
                print(f"    {model}: {done}/{len(prompts)} windows, {len(flags)} flags, {time.time()-t0:.0f}s")
    print(f"  {model}: done {len(prompts)} windows in {time.time()-t0:.0f}s, "
          f"{errors} errors, {bad_ids} unmappable ids, {len(flags)} unique flags")
    return flags, in_tok, out_tok


def score_and_save(test, model, flags, in_tok, out_tok):
    y = test.label.values
    sev = np.array([flags.get(int(sl), 0.0) for sl in test.src_line])
    n_days = (test.ts.max() - test.ts.min()).days + 1
    res = metrics.evaluate(sev, y, n_days)
    pred = (sev > 0).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    pin, pout = PRICING.get(model, (0, 0))
    res.update(model=f"LLM:{model}", view="blind", flagged=int(pred.sum()),
               tp=tp, fp=fp, fn=fn,
               precision=round(tp / max(tp + fp, 1), 4), recall=round(tp / max(tp + fn, 1), 4),
               f1=round((2 * tp) / max(2 * tp + fp + fn, 1), 4),
               input_tokens=in_tok, output_tokens=out_tok,
               est_cost_usd=round(in_tok / 1e6 * pin + out_tok / 1e6 * pout, 4))
    RESULTS.mkdir(exist_ok=True)
    safe = model.replace("/", "_")
    pd.DataFrame([res]).to_csv(RESULTS / f"llm_{safe}.csv", index=False)
    # dump the actual flags with labels for inspection
    rec = []
    stage = test["stage"] if "stage" in test else pd.Series([""] * len(test), index=test.index)
    for (_, r), st in zip(test.iterrows(), stage):
        sl = int(r["src_line"])
        if flags.get(sl):
            rec.append({"src_line": sl, "severity": flags[sl], "label": int(r["label"]),
                        "stage": st, "line": data.to_line(r)})
    pd.DataFrame(rec).to_csv(RESULTS / f"llm_flags_{safe}.csv", index=False)
    print(json.dumps({k: res[k] for k in ["model", "pr_auc", "roc_auc", "recall@50", "flagged",
                                          "tp", "fp", "fn", "precision", "recall", "f1",
                                          "input_tokens", "output_tokens", "est_cost_usd"]},
                     indent=2, default=str))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", choices=["anthropic", "openai", "both"], default="both")
    ap.add_argument("--model", help="single model id; overrides defaults")
    ap.add_argument("--anthropic-model", default="claude-opus-5")
    ap.add_argument("--openai-model", default="gpt-5")
    ap.add_argument("--limit", type=int, default=0, help="cap number of windows (smoke test)")
    args = ap.parse_args()

    df = labels.attach(data.load())
    _, _, test = data.split(df)
    windows = make_windows(test)
    if args.limit:
        windows = windows[:args.limit]
        print(f"LIMIT: {len(windows)} windows only (smoke test)")
    print(f"test={len(test)} lines, {int(test.label.sum())} attacks, {len(windows)} windows")

    jobs = []
    if args.model:
        jobs.append((args.provider if args.provider != "both" else "anthropic", args.model))
    else:
        if args.provider in ("anthropic", "both"):
            jobs.append(("anthropic", args.anthropic_model))
        if args.provider in ("openai", "both"):
            jobs.append(("openai", args.openai_model))

    summary = []
    for prov, model in jobs:
        print(f"\n=== {prov} / {model} ===")
        flags, it, ot = run(prov, model, windows)
        summary.append(score_and_save(test, model, flags, it, ot))
    if len(summary) > 1:
        pd.DataFrame(summary).to_csv(RESULTS / "llm_summary.csv", index=False)


if __name__ == "__main__":
    main()
