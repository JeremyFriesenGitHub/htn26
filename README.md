# trace.cooking — Log anomaly detection using Unsupervised Learning

Unsupervised detection of a security incident hidden in 180,800 Apache access-log lines
(Aug 2025 – Mar 2026), a rigorous comparison of detector architectures against blind LLM
baselines, and an interactive console for scoring new logs.

## Final report

The completed investigation for the challenge is available in the [Evidence Report](https://trace.cooking/final_htn26_report). It reconstructs the incident from the detected anomalies and the surrounding HTTP requests.

## The problem
The log has 7 informative fields (IP, user, timestamp, method, path, status, bytes). One
real multi-stage attack is buried in it (22 lines in March 2026): credential brute force
from a mismatched IP, a CSRF probe, a privilege escalation, and an account takeover with
data exfiltration. There are **no labels** — this is unsupervised anomaly detection. The
background is seeded with decoys (off-hours activity, weekend traffic, 403 probes, isolated
failed logins) so naive rules drown in false positives.

## How the model works (plain version)

1. **Learn each person's habits** from the training months: which IP they normally use,
   which resources they normally access or are always denied, which endpoints exist at all.
2. **Turn every new log line into 15 numbers** describing how unusual it is — *has this user
   ever come from this IP? how many failed logins in the last 60s? is this a resource they
   are normally denied?* (`bench/features.py`).
3. **Score those 15 numbers** with a density model that learned what normal combinations
   look like. Rare combination = high score.
4. **Threshold into three tiers** — anomaly / suspicious / normal.

The feature step is the model. Swapping the scorer barely matters (GMM 0.909 vs deep AE
0.918, overlapping CIs); swapping the *features* matters enormously (the same GMM goes
0.61 → 0.91 moving from raw fields to these). **No LLM runs in the detector or the console** —
"context features" means learned statistics, not an LLM context window.

## Approach
- **Two feature views** (`bench/features.py`): a naive 7-field `RAW` view, and a causal,
  behavioural `CTX` view. All statistics are fit on training data only and computed causally
  (each row sees only earlier rows).
- **Time split** (`bench/data.py`): fit on Aug 2025–Jan 2026, validate on Feb, test on Mar.
- **Ground truth** (`bench/labels.py`): the 22 real attack lines, hand-labelled from a
  forensic reading and tiered `detectable` (20) vs `context`-only (2). Used **only** to
  score, never to fit. These labels are a human judgement, not data that shipped with the log.
- **Detector zoo** (`bench/models.py`): KMeans, GMM, IsolationForest, OneClassSVM, LOF,
  HBOS, ECOD, COPOD, PCA, AutoEncoder, DeepSVDD, and a no-ML weighted-surprisal rule.
- **Deep model** (`bench/deep_model.py`): a GPU autoencoder ensemble with BatchNorm, GELU,
  dropout + weight-decay regularisation, AdamW, cosine-annealing-with-warm-restarts LR,
  gradient clipping, AMP mixed precision, early stopping, and per-feature-error-weighted
  reconstruction scoring.
- **Label-free model selection** (`bench/inject.py`, `bench/evaluate_final.py`): synthetic
  attacks are injected into the February validation window to pick hyperparameters and the
  operating threshold. The real March attack is used only for the final, one-shot
  evaluation, reported with 1000× bootstrap 95% confidence intervals.
- **LLM baselines** (`bench/llm_baseline.py`) and **hybrid triage** (`bench/hybrid.py`).
- **Metrics** (`bench/metrics.py`): PR-AUC, ROC-AUC, recall@k, best-F1, alerts/day.

## Results (real March test, PR-AUC with 95% CI; higher = better)

| Model | View | PR-AUC | 95% CI | Recall@50 | Notes |
|---|---|---|---|---|---|
| Deep AE ensemble (×7) | CTX | **0.918** | [0.79, 1.00] | 20/22 | GPU, best recall (21/22 at op point) |
| GMM (k=4, diag) | CTX | 0.909 | [0.77, 1.00] | 20/22 | trains in <1s, no GPU, **recommended** |
| Ensemble | CTX | 0.907 | [0.77, 1.00] | 20/22 | no better than GMM alone |
| RuleNovelty (no ML) | CTX | 0.867 | [0.71, 1.00] | 19/22 | interpretable, best ROC (0.990) |
| ECOD | CTX | 0.862 | [0.70, 0.99] | 19/22 | |
| KMeans | CTX | 0.836 | — | 20/22 | |
| GPT-5 (blind LLM) | — | 0.324 | — | 10/22 | recall 0.77, precision 0.07, $4.72/run |
| Claude Opus 5 (blind LLM) | — | ≤0.11* | — | 6/22 | recall 0.77, precision 0.03, 614 FPs; *partial run (154/192 windows, credit exhausted) |
| KMeans | RAW | 0.646 | — | 16/22 | same algorithm, naive features |

### Hybrid: detector shortlist → LLM triage (best design; CLI only, not in the console)

| Approach | Precision | Recall | False positives | Cost/run | Alerts/day |
|---|---|---|---|---|---|
| Raw GPT-5 (blind, all lines) | 0.07 | 0.77 | 225 | $4.72 | — |
| GMM alone (op threshold) | 0.20 | 0.91 | 78 | $0 | ~2.5 |
| **Hybrid (GMM → GPT-5, top-60)** | **1.00** | **0.86** | **0** | **$0.08** | **0.6** |

The detector scores every line cheaply; the LLM adjudicates only the top-K candidates **with
each user's learned permission profile** — the context raw GPT lacked. That removes every
false positive and costs 60× less. Its 3 misses are the two context-only rows and one
benign-looking CSRF-chain step the LLM reasonably cleared.

**Takeaways**
1. *Representation beats algorithm.* The CTX features lift every clusterer (KMeans
   0.65→0.84, GMM 0.61→0.91, OneClassSVM 0.57→0.86). K-means/SVM weren't the wrong idea —
   raw features were.
2. *Proper engineering matters.* A naive autoencoder loses to GMM (0.87 vs 0.91); the fully
   engineered AE ensemble edges ahead (0.918) — though with 22 attacks the CI overlap means
   the AE-vs-GMM gap is not statistically significant.
3. *The trained models crush the blind LLMs* (0.92 vs 0.32). **Both** GPT-5 and Claude Opus 5
   find the attack (recall 0.77) but have no learned permission model, so they flag every
   authorised read of a `*_CONFIDENTIAL` file — 225 and 614 false positives respectively.
   The failure is architectural, not provider-specific.

## Web console

`results/webapp.html` (built by `bench/webapp.py`) is an interactive console:

- paste, **drag-and-drop or upload** `.log`/`.txt` files; append or replace
- **red / yellow / green triage** with the reasons that fired per line
- **detected incidents** — flagged lines grouped per user into bursts, so the attack shows
  up as discrete incidents (brute-force bursts, CSRF probes, escalation, takeover); click
  one to filter the table to it
- **filters**: text search, user, IP, status, method, date range, tier chips, reset
- sortable paged table with expandable row detail, **CSV export**, stat tiles, and two live
  charts (score over time, flagged lines by user); light/dark

**Model selector.** Opened as a plain file it runs the interpretable RuleNovelty scorer in
the browser (a JS port validated to reproduce the Python scorer exactly — `bench/export_web.py`
prints the parity check). Run `bench/serve.py` and it auto-detects the backend, defaults to
the **real GMM**, and offers the **deep AE** too, scoring through `/api/score` with tier
thresholds calibrated per model on training traffic. The hybrid LLM layer is **not** wired
into the console.

## Repo map
```
bench/data.py           parse logs, template paths, time split
bench/labels.py         the 22 hand-labelled attack lines (evaluation only)
bench/features.py       RAW and CTX feature views
bench/models.py         detector zoo + RuleNovelty
bench/deep_model.py     GPU autoencoder ensemble
bench/inject.py         synthetic attacks for label-free selection
bench/metrics.py        PR-AUC, recall@k, alerts/day
bench/run_models.py     full benchmark (both views, 3 seeds)
bench/evaluate_final.py val-selected, bootstrapped final evaluation
bench/train.py          train + persist champions to results/model_store/
bench/predict.py        score logs from the CLI, with reasons
bench/llm_baseline.py   blind GPT/Claude baselines
bench/hybrid.py         detector shortlist -> LLM triage
bench/export_web.py     export model to JSON (+ Python/JS parity check)
bench/webapp.py         build results/webapp.html
bench/serve.py          localhost site + /api/score using the real models
bench/report.py         build results/report.html (charts write-up)
bench/aggregate.py      merge benchmark + LLM results into one leaderboard
```

## Usage

### Hosting on Vercel and Railway

See [DEPLOYMENT.md](DEPLOYMENT.md) for the complete setup. Vercel serves `dashboard/`
and proxies `/api/*` to a Railway Flask/Gunicorn service using the existing scoring
pipeline. Set `BACKEND_URL` on Vercel. The trained models in `deployment/models/` are
bundled into the Railway image automatically; no model upload is required. Hybrid OpenAI triage is available in the current
dashboard when the GMM artifacts and `OPENAI_API_KEY` are present (the older
generated web console described above is separate).

### Local dashboard

```bash
python3 -m bench.dashboard
```

Open **http://127.0.0.1:8765** for the log-review dashboard. Python 3.9+ is enough to
explore the included synthetic sample; no frontend build or additional packages
are needed. Use `--port 8766` to choose another port.

The home and investigation overview is at `/`, log input at `/analyze`, and model
methodology and benchmarks at `/models`. Individual investigations use
`/investigations/<id>`. Browser Back and Forward preserve the active in-memory
analysis; after a page reload or in a new tab, load a saved investigation to restore
its records and notes. The local server and Vercel build both serve these routes.

- Upload a `.log` / `.txt` file, drag and drop it, or paste Apache Common or
  Combined Log Format lines. There is no application-level file-size or total-line
  limit; available memory determines how large a batch can be processed.
- Start with **Investigations found**, grouped by authenticated account across IP
  changes (anonymous traffic groups by IP) and gaps of no more than 30 minutes.
  A red-only overview chart locates candidates; other traffic is optional.
- Open an investigation for its chronological episodes and a linked evidence
  workspace. Episode labels use literal request methods and paths, not inferred
  attack phases. Nearby requests remain visible as context.
- Inspect events, native model scores, and earlier-upload comparisons together.
  Switch detector lenses without losing the selected event. A model not yet run
  requires an explicit analysis action on the same upload; unavailable models
  are not simulated. Current results do not expose embeddings or feature-level
  model attribution, so the UI does not invent them.
- Use **Save investigation data** to download original records, cached model
  results, timeline edits and notes as a portable `.json.gz` file. **Load saved investigation** on the Analyze page restores that save without rerunning detectors; plain JSON
  saves are also supported.
- Rename, merge, or split episodes; annotate events; mark them important or
  benign; remove/restore events or promote history into the reconstruction.
  Edits last for this browser session and are included in exported reports.
- Export an investigation report with Who / What / When / How, model evidence,
  analyst interpretation, and original records. Raw CSV remains available.
- **Preview rules** use fixed request indicators; they are not a trained detector.
  **Try sample logs** loads a synthetic example only when requested.
- **GMM** and **Deep autoencoder** become selectable when their dependencies and
  saved artifacts under `results/model_store/` are available. Train them using
  the commands below, then start the dashboard with that environment's Python:
  `.venv/bin/python -m bench.dashboard`.

Trained results preserve raw anomaly scores and use training-baseline percentiles
when calibration is available, otherwise batch percentiles. Neither is attack
confidence. Defaults are 99.9 for calibrated scores, 98 for batch percentiles, and
75 for preview rules; the cutoff is adjustable. Explanation tags describe request
features, not model attribution. Optional hybrid review sends shortlisted traffic
to OpenAI; local model and rule runs do not. Uploads are processed in memory.
The dashboard analyzes uploaded batches; it does not continuously ingest logs.
The server binds to `127.0.0.1` by default and is intended for local use.

Run the dashboard backend checks with `python3 -m unittest discover -s tests -v`.

### Training and benchmarks

```bash
uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt
# for GPU: pip install torch==2.6.0 --index-url https://download.pytorch.org/whl/cu124

.venv/bin/python -m bench.run_models       # full detector benchmark
.venv/bin/python -m bench.evaluate_final   # val-selected, bootstrapped final eval
.venv/bin/python -m bench.train            # train + persist champions
.venv/bin/python -m bench.predict --demo --model ae --top 20
.venv/bin/python -m bench.aggregate        # combined leaderboard
.venv/bin/python -m bench.report           # build results/report.html

# web console
.venv/bin/python -m bench.export_web       # model.json + demo sample (+ parity check)
.venv/bin/python -m bench.webapp           # build results/webapp.html
.venv/bin/python -m bench.serve            # http://localhost:8000 (real GMM + deep AE)

# LLM baseline + hybrid (need a funded key in .keys.env; source it first:
#   set -a && . ./.keys.env && set +a)
.venv/bin/python -m bench.llm_baseline --provider openai --openai-model gpt-5
.venv/bin/python -m bench.hybrid --model gmm --topk 60 --llm gpt-5
```

Generated outputs live in `results/` (gitignored, fully reproducible from the commands above).
