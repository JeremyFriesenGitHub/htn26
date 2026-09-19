# htn26 — Log anomaly detection

Unsupervised detection of a security incident hidden in 180,800 Apache access-log lines
(Aug 2025 – Mar 2026), plus a rigorous comparison of detector architectures against a
blind LLM baseline.

## The problem
The log has 7 informative fields (IP, user, timestamp, method, path, status, bytes). One
real multi-stage attack is buried in it (22 lines in March 2026): credential brute force
from a mismatched IP, a CSRF probe, a privilege escalation, and an account takeover with
data exfiltration. There are **no labels** — this is unsupervised anomaly detection. The
background is seeded with decoys (off-hours activity, weekend traffic, 403 probes, isolated
failed logins) so naive rules drown in false positives.

## Approach
- **Two feature views** (`bench/features.py`): a naive 7-field `RAW` view, and a causal,
  behavioural `CTX` view (per-user IP/endpoint/parameter rarity, novelty flags, rolling
  failed-login and request bursts, per-user resource-denial history). All statistics are
  fit on training data only and computed causally (each row sees only earlier rows).
- **Time split** (`bench/data.py`): fit on Aug 2025–Jan 2026, validate on Feb, test on Mar
  (the month with the incident). Nothing before March is ever labelled.
- **Detector zoo** (`bench/models.py`): KMeans, GMM, IsolationForest, OneClassSVM, LOF,
  HBOS, ECOD, COPOD, PCA, AutoEncoder, DeepSVDD, and a no-ML weighted-surprisal rule.
- **Deep model** (`bench/deep_model.py`): a GPU autoencoder ensemble with BatchNorm, GELU,
  dropout + weight-decay regularisation, AdamW, cosine-annealing-with-warm-restarts LR,
  gradient clipping, AMP mixed precision, early stopping, and per-feature-error-weighted
  reconstruction scoring.
- **Label-free model selection** (`bench/inject.py`, `bench/evaluate_final.py`): synthetic
  attacks are injected into the February validation window to pick hyperparameters and the
  operating threshold. The real March attack is used **only** for the final, one-shot
  evaluation, reported with 1000× bootstrap 95% confidence intervals.
- **LLM baseline** (`bench/llm_baseline.py`): a blind, chunked Claude/GPT reviewer scored on
  the identical test set.

## Results (real March test, PR-AUC with 95% CI; higher = better)

| Model | View | PR-AUC | 95% CI | Recall@50 | Notes |
|---|---|---|---|---|---|
| Deep AE ensemble (×7) | CTX | **0.918** | [0.79, 1.00] | 20/22 | GPU, best recall (21/22 at op point) |
| GMM (k=4, diag) | CTX | 0.909 | [0.77, 1.00] | 20/22 | trains in <1s, no GPU, recommended |
| Ensemble | CTX | 0.907 | [0.77, 1.00] | 20/22 | |
| RuleNovelty (no ML) | CTX | 0.867 | [0.71, 1.00] | 19/22 | interpretable, best ROC (0.990) |
| ECOD | CTX | 0.862 | [0.70, 0.99] | 19/22 | |
| KMeans | CTX | 0.836 | — | 20/22 | |
| GPT-5 (blind LLM) | — | 0.324 | — | 10/22 | recall 0.77, precision 0.07, $4.72/run |
| Claude Opus 5 (blind LLM) | — | ≤0.11* | — | 6/22 | recall 0.77, precision 0.03, 614 FPs; *partial run (154/192 windows, credit exhausted) |
| KMeans | RAW | 0.646 | — | 16/22 | same algorithm, naive features |

### Hybrid: detector shortlist → LLM triage (recommended production design)

| Approach | Precision | Recall | False positives | Cost/run | Alerts/day |
|---|---|---|---|---|---|
| Raw GPT-5 (blind, all lines) | 0.07 | 0.77 | 225 | $4.72 | — |
| GMM alone (op threshold) | 0.20 | 0.91 | 78 | $0 | ~2.5 |
| **Hybrid (GMM → GPT-5, top-60)** | **1.00** | **0.86** | **0** | **$0.08** | **0.6** |

The detector scores every line cheaply; the LLM adjudicates only the top-K candidates **with
each user's learned permission profile** (usual IPs, normally-accessed/denied resources) —
the context raw GPT lacked. That removes every false positive and costs 60× less (it never
sees the bulk of the log). Its 3 misses are the two context-only rows and one benign-looking
CSRF-chain step the LLM reasonably cleared.

**Takeaways**
1. *Representation beats algorithm.* The CTX features lift every clusterer (KMeans
   0.65→0.84, GMM 0.61→0.91, OneClassSVM 0.57→0.86). K-means/SVM weren't the wrong idea —
   raw features were.
2. *Proper engineering matters.* A naive autoencoder loses to GMM (0.87 vs 0.91); the fully
   engineered AE ensemble edges ahead (0.918) — though with 22 attacks the CI overlap means
   the AE-vs-GMM gap is not statistically significant.
3. *The trained models crush the blind LLMs* (0.92 vs 0.32). **Both** GPT-5 and Claude
   Opus 5 find the attack (recall 0.77) but have no learned permission model, so they flag
   every authorised read of a `*_CONFIDENTIAL` file — 225 and 614 false positives
   respectively. The failure is architectural, not provider-specific. The detectors, having
   learned each user's normal resource set, don't make that mistake. The strongest
   production design is the hybrid below: a detector scores every line, the LLM triages the
   top-k with permission context.

## Usage
```bash
uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt
# for GPU: pip install torch==2.6.0 --index-url https://download.pytorch.org/whl/cu124

.venv/bin/python -m bench.run_models       # full detector benchmark (both views, 3 seeds)
.venv/bin/python -m bench.evaluate_final   # rigorous val-selected, bootstrapped final eval
.venv/bin/python -m bench.train            # train + persist champions to results/model_store/
.venv/bin/python -m bench.predict --demo --model ae --top 20   # score logs, with reasons
.venv/bin/python -m bench.predict --input newlogs.txt --model gmm

# LLM baseline + hybrid (need a funded key in .keys.env; source it first:
#   set -a && . ./.keys.env && set +a)
.venv/bin/python -m bench.llm_baseline --provider openai --openai-model gpt-5
.venv/bin/python -m bench.hybrid --model gmm --topk 60 --llm gpt-5

# Interactive web console (scores logs in-browser; open results/webapp.html)
.venv/bin/python -m bench.export_web    # dump model.json + demo sample (+ parity check)
.venv/bin/python -m bench.webapp        # build results/webapp.html
```

## Web console

`bench/webapp.py` builds a self-contained page (`results/webapp.html`) that scores pasted
logs entirely in the browser: red/yellow/green triage with the reasons that fired, filters
by user / IP / date / tier / text, and live charts (score-over-time, flagged-by-user). It
runs the interpretable RuleNovelty model — a JS port validated to reproduce the Python
scorer exactly (`bench/export_web.py` prints the parity check). The deep AE and GMM stay in
the Python CLI for maximum accuracy.
