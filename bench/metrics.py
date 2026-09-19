"""Scoring for a ranked anomaly detector against binary ground truth.

Accuracy is meaningless here (all-normal scores 99.99%), so we report ranking and
detection metrics: PR-AUC / ROC-AUC, recall at a fixed alert budget, precision@k, and
the operational cost (alerts per day) at the threshold that maximises F1.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, precision_recall_curve


def evaluate(scores, labels, n_days: int, budgets=(20, 50, 100)) -> dict:
    scores = np.asarray(scores, float)
    labels = np.asarray(labels, int)
    n_pos = int(labels.sum())
    order = np.argsort(-scores)
    ranked = labels[order]

    out = {
        "n": len(labels),
        "n_pos": n_pos,
        "pr_auc": float(average_precision_score(labels, scores)) if n_pos else float("nan"),
        "roc_auc": float(roc_auc_score(labels, scores)) if 0 < n_pos < len(labels) else float("nan"),
    }
    # recall at fixed alert budgets (how many attacks caught if an analyst reads top-k)
    for k in budgets:
        k = min(k, len(labels))
        out[f"recall@{k}"] = float(ranked[:k].sum() / n_pos) if n_pos else float("nan")
        out[f"prec@{k}"] = float(ranked[:k].sum() / k)
    # best achievable F1 and the operating point that gives it
    prec, rec, thr = precision_recall_curve(labels, scores)
    f1 = np.divide(2 * prec * rec, prec + rec, out=np.zeros_like(prec), where=(prec + rec) > 0)
    bi = int(np.argmax(f1))
    out["best_f1"] = float(f1[bi])
    out["best_f1_precision"] = float(prec[bi])
    out["best_f1_recall"] = float(rec[bi])
    thr_star = float(thr[min(bi, len(thr) - 1)]) if len(thr) else float("inf")
    n_alerts = int((scores >= thr_star).sum())
    out["alerts_per_day_at_best_f1"] = n_alerts / n_days
    # recall the detectable-only tier would give is handled by the caller
    return out


def confusion_at_threshold(scores, labels, thr) -> dict:
    scores, labels = np.asarray(scores, float), np.asarray(labels, int)
    pred = (scores >= thr).astype(int)
    tp = int(((pred == 1) & (labels == 1)).sum())
    fp = int(((pred == 1) & (labels == 0)).sum())
    fn = int(((pred == 0) & (labels == 1)).sum())
    tn = int(((pred == 0) & (labels == 0)).sum())
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}
