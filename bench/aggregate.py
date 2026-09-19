"""Merge detector results + LLM baselines into one leaderboard and a compact report."""
from __future__ import annotations

import glob
import json
from pathlib import Path

import pandas as pd

RESULTS = Path(__file__).resolve().parent.parent / "results"

CORE = ["model", "view", "pr_auc", "roc_auc", "recall@50", "prec@50", "best_f1",
        "alerts_per_day_at_best_f1", "seconds"]


def load_all() -> pd.DataFrame:
    frames = []
    ms = RESULTS / "model_scores.csv"
    if ms.exists():
        frames.append(pd.read_csv(ms))
    for f in glob.glob(str(RESULTS / "llm_*.csv")):
        if Path(f).name in ("llm_summary.csv",) or "flags" in Path(f).name:
            continue
        frames.append(pd.read_csv(f))
    df = pd.concat(frames, ignore_index=True, sort=False)
    return df


def main():
    df = load_all()
    df = df.sort_values("pr_auc", ascending=False)
    cols = [c for c in CORE if c in df.columns]
    board = df[cols].copy()
    board.to_csv(RESULTS / "leaderboard.csv", index=False)
    pd.set_option("display.width", 160, "display.max_rows", 100)
    print("== FULL LEADERBOARD (by PR-AUC on March test) ==")
    print(board.to_string(index=False, float_format=lambda x: f"{x:.3f}"))

    # LLM detail rows if present
    llm = df[df.model.astype(str).str.startswith("LLM:")]
    if len(llm):
        print("\n== LLM baselines (binary detection at their own flag set) ==")
        show = ["model", "pr_auc", "recall@50", "flagged", "tp", "fp", "fn",
                "precision", "recall", "f1", "input_tokens", "output_tokens", "est_cost_usd"]
        show = [c for c in show if c in llm.columns]
        print(llm[show].to_string(index=False, float_format=lambda x: f"{x:.3f}"))


if __name__ == "__main__":
    main()
