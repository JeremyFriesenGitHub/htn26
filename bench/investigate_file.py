"""Score a local upload and save reusable results plus held-out reference metrics.

No model is fitted or tuned here. Reference labels are repository annotations,
not independently verified incident truth. Run from the project environment:
  python -m bench.investigate_file --input logs/htn_challenge_logs_2026.txt
"""
from __future__ import annotations
import argparse
import csv
import gzip
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def write_json(path, value):
    with path.open("w") as stream:
        json.dump(value, stream, allow_nan=False, separators=(",", ":"))


def main():
    from . import dashboard, data, labels
    import numpy as np
    import pandas as pd
    from sklearn.metrics import average_precision_score, roc_auc_score

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--models", nargs="+", default=["gmm", "ae"])
    parser.add_argument("--output", type=Path, default=Path("results/investigation"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    raw_bytes = args.input.read_bytes()
    logs = raw_bytes.decode("utf-8")
    frame = labels.attach(data.parse_lines(logs.splitlines()))
    frame["src_line"] = np.arange(1, len(frame) + 1)
    heldout = frame[frame.ts >= data.VAL_END].copy()
    truth = dict(zip(heldout.src_line, heldout.label))
    print(f"Dataset: {len(frame)} requests; March holdout {len(heldout)}; reference positives {int(heldout.label.sum())}", flush=True)
    runs, metrics, provenance = [], {}, {}
    for model in args.models:
        last_stage = [None]
        def progress(event):
            stage = event.get("stage")
            if stage != last_stage[0]:
                print(f"{model}: {stage} — {event.get('message', '')}", flush=True)
                last_stage[0] = stage
        result = dashboard.predict_payload({"logs": logs, "model": model}, progress=progress)
        runs.append(result)
        with gzip.open(args.output / f"model-{model}.json.gz", "wt") as stream:
            json.dump(result, stream, allow_nan=False, separators=(",", ":"))
        rows = [row for row in result["rows"] if row["id"] in truth]
        rows.sort(key=lambda row: (-(row.get("raw_score") if row.get("raw_score") is not None else row["score"]), row["id"]))
        y = np.asarray([truth[row["id"]] for row in rows])
        scores = np.asarray([row.get("raw_score") if row.get("raw_score") is not None else row["score"] for row in rows])
        cutoff = result["review_threshold"]
        flagged = [row for row in rows if row["score"] >= cutoff]
        found = sum(truth[row["id"]] for row in flagged)
        model_metrics = {"holdout_requests":len(rows), "reference_positives":int(y.sum()),
                         "average_precision":float(average_precision_score(y, scores)),
                         "roc_auc":float(roc_auc_score(y, scores)), "cutoff":cutoff,
                         "cutoff_kind":result["score_kind"], "alerts_at_default_cutoff":len(flagged),
                         "reference_positives_at_default_cutoff":found,
                         "unlabelled_alerts_at_default_cutoff":len(flagged)-found,
                         "missed_reference_ids":[row["id"] for row in rows if truth[row["id"]] and row["score"] < cutoff],
                         "top_k":{}}
        for k in (10, 20, 22, 25, 50, 100, 250):
            n = min(k, len(rows)); hits = int(y[:n].sum())
            model_metrics["top_k"][str(k)] = {"reviewed":n,"reference_hits":hits,"precision_against_reference":hits/n,"reference_recall":hits/int(y.sum())}
        model_metrics["reference_ranks"] = [{"id":row["id"],"rank":i+1,"raw_score":row.get("raw_score"),"baseline_percentile":row.get("baseline_percentile")} for i,row in enumerate(rows) if truth[row["id"]]]
        metrics[model] = model_metrics
        with (args.output / f"march-ranked-{model}.csv").open("w", newline="") as stream:
            writer=csv.writer(stream);writer.writerow(["rank","source_line","timestamp","account","source_ip","method","path","status","bytes","raw_score","baseline_percentile","reference_label"])
            for rank,row in enumerate(rows,1):writer.writerow([rank,row["id"],row["timestamp"],row["user"],row["ip"],row["method"],row["path"],row["status"],row["bytes"],row.get("raw_score"),row.get("baseline_percentile"),truth[row["id"]]])
        for filename in dashboard.MODEL_FILES[model]:
            path=dashboard.STORE/filename
            if path.exists():provenance[filename]=hashlib.sha256(path.read_bytes()).hexdigest()
        print(model, json.dumps(model_metrics, separators=(",", ":")), flush=True)
    metadata = {"source":str(args.input),"source_sha256":hashlib.sha256(raw_bytes).hexdigest(),"created_utc":datetime.now(timezone.utc).isoformat(),"model_artifact_sha256":provenance,"holdout_start":str(data.VAL_END),"reference":"bench/labels.py manually curated 22-record incident; not independent ground truth","metrics":metrics}
    write_json(args.output/"model-evaluation.json", metadata)
    canonical = sorted(runs[0]["rows"],key=lambda row:row["id"])
    for row in canonical:row["time"]=int(datetime.fromisoformat(row["timestamp"]).timestamp()*1000)
    shared={"ip","ident","user","timestamp","method","path","proto","status","bytes","raw","time","signals"}
    saved_runs=[]
    for run in runs:
        saved={key:value for key,value in run.items() if key!="rows"}
        saved["rows"]=[{key:value for key,value in row.items() if key not in shared} for row in run["rows"]]
        saved_runs.append(saved)
    session={"schema":"log-order-investigation","version":1,"source":args.input.name,"synthetic":False,"base_model":runs[0]["model"],"active_model":runs[0]["model"],"threshold":runs[0]["review_threshold"],"rows":canonical,"runs":saved_runs,"analysis_provenance":metadata}
    write_json(args.output/"scored-session.json",session)
    print(f"Saved model runs, evaluation, ranked CSVs and scored-session.json in {args.output}",flush=True)


if __name__ == "__main__":
    main()
