#!/usr/bin/env python3
"""Precision of the awareness regexes from out/handcheck_round2.csv, and table 2a rescaled by it.

    python3 score_handcheck.py            # scores the judge_label column (model judge)
    python3 score_handcheck.py --human    # scores your label column instead
When both columns are filled, agreement per type (per tier for benchmark_naming) and Cohen's kappa are reported.
"""
import collections, csv, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "results")
ARMS = ["DEFAULT", "SCRUB-ONLY", "NO-CHEAT"]
LABELS = ("true_positive", "false_positive", "ambiguous")

paths = [a for a in sys.argv[1:] if not a.startswith("--")]
path = paths[0] if paths else os.path.join(OUT, "handcheck_round2.csv")
if not os.path.exists(path) and os.path.exists(os.path.join(OUT, path)):
    path = os.path.join(OUT, path)
with open(path, newline="", encoding="utf-8-sig") as f:  # spreadsheets re-save with ; and a BOM
    dialect = csv.Sniffer().sniff(f.read(4096), delimiters=",;\t")
    f.seek(0)
    rows = list(csv.DictReader(f, dialect=dialect))
col = "label" if "--human" in sys.argv else "judge_label"
print(f"file: {path}")
print(f"scoring column: {col}\n")


def precision_table(col):
    lab = collections.defaultdict(collections.Counter)
    for r in rows:
        lab[(r["type"], r["tier"])][r.get(col, "").strip() or "unlabelled"] += 1
    prec = {}
    for (ty, tier), c in sorted(lab.items()):
        tp, fp = c["true_positive"], c["false_positive"]
        p = tp / (tp + fp) if tp + fp else None
        prec[(ty, tier)] = p
        print(f"{ty:24s} {tier or '-':6s} labelled {tp + fp + c['ambiguous']:3d}  TP {tp:3d}  FP {fp:3d}  ambiguous {c['ambiguous']:3d}  unlabelled {c['unlabelled']:3d}  precision {'n/a' if p is None else f'{p:.2f}'}")
    return prec


print("precision per type / tier (ambiguous excluded from the denominator)\n")
prec = precision_table(col)

# agreement between the two label columns where both are filled
both = [r for r in rows if r.get("label", "").strip() in LABELS and r.get("judge_label", "").strip() in LABELS]
if both:
    print("\nagreement human vs judge (rows with both labels)\n")
    for key in sorted({(r["type"], r["tier"]) for r in both}):
        xs = [r for r in both if (r["type"], r["tier"]) == key]
        n = len(xs)
        po = sum(r["label"] == r["judge_label"] for r in xs) / n
        pe = sum((sum(r["label"] == l for r in xs) / n) * (sum(r["judge_label"] == l for r in xs) / n) for l in LABELS)
        kappa = (po - pe) / (1 - pe) if pe < 1 else float("nan")
        print(f"{key[0]:24s} {key[1] or '-':6s} n {n:3d}  agreement {po:.2f}  Cohen's kappa {kappa:+.2f}")
    n = len(both)
    po = sum(r["label"] == r["judge_label"] for r in both) / n
    pe = sum((sum(r["label"] == l for r in both) / n) * (sum(r["judge_label"] == l for r in both) / n) for l in LABELS)
    print(f"{'all types':24s} {'-':6s} n {n:3d}  agreement {po:.2f}  Cohen's kappa {(po - pe) / (1 - pe):+.2f}")
else:
    print("\n(no rows carry both a human label and a judge label yet, so no agreement statistics)")

# table 2a rescaled: hits x precision; runs with >= 1 hit scaled by the same factor (assumes false positives are spread evenly over runs)
runs = [r for r in csv.DictReader(open(os.path.join(OUT, "runs.csv"))) if r["has_transcript"] == "1" and not r["reasoning_visible"].startswith("no")]
print(f"\ntable 2a rescaled by {col} precision: runs with >=1 hit (scaled) / hits (scaled), per model x harness x arm\n")
for ty, tier in [("benchmark_naming", "exact"), ("benchmark_naming", "any"), ("recall_from_memory", ""), ("network_closed_belief", ""), ("grader_reasoning", "")]:
    p = prec.get((ty, tier))
    c = {"exact": "benchmark_exact_count", "any": "benchmark_any_count"}.get(tier, f"{ty}_count")
    if ty == "network_closed_belief":
        c = "network_closed_belief"  # 0/1 per run; sentence counts are in awareness_events.csv
    print(f"## {ty}{' / ' + tier if tier else ''}: precision {'n/a (not labelled)' if p is None else f'{p:.2f}'}")
    cells = collections.defaultdict(list)
    for r in runs:
        cells[(r["model"], r["harness"], r["arm"])].append(int(r[c]) if r[c] not in ("", "n/a") else 0)
    for (m, h, a), xs in sorted(cells.items(), key=lambda kv: (kv[0][0], kv[0][1], ARMS.index(kv[0][2]))):
        n1, nh = sum(1 for x in xs if x > 0), sum(xs)
        print(f"  {m:9s} {h:9s} {a:11s} raw {n1:3d} / {nh:5d}" + ("" if p is None else f"   scaled {n1 * p:5.1f} / {nh * p:7.1f}"))
