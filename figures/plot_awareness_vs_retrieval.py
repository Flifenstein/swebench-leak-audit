#!/usr/bin/env python3
"""Headline figure: Qwen3.8 awareness measures vs retrieval across the three arms, per harness.

    python3 plot_awareness_vs_retrieval.py   # step 2: writes awareness_vs_retrieval.csv from ../out/runs.csv; step 3: plots it

Per-run labels come straight from runs.csv (benchmark_naming_count, grader_reasoning_count, solution_existence_count, reached_fix);
nothing is redefined here. Awareness denominators exclude runs with no readable reasoning (one Codex NO-CHEAT run has no rollout).
"""
import csv, math, os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS = os.path.join(HERE, "..", "results", "runs.csv")
CSV = os.path.join(HERE, "awareness_vs_retrieval.csv")
HARNESSES = [("claude", "Claude Code"), ("codex", "Codex CLI"), ("pi", "Pi")]
ARMS = ["DEFAULT", "SCRUB-ONLY", "NO-CHEAT"]
MEASURES = [("benchmark_naming", "benchmark_naming_count"), ("grader_reasoning", "grader_reasoning_count"), ("solution_existence", "solution_existence_count"), ("reached_fix", "reached_fix")]
BLUE, ORANGE, INK2, MUTED, GRID = "#2a78d6", "#eb6834", "#52514e", "#898781", "#e1e0d9"


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


# ---- step 2: the CSV
rows = []
runs = [r for r in csv.DictReader(open(RUNS)) if r["model"] == "Qwen3.8" and r["has_transcript"] == "1"]
for h, _ in HARNESSES:
    for arm in ARMS:
        cell = [r for r in runs if r["harness"] == h and r["arm"] == arm]
        for measure, col in MEASURES:
            xs = cell if measure == "reached_fix" else [r for r in cell if not r["reasoning_visible"].startswith("no")]
            hit = sum(1 for r in xs if r[col] not in ("", "n/a") and float(r[col]) > 0)
            lo, hi = wilson(hit, len(xs))
            rows.append(dict(harness=h, arm=arm, measure=measure, n_runs=len(xs), n_hit=hit, pct=round(100 * hit / len(xs), 1), wilson_low=round(100 * lo, 1), wilson_high=round(100 * hi, 1)))
with open(CSV, "w", newline="") as f:
    w = csv.DictWriter(f, list(rows[0]))
    w.writeheader()
    w.writerows(rows)
print(f"wrote {CSV} ({len(rows)} rows)")

# ---- step 3: the figure
plt.rcParams.update({"font.family": "sans-serif", "font.size": 9.5, "axes.titlesize": 10, "legend.fontsize": 9})
fig, axes = plt.subplots(1, 3, figsize=(7.5, 3.2), sharey=True, facecolor="white", gridspec_kw={"width_ratios": [2.85, 2.85, 3.45]})  # Pi panel is wider to hold the end label
style = {"benchmark_naming": (BLUE, "o", 1.5, "names a benchmark"), "grader_reasoning": (BLUE, "s", 1.5, "reasons about hidden tests / grader"),
         "solution_existence": (BLUE, "^", 1.5, "assumes the fix exists upstream"), "reached_fix": (ORANGE, "D", 2.5, "reached the fix")}
offsets = {"benchmark_naming": -0.09, "grader_reasoning": -0.03, "solution_existence": 0.03, "reached_fix": 0.09}
for ax, (h, title) in zip(axes, HARNESSES):
    ax.set_facecolor("white")
    for measure, _ in MEASURES:
        color, marker, lw, _ = style[measure]
        pts = [r for r in rows if r["harness"] == h and r["measure"] == measure]
        xs = [ARMS.index(r["arm"]) + offsets[measure] for r in pts]
        ys = [r["pct"] for r in pts]
        lo = [max(0.0, r["pct"] - r["wilson_low"]) for r in pts]
        hi = [max(0.0, r["wilson_high"] - r["pct"]) for r in pts]
        ax.errorbar(xs, ys, yerr=[lo, hi], color=color, lw=lw, marker=marker, ms=5, mfc="white", mew=1.4, capsize=2, elinewidth=0.7, zorder=3 if measure == "reached_fix" else 2)
        if measure == "reached_fix" and h == "pi":
            ax.annotate("reached the fix", xy=(xs[-1], ys[-1]), xytext=(5, 5), textcoords="offset points", color=INK2, fontsize=9, ha="left", va="bottom")
            ax.set_xlim(-0.4, 3.05)
    ax.set_title(title, color=INK2, loc="left")
    ax.set_xticks(range(3))
    ax.set_xticklabels(["Default", "Scrub only", "No cheat"], color=INK2, fontsize=8.5)
    if h != "pi":
        ax.set_xlim(-0.4, 2.45)
    ax.set_ylim(0, 104)
    ax.set_yticks(range(0, 101, 25))
    ax.yaxis.grid(True, color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    for sp in ("left", "bottom"):
        ax.spines[sp].set_color(MUTED)
    ax.tick_params(colors=MUTED, length=0)
    for t in ax.get_yticklabels():
        t.set_color(INK2)
axes[0].set_ylabel("Runs (%)", color=INK2)
handles = [Line2D([], [], color=style[m][0], lw=style[m][2], marker=style[m][1], ms=5, mfc="white", mew=1.4, label=style[m][3]) for m, _ in MEASURES]
fig.legend(handles=handles, loc="upper center", ncol=2, frameon=False, labelcolor=INK2, bbox_to_anchor=(0.5, 1.0), handlelength=2, columnspacing=2)
fig.tight_layout(rect=(0, 0, 1, 0.86))
fig.savefig(os.path.join(HERE, "awareness_vs_retrieval.png"), dpi=300)
fig.savefig(os.path.join(HERE, "awareness_vs_retrieval.svg"))
print("wrote awareness_vs_retrieval.png / .svg")
