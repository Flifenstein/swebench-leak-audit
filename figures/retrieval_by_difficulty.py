#!/usr/bin/env python3
"""Figure: share of DEFAULT-arm runs that reached the leaked fix, by task difficulty bin.

    python3 retrieval_by_difficulty.py   # writes retrieval_by_difficulty.{png,svg} next to this file and prints the appendix table
"""
import math, os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
BINS = [("Easy", 21, "10–12"), ("Medium", 22, "3–10"), ("Hard", 21, "0–2")]  # name, tasks, no-cheat solves out of 12
SERIES = [  # label, model colour, marker, counts per bin
    ("DeepSeek-V4.1, Pi", "#2a78d6", "o", [21, 22, 20]),
    ("GLM-5.3, Claude Code", "#eb6834", "o", [20, 22, 20]),
    ("Qwen3.8, Claude Code", "#1baf7a", "o", [13, 14, 15]),
    ("Qwen3.8, Codex CLI", "#1baf7a", "s", [9, 18, 16]),
    ("Qwen3.8, Pi", "#1baf7a", "^", [3, 12, 10]),
]
INK, INK2, MUTED, GRID = "#0b0b0b", "#52514e", "#898781", "#e1e0d9"


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


plt.rcParams.update({"font.family": "sans-serif", "font.size": 9.5, "axes.labelsize": 9.5, "xtick.labelsize": 9.5, "ytick.labelsize": 9.5, "legend.fontsize": 9})
fig, ax = plt.subplots(figsize=(6.5, 4), facecolor="white")
ax.set_facecolor("white")
offsets = [-0.09, -0.045, 0.0, 0.045, 0.09]
for (label, color, marker, counts), off in zip(SERIES, offsets):
    xs = [i + off for i in range(3)]
    ys = [100 * k / n for k, (_, n, _) in zip(counts, BINS)]
    lo = [max(0.0, y - 100 * wilson(k, n)[0]) for y, k, (_, n, _) in zip(ys, counts, BINS)]
    hi = [max(0.0, 100 * wilson(k, n)[1] - y) for y, k, (_, n, _) in zip(ys, counts, BINS)]
    ax.errorbar(xs, ys, yerr=[lo, hi], color=color, lw=1.75, marker=marker, ms=6, mfc="white", mew=1.75, capsize=2, elinewidth=0.8, ecolor=color, zorder=3)

# right-end labels in dark grey, nudged apart where they would collide
ends = sorted(((100 * c[-1] / BINS[-1][1], s[0]) for s, c in ((s, s[3]) for s in SERIES)), reverse=True)
placed = []
for y, label in ends:
    yy = y
    for py in placed:
        if abs(yy - py) < 6:
            yy = py - 6
    placed.append(yy)
    ax.annotate(label, xy=(2 + 0.09, y), xytext=(2.22, yy), textcoords="data", color=INK2, fontsize=9, va="center", ha="left",
                arrowprops=dict(arrowstyle="-", color=GRID, lw=0.8, shrinkA=0, shrinkB=2) if abs(yy - y) > 0.5 else None)

ax.set_xlim(-0.35, 3.3)
ax.set_xticks(range(3))
ax.set_xticklabels([f"{b}\n({solv} of 12)" for b, n, solv in BINS], color=INK2)
ax.set_xlabel("Task difficulty: no-cheat runs (of 12, retrieval impossible) that solved the task\n21 / 22 / 21 tasks per bin", color=INK2, labelpad=6, fontsize=8.5)
ax.set_ylim(0, 104)  # headroom so markers at 100% are not clipped
ax.set_yticks(range(0, 101, 25))
ax.set_ylabel("Runs that reached the fix (%)", color=INK2)
ax.yaxis.grid(True, color=GRID, lw=0.8)
ax.set_axisbelow(True)
for sp in ("top", "right"):
    ax.spines[sp].set_visible(False)
for sp in ("left", "bottom"):
    ax.spines[sp].set_color(MUTED)
ax.tick_params(colors=MUTED, length=0)
for t in ax.get_xticklabels() + ax.get_yticklabels():
    t.set_color(INK2)

from matplotlib.lines import Line2D
handles = [Line2D([], [], color=c, lw=1.75, marker="o", ms=5, mfc="white", mew=1.5, label=l) for l, c in (("DeepSeek-V4.1", "#2a78d6"), ("GLM-5.3", "#eb6834"), ("Qwen3.8", "#1baf7a"))]
ax.text(0.07, 92, "DeepSeek and GLM:\nat ceiling in every bin", color=INK2, fontsize=8.5, ha="left", va="top")
ax.annotate("Qwen3.8: fewer lookups\non the easy tasks", xy=(0.14, 24), xytext=(0.55, 10), color=INK2, fontsize=8.5, ha="left", va="center",
            arrowprops=dict(arrowstyle="-", color=MUTED, lw=0.8, shrinkB=3))
ax.legend(handles=handles, loc="lower right", frameon=False, labelcolor=INK2, handlelength=1.6)  # harness is given by the right-end label of each line
fig.tight_layout()
fig.savefig(os.path.join(HERE, "retrieval_by_difficulty.png"), dpi=300)
fig.savefig(os.path.join(HERE, "retrieval_by_difficulty.svg"))

print("| Model, harness | " + " | ".join(f"{b} (n={n})" for b, n, _ in BINS) + " |")
print("|---|" + "---|" * 3)
for label, _, _, counts in SERIES:
    cells = []
    for k, (_, n, _) in zip(counts, BINS):
        lo, hi = wilson(k, n)
        cells.append(f"{k}/{n} = {100 * k / n:.0f}% [{100 * lo:.0f}–{100 * hi:.0f}]")
    print(f"| {label} | " + " | ".join(cells) + " |")
