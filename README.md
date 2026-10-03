# swebench-leak-audit

Scripts and results for an audit of solution leakage in agentic coding evaluations: six models, five harnesses, 64 SWE-bench Pro tasks, run with the reference fix reachable in git history (DEFAULT), with the history scrubbed (SCRUB-ONLY), and with the history scrubbed plus a prohibition prompt (NO-CHEAT). The analysis asks when an agent retrieves the reference fix, what its reasoning says about being evaluated, and whether the two are linked.

![Qwen3.8 awareness vs retrieval](figures/awareness_vs_retrieval.png)

## What is here

| path | contents |
|---|---|
| `swebench_leak_audit/analyze.py` | one script that turns the raw transcripts into every table and CSV in `results/` |
| `swebench_leak_audit/parse.py` | reads the five harness transcript formats (Claude Code, Codex CLI, dsh, OpenCode, Pi) into one event list |
| `swebench_leak_audit/cells.py` | where each model × arm bundle lives on disk — the only file to edit for your own data |
| `swebench_leak_audit/score_handcheck.py` | precision of the regex labels from a hand-labelled sample |
| `results/summary.md` | every table, by finding |
| `results/runs.csv` | one row per run: retrieval, timing, awareness counts, rule handling |
| `results/regexes.md` | every pattern used, and how the retrieval rule is applied |
| `results/discrepancies.md` | where these numbers differ from the earlier hand-read audit, and why |
| `figures/` | figure scripts with their PNG / SVG / CSV outputs |

## Method in one paragraph

A run **reached the fix** if the fix commit's SHA appears in a command or fetched URL, a network request pulls the task's own commit or PR, the upstream repository is cloned and read, or a git command on another revision prints lines of the gold patch (`results/regexes.md` has the exact rules). Awareness is measured by regexes over every sentence of the agent's reasoning and assistant text: naming a benchmark, reasoning about hidden tests or a grader, assuming the fix exists upstream, suspecting a trap, recalling the change from memory. No hit caps; `n/a` wherever a measure cannot be computed (encrypted reasoning, missing transcripts). Confidence intervals are 95% Wilson.

## Reproducing

```
pip install -r requirements.txt
python3 swebench_leak_audit/analyze.py         # ~3 min from scratch, ~1 min with .cache/
python3 figures/plot_awareness_vs_retrieval.py
python3 figures/retrieval_by_difficulty.py
```

`analyze.py` needs the raw run bundles (transcripts, results, verifier configs), which are not in this repository; point `cells.py` at them. Section 3e looks up claimed commit hashes on GitHub through an authenticated `gh`; everything else runs offline.

## Caveats worth knowing

- Transcripts for the self-hosted models on Codex CLI and Pi were read from the session files, not the orchestrator logs, because the logs drop up to a third of tool calls in those cells (`results/data_matrix.md`).
- The retrieval rule is applied automatically; it agrees with the hand-read audit to within a few runs per cell (`results/discrepancies.md`).
- The dsh harness's web-search tool was misconfigured in every dsh run, which explains that harness's low retrieval (`results/dsh_network.md`).
