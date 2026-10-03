# Data matrix (step 0)

One row per model x harness x arm found on disk or expected by the scope list. Nothing is imputed.

| model | harness | arm | transcripts | results | abandoned | reasoning text present | event source | flags |
|---|---|---|---|---|---|---|---|---|
| Astra | codex | DEFAULT | 63 | 64 | 1 | no | log:63 |  |
| Astra | codex | NO-CHEAT | 64 | 64 | 0 | no | log:64 |  |
| Fable | claude | DEFAULT | 64 | 64 | 0 | yes | log:64 |  |
| Fable | claude | NO-CHEAT | 64 | 64 | 0 | yes | log:64 |  |
| DeepSeek | pi | DEFAULT | 64 | 64 | 0 | yes | log:64 |  |
| DeepSeek | pi | NO-CHEAT | 63 | 64 | 1 | yes | log:63 |  |
| GLM | claude | DEFAULT | 64 | 64 | 0 | yes | log:64 |  |
| GLM | claude | NO-CHEAT | 64 | 64 | 0 | yes | log:64 |  |
| GLM | codex | DEFAULT | 64 | 64 | 0 | yes | trajectory-parquet:64 | orchestrator log is lossy (16% of tool calls missing); events read from trajectories/*.parquet for 64 runs |
| GLM | codex | NO-CHEAT | 64 | 64 | 0 | no | log:64 | raw-stdout log, 38 cut-off rows, no session file to recover from: counts are lower bounds |
| GLM | dsh | DEFAULT | 64 | 64 | 0 | yes | log:64 |  |
| GLM | opencode | DEFAULT | 64 | 64 | 0 | no | log:64 | raw-stdout log, 31 cut-off rows, no session file to recover from: counts are lower bounds |
| GLM | pi | DEFAULT | 64 | 64 | 0 | yes | log:64 |  |
| GLM | pi | NO-CHEAT | 64 | 64 | 1 | yes | log:64 | 64 transcripts for 64 results (1 abandoned); raw-stdout log, 22 cut-off rows, no session file to recover from: counts are lower bounds |
| Qwen3.8 | claude | DEFAULT | 64 | 64 | 0 | yes | log:64 |  |
| Qwen3.8 | claude | SCRUB-ONLY | 64 | 64 | 0 | yes | log:64 |  |
| Qwen3.8 | claude | NO-CHEAT | 64 | 64 | 0 | yes | log:64 |  |
| Qwen3.8 | codex | DEFAULT | 64 | 64 | 0 | yes | trajectory-parquet:64 | orchestrator log is lossy (6% of tool calls missing); events read from trajectories/*.parquet for 64 runs |
| Qwen3.8 | codex | SCRUB-ONLY | 64 | 64 | 0 | yes | trajectory-parquet:64 | orchestrator log is lossy (7% of tool calls missing); events read from trajectories/*.parquet for 64 runs |
| Qwen3.8 | codex | NO-CHEAT | 64 | 64 | 0 | yes | trajectory-parquet:63, log:1 | orchestrator log is lossy (6% of tool calls missing); events read from trajectories/*.parquet for 63 runs |
| Qwen3.8 | dsh | DEFAULT | 64 | 64 | 0 | yes | log:64 |  |
| Qwen3.8 | dsh | SCRUB-ONLY | 64 | 64 | 0 | yes | log:64 |  |
| Qwen3.8 | opencode | DEFAULT | 64 | 64 | 0 | no | log:64 | raw-stdout log, 41 cut-off rows, no session file to recover from: counts are lower bounds |
| Qwen3.8 | opencode | SCRUB-ONLY | 64 | 64 | 0 | no | log:64 | raw-stdout log, 54 cut-off rows, no session file to recover from: counts are lower bounds |
| Qwen3.8 | pi | DEFAULT | 64 | 64 | 0 | yes | trajectory-parquet:64 | orchestrator log is lossy (34% of tool calls missing); events read from trajectories/*.parquet for 64 runs |
| Qwen3.8 | pi | SCRUB-ONLY | 64 | 64 | 0 | yes | log:64 |  |
| Qwen3.8 | pi | NO-CHEAT | 63 | 64 | 1 | yes | log:63 |  |
| Qwen3.6 | claude | DEFAULT | 64 | 64 | 0 | yes | log:64 |  |
| Qwen3.6 | claude | NO-CHEAT | 64 | 64 | 0 | yes | log:64 |  |
| Qwen3.6 | codex | DEFAULT | 64 | 64 | 0 | yes | trajectory-parquet:61, log:3 | orchestrator log is lossy (6% of tool calls missing); events read from trajectories/*.parquet for 61 runs |
| Qwen3.6 | codex | NO-CHEAT | 64 | 64 | 0 | yes | trajectory-parquet:63, log:1 | orchestrator log is lossy (7% of tool calls missing); events read from trajectories/*.parquet for 63 runs |
| Qwen3.6 | dsh | DEFAULT | 64 | 64 | 0 | yes | log:64 |  |
| Qwen3.6 | opencode | DEFAULT | 64 | 64 | 0 | no | log:64 | raw-stdout log, 39 cut-off rows, no session file to recover from: counts are lower bounds |
| Qwen3.6 | pi | DEFAULT | 64 | 64 | 0 | yes | trajectory-parquet:62, log:2 | orchestrator log is lossy (8% of tool calls missing); events read from trajectories/*.parquet for 62 runs |
| Qwen3.6 | pi | NO-CHEAT | 64 | 64 | 0 | yes | log:64 |  |

Total transcripts: 2237. Total result rows: 2240.

## Notes

- `reasoning text present = yes` on a codex row means the session file holds plaintext reasoning (self-hosted models); since round 2 those runs count as reasoning-visible (marked † in summary.md).
- OpenCode logs carry assistant text and tool calls only (no reasoning stream) and no session file was exported.
