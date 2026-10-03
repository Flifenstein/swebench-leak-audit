"""Where each model x arm bundle lives on disk. Edit paths here only."""
import os
P = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = os.path.expanduser("~/Downloads")
HB = D + "/harness blogpost"
# (model, arm, bundle root, {harness: logs subdir / results prefix})
BUNDLES = [
    ("Astra", "DEFAULT", P + "/astra", {"codex": "codex-default"}),
    ("Astra", "NO-CHEAT", P + "/astra", {"codex": "codex-no-cheat"}),
    ("Fable", "DEFAULT", P + "/fable", {"claude": "claude-default"}),
    ("Fable", "NO-CHEAT", P + "/fable", {"claude": "claude-no-cheat"}),
    ("DeepSeek", "DEFAULT", P + "/deepseek", {"pi": "pi-default"}),
    ("DeepSeek", "NO-CHEAT", P + "/deepseek", {"pi": "pi-no-cheat"}),
    ("GLM", "DEFAULT", HB + "/benchy-leak-audit-2026-08-31-glm53-flash-ox-alpha-harness-accuracy-sweep-s1", None),
    ("GLM", "NO-CHEAT", HB + "/benchy-leak-audit-2026-09-01-glm53-flash-no-git-appended-prompt", None),
    ("Qwen3.8", "DEFAULT", D + "/benchy-leak-audit-2026-08-27-harness-calibration-qwen38-xhigh-s3", None),
    ("Qwen3.8", "SCRUB-ONLY", HB + "/qwen3.8 files audit", None),
    ("Qwen3.8", "NO-CHEAT", HB + "/benchy-leak-audit-2026-09-01-qwen38-no-git-appended-prompt", None),
    ("Qwen3.6", "DEFAULT", D + "/benchy-leak-audit-2026-08-28-harness-calibration-qwen36-xhigh-s1", None),
    ("Qwen3.6", "NO-CHEAT", HB + "/benchy-leak-audit-2026-09-01-qwen36-no-git-appended-prompt", None),
]
HARNESSES = ["claude", "codex", "dsh", "opencode", "pi"]
