"""Turn every per-task orchestrator log (logs/<harness>/<task>.jsonl) into one flat event list.

Event kinds: user, sys, think (reasoning), say (assistant text), call (tool call, with its output attached).
`L` is the `line` field of the log row (the anchor used in the HTML viewers). Rows without a line number
inherit the last numbered line and are marked approx=True (cited as L~n).
"""
import glob, json, os, pickle, re
from cells import BUNDLES, HARNESSES, P

CACHE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".cache", "transcripts")
STAGE = re.compile(r'stage=(\w+) stream="(\w+)" line=')
SHELL = {"bash", "exec_command", "shell", "command_execution", "exec", "local_shell"}
WRITE = {"edit", "write", "multiedit", "str_replace_editor", "apply_patch", "file_change", "notebookedit"}
READ = {"read", "grep", "glob", "view", "ls"}
WEB = {"webfetch", "web_fetch", "websearch", "web_search", "fetch"}


def task_key(task_id):
    return task_id.split("@")[0]


def _text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in content)
    return "" if content is None else str(content)


def _salvage(body):
    """Best effort for a JSON line cut off by the log pipeline: recover type + the main string field."""
    ev = {"_truncated": True}
    m = re.search(r'"type":"([^"]+)"', body)
    ev["type"] = m.group(1) if m else None
    for key in ("command", "text", "thinking", "output", "aggregated_output"):
        m = re.search(r'"%s":"((?:[^"\\]|\\.)*)' % key, body)
        if m:
            s = m.group(1)
            try:
                ev[key] = json.loads('"' + s.rstrip("\\") + '"')
            except Exception:
                ev[key] = s.replace("\\n", "\n").replace('\\"', '"')
    return ev


def patch_parts(txt):
    """(paths, added text) from an apply_patch envelope."""
    txt = txt.replace("\\n", "\n")
    paths = re.findall(r"\*\*\* (?:Update|Add|Delete) File: (\S+)", txt)
    added = "\n".join(l[1:] for l in txt.split("\n") if l.startswith("+") and not l.startswith("+++"))
    return paths, added


def norm_call(name, args, cmd=None):
    """Uniform view of a tool call: tool, shell, cmd (string to regex), paths, url, new (text written)."""
    tool = (name or "").lower()
    args = args if isinstance(args, dict) else {}
    c = {"tool": tool, "shell": tool in SHELL, "paths": [], "url": "", "new": "", "cmd": ""}
    if c["shell"]:
        c["cmd"] = cmd if cmd is not None else _text(args.get("command") or args.get("cmd") or "")
        if "*** Begin Patch" in c["cmd"]:
            c["paths"], c["new"] = patch_parts(c["cmd"])
        return c
    p = args.get("file_path") or args.get("path") or args.get("filePath") or ""
    if p:
        c["paths"] = [p]
    c["url"] = args.get("url") or ""
    q = args.get("query") or args.get("queries") or ""
    q = " | ".join(q) if isinstance(q, list) else q
    if tool in WRITE:
        new = [args.get(k, "") for k in ("content", "new_string", "newString", "new_str", "file_text")]
        new += [e.get("newText", "") for e in args.get("edits", []) if isinstance(e, dict)]
        c["new"] = "\n".join(x for x in new if isinstance(x, str) and x)
        if "script" in args or tool == "apply_patch":
            c["paths"], c["new"] = patch_parts(_text(args.get("script") or args.get("input") or cmd or ""))
        if "changes" in args:
            c["paths"] = [x.get("path", "") for x in args["changes"]]
    if not c["paths"] and tool in WRITE | READ and cmd:  # old dsh rows keep only the summary string
        m = re.match(r"\w+\s+(\S+)", cmd)
        c["paths"] = [m.group(1)] if m else []
    c["cmd"] = " ".join(x for x in (tool, c["url"], q, " ".join(c["paths"]), _text(args.get("pattern") or "")) if x)
    return c


def parse_run(path, harness):
    ev, calls, seen_calls, seen_msgs, last_L = [], {}, set(), set(), 0
    meta = {"tools": None, "final": None, "truncated_rows": 0}

    def add(kind, L, approx, text="", **kw):
        if kind != "call" and not (text or "").strip():
            return None
        e = dict(k=kind, L=L, approx=approx, t=text or "", **kw)
        ev.append(e)
        return e

    def call(L, approx, cid, name, args, cmd=None):
        if cid is not None and (cid, name) in seen_calls:  # item.started / item.completed of the same call
            return calls[cid]
        e = add("call", L, approx, out="", **norm_call(name, args, cmd))
        if cid is not None:
            seen_calls.add((cid, name))
            calls.setdefault(cid, e)  # Astra runs several tools inside one script call: output goes to the first
        return e

    def out(cid, text):
        if cid in calls and not calls[cid]["out"]:
            calls[cid]["out"] = _text(text)

    def assistant_parts(L, approx, parts):
        for c in parts or []:
            ty = c.get("type")
            if ty == "thinking":
                add("think", L, approx, c.get("thinking", ""))
            elif ty == "text":
                add("say", L, approx, c.get("text", ""))
            elif ty == "tool_use":
                call(L, approx, c.get("id"), c.get("name"), c.get("input"))
            elif ty == "toolCall":
                call(L, approx, c.get("id"), c.get("name"), c.get("arguments"))

    with open(path, errors="replace") as fh:
        for raw in fh:
            if 'line={\\"type\\":\\"message_update' in raw or 'line={\\"type\\":\\"tool_execution_update' in raw:
                continue  # Pi token-stream deltas; the complete message arrives in message_end
            r = json.loads(raw)
            t = r["text"]
            approx = r.get("line") is None
            if not approx:
                last_L = r["line"]
            L = last_L
            m = STAGE.search(t)
            if not m or m.group(1) != "agent":
                continue
            body = t[m.end():]
            if not body.startswith("{"):
                continue
            try:
                e = json.loads(body)
            except Exception:
                e = _salvage(body)
                meta["truncated_rows"] += 1
            if not isinstance(e, dict):
                continue
            ty = e.get("type")
            if e.get("_truncated"):  # keep what is recoverable as the right kind
                if "command" in e:
                    call(L, approx, None, "bash", {}, e["command"])
                elif "thinking" in e:
                    add("think", L, approx, e["thinking"])
                elif "text" in e and ty in ("assistant", "reasoning", "text", "item.completed"):
                    add("think" if ty == "reasoning" else "say", L, approx, e["text"])
                continue
            # --- normalized trajectory (pi/dsh everywhere; claude/codex in the 2026-09-17 bundles)
            if m.group(2) == "trajectory":
                if ty == "user":
                    add("user", L, approx, e.get("text", ""))
                elif ty == "system_prompt":
                    add("sys", L, approx, e.get("text", ""))
                elif ty == "assistant":
                    add("say", L, approx, e.get("text", ""))
                elif ty == "reasoning":
                    add("think", L, approx, e.get("text", ""))
                elif ty == "tool_call":
                    call(L, approx, e.get("callId"), e.get("name"), e.get("args"), e.get("command"))
                elif ty == "tool_result":
                    out(e.get("callId"), e.get("output"))
            # --- Claude Code stream-json
            elif ty == "system" and e.get("subtype") == "init":
                meta["tools"] = e.get("tools")
            elif ty == "assistant" and "message" in e:
                assistant_parts(L, approx, e["message"].get("content"))
            elif ty == "user" and "message" in e:
                for c in e["message"].get("content") or []:
                    if isinstance(c, dict) and c.get("type") == "tool_result":
                        out(c.get("tool_use_id"), c.get("content"))
            elif ty == "result":
                meta["final"] = e.get("result")
            # --- Codex exec --json
            elif ty in ("item.started", "item.completed", "item.updated"):
                it = e.get("item") or {}
                ity = it.get("type")
                if ity == "command_execution":
                    call(L, approx, it.get("id"), "command_execution", {}, it.get("command", ""))
                    if ty == "item.completed":
                        out(it.get("id"), it.get("aggregated_output"))
                elif ity == "file_change":
                    call(L, approx, it.get("id"), "file_change", {"changes": it.get("changes", [])})
                elif ity == "agent_message" and ty == "item.completed":
                    add("say", L, approx, it.get("text", ""))
                elif ity == "reasoning" and ty == "item.completed":
                    add("think", L, approx, it.get("text", ""))
            # --- OpenCode run --format json
            elif ty == "text" and "part" in e:
                add("say", L, approx, e["part"].get("text", ""))
            elif ty == "reasoning" and "part" in e:
                add("think", L, approx, e["part"].get("text", ""))
            elif ty == "tool_use" and "part" in e:
                p = e["part"]
                st = p.get("state") or {}
                c = call(L, approx, p.get("callID"), p.get("tool"), st.get("input"))
                out(p.get("callID"), st.get("output"))
            # --- Pi --mode json (streaming)
            elif ty in ("message_end", "turn_end") and isinstance(e.get("message"), dict):
                msg = e["message"]
                sig = (msg.get("role"), msg.get("timestamp"), msg.get("toolCallId"), str(msg.get("content"))[:200])
                if sig in seen_msgs:
                    continue
                seen_msgs.add(sig)
                if msg.get("role") == "assistant":
                    assistant_parts(L, approx, msg.get("content"))
                elif msg.get("role") == "user":
                    add("user", L, approx, _text(msg.get("content")))
                elif msg.get("role") == "toolResult":
                    out(msg.get("toolCallId"), msg.get("content"))
            elif ty == "tool_execution_end":
                out(e.get("toolCallId"), (e.get("result") or {}).get("content"))
    n = 0
    for e in ev:  # idx = number of tool calls made so far; a call's own idx is its 1-based number
        if e["k"] == "call":
            n += 1
        e["idx"] = n
    meta["n_calls"] = n
    return ev, meta


def parse_traj(text, fmt):
    """Events from a raw session file in trajectories/*.parquet (complete, but without log line anchors)."""
    ev, calls = [], {}
    meta = {"tools": None, "final": None, "truncated_rows": 0}

    def add(kind, text="", **kw):
        if kind == "call" or (text or "").strip():
            ev.append(dict(k=kind, L=0, approx=True, t=text or "", **kw))
            return ev[-1]

    for l in text.split("\n"):
        if not l.strip():
            continue
        try:
            e = json.loads(l)
        except Exception:
            continue
        ty = e.get("type")
        if fmt == "pi-session" and ty == "message":
            msg = e.get("message") or {}
            if msg.get("role") == "user":
                add("user", _text(msg.get("content")))
            elif msg.get("role") == "toolResult" and msg.get("toolCallId") in calls:
                calls[msg["toolCallId"]]["out"] = _text(msg.get("content"))
            elif msg.get("role") == "assistant":
                for c in msg.get("content") or []:
                    if c.get("type") == "thinking":
                        add("think", c.get("thinking", ""))
                    elif c.get("type") == "text":
                        add("say", c.get("text", ""))
                    elif c.get("type") == "toolCall":
                        calls[c.get("id")] = add("call", out="", **norm_call(c.get("name"), c.get("arguments")))
        elif fmt == "codex-rollout":
            p = e.get("payload") if isinstance(e.get("payload"), dict) else {}
            pt = p.get("type")
            if ty == "session_meta":
                add("sys", _text((p.get("base_instructions") or {}).get("text")))
            elif ty == "event_msg" and pt == "user_message":
                add("user", p.get("message", ""))
            elif ty == "event_msg" and pt == "agent_message":
                add("say", p.get("message", ""))
            elif ty == "response_item" and pt == "reasoning":
                add("think", _text(p.get("content")))  # plaintext for self-hosted models; absent when encrypted
            elif ty == "response_item" and pt in ("function_call", "custom_tool_call", "local_shell_call"):
                a = p.get("arguments") or p.get("input") or p.get("action") or {}
                if isinstance(a, str):
                    try:
                        a = json.loads(a)
                    except Exception:
                        a = {"input": a}
                cmd = a.get("cmd") or a.get("command")
                cmd = (cmd[-1] if cmd and cmd[0] in ("bash", "/bin/bash", "sh") else " ".join(cmd)) if isinstance(cmd, list) else cmd
                name = p.get("name") or "shell"
                calls[p.get("call_id")] = add("call", out="", **norm_call("bash" if cmd is not None and name != "apply_patch" else name, a, cmd))
            elif ty == "response_item" and pt in ("function_call_output", "custom_tool_call_output") and p.get("call_id") in calls:
                calls[p["call_id"]]["out"] = _text(p.get("output"))
            elif ty == "event_msg" and pt == "patch_apply_end" and p.get("call_id") in calls:
                ch = p.get("changes") or {}
                c = calls[p["call_id"]]
                c["paths"] = list(ch)
                c["new"] = "\n".join(x[1:] for v in ch.values() for x in (v.get("unified_diff") or v.get("content") or "").split("\n")
                                     if x.startswith("+") and not x.startswith("+++"))
                c["tool"], c["shell"] = "apply_patch", False
    return ev, meta


def _sig(e):
    s = e.get("cmd") if e["k"] == "call" else e["t"]
    s = re.sub(r"^/bin/bash -lc ", "", s or "")
    return e["k"][0] + re.sub(r"\W", "", s)[:40]


def align(ev, log_ev):
    """Give trajectory events the line anchors of the matching log events (monotone, by kind + text prefix)."""
    pos, last = 0, 0
    sigs = [(_sig(x), x["L"]) for x in log_ev]
    for e in ev:
        s = _sig(e)
        for j in range(pos, min(pos + 60, len(sigs))):
            if sigs[j][0] == s:
                e["L"], e["approx"], pos, last = sigs[j][1], False, j + 1, sigs[j][1]
                break
        else:
            e["L"] = last
    n = 0
    for e in ev:
        if e["k"] == "call":
            n += 1
        e["idx"] = n
    return n


def cells():
    """Yield (model, arm, harness, root, sub) for every cell that could exist."""
    for model, arm, root, hm in BUNDLES:
        for h, sub in (hm or {h: h for h in HARNESSES}).items():
            yield model, arm, h, root, sub


def load_cell(model, arm, h, root, sub):
    """{task_key: (events, meta)} for one cell, cached on disk.

    Codex and Pi runs whose log is the raw CLI stdout lose rows in the log pipeline (up to a third of tool calls),
    so for those the session file in trajectories/*.parquet is the event source and the log only supplies anchors.
    """
    os.makedirs(CACHE, exist_ok=True)
    cf = f"{CACHE}/{model}_{arm}_{h}.pkl"
    files = sorted(glob.glob(f"{root}/logs/{sub}/*.jsonl"))
    if os.path.exists(cf) and os.path.getmtime(cf) > os.path.getmtime(__file__):
        return pickle.load(open(cf, "rb"))
    runs = {task_key(os.path.basename(f)[:-6]): parse_run(f, h) for f in files}
    for ev, meta in runs.values():
        meta["source"] = "log"
    if h in ("codex", "pi") and files and 'stream=\\"trajectory\\"' not in open(files[0]).read(20000):
        import pandas as pd
        for pq in glob.glob(f"{root}/trajectories/{sub}.*.parquet"):
            d = pd.read_parquet(pq)
            col = "text" if "text" in d else "content"
            for _, r in d.iterrows():
                txt = r[col].decode("utf-8", "replace") if isinstance(r[col], (bytes, bytearray)) else r[col]
                k = task_key(r.task_id)
                ev, meta = parse_traj(txt, r.format)
                log_ev, log_meta = runs.get(k, ([], {}))
                if len([e for e in ev if e["k"] == "call"]) < log_meta.get("n_calls", 0):
                    continue  # never trade a fuller log for a shorter session file
                meta.update(n_calls=align(ev, log_ev), source="trajectory-parquet", log_calls=log_meta.get("n_calls", 0))
                runs[k] = (ev, meta)
    pickle.dump(runs, open(cf, "wb"))
    return runs


def load_results(root, sub):
    out = {}
    for f in glob.glob(f"{root}/results/{sub}.*.results.jsonl"):
        for l in open(f):
            d = json.loads(l)
            out[task_key(d["taskId"])] = d
    return out


if __name__ == "__main__":
    import collections, time
    for cell in cells():
        t0 = time.time()
        runs = load_cell(*cell)
        k = collections.Counter(e["k"] for ev, _ in runs.values() for e in ev)
        noout = sum(1 for ev, _ in runs.values() for e in ev if e["k"] == "call" and not e["out"])
        trunc = sum(m["truncated_rows"] for _, m in runs.values())
        src = collections.Counter(m["source"] for _, m in runs.values())
        anch = sum(1 for ev, _ in runs.values() for e in ev if e["approx"]) / max(1, sum(k.values()))
        print(f"{cell[0]:9s} {cell[1]:10s} {cell[2]:8s} runs={len(runs):3d} {dict(k)} no_output={noout} trunc_rows={trunc} src={dict(src)} approx_anchor={anch:.0%} {time.time()-t0:.0f}s")
