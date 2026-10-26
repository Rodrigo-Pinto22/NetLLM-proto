"""Phase 0 go/no-go: does the local model call the pcap tools correctly?

Runs the real tool functions (real signatures and docstrings) on a StubBackend with fixed outputs,
so it needs Ollama but not tshark. Each trial is a full tool loop: the model's calls are executed,
their outputs fed back, until it answers without calling a tool (or --max-steps is hit).

Metrics, per trial (n/a ones are left out of the rate):
  tool selected  first call is the expected tool               (cases that need a tool)
  valid args     every call validates against the signature     (trials that made a call)
  correct args   calls match the expected args, position by position
  call count     number of calls equals the expected number     (cases that need a tool)
  no-tool ok     no call at all                                 (cases that need none)
  pass           exact match with an accepted call sequence

Writes runs/smoke-<timestamp>/{results.jsonl,summary.md,meta.json}. Exit code 0 = every model GO.

    uv run scripts/smoke_tool_calling.py --models gemma4:e2b gemma4:e4b --trials 3
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime
from pathlib import Path

import ollama
import pydantic
import yaml

from netllm.config import get_settings
from netllm.pcap import tools
from netllm.pcap.stub_backend import StubBackend

PCAP = "data/traces/tcp-wireshark-trace1-1.pcapng"
CASES = Path(__file__).with_name("smoke_cases.yaml")
SYSTEM = (
    "You are a networking tutor. When a question is about a specific capture file, inspect it with "
    "the tools. When it can be answered from general networking knowledge, answer directly."
)

_stub = StubBackend()
tools._backend = lambda pcap_path: _stub  # real tool wrappers, fixed outputs
TOOL_BY_NAME = {fn.__name__: pydantic.validate_call(fn) for fn in tools.TOOLS}
METRICS = ["selected", "args_valid", "args_correct", "count_ok", "no_tool_ok", "passed"]


def execute(name: str, args: dict) -> tuple[bool, str]:
    """Run one tool call. Returns (args were valid, content fed back to the model)."""
    fn = TOOL_BY_NAME.get(name)
    if fn is None:
        return False, f"Error: unknown tool {name!r}"
    try:
        return True, json.dumps(fn(**args))
    except pydantic.ValidationError as e:
        return False, f"Error: invalid arguments: {e.errors(include_url=False)}"


def run_trial(client: ollama.Client, model: str, prompt: str, think: bool | None, max_steps: int) -> dict:
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]
    calls: list[dict] = []
    start = time.perf_counter()
    try:
        for _ in range(max_steps):
            resp = client.chat(model=model, messages=messages, tools=tools.TOOLS, think=think,
                               options={"temperature": 0.2})
            messages.append(resp.message)
            if not resp.message.tool_calls:
                return {"calls": calls, "answer": resp.message.content, "error": None,
                        "seconds": time.perf_counter() - start}
            for call in resp.message.tool_calls:
                name, args = call.function.name, dict(call.function.arguments)
                valid, content = execute(name, args)
                calls.append({"name": name, "args": args, "valid": valid})
                messages.append({"role": "tool", "tool_name": name, "content": content})
        error = f"no final answer after {max_steps} steps"
    except ollama.ResponseError as e:
        error = str(e)
    return {"calls": calls, "answer": None, "error": error, "seconds": time.perf_counter() - start}


def arg_matches(got, want) -> bool:
    if isinstance(want, str):
        return want.lower() in str(got).lower()
    return str(got) == str(want)


def call_matches(call: dict, want: dict) -> bool:
    expected = {"pcap_path": PCAP, **want.get("args", {})}
    return call["name"] == want["name"] and all(arg_matches(call["args"].get(k), v) for k, v in expected.items())


def score(case: dict, trial: dict) -> dict:
    calls = trial["calls"]
    seqs = [case["calls"], *case.get("also_ok", [])]
    needs_tool = bool(case["calls"])
    ok = trial["error"] is None
    return {
        "selected": bool(calls) and calls[0]["name"] in {s[0]["name"] for s in seqs} if needs_tool else None,
        "args_valid": all(c["valid"] for c in calls) if calls else None,
        "args_correct": bool(calls) and any(all(call_matches(c, w) for c, w in zip(calls, s)) for s in seqs)
        if needs_tool else None,
        "count_ok": len(calls) in {len(s) for s in seqs} if needs_tool else None,
        "no_tool_ok": not calls if not needs_tool else None,
        "passed": ok and any(len(calls) == len(s) and all(map(call_matches, calls, s)) for s in seqs),
    }


def rate(rows: list[dict], metric: str) -> str:
    vals = [r["metrics"][metric] for r in rows if r["metrics"][metric] is not None]
    return f"{sum(vals)}/{len(vals)} ({sum(vals) / len(vals):.0%})" if vals else "n/a"


def summary_table(rows: list[dict], models: list[str]) -> str:
    head = ["Model", "Tool selected", "Valid args", "Correct args", "Call count", "No-tool OK", "Pass",
            "Errors", "Median s/trial"]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for m in models:
        mr = [r for r in rows if r["model"] == m]
        cells = [m, *(rate(mr, k) for k in METRICS), str(sum(r["error"] is not None for r in mr)),
                 f"{statistics.median(r['seconds'] for r in mr):.1f}"]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def case_table(rows: list[dict], models: list[str], cases: list[dict]) -> str:
    lines = ["| Case | " + " | ".join(models) + " |", "|" + "---|" * (len(models) + 1)]
    for c in cases:
        cells = []
        for m in models:
            cr = [r for r in rows if r["model"] == m and r["case"] == c["id"]]
            cells.append(f"{sum(r['metrics']['passed'] for r in cr)}/{len(cr)}")
        lines.append(f"| {c['id']} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main() -> int:
    s = get_settings()
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=[s.chat_model])
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--threshold", type=float, default=0.8, help="Minimum pass rate for GO")
    ap.add_argument("--think", choices=["default", "on", "off"], default="default")
    ap.add_argument("--max-steps", type=int, default=5)
    ap.add_argument("--host", default=s.ollama_host)
    ap.add_argument("--cases", type=Path, default=CASES)
    ap.add_argument("--only", nargs="*", help="Run only these case ids")
    args = ap.parse_args()

    think = {"default": None, "on": True, "off": False}[args.think]
    cases = yaml.safe_load(args.cases.read_text(encoding="utf-8"))["cases"]
    if args.only:
        cases = [c for c in cases if c["id"] in args.only]
    client = ollama.Client(host=args.host)

    run_dir = s.runs_dir / f"smoke-{datetime.now():%Y%m%d-%H%M%S}"
    run_dir.mkdir(parents=True)
    meta = {"models": args.models, "trials": args.trials, "think": args.think, "max_steps": args.max_steps,
            "host": args.host, "cases": str(args.cases), "n_cases": len(cases), "system": SYSTEM,
            "tools": [fn.__name__ for fn in tools.TOOLS]}
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2))

    rows = []
    with (run_dir / "results.jsonl").open("w") as out:
        for model in args.models:
            for case in cases:
                for t in range(args.trials):
                    trial = run_trial(client, model, case["prompt"].format(pcap=PCAP), think, args.max_steps)
                    row = {"model": model, "case": case["id"], "trial": t + 1, **trial,
                           "metrics": score(case, trial)}
                    rows.append(row)
                    out.write(json.dumps(row) + "\n")
                    out.flush()
                    got = ", ".join(f"{c['name']}({json.dumps(c['args'])})" for c in trial["calls"]) or "-"
                    print(f"{'PASS' if row['metrics']['passed'] else 'FAIL'}  {model:12s} {case['id']:13s} "
                          f"#{t + 1}  {trial['seconds']:5.1f}s  {trial['error'] or got}")

    verdicts = {}
    for m in args.models:
        mr = [r for r in rows if r["model"] == m]
        verdicts[m] = "GO" if sum(r["metrics"]["passed"] for r in mr) / len(mr) >= args.threshold else "NO-GO"
    report = "\n\n".join([
        f"# Tool-calling smoke test, {datetime.now():%Y-%m-%d %H:%M}",
        f"{len(cases)} cases x {args.trials} trials, think={args.think}, threshold {args.threshold:.0%}",
        summary_table(rows, args.models),
        "Verdict: " + ", ".join(f"{m} {v}" for m, v in verdicts.items()),
        "## Pass count per case",
        case_table(rows, args.models, cases),
    ])
    (run_dir / "summary.md").write_text(report + "\n")
    print("\n" + report + f"\n\nWritten to {run_dir}")
    return 0 if all(v == "GO" for v in verdicts.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
