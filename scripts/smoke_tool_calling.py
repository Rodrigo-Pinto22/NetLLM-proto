"""Phase 0 go/no-go: does the local model call the pcap tools correctly?

Uses the real tool signatures/docstrings with canned outputs, so it needs Ollama but not tshark.
Each case checks the first tool call (name + key args). Exit code 0 = GO.

    uv run scripts/smoke_tool_calling.py --trials 5 --threshold 0.8
"""

from __future__ import annotations

import argparse
import json
import sys

import ollama

from netllm.config import get_settings
from netllm.pcap import tools

PCAP = "data/traces/tcp-wireshark-trace1-1.pcapng"

CASES = [
    ("What conversations are in {pcap}?", "list_flows", {}),
    ("Show me every field of packet 4 in {pcap}.", "packet_detail", {"number": 4}),
    ("In {pcap}, which packets are TCP SYNs? Use a display filter.", "apply_filter", {"display_filter": "syn"}),
    ("Show the three-way handshake of TCP stream 0 in {pcap}.", "tcp_handshake", {"stream": 0}),
]


def check(call, want_name: str, want_args: dict) -> tuple[bool, str]:
    if call is None:
        return False, "no tool call"
    name, args = call.function.name, dict(call.function.arguments)
    if name != want_name:
        return False, f"called {name}"
    for k, v in want_args.items():
        got = args.get(k)
        # Strings: substring match (filters can be written several valid ways); others: equality.
        ok = (isinstance(v, str) and v in str(got)) or str(got) == str(v)
        if not ok:
            return False, f"{k}={got!r}"
    return True, json.dumps(args)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=None)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--threshold", type=float, default=0.8)
    args = ap.parse_args()

    s = get_settings()
    model = args.model or s.chat_model
    client = ollama.Client(host=s.ollama_host)

    passed = total = 0
    for prompt, want_name, want_args in CASES:
        for t in range(args.trials):
            resp = client.chat(model=model, tools=tools.TOOLS, options={"temperature": 0.2},
                               messages=[{"role": "user", "content": prompt.format(pcap=PCAP)}])
            calls = resp.message.tool_calls or []
            ok, info = check(calls[0] if calls else None, want_name, want_args)
            passed += ok
            total += 1
            print(f"{'PASS' if ok else 'FAIL'}  {want_name:14s} #{t + 1}  {info}")

    rate = passed / total
    verdict = "GO" if rate >= args.threshold else "NO-GO"
    print(f"\n{model}: {passed}/{total} = {rate:.0%}  (threshold {args.threshold:.0%})  -> {verdict}")
    return 0 if verdict == "GO" else 1


if __name__ == "__main__":
    sys.exit(main())
