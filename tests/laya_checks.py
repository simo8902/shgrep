"""User-run Laya checks against the real llama-server with the Laya GGUF; nothing is mocked.
Usage: python tests/laya_checks.py build-rel/shgrep.exe [--port 8080]
Start llama-server first, e.g. llama-server -m Laya-Q8_0.gguf -ngl 99 -c 8192 -np 4 --port 8080.
Checks transport, ranking contract and failure handling. retrieval_eval.py measures retrieval quality.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time

from laya_fixture import require_server
from lsp_smoke import Client

INTERVALS = '''def merge_intervals(intervals):
    """Merge overlapping intervals into one sorted list."""
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged
'''
CIRCLE = '''def draw_circle(canvas, x, y, radius, color):
    """Paint a filled circle on the canvas."""
    for dy in range(-radius, radius + 1):
        for dx in range(-radius, radius + 1):
            if dx * dx + dy * dy <= radius * radius:
                canvas.set_pixel(x + dx, y + dy, color)
'''
INTENT = "merge overlapping intervals into one sorted list"
LONG = 120000  # budget large enough that a CPU-only server still scores every candidate


def environment(port, **settings):
    return {**os.environ, "SHGREP_LAYA_PORT": str(port), **{key: str(value) for key, value in settings.items()}}


def search(client, arguments, error=False):
    result = client.call("tools/call", {"name": "search", "arguments": {"operation": "text", "timeout_ms": 300000, **arguments}})
    assert bool(result.get("isError")) == error, result
    return result["content"][0]["text"]


def check_ranking(executable, port, root):
    client = Client(executable, root, regression_laya=False, timeout=330, environment=environment(port, SHGREP_LAYA_BUDGET_MS=LONG))
    try:
        missing = search(client, {"pattern": "def "}, error=True)
        assert "intent" in missing, missing

        data = json.loads(search(client, {"pattern": "def ", "intent": INTENT, "output": "json", "include": ["*.py"],
                                          "path": "pair"}))
        laya = data["laya"]
        assert laya["required"] and laya["mode"] == "laya", laya
        # Fewer than 3 pass P >= 0.5, so the minimum of 3 keeps both.
        assert laya["candidates"] == 2 and laya["scored"] == 2 and laya["returned"] == 2, laya
        assert laya["model"], laya
        top = data["results"][0]
        assert Path(top["path"]).name == "intervals.py", data["results"]
        assert top["laya"]["rank"] == 1 and 0 <= top["laya"]["p"] <= 1, top
        for item in data["results"]:
            print(f"  P(relevant) {Path(item['path']).name}: {item['laya']['p']:.3f} score {item['laya']['score']:.3f}")

        text = search(client, {"pattern": "def ", "intent": INTENT, "include": ["*.py"], "path": "pair"})
        assert text.startswith("[laya selection "), text
        body = [line for line in text.splitlines()[1:] if line and not line.startswith("[")]
        # Hunks keep their original path:line: prefixes and come best first.
        assert "intervals.py:1:def merge_intervals" in body[0], body
    finally:
        client.close()


def check_limits(executable, port, root):
    client = Client(executable, root, regression_laya=False, timeout=330, environment=environment(port, SHGREP_LAYA_BUDGET_MS=LONG))
    try:
        data = json.loads(search(client, {"pattern": "def handler_", "intent": "handle the request for user 7",
                                          "output": "json", "path": "many"}))
        laya = data["laya"]
        assert laya["candidates"] == 30 and laya["pool"] == 24, laya
        assert laya["scored"] == 16 and laya["unscored"] == 0 and laya["mode"] == "laya", laya
        # P >= 0.5 keeps between 3 (the minimum) and 10 (the return limit).
        assert 3 <= laya["returned"] <= 10 and len(data["results"]) == laya["returned"], laya
        ranks = [item["laya"]["rank"] for item in data["results"]]
        assert ranks == list(range(1, laya["returned"] + 1)), ranks
        passing = [item for item in data["results"] if item["laya"]["p"] >= 0.5]
        assert len(passing) == len(data["results"]) or laya["returned"] == 3, data["results"]
        print(f"  16 decisions in {laya['laya_ms']} ms with {laya['parallel']} parallel slots, {laya['returned']} kept")

        limited = json.loads(search(client, {"pattern": "def handler_", "intent": "handle the request for user 7",
                                             "output": "json", "path": "many", "max_results": 2}))
        assert len(limited["results"]) == 2 and limited["summary"]["truncated"], limited["summary"]
    finally:
        client.close()

    # A tiny budget is not an error: unscored candidates keep keyword order below scored ones.
    client = Client(executable, root, regression_laya=False, timeout=330, environment=environment(port, SHGREP_LAYA_BUDGET_MS=1))
    try:
        data = json.loads(search(client, {"pattern": "def handler_", "intent": "handle the request for user 7",
                                          "output": "json", "path": "many"}))
        assert data["laya"]["mode"] in ("lexical", "laya-partial"), data["laya"]
        assert data["laya"]["returned"] >= 1 and data["laya"]["unscored"] > 0, data["laya"]
    finally:
        client.close()


def check_unreachable(executable, root):
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        client = Client(executable, root, regression_laya=False, environment=environment(reserved.getsockname()[1]))
        try:
            text = search(client, {"pattern": "def ", "intent": INTENT}, error=True)
            assert "LAYA_REQUIRED" in text and "merge_intervals" not in text, text
        finally:
            client.close()


def check_cancel_and_freshness(executable, port, root):
    # Every one of 400 candidates is scored, so the search is still inside Laya when the checks act.
    settings = {"SHGREP_LAYA_BUDGET_MS": LONG, "SHGREP_LAYA_POOL": 0, "SHGREP_LAYA_SCORE": 0}
    client = Client(executable, root, regression_laya=False, timeout=330, environment=environment(port, **settings))
    try:
        response = []
        thread = threading.Thread(target=lambda: response.append(client.call("tools/call", {"name": "search", "arguments": {
            "operation": "text", "pattern": "def worker_", "intent": "start the worker", "path": "bulk", "timeout_ms": 300000}})))
        thread.start()
        time.sleep(1.0)
        client.process.stdin.write((json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled",
                                                "params": {"requestId": client.next_id}}) + "\n").encode())
        client.process.stdin.flush()
        thread.join(timeout=30)
        assert not thread.is_alive() and response and response[0].get("isError"), response
        assert "cancel" in response[0]["content"][0]["text"].lower(), response
    finally:
        client.close()

    # A file edited while Laya runs is never returned stale. The 20 s timeout caps Laya at 10 s on slow servers.
    client = Client(executable, root, regression_laya=False, timeout=330, environment=environment(port, **settings))
    target = root / "bulk" / "worker_0.py"
    original = target.read_text(encoding="utf-8")
    try:
        response = []
        thread = threading.Thread(target=lambda: response.append(client.call("tools/call", {"name": "search", "arguments": {
            "operation": "text", "pattern": "def worker_", "intent": "start the worker", "path": "bulk", "timeout_ms": 20000}})))
        thread.start()
        time.sleep(1.0)
        target.write_text(original + "def worker_changed_during_inference():\n    pass\n", encoding="utf-8")
        thread.join(timeout=60)
        assert not thread.is_alive() and response and response[0].get("isError"), response
        assert "changed during selection" in response[0]["content"][0]["text"], response
    finally:
        target.write_text(original, encoding="utf-8")
        client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--port", type=int, default=int(os.environ.get("SHGREP_LAYA_PORT", "8080")))
    args = parser.parse_args()
    props = require_server(args.port)
    print(f"llama-server {props.get('model_alias')} with {props.get('total_slots')} slots on port {args.port}")
    executable = args.executable.resolve()
    with tempfile.TemporaryDirectory(prefix="shgrep-laya-", ignore_cleanup_errors=True) as folder:
        root = Path(folder)
        (root / ".shgrep").mkdir()
        (root / ".shgrep/lsp.json").write_text('{"servers":[],"bundled":false}', encoding="utf-8")
        for name, folder_name, count in (("handler", "many", 30), ("worker", "bulk", 400)):
            (root / folder_name).mkdir()
            for i in range(count):
                (root / folder_name / f"{name}_{i}.py").write_text(
                    f"def {name}_{i}(request):\n    return request.reply({i})\n", encoding="utf-8")
        (root / "pair").mkdir()
        (root / "pair/intervals.py").write_text(INTERVALS, encoding="utf-8")
        (root / "pair/render.py").write_text(CIRCLE, encoding="utf-8")
        steps = [("ranking", lambda: check_ranking(executable, args.port, root)),
                 ("limits and budget", lambda: check_limits(executable, args.port, root)),
                 ("unreachable server", lambda: check_unreachable(executable, root)),
                 ("cancel and freshness", lambda: check_cancel_and_freshness(executable, args.port, root))]
        for label, step in steps:
            started = time.monotonic()
            step()
            print(f"ok  {label} ({time.monotonic() - started:.1f} s)")
    print("Laya checks passed against the real model")


if __name__ == "__main__":
    sys.exit(main())
