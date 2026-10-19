"""User-run checks of shgrep's keyword ranking; no model, no server.
Usage: python tests/rank_checks.py build-rel/shgrep.exe
Checks: an intent ranks hunks best first, no intent keeps scan order and every finding (SHGREP_REQUIRE_INTENT=0),
the per-file cap and return limit (defaults and SHGREP_RANK_* settings), explicit max_results, bad settings, that
edits show up at once, that MCP sessions require intent and report their health on the first result, and that an
unreachable reranker fails the search with a RERANK FAILURE banner. With --rerank-port N (a llama-server running a
reranker model with --reranking --pooling rank) it also checks the real reranker stage.
retrieval_eval.py measures ranking quality on a real repository.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import sys
import tempfile

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


def search(client, **arguments):
    return client.tool("search", {"operation": "text", "output": "json", **arguments})


def results_of(client, **arguments):
    reply = search(client, **arguments)
    return reply["results"], reply


def check_ranking(client):
    results, reply = results_of(client, pattern="def ", path="pair", include=["*.py"], intent=INTENT)
    assert [Path(r["path"]).name for r in results] == ["intervals.py", "render.py"], results
    assert [r["ranking"]["rank"] for r in results] == [1, 2], results
    assert results[0]["ranking"]["score"] > results[1]["ranking"]["score"], results
    report = reply["ranking"]
    assert report["mode"] == "keyword" and report["candidates"] == 2 and report["returned"] == 2, report

    text = client.tool("search", {"operation": "text", "pattern": "def ", "path": "pair", "include": ["*.py"],
                                  "intent": INTENT}, raw=True)
    assert text.startswith("[ranking "), text
    body = [line for line in text.splitlines()[1:] if line and not line.startswith("[")]
    assert "intervals.py" in body[0], body

    # Without an intent nothing is ranked, limited or annotated: every finding in scan order, as before.
    plain, reply = results_of(client, pattern="def ", path="pair", include=["*.py"])
    assert len(plain) == 2 and "ranking" not in reply and all("ranking" not in r for r in plain), reply
    blank, reply = results_of(client, pattern="def ", path="pair", include=["*.py"], intent="   ")
    assert len(blank) == 2 and "ranking" not in reply, reply


def reply_note(reply):
    return reply["ranking"].get("note", "")


def check_limits(client):
    results, reply = results_of(client, pattern="def handler_", path="many", intent="handle the request")
    assert reply["ranking"]["candidates"] == 30, reply["ranking"]
    assert len(results) == 10 and reply["ranking"]["returned"] == 10, reply["ranking"]
    assert [r["ranking"]["rank"] for r in results] == list(range(1, 11)), [r["ranking"] for r in results]

    # One file with 8 distant hits: the default cap keeps 3 of them.
    results, _ = results_of(client, pattern="def repeated_", path="deep", intent="repeated")
    assert len(results) == 3, [r["path"] for r in results]

    # Explicit limits apply after ranking.
    limited, reply = results_of(client, pattern="def handler_", path="many", intent="handle the request", max_results=2)
    assert len(limited) == 2 and reply["summary"]["truncated"], reply["summary"]
    assert [r["ranking"]["rank"] for r in limited] == [1, 2], limited

    # What the ranking left out is stated, in the report and as a plain line of the text output.
    assert "showing 10 of 30 matching hunks" in reply_note(results_of(client, pattern="def handler_", path="many",
                                                                        intent="handle the request")[1]), "note missing"
    text = client.tool("search", {"operation": "text", "pattern": "def handler_", "path": "many",
                                  "intent": "handle the request"}, raw=True)
    assert "[showing 10 of 30 matching hunks" in text and "to see the rest" in text, text[:400]
    _, whole = results_of(client, pattern="def ", path="pair", include=["*.py"], intent=INTENT)
    assert "note" not in whole["ranking"], whole["ranking"]

    # Without an intent no limit applies: all 30.
    everything, _ = results_of(client, pattern="def handler_", path="many")
    assert len(everything) == 30, len(everything)


def check_settings(executable, root):
    client = Client(executable, root, environment={**os.environ, "SHGREP_RANK_RETURN": "4", "SHGREP_RANK_PER_FILE": "0"})
    try:
        results, reply = results_of(client, pattern="def handler_", path="many", intent="handle the request")
        assert len(results) == 4 and reply["ranking"]["return_limit"] == 4, reply["ranking"]
        results, _ = results_of(client, pattern="def repeated_", path="deep", intent="repeated")
        assert len(results) == 4, len(results)
    finally:
        client.close()
    client = Client(executable, root, environment={**os.environ, "SHGREP_RANK_RETURN": "0", "SHGREP_RANK_PER_FILE": "0"})
    try:
        results, _ = results_of(client, pattern="def repeated_", path="deep", intent="repeated")
        assert len(results) == 8, len(results)
    finally:
        client.close()
    # A tiny scan limit stops the scan early, says so, and ranks what was found.
    client = Client(executable, root, environment={**os.environ, "SHGREP_RANK_SCAN_LIMIT": "5"})
    try:
        results, reply = results_of(client, pattern="def handler_", path="many", intent="handle the request")
        assert reply["summary"]["status"] == "limit" and len(results) <= 5, reply["summary"]
        assert "SHGREP_RANK_SCAN_LIMIT" in reply["ranking"]["note"], reply["ranking"]
    finally:
        client.close()
    client = Client(executable, root, environment={**os.environ, "SHGREP_RANK_RETURN": "many"})
    try:
        text = client.tool("search", {"operation": "text", "pattern": "def ", "intent": INTENT}, error=True)
        assert "SHGREP_RANK_RETURN" in text, text
    finally:
        client.close()


def check_fresh(client, root):
    target = root / "pair" / "intervals.py"
    original = target.read_text(encoding="utf-8")
    try:
        target.write_text(original.replace("merge_intervals", "merge_ranges"), encoding="utf-8")
        results, _ = results_of(client, pattern="def ", path="pair", include=["*.py"], intent=INTENT)
        assert "merge_ranges" in results[0]["context"] and "merge_intervals" not in results[0]["context"], results[0]
    finally:
        target.write_text(original, encoding="utf-8")


def check_unreachable_reranker(executable, root):
    # A bound but unlistened port refuses connections: the reranker is down, so the ranked search fails loudly.
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
        client = Client(executable, root, environment={**os.environ, "SHGREP_RERANK_PORT": str(port),
                                                       "SHGREP_RERANK_BUDGET_MS": "1000"})
        try:
            first = client.call("tools/call", {"name": "search", "arguments": {
                "operation": "text", "pattern": "def ", "path": "pair", "include": ["*.py"], "intent": INTENT}})
            text = first["content"][0]["text"]
            assert first.get("isError") and text.startswith("[RERANK FAILURE - tell the user"), first
            assert f"127.0.0.1:{port}" in text and "llama-server" in text, text
            # The session health check found the same reranker down and says so on this first result.
            assert len(first["content"]) == 2 and f"127.0.0.1:{port} does not work" in first["content"][1]["text"], first
        finally:
            client.close()


def check_enforcement(executable, root):
    client = Client(executable, root, environment={**os.environ, "SHGREP_REQUIRE_INTENT": "1"})
    try:
        first = client.call("tools/call", {"name": "search", "arguments": {"operation": "text", "pattern": "def ", "path": "pair"}})
        assert first.get("isError") and "requires intent" in first["content"][0]["text"], first
        # The first result of a session carries the health notice as a second block; here the reranker is off.
        health = first["content"][1]["text"] if len(first["content"]) == 2 else ""
        assert health.startswith("[SHGREP HEALTH - tell the user") and "SHGREP_RERANK_PORT=0" in health, first
        blank = client.tool("search", {"operation": "text", "pattern": "def ", "path": "pair", "intent": "  "}, error=True)
        assert "requires intent" in blank, blank
        later = client.call("tools/call", {"name": "search", "arguments": {"operation": "text", "pattern": "def ", "path": "pair",
                                                                         "include": ["*.py"], "intent": INTENT}})
        assert not later.get("isError") and len(later["content"]) == 1, later
        assert "off (SHGREP_RERANK_PORT=0)" in later["content"][0]["text"], later
    finally:
        client.close()


def check_real_reranker(executable, root, port):
    client = Client(executable, root, environment={**os.environ, "SHGREP_RERANK_PORT": str(port)})
    try:
        results, reply = results_of(client, pattern="def ", path="pair", include=["*.py"], intent=INTENT)
        report = reply["ranking"]
        assert report["mode"] == "rerank" and report["rerank_scored"] == 2 and "rerank_error" not in report, report
        assert all("rerank_score" in r["ranking"] for r in results), results
        assert Path(results[0]["path"]).name == "intervals.py", [(r["path"], r["ranking"]) for r in results]
        print(f"  rerank scores {[round(r['ranking']['rerank_score'], 3) for r in results]} in {report['rerank_ms']} ms")

        results, reply = results_of(client, pattern="def handler_", path="many", intent="handle the request")
        report = reply["ranking"]
        assert report["mode"] == "rerank" and report["rerank_scored"] == 24 and report["returned"] == 10, report
        scores = [r["ranking"]["rerank_score"] for r in results]
        assert scores == sorted(scores, reverse=True), scores
        assert [r["ranking"]["rank"] for r in results] == list(range(1, 11)), results
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--rerank-port", type=int, help="port of a running llama-server --reranking, to test the real stage")
    args = parser.parse_args()
    executable = args.executable.resolve()
    with tempfile.TemporaryDirectory(prefix="shgrep-rank-", ignore_cleanup_errors=True) as folder:
        root = Path(folder)
        (root / ".shgrep").mkdir()
        (root / ".shgrep/lsp.json").write_text('{"servers":[],"bundled":false}', encoding="utf-8")
        (root / "pair").mkdir()
        (root / "pair/intervals.py").write_text(INTERVALS, encoding="utf-8")
        (root / "pair/render.py").write_text(CIRCLE, encoding="utf-8")
        (root / "many").mkdir()
        for i in range(30):
            (root / "many" / f"handler_{i}.py").write_text(
                f"def handler_{i}(request):\n    return request.reply({i})\n", encoding="utf-8")
        (root / "deep").mkdir()
        filler = "".join(f"    step_{n} = {n}\n" for n in range(40))
        (root / "deep/repeated.py").write_text(
            "".join(f"def repeated_{i}():\n{filler}\n" for i in range(8)), encoding="utf-8")
        client = Client(executable, root)
        try:
            check_ranking(client)
            print("ok  ranking")
            check_limits(client)
            print("ok  limits")
            check_fresh(client, root)
            print("ok  freshness")
        finally:
            client.close()
        check_settings(executable, root)
        print("ok  settings")
        check_enforcement(executable, root)
        print("ok  intent required and session health reported")
        check_unreachable_reranker(executable, root)
        print("ok  unreachable reranker fails the search with a RERANK FAILURE banner")
        if args.rerank_port:
            check_real_reranker(executable, root, args.rerank_port)
            print("ok  real reranker")
    print("Ranking checks passed")


if __name__ == "__main__":
    sys.exit(main())
