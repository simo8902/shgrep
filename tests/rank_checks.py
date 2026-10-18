"""User-run checks of shgrep's keyword ranking; no model, no server.
Usage: python tests/rank_checks.py build-rel/shgrep.exe
Checks: an intent ranks hunks best first, no intent keeps scan order and every finding, the per-file cap and return
limit (defaults and SHGREP_RANK_* settings), explicit max_results, bad settings, and that edits show up at once.
retrieval_eval.py measures ranking quality on a real repository.
"""
import argparse
import json
import os
from pathlib import Path
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("executable", type=Path)
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
    print("Ranking checks passed")


if __name__ == "__main__":
    sys.exit(main())
