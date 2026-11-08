"""User-run checks for complete results and explicit-only clipping. Native Windows required.
Usage: python tests/complete_results.py build-rel/shgrep.exe [--large]
--large also exercises streamed reads/searches with a >64 MiB UTF-8 fixture.
"""
import argparse
import contextlib
import io
import json
from pathlib import Path
import tempfile

from lsp_smoke import Client
from mcp_protocol import flat_lines
from retrieval_eval import keywords, lexical


def check_candidate_coverage():
    class Findings:
        status = "complete"

        def tool(self, name, arguments):
            if name == "search":
                assert "max_results" not in arguments and arguments["index"] is False
                return {"summary": {"status": self.status, "truncated": self.status != "complete"},
                        "results": [{"path": f"file{i:02}.rs", "line": line}
                                    for i in range(48) for line in range(1, 131)]}
            assert name == "read_file" and arguments["depth"] == -1
            if arguments["path"] == "file00.rs":
                raise AssertionError("fixture: no LSP outline")
            return {"results": [{"kind": 12, "name": "work", "name_path": "work",
                                 "range": {"start_line": 1, "end_line": 129}}]}

    client = Findings()
    with contextlib.redirect_stderr(io.StringIO()) as warnings:
        candidates, findings = lexical(client, ["needle"], ["rs"])
    assert "retaining text candidates" in warnings.getvalue()
    assert len(findings["results"]) == 6240
    assert len({c["path"] for c in candidates}) == 48
    assert sum(c["hits"] for c in candidates) == 6240
    assert sum(c["kind"] == "text" for c in candidates) == 48
    assert len(keywords(" ".join(f"term{i}" for i in range(30)))) > 40
    client.status = "timeout"
    try:
        lexical(client, ["needle"], ["rs"])
    except RuntimeError as error:
        assert "Incomplete search" in str(error)
    else:
        raise AssertionError("partial retrieval reported as complete")


def check_complete(result, count, label=""):
    assert result["summary"]["status"] == "complete", (label, result["summary"])
    assert not result["summary"]["truncated"], (label, result["summary"])
    assert len(result["results"]) == count, (label, result["summary"])


def check_server(executable, large):
    with tempfile.TemporaryDirectory(prefix="shgrep-complete-", ignore_cleanup_errors=True) as folder:
        root = Path(folder)
        (root / ".shgrep").mkdir()
        (root / ".shgrep/lsp.json").write_text(json.dumps({"servers": [], "bundled": False}), encoding="utf-8")
        many = root / "many"
        many.mkdir()
        for index in range(48):
            (many / f"file{index:02}.txt").write_bytes(b"completion_needle\n" * 130)
        (root / "read.txt").write_text("".join(f"line_{i:04}\n" for i in range(1, 401)), encoding="utf-8")
        body = "\u20ac" * 1200
        # Explicit line endings: write_text would turn "\n" into CRLF on Windows. $ sits before \n (as in rg), so a
        # CRLF line's \r belongs to the line: ^€+$ matches the LF file only, ^€+\r?$ matches both.
        (root / "long.txt").write_bytes((body + "\n").encode("utf-8"))
        (root / "long_crlf.txt").write_bytes((body + "\r\n").encode("utf-8"))
        binary = b"\x00" + b"A" * 6000 + b"\x00"
        (root / "long.bin").write_bytes(binary)
        block = "def work():\n    completion_block_needle = 1\n" + "    pass\n" * 350
        (root / "block.py").write_text(block, encoding="utf-8")
        if large:
            with (root / "large.txt").open("wb") as stream:
                piece = b"padding\n" * (1 << 17)
                for _ in range(65):
                    stream.write(piece)
                stream.write((body + "\n").encode("utf-8"))

        client = Client(executable, root, timeout=330)
        try:
            query = {"operation": "text", "pattern": "completion_needle", "mode": "literal", "path": "many",
                     "index": False, "timeout_ms": 300000}
            result = client.tool("search", {**query, "output": "json"})
            check_complete(result, 6240)
            assert len({item["path"] for item in result["results"]}) == 48
            # Lines output groups matches under a heading per file; over 50 matches it starts with a summary line.
            # offload_output=false keeps the whole text inline (by default text over 8000 bytes is saved to a file).
            lines = client.tool("search", {**query, "offload_output": False}, raw=True)
            assert "[status" not in lines and ".shgrep-output" not in lines, lines[:500]
            rows = [line for line in lines.splitlines() if line.split(":", 1)[0].isdigit()]
            assert len(rows) == 6240, (len(rows), lines[:500])
            headings = [line for line in lines.splitlines() if line.endswith(".txt") and "many" in line]
            assert len(headings) == 48, (len(headings), lines[:500])
            assert all(row.endswith(":completion_needle") for row in rows), [r for r in rows if not r.endswith(":completion_needle")][:3]
            found = client.tool("find_files", {"path_filter": "many/", "output": "json"})
            check_complete(found, 48)
            capped = client.tool("search", {**query, "output": "json", "max_results": 3})
            assert len(capped["results"]) == 3 and capped["summary"]["truncated"], capped["summary"]

            # Text reads default to 100 lines and name the offset that continues; an explicit limit reads more.
            for arguments in ({}, {"operation": "text"}):
                text = client.tool("read_file", {"path": "read.txt", **arguments}, raw=True)
                assert "line_0001" in text and "line_0100" in text and "line_0101" not in text, text[-300:]
                assert "[status limit: showed lines 1-100 of 400" in text and "offset=101" in text, text[-300:]
            text = client.tool("read_file", {"path": "read.txt", "limit": 400, "offload_output": False}, raw=True)
            assert all(f"line_{i:04}" in text for i in range(1, 401)) and "[status limit" not in text, text[-300:]
            text = client.tool("read_file", {"path": "read.txt", "offset": 351}, raw=True)
            assert "line_0350" not in text and "line_0351" in text and "line_0400" in text, text[-300:]
            assert "[status limit" not in text, text[-300:]  # the window reaches the end of the file
            text = client.tool("read_file", {"path": "read.txt", "limit": 7}, raw=True)
            assert "line_0007" in text and "line_0008" not in text and "[status limit" in text and "offset=8" in text, text

            crlf = client.tool("search", {"operation": "text", "path": "long_crlf.txt", "pattern": "^\u20ac+$", "output": "json",
                                          "index": False})
            check_complete(crlf, 0, "^\u20ac+$ in long_crlf.txt (the \\r stays on the line)")
            crlf = client.tool("search", {"operation": "text", "path": "long_crlf.txt", "pattern": "^\u20ac+\r?$",
                                          "output": "json", "context_bytes": 0, "index": False})
            check_complete(crlf, 1, "^\u20ac+\\r?$ in long_crlf.txt")
            assert crlf["results"][0]["context"].rstrip("\r") == body, crlf["results"][0]["context"][-20:]
            for path in (["long.txt", "large.txt"] if large else ["long.txt"]):
                result = client.tool("search", {"operation": "text", "path": path, "pattern": "^\u20ac+$",
                                               "output": "json", "context_bytes": 0, "index": False,
                                               "timeout_ms": 300000})
                check_complete(result, 1, f"^\u20ac+$ in {path}")
                hit = result["results"][0]
                assert hit["context"] == body and not hit["context_truncated"], (path, hit["context"][-20:])
                assert hit["context_match_end"] == len(body.encode("utf-8"))
            result = client.tool("search_bytes", {"path_filter": "long.bin", "mode": "regex",
                                                  "pattern": r"^\x00A{6000}\x00$", "context_bytes": 0,
                                                  "output": "json"})
            check_complete(result, 1)
            hit = result["results"][0]
            assert hit["context_hex"] == binary.hex() and not hit["context_truncated"]
            assert hit["byte_start"] == 0 and hit["byte_end"] == len(binary)
            # block=true prints the whole enclosing function (offload_output=false keeps 350 lines inline).
            text = client.tool("search", {"operation": "text", "path": "block.py", "offload_output": False,
                                          "pattern": "completion_block_needle", "block": True}, raw=True)
            rows = flat_lines(text, "block.py").splitlines()
            assert len(rows) == len(block.splitlines()), (len(rows), text[-500:])
            assert rows[1] == "block.py:2:    completion_block_needle = 1" and rows[0] == "block.py-1-def work():", rows[:3]
            # A block over max_block_lines shows its header line and the match with 3 lines of context each side;
            # explicit context_lines=0 leaves the header and the match.
            text = client.tool("search", {"operation": "text", "path": "block.py", "pattern": "completion_block_needle",
                                          "block": True, "max_block_lines": 200}, raw=True)
            rows = flat_lines(text, "block.py").splitlines()
            assert rows[:2] == ["block.py-1-def work():", "block.py:2:    completion_block_needle = 1"], text
            assert rows[2:] == [f"block.py-{n}-    pass" for n in range(3, 6)], text
            text = client.tool("search", {"operation": "text", "path": "block.py", "pattern": "completion_block_needle",
                                          "block": True, "max_block_lines": 200, "context_lines": 0}, raw=True)
            assert flat_lines(text, "block.py").splitlines() == ["block.py-1-def work():",
                                                                "block.py:2:    completion_block_needle = 1"], text
            if large:
                text = client.tool("read_file", {"path": "large.txt", "offset": 65 * (1 << 17) + 1}, raw=True)
                assert body in text and "[status limit" not in text
        finally:
            client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--large", action="store_true")
    args = parser.parse_args()
    check_candidate_coverage()
    check_server(args.executable.resolve(), args.large)
    print("Complete-result checks passed")


if __name__ == "__main__":
    main()
