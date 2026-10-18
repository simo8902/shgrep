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


def check_complete(result, count):
    assert result["summary"]["status"] == "complete", result["summary"]
    assert not result["summary"]["truncated"], result["summary"]
    assert len(result["results"]) == count, result["summary"]


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
        (root / "long.txt").write_text(body + "\n", encoding="utf-8")
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
            lines = client.tool("search", query, raw=True)
            assert len(lines.splitlines()) == 6240 and "[status" not in lines
            found = client.tool("find_files", {"path_filter": "many/", "output": "json"})
            check_complete(found, 48)
            capped = client.tool("search", {**query, "output": "json", "max_results": 3})
            assert len(capped["results"]) == 3 and capped["summary"]["truncated"], capped["summary"]

            for arguments in ({}, {"operation": "text"}):
                text = client.tool("read_file", {"path": "read.txt", **arguments}, raw=True)
                assert "line_0001" in text and "line_0400" in text and "[status limit" not in text
            text = client.tool("read_file", {"path": "read.txt", "offset": 351}, raw=True)
            assert "line_0350" not in text and "line_0351" in text and "line_0400" in text
            text = client.tool("read_file", {"path": "read.txt", "limit": 7}, raw=True)
            assert "line_0007" in text and "line_0008" not in text and "[status limit" in text

            for path in (["long.txt", "large.txt"] if large else ["long.txt"]):
                result = client.tool("search", {"operation": "text", "path": path, "pattern": "^\u20ac+$",
                                               "output": "json", "context_bytes": 0, "index": False,
                                               "timeout_ms": 300000})
                check_complete(result, 1)
                hit = result["results"][0]
                assert hit["context"] == body and not hit["context_truncated"]
                assert hit["context_match_end"] == len(body.encode("utf-8"))
            result = client.tool("search_bytes", {"path_filter": "long.bin", "mode": "regex",
                                                  "pattern": r"^\x00A{6000}\x00$", "context_bytes": 0,
                                                  "output": "json"})
            check_complete(result, 1)
            hit = result["results"][0]
            assert hit["context_hex"] == binary.hex() and not hit["context_truncated"]
            assert hit["byte_start"] == 0 and hit["byte_end"] == len(binary)
            text = client.tool("search", {"operation": "text", "path": "block.py",
                                          "pattern": "completion_block_needle", "block": True}, raw=True)
            assert len(text.splitlines()) == len(block.splitlines()), text[-500:]
            text = client.tool("search", {"operation": "text", "path": "block.py",
                                          "pattern": "completion_block_needle", "block": True,
                                          "max_block_lines": 200}, raw=True)
            assert len(text.splitlines()) == 1, text
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
