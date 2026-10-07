"""User-run STDIO MCP smoke check. Usage: python tests/smoke.py build/Release/shgrep.exe"""

import json
import pathlib
import subprocess
import sys
import tempfile


def main():
    executable = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="shgrep-") as root:
        root = pathlib.Path(root)
        source = root / "unicøde source.cpp"
        source.write_bytes(b"first needle\nother line\n")
        (root / "blob.bin").write_bytes(b"\x00\xffneedle\x00")
        (root / "boundary.dat").write_bytes(b"x" * ((1 << 20) - 2) + b"abcd")
        process = subprocess.Popen(
            [str(executable), "--root", str(root)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        def call(method, params=None, request_id=1):
            message = {"jsonrpc": "2.0", "id": request_id, "method": method}
            if params is not None:
                message["params"] = params
            process.stdin.write(json.dumps(message).encode() + b"\n")
            process.stdin.flush()
            response = json.loads(process.stdout.readline())
            assert response["id"] == request_id, response
            assert "error" not in response, response
            return response["result"]

        def tool(name, arguments, request_id):
            reply = call("tools/call", {"name": name, "arguments": {"output": "json", **arguments}}, request_id)
            assert not reply.get("isError"), reply
            return json.loads(reply["content"][0]["text"])

        def tool_text(name, arguments, request_id):
            reply = call("tools/call", {"name": name, "arguments": arguments}, request_id)
            assert not reply.get("isError"), reply
            return reply["content"][0]["text"]

        try:
            assert call("initialize", {"protocolVersion": "2025-06-18"})["serverInfo"]["name"] == "shgrep"
            assert len(call("tools/list", request_id=2)["tools"]) == 10
            result = tool("search", {"patterns": ["needle", "other"], "line_numbers": True}, 3)
            assert {(item["pattern_id"], item["byte_start"]) for item in result["results"] if item["path"].endswith("source.cpp")} == {(0, 6), (1, 13)}
            # blob.bin is recognized as binary from its first block and skipped, not scanned.
            assert result["summary"]["files_scanned"] == 2, result["summary"]
            assert result["summary"]["files_skipped_binary"] == 1, result["summary"]
            lines = tool_text("search", {"pattern": "needle", "include": ["*source.cpp"]}, 21)
            assert lines == f"{source}:1:first needle\n", lines
            context = tool_text("search", {"pattern": "other", "include": ["*source.cpp"], "before_lines": 1}, 22)
            assert context == f"{source}-1-first needle\n{source}:2:other line\n", context
            partial_word = tool_text("search", {"pattern": "need", "word": True, "include": ["*source.cpp"]}, 23)
            assert partial_word.startswith("No matches."), partial_word
            assert tool_text("search", {"pattern": "needle", "word": True, "include": ["*source.cpp"]}, 24) == lines
            counted = tool_text("search", {"pattern": "needle|other", "output": "count", "include": ["*source.cpp"]}, 25)
            assert counted == f"{source}:2\n", counted
            typed = tool_text("search", {"pattern": "needle", "output": "files", "types": ["cpp"]}, 26)
            assert typed == f"{source}\n", typed
            assert tool_text("find_files", {"types": ["cpp"]}, 27) == f"{source}\n"
            literal = tool_text("search", {"pattern": "a.c", "mode": "literal", "include": ["*source.cpp"]}, 28)
            assert literal.startswith("No matches."), literal
            anchored = tool_text("search", {"pattern": "^other", "include": ["*source.cpp"]}, 29)
            assert anchored == f"{source}:2:other line\n", anchored
            cached = tool_text("search", {"pattern": "^other", "include": ["*source.cpp"]}, 30)
            assert cached == anchored, cached
            # PCRE-only syntax falls back to PCRE2 JIT.
            first = f"{source}:1:first needle\n"
            second = f"{source}:2:other line\n"
            for request_id, pattern, expected in [(31, r"(e)\1", first), (32, r"first(?= needle)", first),
                                                  (33, r"(?<=other )line", second), (34, r"\bneedle\b", first)]:
                pcre = tool_text("search", {"pattern": pattern, "include": ["*source.cpp"]}, request_id)
                assert pcre == expected, (pattern, pcre)
            # Lines output counts lines, not matches, toward max_results (like rg -m).
            per_line = tool_text("search", {"pattern": "e", "include": ["*source.cpp"], "max_results": 2}, 35)
            assert per_line.startswith(first + second), per_line
            oversized = tool("search", {"pattern": "needle", "include": ["*source.cpp"],
                                        "max_file_bytes": 1}, 19)
            assert oversized["summary"]["status"] == "partial_files", oversized
            assert oversized["skipped_files"][0]["path"].endswith("source.cpp"), oversized
            assert oversized["selection"]["regular_files_seen"] >= 1, oversized
            large_binary = tool("search", {"pattern": "needle", "include": ["blob.bin"],
                                           "max_file_bytes": 1}, 20)
            assert large_binary["summary"]["files_skipped_binary"] == 1, large_binary
            assert large_binary["summary"]["files_skipped_size"] == 0, large_binary
            result = tool("search_bytes", {"pattern": "00ff6e", "mode": "literal"}, 4)
            assert any(item["byte_start"] == 0 and item["context_hex"].startswith("00ff") for item in result["results"])
            result = tool("find_files", {"glob": "*.cpp"}, 5)
            assert len(result["results"]) == 1
            across = tool("search", {"pattern": "ab.d", "mode": "regex", "include": ["*.dat"]}, 11)
            assert len(across["results"]) == 1
            assert across["results"][0]["byte_start"] == (1 << 20) - 2
            utf16 = root / "utf16.cpp"
            utf16.write_bytes("Ωmega needle\n".encode("utf-16"))
            decoded = tool("search", {"pattern": "needle", "include": ["utf16.cpp"]}, 12)
            assert len(decoded["results"]) == 1, decoded
            assert decoded["results"][0]["byte_start"] == 14, decoded
            assert decoded["results"][0]["line"] == 1, decoded
            assert "Ωmega needle" in decoded["results"][0]["context"], decoded
            repaired = root / "repaired.cpp"
            repaired.write_bytes(b"bad \xffneedle\n")
            repaired_result = tool("search", {"pattern": "needle", "include": ["repaired.cpp"]}, 13)
            assert repaired_result["results"][0]["byte_start"] == 5, repaired_result
            assert "�needle" in repaired_result["results"][0]["context"], repaired_result
            ignored_dir = root / "ignored"
            ignored_dir.mkdir()
            (ignored_dir / "hidden.cpp").write_text("needle\n", encoding="utf-8")
            ignore = root / ".gitignore"
            ignore.write_text("ignored/\n", encoding="utf-8")
            assert tool("find_files", {"exact_name": "hidden.cpp"}, 14)["results"] == []
            assert len(tool("find_files", {"exact_name": "hidden.cpp", "no_ignore": True}, 15)["results"]) == 1
            ignore.write_text("", encoding="utf-8")
            assert len(tool("find_files", {"exact_name": "hidden.cpp"}, 16)["results"]) == 1
            secret = root / ".secret.cpp"
            secret.write_text("needle\n", encoding="utf-8")
            assert tool("find_files", {"exact_name": ".secret.cpp"}, 17)["results"] == []
            assert len(tool("find_files", {"exact_name": ".secret.cpp", "hidden": True}, 18)["results"]) == 1
            source.write_bytes(b"changed\n")
            result = tool("search", {"pattern": "needle", "include": ["*source.cpp"]}, 6)
            assert result["results"] == []
            result = tool("search", {"pattern": "changed", "include": ["*source.cpp"]}, 7)
            assert len(result["results"]) == 1
            limited = tool("search", {"pattern": "e", "max_results": 1}, 8)
            assert limited["summary"]["truncated"] is True
            invalid = call("tools/call", {"name": "search", "arguments": {"pattern": "[", "mode": "regex"}}, 9)
            assert invalid["isError"] is True
            outside = call("tools/call", {"name": "find_files", "arguments": {"roots": [str(root.parent)]}}, 10)
            assert outside["isError"] is True
        finally:
            process.stdin.close()
            process.wait(timeout=10)
            if process.returncode:
                raise AssertionError(process.stderr.read().decode(errors="replace"))
        cli = subprocess.run([str(executable), "search", "--root", str(root),
                              "--pattern", "changed", "--include", "*source.cpp"],
                             capture_output=True, text=True, encoding="utf-8", check=True)
        assert "source.cpp:1:changed" in cli.stdout, cli.stdout
        included_cli = subprocess.run([str(executable), "search", "--root", str(root),
                                       "--pattern", "changed", "--include", "*.cpp"],
                                      capture_output=True, text=True, encoding="utf-8", check=True)
        assert "source.cpp:1:changed" in included_cli.stdout, included_cli.stdout
        filename_cli = subprocess.run([str(executable), "find_files", source.name,
                                       "--root", str(root)],
                                      capture_output=True, text=True, encoding="utf-8", check=True)
        assert str(source) in filename_cli.stdout, filename_cli.stdout
        oversized_cli = subprocess.run([str(executable), "search", "--root", str(root),
                                        "--pattern", "changed", "--include", "*source.cpp",
                                        "--max-file-bytes", "1"],
                                       capture_output=True, text=True, encoding="utf-8", check=True)
        assert "Skipped oversized text file:" in oversized_cli.stdout, oversized_cli.stdout
        assert str(source) in oversized_cli.stdout, oversized_cli.stdout
    print("MCP smoke checks passed")


if __name__ == "__main__":
    main()
