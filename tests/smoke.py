"""User-run STDIO MCP smoke check. Usage: python tests/smoke.py build/Release/shgrep.exe"""

import hashlib
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
        # The server runs from an empty folder inside the root, so a write that lands in the working directory
        # instead of its target folder is caught below.
        working = root / "cwd"
        working.mkdir()
        process = subprocess.Popen(
            [str(executable), "--root", str(root)],
            cwd=working,
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

        def tool_error(name, arguments, request_id):
            reply = call("tools/call", {"name": name, "arguments": arguments}, request_id)
            assert reply.get("isError") is True, reply
            return reply["content"][0]["text"]

        try:
            assert call("initialize", {"protocolVersion": "2025-06-18"})["serverInfo"]["name"] == "shgrep"
            tools = call("tools/list", request_id=2)["tools"]
            assert [t["name"] for t in tools] == ["search", "search_bytes", "find_files", "read_file", "list_dir",
                                                 "file_info", "edit_file", "write_file", "move_file",
                                                 "create_directory"], tools
            assert all(t["inputSchema"].get("additionalProperties") is False for t in tools), tools
            # A misplaced filter (glob belongs to find_files) is rejected instead of silently searching everything.
            misplaced = call("tools/call", {"name": "search", "arguments": {"pattern": "needle", "glob": "*.cpp"}}, 40)
            assert misplaced.get("isError") is True, misplaced
            assert 'unknown argument "glob" for search' in misplaced["content"][0]["text"], misplaced
            assert "include" in misplaced["content"][0]["text"], misplaced
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
            # PCRE-only syntax falls back to PCRE2.
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
            # Many files in one directory are scanned in batches by several workers; output stays sorted.
            many = root / "many"
            many.mkdir()
            batch_paths = [many / f"f{i:02d}.txt" for i in range(20)]
            for path in reversed(batch_paths):
                path.write_bytes(b"x\nbatchneedle\n")
            batched = tool_text("search", {"pattern": "batchneedle", "output": "files"}, 36)
            assert batched == "".join(f"{path}\n" for path in batch_paths), batched
            # 64 KiB is the largest file read in one call from its listed size; one byte more takes the measured path.
            for size in (65535, 65536, 65537):
                (root / f"edge{size}.txt").write_bytes(b"y" * (size - 10) + b"edgeneedle")
            edges = tool("search", {"pattern": "edgeneedle", "mode": "literal", "include": ["edge*.txt"]}, 37)
            assert sorted(item["byte_start"] for item in edges["results"]) == [65525, 65526, 65527], edges
            # rg-style extras: invert, files_without_match, multiline, per-pattern counts, relative paths.
            feat = root / "feat"
            feat.mkdir()
            a, b, c = feat / "a.txt", feat / "b.txt", feat / "c.txt"
            a.write_bytes(b"keep one\ndrop alpha\nkeep two\n")
            b.write_bytes(b"nothing here\n")
            c.write_bytes(b"start(\n  arg)\nend\n")
            inverted = tool_text("search", {"pattern": "alpha", "invert": True, "include": ["feat/a.txt"]}, 41)
            assert inverted == f"{a}:1:keep one\n{a}:3:keep two\n", inverted
            inverted_count = tool_text("search", {"pattern": "alpha", "invert": True, "output": "count",
                                                 "include": ["feat/a.txt"]}, 42)
            assert inverted_count == f"{a}:2\n", inverted_count
            without = tool_text("search", {"pattern": "alpha", "output": "files_without_match", "include": ["feat/*"]}, 43)
            assert without == f"{b}\n{c}\n", without
            spanned = tool_text("search", {"pattern": r"start\(\n\s*arg\)", "multiline": True, "include": ["feat/c.txt"]}, 44)
            assert spanned == f"{c}:1:start(\n{c}:2:  arg)\n", spanned
            per_pattern = tool_text("search", {"patterns": ["keep", "alpha", "zzz"], "output": "count",
                                               "include": ["feat/a.txt"]}, 45)
            assert per_pattern == f"{a}:3 [0:2 1:1]\n", per_pattern
            relative = tool_text("search", {"pattern": "alpha", "paths": "relative", "include": ["feat/*"]}, 46)
            assert relative == f"[paths relative to {root}]\nfeat\\a.txt:2:drop alpha\n", relative
            bad_invert = call("tools/call", {"name": "search", "arguments": {"pattern": "x", "invert": True,
                                                                           "output": "json"}}, 47)
            assert bad_invert.get("isError") is True, bad_invert
            readable = tool("search_bytes", {"pattern": "needle", "mode": "regex", "include": ["blob.bin"]}, 48)
            assert readable["results"][0]["context_text"] == "..needle.", readable
            empty = root / "empty.txt"
            empty.write_bytes(b"")
            assert tool_text("search", {"pattern": "emptyneedle", "include": ["empty.txt"]}, 38).startswith("No matches.")
            empty.write_bytes(b"emptyneedle\n")
            assert tool_text("search", {"pattern": "emptyneedle", "include": ["empty.txt"]}, 39) == f"{empty}:1:emptyneedle\n"
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

            # write_file creates missing folders and never replaces a file without overwrite.
            ft = root / "ft"
            created = tool_text("write_file", {"path": "ft/sub/new.txt", "content": "a\nb\n"}, 100)
            assert created.startswith(f"Created {ft / 'sub' / 'new.txt'} (2 lines, 4 bytes, utf-8, lf)"), created
            assert "Created folders: ft/ ft/sub/" in created, created
            assert (ft / "sub" / "new.txt").read_bytes() == b"a\nb\n"
            assert "overwrite: true" in tool_error("write_file", {"path": "ft/sub/new.txt", "content": "x"}, 101)
            # read_file: format header, numbered lines, offset/limit with a continuation status.
            crlf = ft / "crlf.txt"
            crlf.write_bytes(b"one\r\ntwo\r\nthree\r\n")
            header, *body = tool_text("read_file", {"path": "ft/crlf.txt"}, 102).splitlines(keepends=True)
            assert header.startswith(f"[file {crlf} | 3 lines, 18 bytes | utf-8, crlf, final newline | mtime "), header
            assert body == ["     1→one\n", "     2→two\n", "     3→three\n"], body
            sha = header.rsplit("sha256 ", 1)[1].rstrip("]\n")
            assert sha == hashlib.sha256(b"one\r\ntwo\r\nthree\r\n").hexdigest(), header
            big = ft / "big.txt"
            big.write_bytes(b"".join(b"line %d " % i + b"x" * 100 + b"\n" for i in range(5000)))
            whole = tool_text("read_file", {"path": "ft/big.txt"}, 134)
            assert "[status" not in whole and whole.endswith("  5000→line 4999 " + "x" * 100 + "\n"), whole[-300:]
            window = tool_text("read_file", {"path": str(crlf), "offset": 2, "limit": 1}, 103).splitlines()[1:]
            assert window == ["     2→two",
                              "[status limit: showed lines 2-2 of 3 (limit=1); continue with offset=3]"], window
            # edit_file: LF old_text matches a CRLF file and is written back as CRLF; the sha256 guard holds.
            edited = tool_text("edit_file", {"path": "ft/crlf.txt", "expected_sha256": sha,
                                             "edits": [{"old_text": "one\ntwo", "new_text": "uno\ndos"}]}, 104)
            assert crlf.read_bytes() == b"uno\r\ndos\r\nthree\r\n", crlf.read_bytes()
            assert "@@ -1,3 +1,3 @@\n-one\n-two\n+uno\n+dos\n three\n" in edited, edited
            stale = tool_error("edit_file", {"path": "ft/crlf.txt", "expected_sha256": sha,
                                             "edits": [{"old_text": "uno", "new_text": "one"}]}, 105)
            assert "changed since it was read" in stale, stale
            # Ambiguous and missing old_text fail with nothing written; replace_all and dry_run.
            dup = ft / "dup.txt"
            dup.write_bytes(b"x\nx\ny\n")
            ambiguous = tool_error("edit_file", {"path": "ft/dup.txt", "edits": [{"old_text": "x", "new_text": "z"}]}, 106)
            assert "matches 2 times (at lines 1, 2)" in ambiguous, ambiguous
            partial = tool_error("edit_file", {"path": "ft/dup.txt", "edits": [{"old_text": "y", "new_text": "w"},
                                                                            {"old_text": "gone", "new_text": "q"}]}, 107)
            assert "edit 2 of 2: old_text was not found" in partial, partial
            assert dup.read_bytes() == b"x\nx\ny\n"
            tool_text("edit_file", {"path": "ft/dup.txt",
                                    "edits": [{"old_text": "x", "new_text": "z", "replace_all": True}]}, 108)
            assert dup.read_bytes() == b"z\nz\ny\n"
            preview = tool_text("edit_file", {"path": "ft/dup.txt", "dry_run": True,
                                              "edits": [{"old_text": "y", "new_text": "w"}]}, 109)
            assert preview.startswith("Dry run, nothing written.") and dup.read_bytes() == b"z\nz\ny\n", preview
            # Encodings and BOMs survive edits; overwrite keeps the replaced file's line endings.
            bom = ft / "bom.txt"
            bom.write_bytes(b"\xef\xbb\xbfhello\n")
            assert "| utf-8-bom, lf, final newline |" in tool_text("read_file", {"path": "ft/bom.txt"}, 110)
            tool_text("edit_file", {"path": "ft/bom.txt", "edits": [{"old_text": "hello", "new_text": "bye"}]}, 111)
            assert bom.read_bytes() == b"\xef\xbb\xbfbye\n", bom.read_bytes()
            wide = ft / "wide.txt"
            wide.write_bytes("Ωmega\r\nline\r\n".encode("utf-16"))
            tool_text("edit_file", {"path": "ft/wide.txt",
                                    "edits": [{"old_text": "Ωmega\nline", "new_text": "Alpha\nline"}]}, 112)
            assert wide.read_bytes() == "Alpha\r\nline\r\n".encode("utf-16"), wide.read_bytes()
            replaced = tool_text("write_file", {"path": "ft/crlf.txt", "content": "new\ncontent\n", "overwrite": True}, 113)
            assert crlf.read_bytes() == b"new\r\ncontent\r\n", crlf.read_bytes()
            assert replaced.startswith(f"Replaced {crlf} (2 lines"), replaced
            # Binary files are refused; direct paths ignore hidden; paths cannot leave the root or name a stream.
            assert "search_bytes" in tool_error("read_file", {"path": "blob.bin"}, 114)
            assert tool_text("read_file", {"path": ".secret.cpp"}, 115).endswith("     1→needle\n")
            assert "leave the root" in tool_error("read_file", {"path": "../outside.txt"}, 116)
            assert "outside the configured roots" in tool_error("read_file", {"path": str(root.parent / "x.txt")}, 117)
            assert "alternate data streams" in tool_error("write_file", {"path": "ft/a.txt:s", "content": "x"}, 118)
            several = tool_text("read_file", {"paths": ["ft/bom.txt", "ft/missing.txt"]}, 119)
            assert "     1→bye\n" in several and "[error " in several and "not found" in several, several
            # list_dir shows folders and every entry by default; hidden/no_ignore false apply search's filters.
            (ft / ".hidden.txt").write_bytes(b"h")
            (ft / ".gitignore").write_bytes(b"*.log\n")
            (ft / "x.log").write_bytes(b"l")
            listing = tool_text("list_dir", {"path": "ft", "depth": 2}, 120)
            assert "d sub/\n" in listing and "f sub/new.txt 4\n" in listing and "f bom.txt 7\n" in listing, listing
            assert "f x.log 1\n" in listing and "f .hidden.txt 1\n" in listing and "[not shown" not in listing, listing
            filtered = tool_text("list_dir", {"path": "ft", "hidden": False, "no_ignore": False}, 121)
            assert "x.log" not in filtered and ".hidden.txt" not in filtered, filtered
            assert "2 hidden" in filtered and "1 ignored" in filtered, filtered
            shallow = tool_text("list_dir", {"path": "ft"}, 122)
            assert "d sub/\n" in shallow and "sub/new.txt" not in shallow, shallow
            info = tool_text("file_info", {"path": "ft/crlf.txt"}, 123)
            assert "type: file\n" in info and "line_endings: crlf\n" in info and "lines: 2\n" in info, info
            assert "type: directory" in tool_text("file_info", {"path": "ft/sub"}, 124)
            # create_directory is mkdir -p; move_file renames and refuses to replace without overwrite.
            made = tool_text("create_directory", {"path": "ft/a/b"}, 125)
            assert (ft / "a" / "b").is_dir() and "Created folders: ft/a/ ft/a/b/" in made, made
            assert tool_text("create_directory", {"path": "ft/a/b"}, 126).startswith("Already exists")
            tool_text("move_file", {"source": "ft/sub/new.txt", "destination": "ft/moved/renamed.txt"}, 127)
            assert (ft / "moved" / "renamed.txt").read_bytes() == b"a\nb\n" and not (ft / "sub" / "new.txt").exists()
            assert "overwrite: true" in tool_error("move_file", {"source": "ft/bom.txt",
                                                                 "destination": "ft/moved/renamed.txt"}, 128)
            # Junctions below the root are refused for reads and writes, and listed without being entered.
            try:
                import _winapi
                _winapi.CreateJunction(str(ft / "sub"), str(ft / "junction"))
            except (ImportError, AttributeError, OSError):
                print("skipped junction checks: cannot create a junction here")
            else:
                assert "never follows links" in tool_error("read_file", {"path": "ft/junction/x.txt"}, 129)
                assert "never follows links" in tool_error("write_file", {"path": "ft/junction/x.txt",
                                                                         "content": "x"}, 130)
                assert not (ft / "sub" / "x.txt").exists()
                assert "l junction/\n" in tool_text("list_dir", {"path": "ft"}, 131)
            # search: max_line_bytes 0 turns off the 400-byte window around long-line matches.
            long_line = ft / "long.txt"
            long_line.write_bytes(b"a" * 600 + b"needle" + b"b" * 600 + b"\n")
            windowed = tool_text("search", {"pattern": "needle", "include": ["ft/long.txt"]}, 132)
            assert "..." in windowed and len(windowed) < 600, windowed
            whole = tool_text("search", {"pattern": "needle", "include": ["ft/long.txt"], "max_line_bytes": 0}, 133)
            assert whole == f"{long_line}:1:" + "a" * 600 + "needle" + "b" * 600 + "\n", whole[:200]
            stray = [p.name for p in working.iterdir()]
            assert not stray, f"files written to the server's working directory: {stray}"
        finally:
            process.stdin.close()
            process.wait(timeout=10)
            if process.returncode:
                raise AssertionError(process.stderr.read().decode(errors="replace"))
        # --read-only hides and refuses the write tools.
        read_only = subprocess.Popen([str(executable), "--root", str(root), "--read-only"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            def read_only_call(method, params, request_id):
                message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
                read_only.stdin.write(json.dumps(message).encode() + b"\n")
                read_only.stdin.flush()
                return json.loads(read_only.stdout.readline())

            read_only_call("initialize", {"protocolVersion": "2025-06-18"}, 1)
            names = [t["name"] for t in read_only_call("tools/list", {}, 2)["result"]["tools"]]
            assert names == ["search", "search_bytes", "find_files", "read_file", "list_dir", "file_info"], names
            refused = read_only_call("tools/call", {"name": "write_file",
                                                    "arguments": {"path": "ro.txt", "content": "x"}}, 3)
            assert "error" in refused and not (root / "ro.txt").exists(), refused
        finally:
            read_only.stdin.close()
            read_only.wait(timeout=10)
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
