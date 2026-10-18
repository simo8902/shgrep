"""User-run checks for text files over 64 MiB: chunked search and streamed read_file windows.
Usage: python tests/large_files.py dist/shgrep.exe
Builds a 72 MiB log (about 9 chunks) and compares shgrep's output with values computed here.
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from lsp_smoke import Client

LINES = 750_000


# Lines are 101 bytes with CRLF, so the 8 MiB chunks end near these line numbers; markers straddle each one.
BOUNDARIES = {round(k * (8 << 20) / 101) + d for k in range(1, 10) for d in range(-2, 3)}


def line_text(i):
    body = f"{i:08d} " + "x" * 90
    if i in BOUNDARIES or i in (5, 6, 7):
        body += " MARK"
    if i == 400_000:
        return (body + " bad \xff byte").encode("latin-1")  # one invalid UTF-8 byte, shown as U+FFFD
    return body.encode()


def main():
    executable = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="shgrep-large-", ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        raw_lines = [line_text(i) for i in range(1, LINES + 1)]
        data = b"\r\n".join(raw_lines) + b"\r\n"
        (root / "big.log").write_bytes(data)
        assert len(data) > 64 << 20, len(data)
        text_lines = [line.decode("utf-8", errors="replace") for line in raw_lines]
        marked = [n for n, line in enumerate(text_lines, 1) if "MARK" in line]
        client = Client(executable, root)
        try:
            # lines with one line of context: groups merge or split exactly as a whole-file scan would.
            out = client.tool("search", {"operation": "text", "pattern": "MARK", "context_lines": 1}, raw=True)
            body = out.split("\n", 1)[1] if out.startswith("[paths ") else out
            ranges = []
            for n in marked:
                first, last = max(1, n - 1), min(LINES, n + 1)
                if ranges and first <= ranges[-1][1] + 1:
                    ranges[-1][1] = max(ranges[-1][1], last)
                else:
                    ranges.append([first, last])
            expected = []
            for index, (first, last) in enumerate(ranges):
                if index:
                    expected.append("--")
                for n in range(first, last + 1):
                    separator = ":" if n in marked else "-"
                    expected.append(f"big.log{separator}{n}{separator}{text_lines[n - 1]}")
            assert body == "\n".join(expected) + "\n", (body[:2000], "\n".join(expected)[:2000])

            count = client.tool("search", {"operation": "text", "pattern": "MARK", "output": "count"}, raw=True)
            assert f"big.log:{len(marked)}" in count, count

            found = client.tool("search", {"operation": "text", "pattern": "MARK", "output": "json", "context_bytes": 16})
            results = json.loads(found["content"][0]["text"])["results"] if "content" in found else found["results"]
            assert len(results) == len(marked), len(results)
            for item in results:
                n = item["line"]
                start = sum(len(line) + 2 for line in raw_lines[:n - 1])
                assert item["byte_start"] == start + raw_lines[n - 1].index(b"MARK"), item

            # Anchors keep whole-file meaning: \A matches once, $ never at a chunk cut, ^$ nowhere (no empty lines).
            start = client.tool("search", {"operation": "text", "pattern": "\\A00000001", "output": "count"}, raw=True)
            assert "big.log:1\n" in start, start
            # CRLF lines: $ sits before \n, so "." takes the \r. Chunk cuts must neither add nor lose line ends.
            ends = client.tool("search", {"operation": "text", "pattern": "MARK.$", "output": "count"}, raw=True)
            assert f"big.log:{sum(1 for line in text_lines if line.endswith('MARK'))}\n" in ends, ends
            empty = client.tool("search", {"operation": "text", "pattern": "^$", "output": "count"}, raw=True)
            assert "No matches." in empty, empty
            invalid = client.tool("search", {"operation": "text", "pattern": "bad", "word": True}, raw=True)
            assert "big.log:400000:" in invalid and "�" in invalid, invalid

            # read_file streams the file and keeps only the window.
            header, *rows = client.tool("read_file", {"path": "big.log", "offset": 600_000, "limit": 3}, raw=True).splitlines()
            assert f"| {LINES} lines, {len(data)} bytes | utf-8, crlf, final newline" in header, header
            assert f"sha256 {hashlib.sha256(data).hexdigest()}" in header, header
            assert rows[:3] == [f"{n:6d}→{text_lines[n - 1]}" for n in range(600_000, 600_003)], rows
            assert rows[3].startswith("[status limit: showed lines 600000-600002 of 750000"), rows
            tail = client.tool("read_file", {"path": "big.log", "offset": LINES, "limit": 5}, raw=True).splitlines()
            assert tail[1] == f"{LINES:6d}→{text_lines[-1]}" and len(tail) == 2, tail
            print("Chunked search (lines, context, count, json, invalid UTF-8) and streamed read_file checks passed.")
        finally:
            client.close()


if __name__ == "__main__":
    main()
