"""User-run Serena edit port checks. Usage: python tests/serena_edits.py dist/shgrep.exe
Uses the protocol mock from lsp_smoke; real language servers are covered by lsp_live.py.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from lsp_smoke import TOOL_NAMES, Client
from mcp_protocol import continuation, lsp_call


def exercise(client, root):
    def edit(path, operation, error=False, **arguments):
        return client.tool("edit_file", {"path": path, "operation": operation, **arguments}, error=error, raw=True)

    def write(path, content):
        """Writes a fixture outside shgrep, then reads it through shgrep as an agent would: edits other than literal
        replacements need this session's latest read of the file (or expected_sha256)."""
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        if not path.endswith(".bin"):  # UTF-16 text holds NUL bytes too; only the binary fixture is unreadable
            client.tool("read_file", {"path": path}, raw=True)
        return target

    # Literal templates are verbatim; regex templates use Serena's $!N syntax.
    source = write("content.txt", b"left=one\r\nright=two\r\n")
    old = source.read_bytes()
    edit("content.txt", "replace_content", needle="left=one\n", repl="left=$!1\n", dry_run=True)
    assert source.read_bytes() == old
    edit("content.txt", "replace_content", needle="left=one\n", repl="left=$!1\n")
    assert source.read_bytes() == b"left=$!1\r\nright=two\r\n"
    edit("content.txt", "replace_content", mode="regex", needle=r"^(right)=(\w+)$", repl="$!2:$!1")
    assert source.read_bytes() == b"left=$!1\r\ntwo:right\r\n"
    before = source.read_bytes()
    for arguments in [
        {"needle": "absent", "repl": "x"},
        {"needle": "(", "repl": "x", "mode": "regex"},
        {"needle": "(right)", "repl": "$!99", "mode": "regex"},
        {"needle": "", "repl": "x"},
        {"needle": "right", "repl": "x", "expected_sha256": "0" * 64},
        {"needle": "right", "repl": "x", "new_text": "wrong field"},
    ]:
        edit("content.txt", "replace_content", error=True, **arguments)
        assert source.read_bytes() == before

    # Nonunique and overlapping multiline matches are refused before writing.
    duplicate = write("duplicates.txt", b"one one\n")
    edit("duplicates.txt", "replace_content", error=True, needle="one", repl="two")
    assert duplicate.read_bytes() == b"one one\n"
    edit("duplicates.txt", "replace_content", needle="one", repl="two", allow_multiple_occurrences=True)
    assert duplicate.read_bytes() == b"two two\n"
    ambiguous = write("ambiguous.txt", b"BEGIN\nBEGIN\nEND\n")
    edit("ambiguous.txt", "replace_content", error=True, mode="regex", needle="BEGIN.*?END", repl="changed")
    assert ambiguous.read_bytes() == b"BEGIN\nBEGIN\nEND\n"

    bulk_ambiguous = {"mode": "regex", "needle": "BEGIN.*?END", "repl": "changed"}
    listing = edit("ambiguous.txt", "replace_in_files", dry_run=True, **bulk_ambiguous)
    ambiguous_ids = re.findall(r"\[([^\]\r\n]+:\d+@[0-9a-f]{16})\]", listing)
    assert len(ambiguous_ids) == 1 and "ambiguous" in listing
    edit("ambiguous.txt", "replace_in_files", error=True, **bulk_ambiguous)
    edit("ambiguous.txt", "replace_in_files", occurrence_ids=ambiguous_ids, **bulk_ambiguous)
    assert ambiguous.read_bytes() == b"changed\n"
    costly = write("costly.txt", b"a" * 300000 + b"!")
    edit("costly.txt", "replace_content", error=True, mode="regex", needle="(a+)+$", repl="x", timeout_ms=10)
    assert costly.read_bytes() == b"a" * 300000 + b"!"

    # Empty matches retry a nonempty alternative at the same position, and advance by Unicode characters.
    zero = write("zero.txt", "😀a".encode())
    edit("zero.txt", "replace_content", mode="regex", needle=r"(?=😀)|a", repl="X", allow_multiple_occurrences=True)
    assert zero.read_text(encoding="utf-8") == "X😀X"
    optional = write("optional.txt", b"b")
    edit("optional.txt", "replace_content", mode="regex", needle=r"(a)?b", repl="$!1X")
    assert optional.read_bytes() == b"X"

    # Inclusive line ranges use shgrep's 1-based convention and preserve the underlying encoding.
    lines = write("lines.txt", b"\xff\xfe" + "one\r\ntwo\r\nthree".encode("utf-16-le"))
    edit("lines.txt", "replace_lines", start_line=2, end_line=2, new_text="second")
    assert lines.read_bytes() == b"\xff\xfe" + "one\r\nsecond\r\nthree".encode("utf-16-le")
    edit("lines.txt", "insert_at_line", line=4, new_text="four")
    assert lines.read_bytes() == b"\xff\xfe" + "one\r\nsecond\r\nthree\r\nfour\r\n".encode("utf-16-le")
    edit("lines.txt", "delete_lines", start_line=2, end_line=3)
    assert lines.read_bytes() == b"\xff\xfe" + "one\r\nfour\r\n".encode("utf-16-le")
    unchanged = lines.read_bytes()
    edit("lines.txt", "replace_lines", error=True, start_line=0, end_line=1, new_text="bad")
    edit("lines.txt", "delete_lines", error=True, start_line=1, end_line=99)
    assert lines.read_bytes() == unchanged
    empty = write("empty.txt", b"")
    edit("empty.txt", "insert_at_line", line=1, new_text="first")
    assert empty.read_bytes() == b"first\n"

    # Mixed endings outside the matched span are preserved byte for byte.
    mixed = write("mixed.txt", b"first\r\nsecond\nthird\r\n")
    edit("mixed.txt", "replace_content", needle="second", repl="changed")
    assert mixed.read_bytes() == b"first\r\nchanged\nthird\r\n"

    a = write("bulk/a.txt", b"old old\r\n")
    b = write("bulk/nested/β.txt", b"old\n")
    excluded = write("bulk/excluded/no.txt", b"old\n")
    ignored = write("bulk/ignored.txt", b"old\n")
    write("bulk/.ignore", b"ignored.txt\n")
    binary = write("bulk/blob.bin", b"old\x00old")
    args = {"needle": "old", "repl": "new", "paths_include_glob": "bulk/**/*.txt", "paths_exclude_glob": "bulk/excluded"}
    preview = edit("bulk", "replace_in_files", dry_run=True, **args)
    ids = re.findall(r"\[([^\]\r\n]+:\d+@[0-9a-f]{16})\]", preview)
    assert len(ids) == 3, preview
    assert a.read_bytes() == b"old old\r\n" and b.read_bytes() == b"old\n"
    edit("bulk", "replace_in_files", error=True, expected_count=4, **args)
    assert a.read_bytes() == b"old old\r\n" and b.read_bytes() == b"old\n"
    edit("bulk", "replace_in_files", occurrence_ids=[ids[1]], **args)
    assert a.read_bytes() == b"old new\r\n" and b.read_bytes() == b"old\n"
    # One stale ID aborts the whole selection, including the still-current ID from the other file.
    edit("bulk", "replace_in_files", error=True, occurrence_ids=[ids[0], ids[2]], **args)
    assert a.read_bytes() == b"old new\r\n" and b.read_bytes() == b"old\n"
    # A changed replacement template invalidates preview IDs as well.
    preview = edit("bulk", "replace_in_files", dry_run=True, **args)
    fresh = re.findall(r"\[([^\]\r\n]+:\d+@[0-9a-f]{16})\]", preview)
    edit("bulk", "replace_in_files", error=True, occurrence_ids=fresh, **{**args, "repl": "different"})
    # Content changes with the same timestamp still invalidate IDs.
    stamp = b.stat()
    b.write_bytes(b"old changed\n")
    os.utime(b, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    edit("bulk", "replace_in_files", error=True, occurrence_ids=fresh, **args)
    assert a.read_bytes() == b"old new\r\n"
    b.write_bytes(b"old\n")
    # Preflight rejects the later read-only file without committing the earlier file.
    os.chmod(b, stat.S_IREAD)
    try:
        edit("bulk", "replace_in_files", error=True, expected_count=2, **args)
        assert a.read_bytes() == b"old new\r\n"
    finally:
        os.chmod(b, stat.S_IREAD | stat.S_IWRITE)
    edit("bulk", "replace_in_files", expected_count=2, **args)
    assert a.read_bytes() == b"new new\r\n" and b.read_bytes() == b"new\n"
    assert excluded.read_bytes() == ignored.read_bytes() == b"old\n"
    assert binary.read_bytes() == b"old\x00old"
    # An explicit cap splits the preview, never cuts it: the part fits and names the rest; bytes stay unchanged.
    cap_args = {"needle": "new", "repl": "x" * 1000, "paths_include_glob": "bulk/**/*.txt"}
    capped = edit("bulk", "replace_in_files", dry_run=True, max_output_bytes=512, offload_output=False, **cap_args)
    assert len(capped.encode("utf-8")) <= 512 and continuation(capped), capped
    assert a.read_bytes() == b"new new\r\n"
    large = write("large.txt", b"x" * 60000)
    uncapped = edit("large.txt", "replace_content", needle="x" * 60000, repl="y" * 90000, dry_run=True, offload_output=False)
    assert len(uncapped) > 90000 and "y" * 90000 in uncapped and large.read_bytes() == b"x" * 60000, len(uncapped)
    # An explicit file permits non-LSP languages and still enforces configured root boundaries.
    edit("../outside.txt", "replace_content", error=True, needle="x", repl="y")

    # Symbol bodies strip boundary whitespace; indentation and BOM/CRLF outside the range survive.
    body = "function target()\r\n    return 1\r\nend\r\n"
    lua = write("layout.lua", b"\xef\xbb\xbf" + body.encode())
    edit("layout.lua", "symbol", name_path="target", new_text="\n  function target()\n    return 2\nend\n\n")
    assert lua.read_bytes() == b"\xef\xbb\xbf" + body.replace("return 1", "return 2").encode()
    # Requests that insert before a namespace don't force a blank separator (Serena's kind rule).
    edit("layout.lua", "insert_before", name_path="/root", new_text="-- header\n")
    assert lua.read_bytes().startswith(b"\xef\xbb\xbf-- header\r\nfunction")
    # Trailing newlines on insert_after collapse to one; caller-requested leading blanks survive.
    edit("layout.lua", "insert_after", name_path="target", new_text="\n\nfunction later()\n    return 3\nend\n\n\n")
    assert lua.read_bytes().endswith(b"end\r\n\r\n\r\nfunction later()\r\n    return 3\r\nend\r\n")
    edit("layout.lua", "safe_delete", name_path="later")
    assert b"function later" not in lua.read_bytes()
    # Code files take symbol edits only: a bulk text edit on layout.lua is refused and writes nothing.
    before = lua.read_bytes()
    edit("layout.lua", "replace_in_files", error=True, needle="return 2", repl="return 9", expected_count=1)
    assert lua.read_bytes() == before
    # A symbol edit refreshes the open document at once: the next read and the server both see the new bytes.
    reply = client.call("tools/call", lsp_call("edit.replace_in_symbol", {"path": "layout.lua", "name_path": "target",
                                                                         "needle": "return 2", "new_text": "return 9"}))
    assert not reply.get("isError"), reply
    selected = client.tool("read_file", {"path": "layout.lua", "name_path": "target"})
    assert "return 9" in selected["results"][0]["body"]
    assert selected["sha256"] == hashlib.sha256(lua.read_bytes()).hexdigest()
    assert "textDocument/didSave" in client.tool("search", {"path": "layout.lua", "operation": "hover",
        "name_path": "target"})["hover"]["contents"]["value"]


def main():
    executable = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="shgrep-serena-edit-") as directory:
        root = Path(directory)
        (root / ".shgrep").mkdir()
        (root / ".shgrep/lsp.json").write_text(json.dumps({"bundled": False, "servers": [{
            "language_id": "lua", "extensions": [".lua"],
            "command": [sys.executable, str(Path(__file__).with_name("lsp_smoke.py").resolve()), "--mock"],
            "settings": {"mock": {"live": True}},
        }]}), encoding="utf-8")
        client = Client(executable, root)
        try:
            assert [t["name"] for t in client.call("tools/list", {})["tools"]] == TOOL_NAMES
            exercise(client, root)
        finally:
            client.close()
    print("Serena content, bulk, line, and symbol edit checks passed.")


if __name__ == "__main__":
    main()
