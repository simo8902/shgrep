"""User-run checks for hardening fixes that the other suites do not exercise.
Usage: python tests/hardening.py dist/shgrep.exe
  1. cache signing: a forged db-cache file (another query's database under this query's key) is ignored
  2. root race: a requested root that is a junction flipping between inside and outside never yields outside files
  3. move re-planning: import edits planned from a stale index are planned again on the current bytes
  4. shared deadline: a rename whose timeout_ms runs out while it waits for the workspace writes nothing
  5. open-document cap: a bulk change of 300 files restarts the server instead of opening all of them
Checks 3-5 run the mock language server from lsp_smoke.py.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import _winapi

from lsp_smoke import Client

MOCK = [sys.executable, str(Path(__file__).with_name("lsp_smoke.py").resolve()), "--mock"]


def mock_config(root, *flags, indexed=False):
    (root / ".shgrep").mkdir(exist_ok=True)
    (root / ".shgrep" / "lsp.json").write_text(json.dumps({"bundled": False, "servers": [{
        "language_id": "lua", "extensions": [".lua"], "command": MOCK + list(flags),
        "indexes_workspace": indexed, "settings": {"mock": {"live": True}}}]}), encoding="utf-8")


def text_of(result):
    return result["content"][0]["text"]


def check_cache_signing(executable):
    with tempfile.TemporaryDirectory(prefix="shgrep-hard-", ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        (root / "data.txt").write_text("zqa0005abc_12x\nzqb0007abc_12x\n", encoding="utf-8")
        queries = {name: [f"zq{name}{i:04d}[a-z]+_[0-9]{{2,}}x" for i in range(150)] for name in ("a", "b")}

        def search(name):
            command = [str(executable), "search", "--root", str(root)]
            for pattern in queries[name]:
                command += ["-e", pattern]
            return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", check=True).stdout

        assert "zqa0005" in search("a") and "zqb0007" in search("b")
        cache = sorted((root / ".shgrep" / "db-cache").glob("*.hsdb"))
        assert len(cache) == 2, f"expected both compiled queries cached, found {cache}"
        parts = {}
        for path in cache:
            data = path.read_bytes()
            assert data[:8] == b"SHGDB002", data[:8]
            key_length = int.from_bytes(data[8:16], "little")
            key = data[16:16 + key_length]
            parts["a" if b"zqa0000" in key else "b"] = (path, data[:16 + key_length], data[16 + key_length:])
        # Query a's header (its key) over query b's signature and database: only the MAC can tell them apart.
        target, header, _ = parts["a"]
        target.write_bytes(header + parts["b"][2])
        out = search("a")
        assert "zqa0005" in out and "zqb0007" not in out, out
        print("PASS  cache signing: a forged database under a valid key is ignored")


def check_root_race(executable):
    with tempfile.TemporaryDirectory(prefix="shgrep-hard-", ignore_cleanup_errors=True) as directory, \
         tempfile.TemporaryDirectory(prefix="shgrep-outside-", ignore_cleanup_errors=True) as outside:
        root = Path(directory)
        (root / "real").mkdir()
        (root / "real" / "inside.txt").write_text("marker INSIDE\n", encoding="utf-8")
        (Path(outside) / "secret.txt").write_text("marker OUTSIDE\n", encoding="utf-8")
        link = root / "link"
        _winapi.CreateJunction(str(root / "real"), str(link))
        stop = threading.Event()

        def flip():
            targets = [Path(outside), root / "real"]
            # Each target is held for a few ms: long enough that searches start inside, short enough that a flip
            # lands between validating the root and walking it.
            while not stop.is_set():
                for target in targets:
                    try:
                        link.rmdir()
                        _winapi.CreateJunction(str(target), str(link))
                    except OSError:
                        pass
                    time.sleep(0.004)
        flipper = threading.Thread(target=flip, daemon=True)
        client = Client(executable, root)
        flipper.start()
        try:
            walked = 0
            for _ in range(200):
                reply = client.call("tools/call", {"name": "search", "arguments": {
                    "operation": "text", "pattern": "marker", "roots": [str(link)], "paths": "absolute"}})
                text = text_of(reply)
                assert "OUTSIDE" not in text, text
                walked += "INSIDE" in text
        finally:
            stop.set()
            flipper.join()
            client.close()
        assert walked >= 20, f"only {walked} of 200 searches ran inside; the race was barely exercised"
        print(f"PASS  root race: 200 searches through a flipping junction, {walked} walked inside, none outside")


def check_move_replanning(executable):
    with tempfile.TemporaryDirectory(prefix="shgrep-hard-", ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        mock_config(root, "--index", indexed=True)
        (root / "main.lua").write_text("function main_thing()\n    return 1\nend\n", encoding="utf-8")
        user = root / "user.lua"
        user.write_text('local x = 1\nlocal m = require("main")\nreturn m\n', encoding="utf-8")
        client = Client(executable, root)
        try:
            client.tool("move_file", {"source": "main.lua", "destination": "moved.lua", "operation": "refactor"}, raw=True)
        finally:
            client.close()
        # The mock's first plan for the unopened user.lua is one line off; applied as is it would garble "return m".
        assert user.read_text(encoding="utf-8") == 'local x = 1\nlocal m = require("moved")\nreturn m\n', user.read_text()
        assert (root / "moved.lua").is_file() and not (root / "main.lua").exists()
        print("PASS  move re-planning: stale import edits were planned again on the current bytes")


class RawClient:
    """Sends several MCP requests before reading their replies, so the server runs them concurrently."""

    def __init__(self, executable, root):
        self.process = subprocess.Popen([str(executable), "--root", str(root)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.replies = {}
        self.send(0, "initialize", {"protocolVersion": "2025-06-18"})
        self.wait(0, 30)

    def send(self, request_id, method, params):
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode() + b"\n")
        self.process.stdin.flush()

    def wait(self, request_id, timeout):
        deadline = time.monotonic() + timeout
        while request_id not in self.replies:
            assert time.monotonic() < deadline, f"no reply to {request_id}"
            message = json.loads(self.process.stdout.readline())
            self.replies[message.get("id")] = message
        return self.replies[request_id]

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=10)


def check_shared_deadline(executable):
    with tempfile.TemporaryDirectory(prefix="shgrep-hard-", ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        mock_config(root)
        (root / "hang.lua").write_text("function slow_one()\n    return 1\nend\n--HANG3\n", encoding="utf-8")
        other = root / "other.lua"
        before = "function target()\n    return 1\nend\n--SLOWRENAME\n"
        other.write_text(before, encoding="utf-8")
        client = RawClient(executable, root)
        try:
            # A holds the workspace for about 3 s (documentSymbol sleeps); B's 4 s budget starts while it waits, and
            # the mock's rename then takes 2 s more. With one deadline for the whole request, B must not commit.
            client.send(1, "tools/call", {"name": "read_file", "arguments": {"path": "hang.lua", "timeout_ms": 20000}})
            time.sleep(0.3)
            started = time.monotonic()
            client.send(2, "tools/call", {"name": "edit_file", "arguments": {
                "path": "other.lua", "operation": "rename", "name_path": "target", "new_name": "renamed", "timeout_ms": 4000}})
            reply = client.wait(2, 30)["result"]
            elapsed = time.monotonic() - started
            client.wait(1, 30)
        finally:
            client.close()
        assert reply.get("isError"), reply
        assert other.read_text(encoding="utf-8") == before, "the rename was written after its deadline"
        assert elapsed < 6, f"B returned after {elapsed:.1f} s, past its 4 s budget plus slack"
        print(f"PASS  shared deadline: the late rename failed after {elapsed:.1f} s and wrote nothing")


def check_open_document_cap(executable):
    with tempfile.TemporaryDirectory(prefix="shgrep-hard-", ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        mock_config(root, indexed=True)
        (root / "probe.lua").write_text("function probe()\n    return 1\nend\n", encoding="utf-8")
        files = [root / f"f{i:03}.lua" for i in range(300)]
        for i, path in enumerate(files):
            path.write_text(f"function f_{i}()\n    return 1\nend\n", encoding="utf-8")
        client = Client(executable, root)
        try:
            client.tool("read_file", {"path": "probe.lua"})
            for path in files:
                path.write_text(path.read_text(encoding="utf-8") + "-- changed\n", encoding="utf-8")
            time.sleep(1)  # let the folder watcher report the changes
            client.tool("read_file", {"path": "probe.lua"})
            status = client.tool("file_info", {"path": "probe.lua", "operation": "lsp"})
            found = client.tool("search", {"path": "f005.lua", "pattern": "f_5"})["results"]
        finally:
            client.close()
        assert status["open_documents"] <= 40, f"{status['open_documents']} documents open after a 300-file change"
        assert found, "the restarted server lost track of current files"
        print(f"PASS  open-document cap: 300 changed files left {status['open_documents']} documents open")


def main():
    executable = Path(sys.argv[1]).resolve()
    for check in (check_cache_signing, check_root_race, check_move_replanning, check_shared_deadline, check_open_document_cap):
        check(executable)
    print("Hardening checks passed.")


if __name__ == "__main__":
    main()
